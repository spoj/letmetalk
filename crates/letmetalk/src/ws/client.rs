//! The forwarder client on both targets: login, routing, liveness and reconnects, over a platform socket.

use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::channel::{mpsc, oneshot};
use futures::future::BoxFuture;
use futures::lock::Mutex as AsyncMutex;
use futures::{FutureExt, StreamExt};
use http::Uri;
use n0_future::task::{AbortOnDropHandle, spawn};
use n0_future::time::{sleep, timeout};

#[cfg(not(target_arch = "wasm32"))]
use super::native::Socket;
#[cfg(target_arch = "wasm32")]
use super::web::Socket;
use super::wire::{self, Down, MAX_ENVELOPE, Up};
use crate::{IceServer, PublicKey, SecretKey, Signal};

const TIMEOUT: Duration = Duration::from_secs(10);
const SILENT: Duration = Duration::from_secs(15);
const RETRY: Duration = Duration::from_secs(2);
const INBOX: usize = 256;

struct Request {
    to: PublicKey,
    envelope: Vec<u8>,
    ack: oneshot::Sender<io::Result<()>>,
}

#[derive(Default)]
struct Shared {
    ice: Mutex<Vec<IceServer>>,
    out: Mutex<Option<mpsc::UnboundedSender<Request>>>,
}

enum Ended {
    Replaced,
    Dropped,
}

enum Step {
    Frame(io::Result<Vec<u8>>),
    Request(Request),
    Silent,
}

/// A forwarder client. It logs in in the background, and again after a drop.
pub struct WsSignal {
    shared: Arc<Shared>,
    inbox: AsyncMutex<mpsc::Receiver<Vec<u8>>>,
    _task: AbortOnDropHandle<()>,
}

impl WsSignal {
    /// `wss://` only, except to loopback. Any other URL stops the carrier at once.
    pub fn new(url: &str, key: &SecretKey) -> WsSignal {
        let (inbox_tx, inbox) = mpsc::channel(INBOX);
        let shared = Arc::new(Shared::default());
        let task = spawn(run(url.to_owned(), key.clone(), shared.clone(), inbox_tx));
        WsSignal {
            shared,
            inbox: AsyncMutex::new(inbox),
            _task: AbortOnDropHandle::new(task),
        }
    }
}

impl Signal for WsSignal {
    fn send(&self, to: PublicKey, envelope: Vec<u8>) -> BoxFuture<'static, io::Result<()>> {
        if envelope.len() > MAX_ENVELOPE {
            return Box::pin(async { Err(io::ErrorKind::InvalidInput.into()) });
        }
        let out = self.shared.out.lock().unwrap().clone();
        Box::pin(async move {
            let out = out.ok_or(io::ErrorKind::NotConnected)?;
            let (ack, done) = oneshot::channel();
            out.unbounded_send(Request { to, envelope, ack })
                .map_err(|_| io::ErrorKind::NotConnected)?;
            done.await.map_err(|_| io::ErrorKind::NotConnected)?
        })
    }

    fn recv(&self) -> BoxFuture<'_, Option<Vec<u8>>> {
        Box::pin(async { self.inbox.lock().await.next().await })
    }

    fn ice_servers(&self) -> Vec<IceServer> {
        self.shared.ice.lock().unwrap().clone()
    }
}

async fn run(url: String, key: SecretKey, shared: Arc<Shared>, mut inbox: mpsc::Sender<Vec<u8>>) {
    let Ok(uri) = url.parse::<Uri>() else { return };
    let Some(host) = uri.host() else { return };
    let loopback = matches!(host, "localhost" | "127.0.0.1" | "[::1]");
    let secure = match uri.scheme_str() {
        Some("wss") => true,
        Some("ws") => loopback,
        _ => false,
    };
    if !secure {
        return;
    }
    loop {
        match session(&url, host, &key, &shared, &mut inbox)
            .await
            .unwrap_or(Ended::Dropped)
        {
            Ended::Replaced => return,
            Ended::Dropped => {
                let mut bytes = [0; 2];
                getrandom::fill(&mut bytes).expect("OS randomness");
                let jitter = Duration::from_millis(u64::from(u16::from_be_bytes(bytes)) % 2000);
                sleep(RETRY + jitter).await;
            }
        }
    }
}

async fn login(url: &str, host: &str, key: &SecretKey) -> io::Result<(Socket, Vec<IceServer>)> {
    let mut socket = Socket::connect(url).await?;
    let challenge = socket.recv().await?;
    let login = wire::answer(key, host, &challenge)?;
    socket.send(login.to_vec()).await?;
    let Down::Ice(ice) = Down::decode(&socket.recv().await?)? else {
        return Err(io::ErrorKind::InvalidData.into());
    };
    Ok((socket, ice))
}

async fn session(
    url: &str,
    host: &str,
    key: &SecretKey,
    shared: &Shared,
    inbox: &mut mpsc::Sender<Vec<u8>>,
) -> io::Result<Ended> {
    let (mut socket, ice) = timeout(TIMEOUT, login(url, host, key))
        .await
        .map_err(io::Error::other)??;
    *shared.ice.lock().unwrap() = ice;

    let (out_tx, mut out_rx) = mpsc::unbounded();
    *shared.out.lock().unwrap() = Some(out_tx);
    let mut pending = HashMap::new();
    let mut next_id = 0u32;
    let mut silent = Box::pin(sleep(SILENT).fuse());
    let ended = loop {
        let step = futures::select! {
            frame = socket.recv().fuse() => Step::Frame(frame),
            req = out_rx.select_next_some() => Step::Request(req),
            _ = silent.as_mut() => Step::Silent,
        };
        match step {
            Step::Silent => break Ended::Dropped,
            Step::Frame(frame) => {
                silent.set(sleep(SILENT).fuse());
                match frame.and_then(|frame| Down::decode(&frame)) {
                    Ok(Down::Deliver(envelope)) => {
                        let _ = inbox.try_send(envelope);
                    }
                    Ok(Down::Passed(id)) => ack(&mut pending, id, Ok(())),
                    Ok(Down::Offline(id)) => ack(&mut pending, id, Err(io::ErrorKind::HostUnreachable.into())),
                    Ok(Down::Limited(id)) => ack(&mut pending, id, Err(io::ErrorKind::ResourceBusy.into())),
                    Ok(Down::Ice(ice)) => *shared.ice.lock().unwrap() = ice,
                    Ok(Down::Alive) => {}
                    Ok(Down::Replaced) => break Ended::Replaced,
                    Err(_) => break Ended::Dropped,
                }
            }
            Step::Request(req) => {
                pending.retain(|_, reply| !reply.is_canceled());
                next_id = next_id.wrapping_add(1);
                pending.insert(next_id, req.ack);
                let up = Up { id: next_id, to: req.to, envelope: req.envelope };
                let sent = timeout(SILENT, socket.send(up.encode())).await;
                if !matches!(sent, Ok(Ok(()))) {
                    break Ended::Dropped;
                }
            }
        }
    };
    *shared.out.lock().unwrap() = None;
    Ok(ended)
}

fn ack(
    pending: &mut HashMap<u32, oneshot::Sender<io::Result<()>>>,
    id: u32,
    result: io::Result<()>,
) {
    if let Some(ack) = pending.remove(&id) {
        let _ = ack.send(result);
    }
}
