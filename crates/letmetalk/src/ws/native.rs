use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::SinkExt;
use futures::StreamExt;
use futures::future::BoxFuture;
use rustls::ClientConfig;
use tokio::sync::{Mutex as AsyncMutex, mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::{Message, http::Uri};
use tokio_tungstenite::{Connector, MaybeTlsStream, WebSocketStream};

use super::wire::{self, Down, MAX_ENVELOPE, Up};
use crate::{IceServer, PublicKey, SecretKey, Signal};

const RETRY: Duration = Duration::from_secs(2);

type Ws = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

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

/// A forwarder client. It logs in in the background, and again after a drop.
pub struct WsSignal {
    shared: Arc<Shared>,
    inbox: AsyncMutex<mpsc::UnboundedReceiver<Vec<u8>>>,
    task: JoinHandle<()>,
}

impl WsSignal {
    /// `wss://` only, except to loopback. Any other URL stops the carrier at once.
    pub fn new(url: &str, key: &SecretKey) -> WsSignal {
        let (inbox_tx, inbox) = mpsc::unbounded_channel();
        let shared = Arc::new(Shared::default());
        let task = tokio::spawn(run(url.to_owned(), key.clone(), shared.clone(), inbox_tx));
        WsSignal {
            shared,
            inbox: AsyncMutex::new(inbox),
            task,
        }
    }
}

impl Drop for WsSignal {
    fn drop(&mut self) {
        self.task.abort();
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
            out.send(Request { to, envelope, ack })
                .map_err(|_| io::ErrorKind::NotConnected)?;
            done.await.map_err(|_| io::ErrorKind::NotConnected)?
        })
    }

    fn recv(&self) -> BoxFuture<'_, Option<Vec<u8>>> {
        Box::pin(async { self.inbox.lock().await.recv().await })
    }

    fn ice_servers(&self) -> Vec<IceServer> {
        self.shared.ice.lock().unwrap().clone()
    }
}

async fn run(
    url: String,
    key: SecretKey,
    shared: Arc<Shared>,
    inbox: mpsc::UnboundedSender<Vec<u8>>,
) {
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
        match session(&url, host, &key, &shared, &inbox)
            .await
            .unwrap_or(Ended::Dropped)
        {
            Ended::Replaced => return,
            Ended::Dropped => tokio::time::sleep(RETRY).await,
        }
    }
}

async fn session(
    url: &str,
    host: &str,
    key: &SecretKey,
    shared: &Shared,
    inbox: &mpsc::UnboundedSender<Vec<u8>>,
) -> io::Result<Ended> {
    let (mut ws, _) =
        tokio_tungstenite::connect_async_tls_with_config(url, None, false, Some(connector()))
            .await
            .map_err(io::Error::other)?;
    let Some(Ok(Message::Binary(challenge))) = ws.next().await else {
        return Err(io::ErrorKind::InvalidData.into());
    };
    let login = wire::answer(key, host, &challenge)?;
    ws.send(Message::Binary(login.to_vec().into()))
        .await
        .map_err(io::Error::other)?;
    let Down::Ice(ice) = next_down(&mut ws).await? else {
        return Err(io::ErrorKind::InvalidData.into());
    };
    *shared.ice.lock().unwrap() = ice;

    let (out_tx, mut out_rx) = mpsc::unbounded_channel();
    *shared.out.lock().unwrap() = Some(out_tx);
    let mut pending = HashMap::new();
    let mut next_id = 0u32;
    let ended = loop {
        tokio::select! {
            down = next_down(&mut ws) => match down {
                Ok(Down::Deliver(envelope)) => {
                    let _ = inbox.send(envelope);
                }
                Ok(Down::Passed(id)) => ack(&mut pending, id, Ok(())),
                Ok(Down::Offline(id)) => ack(&mut pending, id, Err(io::ErrorKind::HostUnreachable.into())),
                Ok(Down::Limited(id)) => ack(&mut pending, id, Err(io::ErrorKind::ResourceBusy.into())),
                Ok(Down::Ice(ice)) => *shared.ice.lock().unwrap() = ice,
                Ok(Down::Replaced) => break Ended::Replaced,
                Err(_) => break Ended::Dropped,
            },
            Some(req) = out_rx.recv() => {
                next_id = next_id.wrapping_add(1);
                pending.insert(next_id, req.ack);
                let up = Up { id: next_id, to: req.to, envelope: req.envelope };
                if ws.send(Message::Binary(up.encode().into())).await.is_err() {
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

fn connector() -> Connector {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .expect("ring supports the default protocol versions")
            .with_root_certificates(roots)
            .with_no_client_auth();
    Connector::Rustls(Arc::new(config))
}

async fn next_down(ws: &mut Ws) -> io::Result<Down> {
    loop {
        match ws.next().await {
            Some(Ok(Message::Binary(frame))) => return Down::decode(&frame),
            Some(Ok(Message::Close(_))) | None => return Err(io::ErrorKind::ConnectionReset.into()),
            Some(Err(e)) => return Err(io::Error::other(e)),
            Some(Ok(_)) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::net::TcpListener;
    use tokio_tungstenite::accept_async;

    use super::*;

    #[tokio::test]
    async fn refuses_plain_ws_to_a_remote_host() {
        let signal = WsSignal::new("ws://example.com/ws", &SecretKey::from_bytes([1; 32]));
        assert!(signal.recv().await.is_none());
    }

    #[tokio::test]
    async fn sends_no_login_for_a_zero_challenge() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}/ws", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = accept_async(stream).await.unwrap();
            ws.send(Message::Binary(vec![0; 32].into())).await.unwrap();
            let next = tokio::time::timeout(Duration::from_millis(500), ws.next()).await;
            !matches!(next, Ok(Some(Ok(Message::Binary(_)))))
        });
        let _signal = WsSignal::new(&url, &SecretKey::from_bytes([1; 32]));
        assert!(server.await.unwrap());
    }
}
