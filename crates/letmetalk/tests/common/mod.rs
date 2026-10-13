#![allow(dead_code)]

//! An in-memory carrier: envelopes go straight to the recipient's inbox. The hub logs what was sent, can inject
//! envelopes, redirect one key's envelopes to another, and hand out a TURN server.

use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex};

use futures::StreamExt;
use futures::channel::mpsc::{UnboundedReceiver, UnboundedSender, unbounded};
use futures::future::BoxFuture;
use futures::lock::Mutex as AsyncMutex;
use letmetalk::{Endpoint, IceServer, PublicKey, SecretKey, Signal};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Default)]
struct Net {
    inboxes: HashMap<PublicKey, UnboundedSender<Vec<u8>>>,
    redirects: HashMap<(PublicKey, PublicKey), PublicKey>,
    sent: Vec<(PublicKey, PublicKey, Vec<u8>)>,
    turn: Vec<IceServer>,
}

#[derive(Clone, Default)]
pub struct Hub(Arc<Mutex<Net>>);

impl Hub {
    /// Envelopes from `from` addressed to `to` are delivered to `instead`.
    pub fn redirect(&self, from: PublicKey, to: PublicKey, instead: PublicKey) {
        self.0.lock().unwrap().redirects.insert((from, to), instead);
    }

    pub fn inject(&self, to: PublicKey, envelope: Vec<u8>) {
        let inbox = self.0.lock().unwrap().inboxes.get(&to).cloned();
        let _ = inbox.unwrap().unbounded_send(envelope);
    }

    /// Every envelope sent so far, as (sender, recipient, envelope).
    pub fn sent(&self) -> Vec<(PublicKey, PublicKey, Vec<u8>)> {
        self.0.lock().unwrap().sent.clone()
    }

    pub fn with_turn(&self, server: IceServer) {
        self.0.lock().unwrap().turn = vec![server];
    }
}

pub struct Carrier {
    hub: Hub,
    me: PublicKey,
    inbox: AsyncMutex<UnboundedReceiver<Vec<u8>>>,
}

impl Carrier {
    pub fn join(hub: &Hub, key: &SecretKey) -> Carrier {
        let (tx, rx) = unbounded();
        hub.0.lock().unwrap().inboxes.insert(key.public(), tx);
        Carrier { hub: hub.clone(), me: key.public(), inbox: AsyncMutex::new(rx) }
    }
}

impl Signal for Carrier {
    fn send(&self, to: PublicKey, envelope: Vec<u8>) -> BoxFuture<'static, io::Result<()>> {
        let target = {
            let mut net = self.hub.0.lock().unwrap();
            let to = net.redirects.get(&(self.me, to)).copied().unwrap_or(to);
            net.sent.push((self.me, to, envelope.clone()));
            net.inboxes.get(&to).cloned()
        };
        Box::pin(async move {
            let target = target.ok_or_else(|| io::Error::new(io::ErrorKind::HostUnreachable, "offline"))?;
            target.unbounded_send(envelope).map_err(|_| io::Error::new(io::ErrorKind::HostUnreachable, "offline"))
        })
    }

    fn recv(&self) -> BoxFuture<'_, Option<Vec<u8>>> {
        Box::pin(async { self.inbox.lock().await.next().await })
    }

    fn ice_servers(&self) -> Vec<IceServer> {
        self.hub.0.lock().unwrap().turn.clone()
    }
}

/// Echoes every stream that `b` accepts, once its sender has finished.
pub async fn serve(b: Endpoint) {
    while let Some(mut stream) = b.accept().await {
        n0_future::task::spawn(async move {
            let mut data = Vec::new();
            stream.read_to_end(&mut data).await.unwrap();
            stream.write_all(&data).await.unwrap();
            stream.shutdown().await.unwrap();
        });
    }
}

pub async fn round_trip(a: &Endpoint, to: PublicKey) -> io::Result<()> {
    let mut stream = a.connect(to, "echo").await?;
    stream.write_all(b"ping").await?;
    stream.shutdown().await?;
    let mut echoed = Vec::new();
    stream.read_to_end(&mut echoed).await?;
    assert_eq!(echoed, b"ping");
    Ok(())
}
