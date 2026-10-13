//! An in-memory carrier: envelopes go straight to the recipient's inbox.

use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex};

use futures::StreamExt;
use futures::channel::mpsc::{UnboundedReceiver, UnboundedSender, unbounded};
use futures::future::BoxFuture;
use futures::lock::Mutex as AsyncMutex;
use letmetalk::{IceServer, PublicKey, SecretKey, Signal};

#[derive(Clone, Default)]
pub struct Hub(Arc<Mutex<HashMap<PublicKey, UnboundedSender<Vec<u8>>>>>);

pub struct Carrier {
    hub: Hub,
    inbox: AsyncMutex<UnboundedReceiver<Vec<u8>>>,
}

impl Carrier {
    pub fn join(hub: &Hub, key: &SecretKey) -> Carrier {
        let (tx, rx) = unbounded();
        hub.0.lock().unwrap().insert(key.public(), tx);
        Carrier { hub: hub.clone(), inbox: AsyncMutex::new(rx) }
    }
}

impl Signal for Carrier {
    fn send(&self, to: PublicKey, envelope: Vec<u8>) -> BoxFuture<'static, io::Result<()>> {
        let target = self.hub.0.lock().unwrap().get(&to).cloned();
        Box::pin(async move {
            let target = target.ok_or_else(|| io::Error::new(io::ErrorKind::HostUnreachable, "offline"))?;
            target.unbounded_send(envelope).map_err(|_| io::Error::new(io::ErrorKind::HostUnreachable, "offline"))
        })
    }

    fn recv(&self) -> BoxFuture<'_, Option<Vec<u8>>> {
        Box::pin(async { self.inbox.lock().await.next().await })
    }

    fn ice_servers(&self) -> Vec<IceServer> {
        Vec::new()
    }
}
