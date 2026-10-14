//! An in-memory peer pair for tests. The pair starts connected; signaling is not modelled.

use std::io;
use std::sync::Arc;

use futures::channel::mpsc::{UnboundedReceiver, UnboundedSender, unbounded};
use futures::future::BoxFuture;
use futures::lock::Mutex;
use futures::StreamExt;

use crate::backend::{Event, Peer};

pub(crate) struct Fake {
    events: Mutex<UnboundedReceiver<Event>>,
    own: UnboundedSender<Event>,
    other: UnboundedSender<Event>,
}

pub(crate) fn pair() -> (Arc<dyn Peer>, Arc<dyn Peer>) {
    let (a_tx, a_rx) = unbounded();
    let (b_tx, b_rx) = unbounded();
    let a = Fake { events: Mutex::new(a_rx), own: a_tx.clone(), other: b_tx.clone() };
    let b = Fake { events: Mutex::new(b_rx), own: b_tx, other: a_tx };
    (Arc::new(a), Arc::new(b))
}

fn gone() -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionReset, "fake peer is gone")
}

impl Peer for Fake {
    fn offer(&self) -> BoxFuture<'_, io::Result<String>> {
        Box::pin(async { unreachable!("the fake pair starts connected") })
    }

    fn answer(&self, _offer: &str) -> BoxFuture<'_, io::Result<String>> {
        Box::pin(async { unreachable!("the fake pair starts connected") })
    }

    fn accept(&self, _answer: &str) -> BoxFuture<'_, io::Result<()>> {
        Box::pin(async { unreachable!("the fake pair starts connected") })
    }

    fn candidate(&self, _candidate: String) -> BoxFuture<'_, io::Result<()>> {
        Box::pin(async { unreachable!("the fake pair starts connected") })
    }

    fn open(&self, channel: u32) -> BoxFuture<'_, io::Result<()>> {
        Box::pin(async move {
            self.other.unbounded_send(Event::Opened(channel)).map_err(|_| gone())?;
            self.own.unbounded_send(Event::Ready(channel)).map_err(|_| gone())
        })
    }

    fn send(&self, channel: u32, data: Vec<u8>) -> BoxFuture<'_, io::Result<()>> {
        Box::pin(async move {
            self.other.unbounded_send(Event::Message(channel, data)).map_err(|_| gone())
        })
    }

    fn close_channel(&self, channel: u32) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            let _ = self.other.unbounded_send(Event::Closed(channel));
            let _ = self.own.unbounded_send(Event::Closed(channel));
        })
    }

    fn kick(&self) -> BoxFuture<'_, ()> {
        Box::pin(async {})
    }

    fn next(&self) -> BoxFuture<'_, Option<Event>> {
        Box::pin(async { self.events.lock().await.next().await })
    }

    fn close(&self) -> BoxFuture<'_, ()> {
        Box::pin(async { let _ = self.other.unbounded_send(Event::Failed); })
    }

    #[cfg(feature = "stats")]
    fn path(&self) -> BoxFuture<'_, Option<crate::backend::Path>> {
        Box::pin(async { None })
    }
}
