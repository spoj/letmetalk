//! An in-memory peer pair for tests. The pair starts with every channel open; signaling is not modelled.

use std::io;
use std::sync::Arc;

use futures::StreamExt;
use futures::channel::mpsc::{UnboundedReceiver, UnboundedSender, unbounded};
use futures::future::BoxFuture;
use futures::lock::Mutex;

use crate::backend::{CHANNELS, Event, Peer};

pub(crate) struct Fake {
    events: Mutex<UnboundedReceiver<Event>>,
    other: UnboundedSender<Event>,
}

pub(crate) fn pair() -> (Arc<Fake>, Arc<Fake>) {
    let (a_tx, a_rx) = unbounded();
    let (b_tx, b_rx) = unbounded();
    for channel in 0..CHANNELS {
        a_tx.unbounded_send(Event::Ready(channel)).expect("fresh queue");
        b_tx.unbounded_send(Event::Opened(channel)).expect("fresh queue");
    }
    let a = Fake { events: Mutex::new(a_rx), other: b_tx };
    let b = Fake { events: Mutex::new(b_rx), other: a_tx };
    (Arc::new(a), Arc::new(b))
}

impl Fake {
    /// Queues an event on the other side, as a channel of its peer connection would report it.
    pub(crate) fn tell(&self, event: Event) {
        let _ = self.other.unbounded_send(event);
    }
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

    fn send(&self, channel: u32, data: Vec<u8>) -> BoxFuture<'_, io::Result<()>> {
        Box::pin(async move {
            self.other.unbounded_send(Event::Message(channel, data)).map_err(|_| gone())
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
