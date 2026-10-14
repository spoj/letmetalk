use std::io;
#[cfg(feature = "stats")]
use std::time::Duration;

use futures::future::BoxFuture;

/// The selected candidate pair of a link: each side's candidate type (`host`, `srflx`, `prflx` or `relay`), and the
/// round-trip time of its latest check, zero until one is answered.
#[cfg(feature = "stats")]
#[derive(Clone, Debug, PartialEq)]
pub struct Path {
    pub local: String,
    pub remote: String,
    pub rtt: Duration,
}

#[cfg(feature = "stats")]
impl Path {
    pub fn relayed(&self) -> bool {
        self.local == "relay" || self.remote == "relay"
    }
}

/// What a peer connection reports. Channels are numbered by letmetalk; channel 0 is the control channel.
pub(crate) enum Event {
    Candidate(String),
    Connected,
    Disconnected,
    Failed,
    Ready(u32),
    Opened(u32),
    Message(u32, Vec<u8>),
    Closed(u32),
}

/// One WebRTC peer connection: the native webrtc-rs backend, the browser's own, or the in-memory fake.
pub(crate) trait Peer: Send + Sync {
    /// Creates the control channel and returns the offer, with candidates arriving as events.
    fn offer(&self) -> BoxFuture<'_, io::Result<String>>;
    /// Applies an offer and returns the answer.
    fn answer(&self, offer: &str) -> BoxFuture<'_, io::Result<String>>;
    fn accept(&self, answer: &str) -> BoxFuture<'_, io::Result<()>>;
    fn candidate(&self, candidate: String) -> BoxFuture<'_, io::Result<()>>;
    /// Creates a channel. It reports `Ready` once it is open.
    fn open(&self, channel: u32) -> BoxFuture<'_, io::Result<()>>;
    fn send(&self, channel: u32, data: Vec<u8>) -> BoxFuture<'_, io::Result<()>>;
    fn close_channel(&self, channel: u32) -> BoxFuture<'_, ()>;
    /// The next event; None once the connection is gone.
    fn next(&self) -> BoxFuture<'_, Option<Event>>;
    fn close(&self) -> BoxFuture<'_, ()>;
    /// Wakes the connection's driver, so that what it has queued goes out. webrtc-rs sends what a packet or event
    /// queues only at its next wake-up, which can be a 200 ms timer away.
    fn kick(&self) -> BoxFuture<'_, ()>;
    #[cfg(feature = "stats")]
    fn path(&self) -> BoxFuture<'_, Option<Path>>;
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) use crate::native::peer;

#[cfg(target_arch = "wasm32")]
pub(crate) use crate::web::peer;
