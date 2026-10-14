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

/// Channel 0 is the control channel, and channels 1 to `LANES` are the lanes. The dialer creates them all before its
/// offer, labelled by their numbers.
pub(crate) const LANES: u32 = 4;
pub(crate) const CHANNELS: u32 = LANES + 1;

/// What a peer connection reports. `Ready` is a channel this side created, `Opened` one the peer created.
pub(crate) enum Event {
    Candidate(String),
    Connected,
    Disconnected,
    Failed,
    Ready(u32),
    Opened(u32),
    Message(u32, Vec<u8>),
    Closed,
}

/// One WebRTC peer connection: the native webrtc-rs backend, the browser's own, or the in-memory fake.
pub(crate) trait Peer: Send + Sync {
    /// Creates the control channel and the lanes, and returns the offer, with candidates arriving as events.
    fn offer(&self) -> BoxFuture<'_, io::Result<String>>;
    /// Applies an offer and returns the answer.
    fn answer(&self, offer: &str) -> BoxFuture<'_, io::Result<String>>;
    fn accept(&self, answer: &str) -> BoxFuture<'_, io::Result<()>>;
    fn candidate(&self, candidate: String) -> BoxFuture<'_, io::Result<()>>;
    fn send(&self, channel: u32, data: Vec<u8>) -> BoxFuture<'_, io::Result<()>>;
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

/// Refuses a peer's SDP that carries candidates or ice-lite, which would aim ICE checks at this side, or that does not
/// pin DTLS to exactly one SHA-256 certificate.
pub(crate) fn check_sdp(sdp: &str) -> io::Result<()> {
    let lines: Vec<&str> = sdp.lines().collect();
    let aimed = lines.iter().any(|l| l.starts_with("a=candidate") || *l == "a=ice-lite");
    let prints = lines.iter().filter(|l| l.starts_with("a=fingerprint:")).count();
    let sha256 = lines.iter().filter(|l| l.starts_with("a=fingerprint:sha-256 ")).count();
    if aimed || prints != 1 || sha256 != 1 {
        return Err(io::Error::other("peer's SDP has candidates, ice-lite, or not one sha-256 fingerprint"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::check_sdp;

    fn sdp(extra: &str) -> String {
        format!("v=0\r\na=fingerprint:sha-256 AA:BB\r\n{extra}")
    }

    #[test]
    fn an_sdp_with_one_sha256_fingerprint_passes() {
        check_sdp(&sdp("m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n")).unwrap();
        assert!(check_sdp("v=0\r\n").is_err());
    }

    #[test]
    fn candidates_ice_lite_and_other_fingerprints_are_refused() {
        assert!(check_sdp(&sdp("a=candidate:1 1 udp 1 10.0.0.1 9 typ host\r\n")).is_err());
        assert!(check_sdp(&sdp("a=ice-lite\r\n")).is_err());
        assert!(check_sdp(&sdp("a=fingerprint:sha-256 CC:DD\r\n")).is_err());
        assert!(check_sdp(&sdp("a=fingerprint:sha-1 CC:DD\r\n")).is_err());
        assert!(check_sdp("v=0\r\na=fingerprint:sha-1 AA:BB\r\n").is_err());
    }
}
