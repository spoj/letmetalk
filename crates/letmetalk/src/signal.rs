use std::io;

use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};

use crate::PublicKey;

pub trait Signal: Send + Sync + 'static {
    /// Delivers an envelope toward `to`. Fails with HostUnreachable if the carrier knows `to` is offline.
    fn send(&self, to: PublicKey, envelope: Vec<u8>) -> BoxFuture<'static, io::Result<()>>;
    /// The next envelope for this endpoint; None once the carrier has stopped.
    fn recv(&self) -> BoxFuture<'_, Option<Vec<u8>>>;
    /// STUN and TURN servers for a new link, with current credentials.
    fn ice_servers(&self) -> Vec<IceServer>;
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IceServer {
    pub urls: Vec<String>,
    pub username: String,
    pub credential: String,
}
