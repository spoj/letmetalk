//! letmetalk as a transport: a dialer for one key through a forwarder, and a server that echoes, sinks and sources.

use std::io;
use std::time::Duration;

use letmetalk::ws::WsSignal;
use letmetalk::{Admit, Endpoint, PublicKey, SecretKey, Signal, Stream};
use n0_future::time::{sleep, timeout};

use crate::{Dialer, Route, handle};

/// A carrier logged in to the forwarder at `url`, and an endpoint on it. Logging in takes a moment, so this waits.
async fn login(url: &str, key: &SecretKey) -> io::Result<Endpoint> {
    let signal = WsSignal::new(url, key);
    timeout(Duration::from_secs(20), async {
        while signal.ice_servers().is_empty() {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .map_err(|_| io::ErrorKind::TimedOut)?;
    Ok(Endpoint::new(key.clone(), signal, |_| Admit::Direct))
}

pub struct Dial {
    pub url: String,
    pub key: SecretKey,
    pub peer: PublicKey,
}

impl Dialer for Dial {
    type Link = Endpoint;
    type Stream = Stream;

    async fn fresh(&self) -> io::Result<Endpoint> {
        login(&self.url, &self.key).await
    }

    async fn open(&self, link: &Endpoint, protocol: &str) -> io::Result<Stream> {
        link.connect(self.peer, protocol).await
    }

    async fn path(&self, link: &Endpoint) -> Option<Route> {
        let path = link.path(self.peer).await?;
        Some(Route {
            relayed: path.relayed(),
            local: path.local,
            remote: path.remote,
            rtt_ms: path.rtt.as_secs_f64() * 1e3,
        })
    }

    async fn close(&self, link: Endpoint) {
        link.close().await;
    }
}

/// Logs in as `key`, reports it, and serves every stream by its protocol until the forwarder drops the login.
pub async fn serve(url: &str, key: &SecretKey, sink: &dyn Fn(String)) -> io::Result<()> {
    let endpoint = login(url, key).await?;
    sink(serde_json::json!({ "role": "serve", "key": key.public().to_string() }).to_string());
    while let Some(stream) = endpoint.accept().await {
        let protocol = stream.protocol().to_string();
        n0_future::task::spawn(async move {
            if let Err(e) = handle(stream, &protocol).await {
                eprintln!("{protocol}: {e}");
            }
        });
    }
    Ok(())
}
