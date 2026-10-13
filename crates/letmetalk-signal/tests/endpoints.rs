mod common;

use std::io;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::*;
use futures::future::{BoxFuture, join_all};
use letmetalk::ws::WsSignal;
use letmetalk::{Admit, Endpoint, IceServer, PublicKey, Signal};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn signal(url: &str, seed: u8) -> WsSignal {
    WsSignal::new(url, &key(seed))
}

async fn serve(b: Endpoint) {
    while let Some(mut stream) = b.accept().await {
        tokio::spawn(async move {
            let mut data = Vec::new();
            stream.read_to_end(&mut data).await.unwrap();
            stream.write_all(&data).await.unwrap();
            stream.shutdown().await.unwrap();
        });
    }
}

async fn round_trip(a: &Endpoint, to: PublicKey) -> io::Result<()> {
    let mut stream = a.connect(to, "echo").await?;
    stream.write_all(b"ping").await?;
    stream.shutdown().await?;
    let mut echoed = Vec::new();
    stream.read_to_end(&mut echoed).await?;
    assert_eq!(echoed, b"ping");
    Ok(())
}

/// A signal that records when each send was submitted, and whether the forwarder accepted it.
struct Counting {
    inner: WsSignal,
    sends: Arc<Mutex<Vec<(Instant, bool)>>>,
}

impl Signal for Counting {
    fn send(&self, to: PublicKey, envelope: Vec<u8>) -> BoxFuture<'static, io::Result<()>> {
        let sends = self.sends.clone();
        let sent = self.inner.send(to, envelope);
        Box::pin(async move {
            let at = Instant::now();
            let result = sent.await;
            sends.lock().unwrap().push((at, result.is_ok()));
            result
        })
    }

    fn recv(&self) -> BoxFuture<'_, Option<Vec<u8>>> {
        self.inner.recv()
    }

    fn ice_servers(&self) -> Vec<IceServer> {
        self.inner.ice_servers()
    }
}

/// The most sends in any window of `width`.
fn busiest(times: &mut [Instant], width: Duration) -> usize {
    times.sort();
    (0..times.len())
        .map(|i| times[i..].iter().take_while(|t| **t < times[i] + width).count())
        .max()
        .unwrap_or(0)
}

#[tokio::test]
async fn two_endpoints_connect_through_the_forwarder() {
    let url = spawn(None, no_turn(), no_turn()).await;
    let (a_signal, b_signal) = (signal(&url, 1), signal(&url, 2));
    logged_in(&a_signal).await;
    logged_in(&b_signal).await;
    let a = Endpoint::new(key(1), a_signal, |_| Admit::Direct);
    let b = Endpoint::new(key(2), b_signal, |_| Admit::Direct);
    tokio::spawn(serve(b));
    round_trip(&a, key(2).public()).await.unwrap();
}

#[tokio::test]
async fn an_endpoint_dialing_twenty_peers_stays_within_the_limits() {
    let url = spawn(None, no_turn(), no_turn()).await;
    // Every login on this host shares one IP, so the forwarder's per-IP bucket sees all their sends together.
    let everyone = Arc::new(Mutex::new(Vec::new()));
    for seed in 2..=21 {
        let ws = signal(&url, seed);
        logged_in(&ws).await;
        let counting = Counting { inner: ws, sends: everyone.clone() };
        let peer = Endpoint::new(key(seed), counting, |_| Admit::Direct);
        tokio::spawn(serve(peer));
    }
    let dialer_signal = signal(&url, 1);
    logged_in(&dialer_signal).await;
    let dialer_sends = Arc::new(Mutex::new(Vec::new()));
    let dialer = Endpoint::new(
        key(1),
        Counting { inner: dialer_signal, sends: dialer_sends.clone() },
        |_| Admit::Direct,
    );
    everyone.lock().unwrap().clear();

    let start = Instant::now();
    let trips = join_all((2..=21).map(|seed| round_trip(&dialer, key(seed).public()))).await;
    let startup = start.elapsed();
    assert!(trips.iter().all(Result::is_ok), "{trips:?}");

    for log in [&dialer_sends, &everyone] {
        let log = log.lock().unwrap();
        let mut times: Vec<Instant> = log.iter().map(|(at, _)| *at).collect();
        let refused = log.iter().filter(|(_, ok)| !ok).count();
        let sent = times.len();
        let per_sec = busiest(&mut times, Duration::from_secs(1));
        let per_tenth = busiest(&mut times, Duration::from_millis(100));
        eprintln!("startup {startup:?}; sent {sent}, refused {refused}; busiest 1 s {per_sec}, 100 ms {per_tenth}");
        assert_eq!(refused, 0);
    }
}
