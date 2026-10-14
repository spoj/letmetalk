//! Scenarios that dial a peer and time it, and the handlers that serve them. The same code runs natively and in the
//! browser. Each transport supplies a `Dialer`, and the peer serves streams by protocol name.

use std::future::Future;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};

use futures::future::{join, try_join_all};
use n0_future::time::{Instant, sleep};
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub mod letmetalk;
#[cfg(all(feature = "iroh", not(target_arch = "wasm32")))]
pub mod iroh;
#[cfg(target_arch = "wasm32")]
mod web;

/// A key file's contents: 64 hex digits, the seed.
pub fn secret_key(hex: &str) -> io::Result<::letmetalk::SecretKey> {
    let mut seed = [0; 32];
    hex::decode_to_slice(hex.trim(), &mut seed).map_err(io::Error::other)?;
    Ok(::letmetalk::SecretKey::from_bytes(seed))
}

pub const ECHO: &str = "echo";
pub const SINK: &str = "sink";
/// `source:<bytes>` writes that many bytes and finishes.
pub const SOURCE: &str = "source:";

const CHUNK: usize = 64 << 10;
const COLD: usize = 5;
const WARM: usize = 20;
const LATENCY: usize = 1000;
const ECHO_BYTES: usize = 100;
const PACING: std::time::Duration = std::time::Duration::from_millis(5);

/// The route of a link: each side's candidate type or address, and whether it is relayed.
#[derive(Serialize)]
pub struct Route {
    pub relayed: bool,
    pub local: String,
    pub remote: String,
    pub rtt_ms: f64,
}

/// What a scenario needs from a transport. A link holds one local identity and, once used, one connection to the peer.
pub trait Dialer: Sync {
    type Link: Send + Sync;
    type Stream: AsyncRead + AsyncWrite + Unpin + Send;
    /// A new local identity, not yet linked to the peer.
    fn fresh(&self) -> impl Future<Output = io::Result<Self::Link>> + Send;
    /// A stream to the peer for `protocol`, forming the link first if there is none.
    fn open(&self, link: &Self::Link, protocol: &str) -> impl Future<Output = io::Result<Self::Stream>> + Send;
    fn path(&self, link: &Self::Link) -> impl Future<Output = Option<Route>> + Send;
    fn close(&self, link: Self::Link) -> impl Future<Output = ()> + Send;
}

#[derive(Serialize)]
struct Line<'a, T: Serialize> {
    pair: &'a str,
    scenario: &'a str,
    #[serde(flatten)]
    fields: T,
}

struct Out<'a> {
    pair: &'a str,
    sink: &'a dyn Fn(String),
}

impl Out<'_> {
    fn line(&self, scenario: &str, fields: impl Serialize) {
        let line = Line { pair: self.pair, scenario, fields };
        (self.sink)(serde_json::to_string(&line).expect("lines serialize"));
    }
}

fn median(mut xs: Vec<f64>) -> f64 {
    xs.sort_by(f64::total_cmp);
    xs[xs.len() / 2]
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    sorted[((sorted.len() as f64 * p).ceil() as usize).max(1) - 1]
}

fn mb_per_s(bytes: usize, secs: f64) -> f64 {
    bytes as f64 / secs / 1e6
}

/// Finishes our side of a stream and waits for the peer to finish, so that the stream closes cleanly.
async fn finish<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S) -> io::Result<()> {
    stream.shutdown().await?;
    tokio::io::copy(stream, &mut tokio::io::sink()).await?;
    Ok(())
}

/// Time from opening an echo stream to its first echoed byte, in ms. The stream is reset when dropped.
async fn first_echo<D: Dialer>(dialer: &D, link: &D::Link) -> io::Result<f64> {
    let start = Instant::now();
    let mut stream = dialer.open(link, ECHO).await?;
    stream.write_all(b"x").await?;
    stream.read_exact(&mut [0]).await?;
    Ok(start.elapsed().as_secs_f64() * 1e3)
}

async fn upload<D: Dialer>(dialer: &D, link: &D::Link, bytes: usize) -> io::Result<()> {
    let mut stream = dialer.open(link, SINK).await?;
    let chunk = vec![7; CHUNK];
    for _ in 0..bytes / CHUNK {
        stream.write_all(&chunk).await?;
    }
    stream.shutdown().await?;
    stream.read_exact(&mut [0]).await?;
    Ok(())
}

async fn download<D: Dialer>(dialer: &D, link: &D::Link, bytes: usize) -> io::Result<usize> {
    let mut stream = dialer.open(link, &format!("{SOURCE}{bytes}")).await?;
    let mut buf = vec![0; CHUNK];
    let mut total = 0;
    loop {
        match stream.read(&mut buf).await? {
            0 => break,
            n => total += n,
        }
    }
    stream.shutdown().await?;
    Ok(total)
}

/// Echoes 100-byte messages on one stream, paced, while `load` runs on another. It sets `stop` when the echoes end,
/// so that a sink can stop writing.
async fn echoes<D: Dialer>(
    dialer: &D,
    link: &D::Link,
    stop: &AtomicBool,
    load: impl Future<Output = io::Result<()>>,
) -> io::Result<Vec<f64>> {
    let sampler = async {
        let rtts = sample(dialer, link).await;
        stop.store(true, Ordering::Relaxed);
        rtts
    };
    let (rtts, loaded) = join(sampler, load).await;
    loaded?;
    rtts
}

async fn sample<D: Dialer>(dialer: &D, link: &D::Link) -> io::Result<Vec<f64>> {
    let mut stream = dialer.open(link, ECHO).await?;
    let message = [3; ECHO_BYTES];
    let mut echo = [0; ECHO_BYTES];
    let mut rtts = Vec::with_capacity(LATENCY);
    for _ in 0..LATENCY {
        sleep(PACING).await;
        let start = Instant::now();
        stream.write_all(&message).await?;
        stream.read_exact(&mut echo).await?;
        rtts.push(start.elapsed().as_secs_f64() * 1e3);
    }
    finish(&mut stream).await?;
    Ok(rtts)
}

/// Writes 64 KiB chunks on a sink stream until the echoes are done, then waits for the sink's ack.
async fn bulk_until_done<D: Dialer>(dialer: &D, link: &D::Link, stop: &AtomicBool) -> io::Result<usize> {
    let mut stream = dialer.open(link, SINK).await?;
    let chunk = vec![7; CHUNK];
    let mut sent = 0;
    while !stop.load(Ordering::Relaxed) {
        stream.write_all(&chunk).await?;
        sent += CHUNK;
    }
    stream.shutdown().await?;
    stream.read_exact(&mut [0]).await?;
    Ok(sent)
}

/// Every scenario, in order, with `bulk` bytes in each bulk transfer. Each measurement gets a link of its own, formed
/// by an echo before it starts, so that setup is not in its timing.
pub async fn dial_all<D: Dialer>(dialer: &D, pair: &str, bulk: usize, sink: &dyn Fn(String)) -> io::Result<()> {
    let out = Out { pair, sink };

    let mut cold = Vec::with_capacity(COLD);
    for _ in 0..COLD {
        let link = dialer.fresh().await?;
        cold.push(first_echo(dialer, &link).await?);
        dialer.close(link).await;
    }
    out.line("cold", serde_json::json!({ "samples_ms": cold, "median_ms": median(cold.clone()) }));

    let link = dialer.fresh().await?;
    first_echo(dialer, &link).await?;
    let mut warm = Vec::with_capacity(WARM);
    for _ in 0..WARM {
        warm.push(first_echo(dialer, &link).await?);
    }
    out.line("warm", serde_json::json!({ "samples_ms": warm, "median_ms": median(warm.clone()) }));
    out.line("path", serde_json::json!({ "route": dialer.path(&link).await }));
    dialer.close(link).await;

    let link = dialer.fresh().await?;
    first_echo(dialer, &link).await?;
    let start = Instant::now();
    upload(dialer, &link, bulk).await?;
    out.line("bulk_up", throughput(bulk, start.elapsed().as_secs_f64()));
    dialer.close(link).await;

    let link = dialer.fresh().await?;
    first_echo(dialer, &link).await?;
    let start = Instant::now();
    let got = download(dialer, &link, bulk).await?;
    out.line("bulk_down", throughput(got, start.elapsed().as_secs_f64()));
    dialer.close(link).await;

    let link = dialer.fresh().await?;
    first_echo(dialer, &link).await?;
    let start = Instant::now();
    try_join_all((0..4).map(|_| upload(dialer, &link, bulk / 4))).await?;
    out.line("bulk_4x64", throughput(bulk, start.elapsed().as_secs_f64()));
    dialer.close(link).await;

    let link = dialer.fresh().await?;
    first_echo(dialer, &link).await?;
    let idle = echoes(dialer, &link, &AtomicBool::new(false), async { Ok(()) }).await?;
    out.line("latency_idle", latency(&idle));
    dialer.close(link).await;

    let link = dialer.fresh().await?;
    first_echo(dialer, &link).await?;
    let stop = AtomicBool::new(false);
    let start = Instant::now();
    let mut sent = 0;
    let loaded = echoes(dialer, &link, &stop, async {
        sent = bulk_until_done(dialer, &link, &stop).await?;
        Ok(())
    })
    .await?;
    let secs = start.elapsed().as_secs_f64();
    out.line("latency_load", serde_json::json!({ "bulk_mb_s": mb_per_s(sent, secs), "echo": latency(&loaded) }));
    dialer.close(link).await;

    Ok(())
}

fn throughput(bytes: usize, secs: f64) -> serde_json::Value {
    serde_json::json!({ "bytes": bytes, "secs": secs, "mb_s": mb_per_s(bytes, secs) })
}

fn latency(rtts: &[f64]) -> serde_json::Value {
    let mut sorted = rtts.to_vec();
    sorted.sort_by(f64::total_cmp);
    serde_json::json!({
        "n": sorted.len(),
        "p50_ms": percentile(&sorted, 0.50),
        "p95_ms": percentile(&sorted, 0.95),
        "p99_ms": percentile(&sorted, 0.99),
    })
}

/// Serves one stream by its protocol. An unknown protocol is an error, and the stream is dropped.
pub async fn handle<S: AsyncRead + AsyncWrite + Unpin>(mut stream: S, protocol: &str) -> io::Result<()> {
    let mut buf = vec![0; CHUNK];
    if protocol == ECHO {
        loop {
            match stream.read(&mut buf).await? {
                0 => return stream.shutdown().await,
                n => stream.write_all(&buf[..n]).await?,
            }
        }
    }
    if protocol == SINK {
        while stream.read(&mut buf).await? != 0 {}
        stream.write_all(&[1]).await?;
        return stream.shutdown().await;
    }
    let Some(bytes) = protocol.strip_prefix(SOURCE) else {
        return Err(io::ErrorKind::InvalidInput.into());
    };
    let mut left: usize = bytes.parse().map_err(io::Error::other)?;
    buf.fill(5);
    while left > 0 {
        let n = left.min(CHUNK);
        stream.write_all(&buf[..n]).await?;
        left -= n;
    }
    stream.shutdown().await
}
