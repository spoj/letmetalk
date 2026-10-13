mod common;

use std::time::Duration;

use common::{Carrier, Hub};
use letmetalk::{Admit, Endpoint, SecretKey};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const TOTAL: usize = 256 << 20;
const CHUNK: usize = 64 << 10;

fn rss_kb() -> u64 {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    let line = status.lines().find(|line| line.starts_with("VmRSS:")).unwrap();
    line.split_whitespace().nth(1).unwrap().parse().unwrap()
}

/// Both endpoints live in this process, so RSS covers the sender's and the receiver's buffers together.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bulk_to_a_slow_reader_stays_in_bounded_memory() {
    let hub = Hub::default();
    let (a_key, b_key) = (SecretKey::generate(), SecretKey::generate());
    let a = Endpoint::new(a_key.clone(), Carrier::join(&hub, &a_key), |_| Admit::Direct);
    let b = Endpoint::new(b_key.clone(), Carrier::join(&hub, &b_key), |_| Admit::Direct);
    let before = rss_kb();

    let mut sent = a.connect(b_key.public(), "bulk").await.unwrap();
    tokio::spawn(async move {
        let chunk = vec![7; CHUNK];
        for _ in 0..TOTAL / CHUNK {
            sent.write_all(&chunk).await.unwrap();
        }
        sent.shutdown().await.unwrap();
        sent
    });
    let mut received = b.accept().await.unwrap();
    let mut buf = vec![0; CHUNK];
    let (mut got, mut peak) = (0, before);
    while got < TOTAL {
        let n = received.read(&mut buf).await.unwrap();
        assert_ne!(n, 0, "the stream ended after {got} bytes");
        got += n;
        peak = peak.max(rss_kb());
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    let grown_mib = (peak - before) / 1024;
    eprintln!("RSS grew by {grown_mib} MiB");
    assert!(grown_mib < 64, "RSS grew by {grown_mib} MiB");
}
