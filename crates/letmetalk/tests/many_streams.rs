mod common;

use common::{Carrier, Hub};
use letmetalk::{Admit, Endpoint, SecretKey};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Each stream's channel closes after the one before it, on one link. Fails at about 40 to 75 streams on loopback, when
/// webrtc-rs loses a stream's last messages after a close (see PLAN's Risks). Run with `--ignored` to reproduce.
#[ignore = "webrtc-rs loses a stream's messages after a close; see PLAN Risks"]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sequential_streams_on_one_link_all_finish() {
    let hub = Hub::default();
    let (a_key, b_key) = (SecretKey::generate(), SecretKey::generate());
    let a = Endpoint::new(a_key.clone(), Carrier::join(&hub, &a_key), |_| Admit::Direct);
    let b = Endpoint::new(b_key.clone(), Carrier::join(&hub, &b_key), |_| Admit::Direct);
    tokio::spawn(async move {
        while let Some(mut stream) = b.accept().await {
            tokio::spawn(async move {
                let mut byte = [0];
                stream.read_exact(&mut byte).await.unwrap();
                stream.write_all(&byte).await.unwrap();
                let mut rest = Vec::new();
                stream.read_to_end(&mut rest).await.unwrap();
                stream.shutdown().await.unwrap();
            });
        }
    });
    for i in 0..200 {
        let mut stream = a.connect(b_key.public(), "echo").await.unwrap();
        stream.write_all(b"x").await.unwrap();
        let mut byte = [0];
        stream.read_exact(&mut byte).await.unwrap_or_else(|e| panic!("stream {i}: {e}"));
        stream.shutdown().await.unwrap();
        let mut rest = Vec::new();
        stream.read_to_end(&mut rest).await.unwrap_or_else(|e| panic!("stream {i} finish: {e}"));
    }
}
