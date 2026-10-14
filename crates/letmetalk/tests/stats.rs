mod common;

use std::time::Duration;

use common::{Carrier, Hub};
use letmetalk::{Admit, Endpoint, SecretKey};
use tokio::io::AsyncWriteExt;

/// Two endpoints on one machine connect directly, and `path` reports host candidates with a round trip.
#[tokio::test]
async fn path_of_a_direct_link_is_host_to_host() {
    let hub = Hub::default();
    let (a_key, b_key) = (SecretKey::generate(), SecretKey::generate());
    let a = Endpoint::new(a_key.clone(), Carrier::join(&hub, &a_key), |_| Admit::Direct);
    let b = Endpoint::new(b_key.clone(), Carrier::join(&hub, &b_key), |_| Admit::Direct);
    let mut stream = a.connect(b_key.public(), "echo").await.unwrap();
    stream.shutdown().await.unwrap();
    let _accepted = b.accept().await.unwrap();
    let path = loop {
        if let Some(path) = a.path(b_key.public()).await.filter(|p| p.rtt > Duration::ZERO) {
            break path;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    assert_eq!((path.local.as_str(), path.remote.as_str()), ("host", "host"));
    assert!(!path.relayed());
    assert!(a.path(SecretKey::generate().public()).await.is_none());
}
