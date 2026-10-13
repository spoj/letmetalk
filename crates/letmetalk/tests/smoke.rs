mod common;

use common::{Carrier, Hub};
use letmetalk::{Admit, Endpoint, SecretKey};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn two_endpoints_dial_by_key_and_echo() {
    let hub = Hub::default();
    let (a_key, b_key) = (SecretKey::generate(), SecretKey::generate());
    let a = Endpoint::new(a_key.clone(), Carrier::join(&hub, &a_key), |_| Admit::Direct);
    let b = Endpoint::new(b_key.clone(), Carrier::join(&hub, &b_key), |_| Admit::Direct);
    let echo = tokio::spawn(async move {
        let mut stream = b.accept().await.unwrap();
        let mut buf = [0; 5];
        stream.read_exact(&mut buf).await.unwrap();
        stream.write_all(&buf).await.unwrap();
        stream.shutdown().await.unwrap();
    });
    let mut stream = a.connect(b_key.public(), "echo").await.unwrap();
    assert_eq!(stream.remote_key(), b_key.public());
    stream.write_all(b"hello").await.unwrap();
    stream.shutdown().await.unwrap();
    let mut echoed = Vec::new();
    stream.read_to_end(&mut echoed).await.unwrap();
    assert_eq!(echoed, b"hello");
    echo.await.unwrap();
}
