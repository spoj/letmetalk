mod common;

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use common::{Carrier, Hub};
use letmetalk::{Admit, Endpoint, SecretKey};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn endpoint(hub: &Hub, key: &SecretKey, admit: impl Fn(&letmetalk::PublicKey) -> Admit + Send + Sync + 'static) -> Endpoint {
    Endpoint::new(key.clone(), Carrier::join(hub, key), admit)
}

async fn echo_once(a: &Endpoint, b: &Endpoint, to: letmetalk::PublicKey) -> io::Result<()> {
    let accepting = b.clone();
    let server = tokio::spawn(async move {
        let mut stream = accepting.accept().await.unwrap();
        let mut buf = [0; 4];
        stream.read_exact(&mut buf).await.unwrap();
        stream.write_all(&buf).await.unwrap();
        stream.shutdown().await.unwrap();
    });
    let mut stream = a.connect(to, "echo").await?;
    stream.write_all(b"ping").await?;
    stream.shutdown().await?;
    let mut echoed = Vec::new();
    stream.read_to_end(&mut echoed).await?;
    assert_eq!(echoed, b"ping");
    server.await.unwrap();
    Ok(())
}

#[tokio::test]
async fn offline_key_is_host_unreachable() {
    let hub = Hub::default();
    let (a_key, b_key) = (SecretKey::generate(), SecretKey::generate());
    let a = endpoint(&hub, &a_key, |_| Admit::Direct);
    let err = a.connect(b_key.public(), "echo").await.err().unwrap();
    assert_eq!(err.kind(), io::ErrorKind::HostUnreachable);
}

#[tokio::test]
async fn refused_key_is_permission_denied() {
    let hub = Hub::default();
    let (a_key, b_key) = (SecretKey::generate(), SecretKey::generate());
    let a = endpoint(&hub, &a_key, |_| Admit::Refuse);
    let _b = endpoint(&hub, &b_key, |_| Admit::Direct);
    let err = a.connect(b_key.public(), "echo").await.err().unwrap();
    assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
}

#[tokio::test]
async fn crossed_connects_still_carry_a_stream() {
    let hub = Hub::default();
    let (a_key, b_key) = (SecretKey::generate(), SecretKey::generate());
    let a = endpoint(&hub, &a_key, |_| Admit::Direct);
    let b = endpoint(&hub, &b_key, |_| Admit::Direct);
    let (to_b, to_a) = (b_key.public(), a_key.public());
    let (first, second) = tokio::join!(echo_once(&a, &b, to_b), echo_once(&b, &a, to_a));
    first.unwrap();
    second.unwrap();
}

#[tokio::test]
async fn key_refused_after_its_link_formed_loses_the_link() {
    let hub = Hub::default();
    let (a_key, b_key) = (SecretKey::generate(), SecretKey::generate());
    let a = endpoint(&hub, &a_key, |_| Admit::Direct);
    let refuse = Arc::new(AtomicBool::new(false));
    let flag = refuse.clone();
    let b = endpoint(&hub, &b_key, move |_| {
        if flag.load(Ordering::SeqCst) { Admit::Refuse } else { Admit::Direct }
    });
    echo_once(&a, &b, b_key.public()).await.unwrap();
    refuse.store(true, Ordering::SeqCst);
    let err = echo_once(&a, &b, b_key.public()).await.unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::ConnectionReset);
}

#[tokio::test]
async fn silent_peer_times_out() {
    let hub = Hub::default();
    let (a_key, b_key) = (SecretKey::generate(), SecretKey::generate());
    let a = endpoint(&hub, &a_key, |_| Admit::Direct);
    let _silent = Carrier::join(&hub, &b_key);
    let err = a.connect(b_key.public(), "echo").await.err().unwrap();
    assert_eq!(err.kind(), io::ErrorKind::TimedOut);
}
