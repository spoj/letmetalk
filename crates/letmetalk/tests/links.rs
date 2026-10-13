mod common;

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use common::{Carrier, Hub, round_trip, serve};
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

#[tokio::test]
async fn replayed_offer_cannot_replace_a_live_link_and_a_fresh_one_does() {
    let hub = Hub::default();
    let (a_key, b_key) = (SecretKey::generate(), SecretKey::generate());
    let a = endpoint(&hub, &a_key, |_| Admit::Direct);
    let b = endpoint(&hub, &b_key, |_| Admit::Direct);
    tokio::spawn(serve(b.clone()));
    let mut first = a.connect(b_key.public(), "echo").await.unwrap();
    let offer = hub
        .sent()
        .into_iter()
        .find(|(from, to, envelope)| *from == a_key.public() && *to == b_key.public() && envelope[1] == 1)
        .unwrap()
        .2;
    hub.inject(b_key.public(), offer);
    tokio::time::sleep(Duration::from_millis(500)).await;
    first.write_all(b"ping").await.unwrap();
    first.shutdown().await.unwrap();
    let mut echoed = Vec::new();
    first.read_to_end(&mut echoed).await.unwrap();
    assert_eq!(echoed, b"ping");

    let mut second = a.connect(b_key.public(), "echo").await.unwrap();
    let a_again = endpoint(&hub, &a_key, |_| Admit::Direct);
    round_trip(&a_again, b_key.public()).await.unwrap();
    let mut buf = [0; 1];
    let err = tokio::time::timeout(Duration::from_secs(10), second.read(&mut buf))
        .await
        .expect("the replaced link closes")
        .unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::ConnectionReset);
}

#[tokio::test]
async fn offer_relayed_to_another_key_gets_no_link() {
    let hub = Hub::default();
    let (a_key, b_key, m_key) = (SecretKey::generate(), SecretKey::generate(), SecretKey::generate());
    let a = endpoint(&hub, &a_key, |_| Admit::Direct);
    let b = endpoint(&hub, &b_key, |_| Admit::Direct);
    let _m = Carrier::join(&hub, &m_key);
    hub.redirect(a_key.public(), m_key.public(), b_key.public());
    let dialed = tokio::time::timeout(Duration::from_secs(2), a.connect(m_key.public(), "echo")).await;
    assert!(dialed.is_err());
    assert!(tokio::time::timeout(Duration::from_secs(2), b.accept()).await.is_err());
}

#[tokio::test]
async fn relayed_link_without_a_relay_server_is_unsupported() {
    let hub = Hub::default();
    let (a_key, b_key) = (SecretKey::generate(), SecretKey::generate());
    let a = endpoint(&hub, &a_key, |_| Admit::Relayed);
    let _b = endpoint(&hub, &b_key, |_| Admit::Direct);
    let err = a.connect(b_key.public(), "echo").await.err().unwrap();
    assert_eq!(err.kind(), io::ErrorKind::Unsupported);
}
