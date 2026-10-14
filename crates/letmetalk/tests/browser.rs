//! Browser tests, run in headless Chrome by `scripts/browser-tests.sh`.
#![cfg(target_arch = "wasm32")]

mod common;

use std::io;
use std::sync::Arc;
use std::time::Duration;

use common::{Carrier, Hub};
use futures::future::BoxFuture;
use letmetalk::ws::WsSignal;
use letmetalk::{Admit, Endpoint, IceServer, PublicKey, SecretKey, Signal};
use n0_future::task::spawn;
use n0_future::time::{sleep, timeout};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

fn echo_key() -> PublicKey {
    env!("LETMETALK_TEST_ECHO").parse().unwrap()
}

async fn within<T>(what: impl std::future::Future<Output = T>) -> T {
    timeout(Duration::from_secs(60), what).await.expect("finished within 60 s")
}

/// Dials `to` and checks that it echoes five bytes back, then that the stream ends.
async fn dial_and_echo(dialer: &Endpoint, to: PublicKey) {
    let mut stream = within(async {
        loop {
            match dialer.connect(to, "echo").await {
                Ok(stream) => break stream,
                Err(_) => sleep(Duration::from_millis(100)).await,
            }
        }
    })
    .await;
    assert_eq!(stream.remote_key(), to);
    stream.write_all(b"hello").await.unwrap();
    stream.shutdown().await.unwrap();
    let mut echoed = Vec::new();
    stream.read_to_end(&mut echoed).await.unwrap();
    assert_eq!(echoed, b"hello");
}

#[wasm_bindgen_test]
async fn browsers_dial_and_echo_within_one_page() {
    let hub = Hub::default();
    let (a_key, b_key) = (SecretKey::generate(), SecretKey::generate());
    let a = Endpoint::new(a_key.clone(), Carrier::join(&hub, &a_key), |_| Admit::Direct);
    let b = Endpoint::new(b_key.clone(), Carrier::join(&hub, &b_key), |_| Admit::Direct);
    let (from, to) = (a_key.public(), b_key.public());
    let server = spawn(async move {
        let mut stream = b.accept().await.expect("a stream");
        assert_eq!(stream.remote_key(), from);
        let mut buf = [0; 5];
        stream.read_exact(&mut buf).await.unwrap();
        stream.write_all(&buf).await.unwrap();
        stream.shutdown().await.unwrap();
    });
    dial_and_echo(&a, to).await;
    within(server).await.unwrap();
}

/// A carrier that is logged in before the endpoint dials, so the first envelope is not sent to a carrier that
/// is still connecting.
struct Forwarded(Arc<WsSignal>);

impl Signal for Forwarded {
    fn send(&self, to: PublicKey, envelope: Vec<u8>) -> BoxFuture<'static, std::io::Result<()>> {
        self.0.send(to, envelope)
    }

    fn recv(&self) -> BoxFuture<'_, Option<Vec<u8>>> {
        self.0.recv()
    }

    fn ice_servers(&self) -> Vec<IceServer> {
        self.0.ice_servers()
    }
}

#[wasm_bindgen_test]
async fn browsers_move_eight_mebibytes_one_way() {
    let hub = Hub::default();
    let (a_key, b_key) = (SecretKey::generate(), SecretKey::generate());
    let a = Endpoint::new(a_key.clone(), Carrier::join(&hub, &a_key), |_| Admit::Direct);
    let b = Endpoint::new(b_key.clone(), Carrier::join(&hub, &b_key), |_| Admit::Direct);
    let server = spawn(async move {
        let mut stream = b.accept().await.expect("a stream");
        let mut buf = vec![0; 64 << 10];
        let mut total = 0;
        loop {
            let n = stream.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            assert!(buf[..n].iter().all(|&byte| byte == 7));
            total += n;
        }
        stream.shutdown().await.unwrap();
        total
    });
    let mut stream = within(a.connect(b_key.public(), "bulk")).await.unwrap();
    let chunk = vec![7; 1 << 20];
    for _ in 0..8 {
        stream.write_all(&chunk).await.unwrap();
    }
    stream.shutdown().await.unwrap();
    assert_eq!(within(server).await.unwrap(), 8 << 20);
}

/// A relayed link is built from TURN candidates only. With no relay in the carrier's ICE servers, none forms.
#[wasm_bindgen_test]
async fn relayed_dial_without_a_relay_forms_no_link() {
    let hub = Hub::default();
    let (a_key, b_key) = (SecretKey::generate(), SecretKey::generate());
    let a = Endpoint::new(a_key.clone(), Carrier::join(&hub, &a_key), |_| Admit::Relayed);
    let _b = Endpoint::new(b_key.clone(), Carrier::join(&hub, &b_key), |_| Admit::Direct);
    let Err(error) = within(a.connect(b_key.public(), "echo")).await else {
        panic!("a link formed without a relay");
    };
    assert_eq!(error.kind(), io::ErrorKind::Unsupported);
}

/// Waits until the forwarder has logged the carrier in, which gives it ICE servers.
async fn logged_in(signal: &WsSignal) {
    within(async {
        while signal.ice_servers().is_empty() {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
}

#[wasm_bindgen_test]
async fn browser_dials_native_echo_through_the_forwarder() {
    let key = SecretKey::generate();
    let signal = Arc::new(WsSignal::new(env!("LETMETALK_TEST_SIGNAL"), &key));
    logged_in(&signal).await;
    let dialer = Endpoint::new(key, Forwarded(signal), |_| Admit::Direct);
    dial_and_echo(&dialer, echo_key()).await;
}

/// The helper dials this key, so the browser accepts a stream whose offer came from webrtc-rs.
#[wasm_bindgen_test]
async fn browser_accepts_a_native_dial_through_the_forwarder() {
    let key = SecretKey::from_bytes([0x43; 32]);
    let signal = Arc::new(WsSignal::new(env!("LETMETALK_TEST_SIGNAL"), &key));
    logged_in(&signal).await;
    let accepter = Endpoint::new(key, Forwarded(signal), |_| Admit::Direct);
    let mut stream = within(accepter.accept()).await.expect("a stream");
    assert_eq!(stream.remote_key(), echo_key());
    assert_eq!(stream.protocol(), "ping");
    let mut buf = [0; 4];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping");
    accepter.close().await;
}

#[wasm_bindgen_test]
async fn refuses_plain_ws_to_a_remote_host() {
    let signal = WsSignal::new("ws://example.com/ws", &SecretKey::generate());
    assert!(within(signal.recv()).await.is_none());
}

/// Forwarder frames keep an idle login alive, so a carrier idle for 20 s still dials.
#[wasm_bindgen_test]
async fn idle_browser_carrier_still_dials() {
    let key = SecretKey::from_bytes([0x44; 32]);
    let signal = Arc::new(WsSignal::new(env!("LETMETALK_TEST_SIGNAL"), &key));
    logged_in(&signal).await;
    sleep(Duration::from_secs(20)).await;
    let dialer = Endpoint::new(key, Forwarded(signal), |_| Admit::Direct);
    dial_and_echo(&dialer, echo_key()).await;
}
