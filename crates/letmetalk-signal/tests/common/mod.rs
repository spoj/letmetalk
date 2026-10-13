#![allow(dead_code)]

use std::collections::HashSet;
use std::net::SocketAddr;
use std::time::Duration;

use letmetalk::ws::WsSignal;
use letmetalk::{PublicKey, SecretKey, Signal};
use letmetalk_signal::{Config, Forwarder, Turn};
use tokio::net::TcpListener;

pub const HOST: &str = "127.0.0.1";

pub fn key(seed: u8) -> SecretKey {
    SecretKey::from_bytes([seed; 32])
}

pub fn no_turn() -> Turn {
    Turn {
        urls: vec!["turn:127.0.0.1:3478?transport=udp".into()],
        secret: "unused".into(),
    }
}

pub async fn spawn(
    allowlist: Option<HashSet<PublicKey>>,
    member_turn: Turn,
    stranger_turn: Turn,
) -> String {
    let forwarder = Forwarder::new(Config {
        host: HOST.into(),
        allowlist,
        member_turn,
        stranger_turn,
        turn_ttl: Duration::from_secs(24 * 3600),
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    let app = forwarder
        .router()
        .into_make_service_with_connect_info::<SocketAddr>();
    tokio::spawn(async move { axum::serve(listener, app).await });
    format!("ws://{addr}/ws")
}

pub async fn logged_in(signal: &WsSignal) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while signal.ice_servers().is_empty() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("logs in")
}
