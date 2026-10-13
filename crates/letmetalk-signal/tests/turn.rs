mod common;

use std::collections::HashSet;
use std::net::{SocketAddr, UdpSocket as StdUdpSocket};
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use common::*;
use hmac::{Hmac, Mac};
use letmetalk::ws::WsSignal;
use letmetalk::{IceServer, Signal};
use letmetalk_signal::Turn;
use sha1::Sha1;
use tokio::process::{Child, Command};
use turn::client::{Client, ClientConfig};
use webrtc_util::Conn;

const REALM: &str = "letmetalk";

/// A coturn started from one of the repo's configs, on free ports.
struct Coturn {
    _child: Child,
    addr: String,
    secret: String,
}

fn free_port() -> u16 {
    StdUdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

impl Coturn {
    async fn start(conf: &str, secret: &str) -> Self {
        let port = free_port();
        let relay = free_port();
        let config = format!("{}/coturn/{conf}", env!("CARGO_MANIFEST_DIR"));
        let child = Command::new("turnserver")
            .args([
                "-c",
                &config,
                "--no-tls",
                "--listening-ip=127.0.0.1",
                "--relay-ip=127.0.0.1",
                &format!("--listening-port={port}"),
                &format!("--min-port={relay}"),
                &format!("--max-port={}", relay + 200),
                &format!("--static-auth-secret={secret}"),
                "--log-file=stdout",
                "--pidfile=/dev/null",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .expect("turnserver on PATH");
        tokio::time::sleep(Duration::from_millis(500)).await;
        Self {
            _child: child,
            addr: format!("127.0.0.1:{port}"),
            secret: secret.into(),
        }
    }

    fn turn(&self) -> Turn {
        Turn {
            urls: vec![format!("turn:{}?transport=udp", self.addr)],
            secret: self.secret.clone(),
        }
    }
}

/// One allocation from a fresh client, with the credentials of `ice`.
async fn allocate(addr: &str, ice: &IceServer) -> Result<impl Conn, turn::Error> {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client = Client::new(ClientConfig {
        stun_serv_addr: addr.into(),
        turn_serv_addr: addr.into(),
        username: ice.username.clone(),
        password: ice.credential.clone(),
        realm: REALM.into(),
        software: String::new(),
        rto_in_ms: 100,
        conn: Arc::new(socket),
        vnet: None,
    })
    .await?;
    client.listen().await?;
    client.allocate().await
}

async fn ice_of(signal: &WsSignal) -> IceServer {
    logged_in(signal).await;
    signal.ice_servers().remove(0)
}

#[tokio::test]
async fn member_credentials_allocate_and_carry_no_key() {
    let member = Coturn::start("member.conf", "member-secret").await;
    let stranger = Coturn::start("stranger.conf", "stranger-secret").await;
    let url = spawn(
        Some(HashSet::from([key(1).public()])),
        member.turn(),
        stranger.turn(),
    )
    .await;
    let a = WsSignal::new(&url, &key(1));
    let ice = ice_of(&a).await;

    let (expiry, _) = ice.username.split_once(':').unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!(expiry.parse::<u64>().unwrap() > now + 23 * 3600);
    assert!(!ice.username.contains(&key(1).public().to_string()));
    assert!(allocate(&member.addr, &ice).await.is_ok());
}

#[tokio::test]
async fn stranger_credentials_hit_the_small_quota() {
    let member = Coturn::start("member.conf", "member-secret").await;
    let stranger = Coturn::start("stranger.conf", "stranger-secret").await;
    let url = spawn(
        Some(HashSet::from([key(9).public()])),
        member.turn(),
        stranger.turn(),
    )
    .await;
    let a = WsSignal::new(&url, &key(1));
    let ice = ice_of(&a).await;

    let mut relays = Vec::new();
    for _ in 0..3 {
        relays.push(allocate(&stranger.addr, &ice).await);
    }
    assert_eq!(
        relays.iter().map(Result::is_ok).collect::<Vec<_>>(),
        [true, true, false]
    );
}

#[tokio::test]
async fn private_peers_are_refused() {
    let member = Coturn::start("member.conf", "member-secret").await;
    let stranger = Coturn::start("stranger.conf", "stranger-secret").await;
    let url = spawn(
        Some(HashSet::from([key(1).public()])),
        member.turn(),
        stranger.turn(),
    )
    .await;
    let a = WsSignal::new(&url, &key(1));
    let ice = ice_of(&a).await;

    let relay = allocate(&member.addr, &ice).await.unwrap();
    let public: SocketAddr = "8.8.8.8:9".parse().unwrap();
    assert!(relay.send_to(b"x", public).await.is_ok());
    let private: SocketAddr = "10.1.2.3:9".parse().unwrap();
    assert!(relay.send_to(b"x", private).await.is_err());
}

/// Credentials for any username, as the forwarder mints them.
fn credential(secret: &str, username: &str) -> IceServer {
    let mut mac = Hmac::<Sha1>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(username.as_bytes());
    IceServer {
        urls: Vec::new(),
        username: username.into(),
        credential: STANDARD.encode(mac.finalize().into_bytes()),
    }
}

#[tokio::test]
async fn total_quota_caps_the_stranger_instance() {
    let stranger = Coturn::start("stranger.conf", "stranger-secret").await;
    let expiry = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3600;
    let ices: Vec<IceServer> = (0..101)
        .map(|user| credential("stranger-secret", &format!("{expiry}:user{user}")))
        .collect();
    let mut relays = Vec::new();
    for ice in &ices {
        relays.push(allocate(&stranger.addr, ice).await);
    }
    assert_eq!(relays.iter().filter(|r| r.is_ok()).count(), 100);
    assert!(relays[100].is_err());
}

#[tokio::test]
async fn mapped_and_nat64_peers_are_refused() {
    let member = Coturn::start("member.conf", "member-secret").await;
    let url = spawn(
        Some(HashSet::from([key(1).public()])),
        member.turn(),
        Coturn::start("stranger.conf", "stranger-secret")
            .await
            .turn(),
    )
    .await;
    let a = WsSignal::new(&url, &key(1));
    let ice = ice_of(&a).await;

    let relay = allocate(&member.addr, &ice).await.unwrap();
    for peer in [
        "[::ffff:10.1.2.3]:9",
        "[::ffff:8.8.8.8]:9",
        "[64:ff9b::a01:203]:9",
        "[64:ff9b:1::1]:9",
        "[2002:a01:203::1]:9",
    ] {
        let peer: SocketAddr = peer.parse().unwrap();
        assert!(relay.send_to(b"x", peer).await.is_err(), "{peer}");
    }
}
