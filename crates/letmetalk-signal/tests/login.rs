mod common;

use std::time::{Duration, Instant};

use common::*;
use ed25519_dalek::VerifyingKey;
use futures::{SinkExt, StreamExt};
use letmetalk::ws::wire::{self, Down};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::http::StatusCode;
use tokio_tungstenite::tungstenite::{self, Message};

/// Logs in with `host` in the MAC, flipping the last byte if `tamper`. Returns the server's first reply.
async fn login(url: &str, host: &str, seed: u8, tamper: bool) -> Option<Message> {
    let (mut ws, _) = connect_async(url).await.unwrap();
    let Some(Ok(Message::Binary(challenge))) = ws.next().await else {
        panic!("no challenge");
    };
    let mut login = wire::answer(&key(seed), host, &challenge).unwrap();
    if tamper {
        login[63] ^= 1;
    }
    ws.send(Message::Binary(login.to_vec().into()))
        .await
        .unwrap();
    ws.next().await.and_then(Result::ok)
}

#[tokio::test]
async fn accepts_a_good_login_with_ice_servers() {
    let url = spawn(None, no_turn(), no_turn()).await;
    let Some(Message::Binary(reply)) = login(&url, HOST, 1, false).await else {
        panic!("no login reply");
    };
    assert!(matches!(Down::decode(&reply).unwrap(), Down::Ice(ice) if ice.len() == 1));
}

#[tokio::test]
async fn closes_on_a_wrong_host() {
    let url = spawn(None, no_turn(), no_turn()).await;
    assert!(login(&url, "other.example", 1, false).await.is_none());
}

#[tokio::test]
async fn closes_on_a_bad_mac() {
    let url = spawn(None, no_turn(), no_turn()).await;
    assert!(login(&url, HOST, 1, true).await.is_none());
}

/// Sends `key` in place of a login's Ed25519 key, with a zero MAC. The server must close the socket.
async fn login_with_key(url: &str, key: [u8; 32]) -> Option<Message> {
    let (mut ws, _) = connect_async(url).await.unwrap();
    let Some(Ok(Message::Binary(_))) = ws.next().await else {
        panic!("no challenge");
    };
    ws.send(Message::Binary([key, [0; 32]].concat().into()))
        .await
        .unwrap();
    ws.next().await.and_then(Result::ok)
}

#[tokio::test]
async fn closes_on_small_order_and_torsioned_keys() {
    let url = spawn(None, no_turn(), no_turn()).await;
    let mut identity = [0; 32];
    identity[0] = 1;
    let torsioned = (2..=255u8)
        .map(|y| {
            let mut bytes = [0; 32];
            bytes[0] = y;
            bytes
        })
        .find(|bytes| {
            VerifyingKey::from_bytes(bytes)
                .is_ok_and(|k| !k.is_weak() && !k.to_edwards().is_torsion_free())
        })
        .unwrap();
    for key in [[0; 32], identity, torsioned] {
        assert!(login_with_key(&url, key).await.is_none());
    }
}

#[tokio::test]
async fn refuses_a_65th_socket_from_one_ip() {
    let url = spawn(None, no_turn(), no_turn()).await;
    let mut open = Vec::new();
    for _ in 0..64 {
        open.push(connect_async(&url).await.unwrap());
    }
    let refused = connect_async(&url).await.unwrap_err();
    assert!(matches!(
        refused,
        tungstenite::Error::Http(response) if response.status() == StatusCode::TOO_MANY_REQUESTS
    ));
}

#[tokio::test]
async fn sends_alive_frames_about_each_ping() {
    let url = spawn(None, no_turn(), no_turn()).await;
    let (mut ws, _) = connect_async(&url).await.unwrap();
    let Some(Ok(Message::Binary(challenge))) = ws.next().await else {
        panic!("no challenge");
    };
    let login = wire::answer(&key(1), HOST, &challenge).unwrap();
    ws.send(Message::Binary(login.to_vec().into())).await.unwrap();
    let mut alive = Vec::new();
    tokio::time::timeout(Duration::from_secs(12), async {
        while let Some(Ok(message)) = ws.next().await {
            if matches!(&message, Message::Binary(frame) if matches!(Down::decode(frame), Ok(Down::Alive))) {
                alive.push(Instant::now());
                if alive.len() == 2 {
                    return;
                }
            }
        }
    })
    .await
    .expect("two alive frames within 12 s");
    assert!(alive[1] - alive[0] >= Duration::from_secs(4), "alive frames {:?} apart", alive[1] - alive[0]);
}
