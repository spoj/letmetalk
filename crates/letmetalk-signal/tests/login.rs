mod common;

use common::*;
use futures::{SinkExt, StreamExt};
use letmetalk::ws::wire::{self, Down};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;

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
    ws.send(Message::Binary(login.to_vec().into())).await.unwrap();
    ws.next().await.and_then(Result::ok)
}

#[tokio::test]
async fn accepts_a_good_login_with_ice_servers() {
    let (url, _) = spawn(None, no_turn(), no_turn()).await;
    let Some(Message::Binary(reply)) = login(&url, HOST, 1, false).await else {
        panic!("no login reply");
    };
    assert!(matches!(Down::decode(&reply).unwrap(), Down::Ice(ice) if ice.len() == 1));
}

#[tokio::test]
async fn closes_on_a_wrong_host() {
    let (url, _) = spawn(None, no_turn(), no_turn()).await;
    assert!(login(&url, "other.example", 1, false).await.is_none());
}

#[tokio::test]
async fn closes_on_a_bad_mac() {
    let (url, _) = spawn(None, no_turn(), no_turn()).await;
    assert!(login(&url, HOST, 1, true).await.is_none());
}
