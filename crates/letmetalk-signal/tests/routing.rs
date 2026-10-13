mod common;

use std::collections::HashSet;
use std::time::Duration;

use common::*;
use letmetalk::ws::WsSignal;
use letmetalk::Signal;

fn signal(url: &str, seed: u8) -> WsSignal {
    WsSignal::new(url, &key(seed))
}

#[tokio::test]
async fn routes_an_envelope_and_acks_it() {
    let (url, _) = spawn(None, no_turn(), no_turn()).await;
    let a = signal(&url, 1);
    let b = signal(&url, 2);
    logged_in(&a).await;
    logged_in(&b).await;
    a.send(key(2).public(), b"hi".to_vec()).await.unwrap();
    assert_eq!(b.recv().await.unwrap(), b"hi");
}

#[tokio::test]
async fn offline_recipient_is_host_unreachable() {
    let (url, _) = spawn(None, no_turn(), no_turn()).await;
    let a = signal(&url, 1);
    logged_in(&a).await;
    let err = a.send(key(9).public(), vec![1]).await.unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::HostUnreachable);
}

#[tokio::test]
async fn non_member_never_learns_presence() {
    let (url, _) = spawn(Some(HashSet::from([key(1).public()])), no_turn(), no_turn()).await;
    let member = signal(&url, 1);
    let stranger = signal(&url, 2);
    logged_in(&member).await;
    logged_in(&stranger).await;
    stranger.send(key(9).public(), vec![1]).await.unwrap();
    let err = member.send(key(9).public(), vec![1]).await.unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::HostUnreachable);
}

#[tokio::test]
async fn limits_a_burst_from_one_login() {
    let (url, _) = spawn(None, no_turn(), no_turn()).await;
    let a = signal(&url, 1);
    let b = signal(&url, 2);
    logged_in(&a).await;
    logged_in(&b).await;
    let sends = (0..300).map(|_| a.send(key(2).public(), vec![1]));
    let results: Vec<_> = futures::future::join_all(sends)
        .await
        .into_iter()
        .map(|r| r.map_err(|e| e.kind()))
        .collect();
    assert!(results[..100].iter().all(Result::is_ok));
    assert!(results.contains(&Err(std::io::ErrorKind::ResourceBusy)));
}

#[tokio::test]
async fn limits_a_stranger_per_recipient() {
    let (url, _) = spawn(Some(HashSet::from([key(1).public()])), no_turn(), no_turn()).await;
    let member = signal(&url, 1);
    let stranger = signal(&url, 2);
    logged_in(&member).await;
    logged_in(&stranger).await;
    let sends = (0..20).map(|_| stranger.send(key(1).public(), vec![1]));
    let results: Vec<_> = futures::future::join_all(sends)
        .await
        .into_iter()
        .map(|r| r.map_err(|e| e.kind()))
        .collect();
    assert!(results[..5].iter().all(Result::is_ok));
    assert!(results.contains(&Err(std::io::ErrorKind::ResourceBusy)));
}

#[tokio::test]
async fn a_new_login_replaces_the_old_one() {
    let (url, _) = spawn(None, no_turn(), no_turn()).await;
    let old = signal(&url, 1);
    logged_in(&old).await;
    let new = signal(&url, 1);
    let b = signal(&url, 2);
    logged_in(&new).await;
    let closed = tokio::time::timeout(Duration::from_secs(5), old.recv()).await;
    assert_eq!(closed.unwrap(), None);
    logged_in(&b).await;
    b.send(key(1).public(), b"to the new one".to_vec()).await.unwrap();
    assert_eq!(new.recv().await.unwrap(), b"to the new one");
}
