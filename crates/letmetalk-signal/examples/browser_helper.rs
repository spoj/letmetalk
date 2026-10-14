//! Runs a forwarder on a free loopback port and a native echo endpoint on it, for the browser tests. Prints the port
//! and the echo's key, on one line.

use std::net::SocketAddr;
use std::time::Duration;

use letmetalk::ws::WsSignal;
use letmetalk::{Admit, Endpoint, SecretKey};
use letmetalk_signal::{Config, Forwarder, Turn};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn turn() -> Turn {
    Turn {
        urls: vec!["turn:127.0.0.1:3478?transport=udp".into()],
        secret: "unused".into(),
    }
}

#[tokio::main]
async fn main() {
    let forwarder = Forwarder::new(Config {
        host: "127.0.0.1".into(),
        allowlist: None,
        member_turn: turn(),
        stranger_turn: turn(),
        turn_ttl: Duration::from_secs(3600),
    });
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let app = forwarder
        .router()
        .into_make_service_with_connect_info::<SocketAddr>();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let key = SecretKey::from_bytes([0x42; 32]);
    let signal = WsSignal::new(&format!("ws://127.0.0.1:{port}/ws"), &key);
    let endpoint = Endpoint::new(key.clone(), signal, |_| Admit::Direct);
    println!("{port} {}", key.public());
    let browser = SecretKey::from_bytes([0x43; 32]).public();
    let dialer = endpoint.clone();
    tokio::spawn(async move {
        let mut stream = loop {
            match dialer.connect(browser, "ping").await {
                Ok(stream) => break stream,
                Err(_) => tokio::time::sleep(Duration::from_millis(200)).await,
            }
        };
        stream.write_all(b"ping").await.unwrap();
        stream.shutdown().await.unwrap();
    });
    loop {
        let mut stream = endpoint.accept().await.expect("the endpoint runs until killed");
        tokio::spawn(async move {
            let mut buf = vec![0; 16 << 10];
            loop {
                let n = stream.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                stream.write_all(&buf[..n]).await.unwrap();
            }
            stream.shutdown().await.unwrap();
        });
    }
}
