//! Logs in to a forwarder with a key file (64 hex digits, a seed) and prints its public key and the ICE servers it got.
//! Usage: `login <wss://host:port/ws> <key file>`.

use std::time::Duration;

use letmetalk::ws::WsSignal;
use letmetalk::{SecretKey, Signal};

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let url = args.next().expect("a URL");
    let path = args.next().expect("a key file");
    let mut seed = [0; 32];
    hex::decode_to_slice(std::fs::read_to_string(path).unwrap().trim(), &mut seed).expect("64 hex digits");
    let key = SecretKey::from_bytes(seed);
    let signal = WsSignal::new(&url, &key);
    println!("key {}", key.public());
    let ice = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let ice = signal.ice_servers();
            if !ice.is_empty() {
                break ice;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("logs in within 20 s");
    for server in ice {
        for url in server.urls {
            println!("url {url}");
        }
        println!("username {}", server.username);
        println!("credential {}", server.credential);
    }
}
