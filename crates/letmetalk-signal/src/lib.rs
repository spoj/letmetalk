mod limit;

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::extract::ws::{Message, WebSocket};
use axum::extract::{ConnectInfo, State, WebSocketUpgrade};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use hmac::{Hmac, Mac};
use letmetalk::ws::wire::{self, Down, Up};
use letmetalk::{IceServer, PublicKey};
use limit::{Bucket, Rate, take_keyed};
use sha1::Sha1;
use tokio::sync::{mpsc, oneshot};

// Sized from a measured startup of an endpoint dialing 20 peers (PLAN, Limits).
const LOGIN_SEND: Rate = Rate {
    per_sec: 50.0,
    burst: 200.0,
};
const IP_SEND: Rate = Rate {
    per_sec: 200.0,
    burst: 800.0,
};
const STRANGER_SEND: Rate = Rate {
    per_sec: 1.0,
    burst: 5.0,
};
const SOCKETS_PER_IP: usize = 64;
const LOGIN_TIMEOUT: Duration = Duration::from_secs(10);
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
const PING: Duration = Duration::from_secs(5);
const SILENT: Duration = Duration::from_secs(15);
const QUEUE: usize = 64;

pub struct Turn {
    pub urls: Vec<String>,
    pub secret: String,
}

pub struct Config {
    pub host: String,
    /// Keys whose TURN credentials are the member instance's. `None` makes every key a routing member.
    pub allowlist: Option<HashSet<PublicKey>>,
    pub member_turn: Turn,
    pub stranger_turn: Turn,
    pub turn_ttl: Duration,
}

struct Session {
    id: u64,
    out: mpsc::Sender<Down>,
    kick: oneshot::Sender<()>,
}

struct Shared {
    config: Config,
    sessions: Mutex<HashMap<[u8; 32], Session>>,
    ip_buckets: Mutex<HashMap<IpAddr, Bucket>>,
    sockets: Mutex<HashMap<IpAddr, usize>>,
    next_id: AtomicU64,
}

#[derive(Clone)]
pub struct Forwarder(Arc<Shared>);

impl Forwarder {
    pub fn new(config: Config) -> Self {
        Self(Arc::new(Shared {
            config,
            sessions: Mutex::default(),
            ip_buckets: Mutex::default(),
            sockets: Mutex::default(),
            next_id: AtomicU64::new(0),
        }))
    }

    /// Serves `/ws`. Connections must be served with `ConnectInfo<SocketAddr>`.
    pub fn router(&self) -> Router {
        Router::new()
            .route("/ws", get(upgrade))
            .with_state(self.0.clone())
    }
}

impl Shared {
    fn ice(&self, key: &PublicKey) -> Vec<IceServer> {
        let listed = self
            .config
            .allowlist
            .as_ref()
            .is_some_and(|list| list.contains(key));
        let turn = if listed {
            &self.config.member_turn
        } else {
            &self.config.stranger_turn
        };
        let mut bytes = [0; 16];
        getrandom::fill(&mut bytes).expect("OS randomness");
        let token = hex::encode(bytes);
        let expiry = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after 1970")
            .as_secs()
            + self.config.turn_ttl.as_secs();
        let username = format!("{expiry}:{token}");
        println!("token {token} key {key}");
        let mut hmac = Hmac::<Sha1>::new_from_slice(turn.secret.as_bytes())
            .expect("HMAC takes any key length");
        hmac.update(username.as_bytes());
        vec![IceServer {
            urls: turn.urls.clone(),
            credential: STANDARD.encode(hmac.finalize().into_bytes()),
            username,
        }]
    }
}

/// Holds one of an IP's socket slots until its socket ends.
struct Slot(Arc<Shared>, IpAddr);

impl Drop for Slot {
    fn drop(&mut self) {
        let mut sockets = self.0.sockets.lock().unwrap();
        let open = sockets.get_mut(&self.1).expect("a slot is held");
        *open -= 1;
        if *open == 0 {
            sockets.remove(&self.1);
        }
    }
}

/// IPv4 addresses as they are, and IPv6 by their /64, so that one host's addresses share a bucket.
fn ip_key(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(v6) => {
            let s = v6.segments();
            IpAddr::V6(Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
        }
        v4 => v4,
    }
}

async fn upgrade(
    State(shared): State<Arc<Shared>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    ws: WebSocketUpgrade,
) -> Response {
    let ip = ip_key(addr.ip());
    {
        let mut sockets = shared.sockets.lock().unwrap();
        let open = sockets.entry(ip).or_insert(0);
        if *open >= SOCKETS_PER_IP {
            return StatusCode::TOO_MANY_REQUESTS.into_response();
        }
        *open += 1;
    }
    let slot = Slot(shared.clone(), ip);
    ws.max_frame_size(wire::MAX_UP)
        .max_message_size(wire::MAX_UP)
        .read_buffer_size(16 << 10)
        .on_upgrade(move |socket| serve(socket, shared, ip, slot))
}

async fn login(socket: &mut WebSocket, shared: &Shared, ip: IpAddr) -> Option<PublicKey> {
    let challenge = wire::Challenge::fresh();
    if !send(socket, Message::Binary(challenge.public().to_vec().into())).await {
        return None;
    }
    let Some(Ok(Message::Binary(login))) = socket.recv().await else {
        return None;
    };
    let key = wire::verify(&challenge, &shared.config.host, &login).ok()?;
    if !take_keyed(
        &mut shared.ip_buckets.lock().unwrap(),
        ip,
        IP_SEND,
        Instant::now(),
    ) {
        return None;
    }
    let reply = Down::Ice(shared.ice(&key)).encode();
    send(socket, Message::Binary(reply.into()))
        .await
        .then_some(key)
}

async fn send(socket: &mut WebSocket, message: Message) -> bool {
    tokio::time::timeout(WRITE_TIMEOUT, socket.send(message))
        .await
        .is_ok_and(|sent| sent.is_ok())
}

async fn serve(mut socket: WebSocket, shared: Arc<Shared>, ip: IpAddr, _slot: Slot) {
    let Ok(Some(key)) = tokio::time::timeout(LOGIN_TIMEOUT, login(&mut socket, &shared, ip)).await
    else {
        return;
    };
    let session = wire::session_key(&key);

    let id = shared.next_id.fetch_add(1, Ordering::Relaxed);
    let (out, mut inbox) = mpsc::channel(QUEUE);
    let (kick, mut kicked) = oneshot::channel();
    let replaced = shared
        .sessions
        .lock()
        .unwrap()
        .insert(session, Session { id, out, kick });
    if let Some(old) = replaced {
        let _ = old.kick.send(());
    }

    let mut login_bucket = Bucket::new(LOGIN_SEND, Instant::now());
    let mut strangers = HashMap::new();
    let renew_every = shared.config.turn_ttl / 2;
    let mut renew =
        tokio::time::interval_at(tokio::time::Instant::now() + renew_every, renew_every);
    let mut ping = tokio::time::interval(PING);
    let silent = tokio::time::sleep(SILENT);
    tokio::pin!(silent);
    loop {
        let message = tokio::select! {
            frame = socket.recv() => {
                silent.as_mut().reset(tokio::time::Instant::now() + SILENT);
                match frame {
                    Some(Ok(Message::Binary(frame))) => {
                        let Ok(up) = Up::decode(&frame) else { break };
                        let reply = route(&shared, key, up, ip, &mut login_bucket, &mut strangers).encode();
                        Message::Binary(reply.into())
                    }
                    Some(Ok(Message::Ping(_) | Message::Pong(_)))
                        if login_bucket.take(LOGIN_SEND, Instant::now()) => continue,
                    _ => break,
                }
            }
            Some(down) = inbox.recv() => Message::Binary(down.encode().into()),
            _ = renew.tick() => Message::Binary(Down::Ice(shared.ice(&key)).encode().into()),
            _ = ping.tick() => Message::Ping(Vec::new().into()),
            _ = &mut silent => break,
            _ = &mut kicked => {
                send(&mut socket, Message::Binary(Down::Replaced.encode().into())).await;
                break;
            }
        };
        if !send(&mut socket, message).await {
            break;
        }
    }

    let mut sessions = shared.sessions.lock().unwrap();
    if sessions.get(&session).is_some_and(|s| s.id == id) {
        sessions.remove(&session);
    }
}

fn route(
    shared: &Shared,
    from: PublicKey,
    up: Up,
    ip: IpAddr,
    login_bucket: &mut Bucket,
    strangers: &mut HashMap<PublicKey, Bucket>,
) -> Down {
    let now = Instant::now();
    let id = up.id;
    let member = shared
        .config
        .allowlist
        .as_ref()
        .is_none_or(|list| list.contains(&from));
    if !login_bucket.take(LOGIN_SEND, now)
        || !take_keyed(&mut shared.ip_buckets.lock().unwrap(), ip, IP_SEND, now)
        || (!member && !take_keyed(strangers, up.to, STRANGER_SEND, now))
    {
        return Down::Limited(id);
    }
    // A non-member gets `Passed` whatever the recipient's state, so it never learns who is online.
    let offline = if member {
        Down::Offline(id)
    } else {
        Down::Passed(id)
    };
    let target = shared
        .sessions
        .lock()
        .unwrap()
        .get(&wire::session_key(&up.to))
        .map(|s| s.out.clone());
    let Some(target) = target else {
        return offline;
    };
    match target.try_send(Down::Deliver(up.envelope)) {
        Ok(()) => Down::Passed(id),
        Err(mpsc::error::TrySendError::Full(_)) if member => Down::Limited(id),
        Err(_) => offline,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv6_is_bucketed_by_slash_64_and_mapped_ipv4_is_ipv4() {
        let a: IpAddr = "2001:db8:1:2:3:4:5:6".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2::9".parse().unwrap();
        assert_eq!(ip_key(a), ip_key(b));
        let mapped: IpAddr = "::ffff:192.0.2.1".parse().unwrap();
        assert_eq!(ip_key(mapped), "192.0.2.1".parse::<IpAddr>().unwrap());
    }
}
