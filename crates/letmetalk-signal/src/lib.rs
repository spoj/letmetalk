mod limit;
mod turn;

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::extract::ws::{Message, WebSocket};
use axum::extract::{ConnectInfo, State, WebSocketUpgrade};
use axum::response::Response;
use axum::routing::get;
use axum::Router;
use letmetalk::ws::wire::{self, Down, Up};
use letmetalk::{IceServer, PublicKey};
use limit::{Bucket, Rate, take_keyed};
use tokio::sync::{mpsc, oneshot};

// Provisional, until they are sized from a measured startup of an endpoint dialing 20 peers.
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
const CREDENTIAL_TTL: Duration = Duration::from_secs(24 * 3600);
const CREDENTIAL_RENEW: Duration = Duration::from_secs(12 * 3600);
const QUEUE: usize = 64;

pub struct Turn {
    pub urls: Vec<String>,
    pub secret: String,
}

pub struct Config {
    pub host: String,
    /// `None` makes every key a member.
    pub allowlist: Option<HashSet<PublicKey>>,
    pub member_turn: Turn,
    pub stranger_turn: Turn,
}

struct Session {
    id: u64,
    out: mpsc::Sender<Down>,
    kick: oneshot::Sender<()>,
}

struct Shared {
    config: Config,
    sessions: Mutex<HashMap<PublicKey, Session>>,
    tokens: Mutex<HashMap<String, (PublicKey, u64)>>,
    ip_buckets: Mutex<HashMap<IpAddr, Bucket>>,
    next_id: AtomicU64,
}

#[derive(Clone)]
pub struct Forwarder(Arc<Shared>);

impl Forwarder {
    pub fn new(config: Config) -> Self {
        Self(Arc::new(Shared {
            config,
            sessions: Mutex::default(),
            tokens: Mutex::default(),
            ip_buckets: Mutex::default(),
            next_id: AtomicU64::new(0),
        }))
    }

    /// Serves `/ws`. Connections must be served with `ConnectInfo<SocketAddr>`.
    pub fn router(&self) -> Router {
        Router::new()
            .route("/ws", get(upgrade))
            .with_state(self.0.clone())
    }

    /// The key a TURN username was minted for, while its credential is valid.
    pub fn key_of(&self, token: &str) -> Option<PublicKey> {
        let now = now_secs();
        self.0
            .tokens
            .lock()
            .unwrap()
            .get(token)
            .filter(|(_, expiry)| *expiry > now)
            .map(|(key, _)| *key)
    }
}

impl Shared {
    fn is_member(&self, key: &PublicKey) -> bool {
        self.config
            .allowlist
            .as_ref()
            .is_none_or(|list| list.contains(key))
    }

    fn ice(&self, key: &PublicKey) -> Vec<IceServer> {
        let turn = if self.is_member(key) {
            &self.config.member_turn
        } else {
            &self.config.stranger_turn
        };
        let mut bytes = [0; 16];
        getrandom::fill(&mut bytes).expect("OS randomness");
        let token = hex::encode(bytes);
        let expiry = now_secs() + CREDENTIAL_TTL.as_secs();
        let username = format!("{expiry}:{token}");
        {
            let mut tokens = self.tokens.lock().unwrap();
            tokens.retain(|_, (_, until)| *until > now_secs());
            tokens.insert(token, (*key, expiry));
        }
        vec![IceServer {
            urls: turn.urls.clone(),
            credential: turn::password(&turn.secret, &username),
            username,
        }]
    }
}

async fn upgrade(
    State(shared): State<Arc<Shared>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    ws: WebSocketUpgrade,
) -> Response {
    ws.max_message_size(wire::MAX_UP)
        .on_upgrade(move |socket| serve(socket, shared, addr.ip()))
}

async fn serve(mut socket: WebSocket, shared: Arc<Shared>, ip: IpAddr) {
    let challenge = wire::Challenge::fresh();
    if socket
        .send(Message::Binary(challenge.public().to_vec().into()))
        .await
        .is_err()
    {
        return;
    }
    let Some(Ok(Message::Binary(login))) = socket.recv().await else {
        return;
    };
    let Ok(key) = wire::verify(&challenge, &shared.config.host, &login) else {
        return;
    };
    let reply = Down::Ice(shared.ice(&key));
    if socket
        .send(Message::Binary(reply.encode().into()))
        .await
        .is_err()
    {
        return;
    }

    let id = shared.next_id.fetch_add(1, Ordering::Relaxed);
    let (out, mut inbox) = mpsc::channel(QUEUE);
    let (kick, mut kicked) = oneshot::channel();
    let replaced = shared
        .sessions
        .lock()
        .unwrap()
        .insert(key, Session { id, out, kick });
    if let Some(old) = replaced {
        let _ = old.kick.send(());
    }

    let mut login_bucket = Bucket::new(LOGIN_SEND, Instant::now());
    let mut strangers = HashMap::new();
    let start = tokio::time::Instant::now() + CREDENTIAL_RENEW;
    let mut renew = tokio::time::interval_at(start, CREDENTIAL_RENEW);
    loop {
        let frame = tokio::select! {
            frame = socket.recv() => match frame {
                Some(Ok(Message::Binary(frame))) => {
                    let Ok(up) = Up::decode(&frame) else { break };
                    route(&shared, key, up, ip, &mut login_bucket, &mut strangers).encode()
                }
                Some(Ok(_)) => continue,
                _ => break,
            },
            Some(down) = inbox.recv() => down.encode(),
            _ = renew.tick() => Down::Ice(shared.ice(&key)).encode(),
            _ = &mut kicked => {
                let _ = socket.send(Message::Binary(Down::Replaced.encode().into())).await;
                break;
            }
        };
        if socket.send(Message::Binary(frame.into())).await.is_err() {
            break;
        }
    }

    let mut sessions = shared.sessions.lock().unwrap();
    if sessions.get(&key).is_some_and(|s| s.id == id) {
        sessions.remove(&key);
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
    let member = shared.is_member(&from);
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
    let target = shared.sessions.lock().unwrap().get(&up.to).map(|s| s.out.clone());
    let Some(target) = target else {
        return offline;
    };
    match target.try_send(Down::Deliver(up.envelope)) {
        Ok(()) => Down::Passed(id),
        Err(mpsc::error::TrySendError::Full(_)) if member => Down::Limited(id),
        Err(_) => offline,
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after 1970")
        .as_secs()
}
