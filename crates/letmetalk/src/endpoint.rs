//! Endpoints and links: setting up a link to a key, confirming it, and ending it.

use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::StreamExt;
use futures::channel::mpsc::{UnboundedReceiver, UnboundedSender, unbounded};
use futures::channel::oneshot;
use futures::lock::Mutex as AsyncMutex;
use n0_future::task::spawn;
use n0_future::time::{SystemTime, sleep, timeout};

use crate::backend::{Event, Peer, peer};
use crate::handshake::{Dialer, Kind, Offer, Replay, Transport, route};
use crate::keys::{PublicKey, SecretKey};
use crate::mux::{Incoming, Mux};
use crate::stream::Stream;
use crate::Signal;

const DIAL_TIMEOUT: Duration = Duration::from_secs(15);
const INBOUND_TIMEOUT: Duration = Duration::from_secs(10);
const CANDIDATE_BATCH: Duration = Duration::from_millis(50);
const LINKS: usize = 256;
const RELAYED_LINKS: usize = 64;
const DIRECT_SETUPS: usize = 16;
const RELAYED_SETUPS: usize = 8;
const DIRECT_BUDGET: usize = 4 << 20;
const RELAYED_BUDGET: usize = 256 << 10;

/// What this endpoint does with a key: refuse it, or link to it relayed or directly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admit {
    Refuse,
    Relayed,
    Direct,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Class {
    Direct,
    Relayed,
}

impl Class {
    fn of(admit: Admit) -> io::Result<Class> {
        match admit {
            Admit::Refuse => Err(io::Error::new(io::ErrorKind::PermissionDenied, "key refused")),
            Admit::Relayed => Ok(Class::Relayed),
            Admit::Direct => Ok(Class::Direct),
        }
    }

    fn budget(self) -> usize {
        match self {
            Class::Direct => DIRECT_BUDGET,
            Class::Relayed => RELAYED_BUDGET,
        }
    }

    fn setups(self) -> usize {
        match self {
            Class::Direct => DIRECT_SETUPS,
            Class::Relayed => RELAYED_SETUPS,
        }
    }
}

enum Input {
    Answer(Vec<u8>),
    Candidates(Vec<u8>),
    Event(Event),
    Expire,
    End,
}

struct Up {
    session: [u8; 16],
    tx: UnboundedSender<Input>,
    mux: Arc<Mux>,
    class: Class,
    used: u64,
    connected: bool,
}

struct Setup {
    session: [u8; 16],
    tx: UnboundedSender<Input>,
    dialed: bool,
    sent_ms: u64,
    class: Class,
    since: u64,
}

#[derive(Default)]
struct Entry {
    up: Option<Up>,
    setup: Option<Setup>,
    waiters: Vec<oneshot::Sender<Arc<Mux>>>,
}

#[derive(Default)]
struct State {
    links: HashMap<[u8; 32], Entry>,
    sessions: HashMap<[u8; 16], UnboundedSender<Input>>,
    replay: Replay,
    clock: u64,
    closed: bool,
}

impl State {
    fn tick(&mut self) -> u64 {
        self.clock += 1;
        self.clock
    }

    fn count(&self, class: Option<Class>) -> usize {
        let keep = |c: Class| class.is_none_or(|want| want == c);
        self.links
            .values()
            .map(|e| {
                e.up.iter().filter(|u| keep(u.class)).count() + e.setup.iter().filter(|s| keep(s.class)).count()
            })
            .sum()
    }

    fn end_setup(&mut self, key: [u8; 32]) {
        if let Some(setup) = self.links.get_mut(&key).and_then(|e| e.setup.take()) {
            let _ = setup.tx.unbounded_send(Input::End);
        }
    }

    /// Makes room for a new link of this class, evicting the least recently used idle link if needed.
    fn make_room(&mut self, class: Class) -> io::Result<()> {
        if class == Class::Relayed && self.count(Some(Class::Relayed)) >= RELAYED_LINKS {
            self.evict(Class::Relayed)?;
        }
        if self.count(None) >= LINKS {
            self.evict(class)?;
        }
        Ok(())
    }

    fn evict(&mut self, class: Class) -> io::Result<()> {
        let victim = self
            .links
            .iter()
            .filter_map(|(k, e)| {
                e.up.as_ref().filter(|u| u.class == class && u.mux.streams() == 0).map(|u| (u.used, *k))
            })
            .min();
        let Some((_, key)) = victim else {
            return Err(io::Error::new(io::ErrorKind::ResourceBusy, "no link can be evicted"));
        };
        if let Some(up) = self.links.get_mut(&key).and_then(|e| e.up.take()) {
            let _ = up.tx.unbounded_send(Input::End);
        }
        Ok(())
    }

    /// Decides whether to answer an offer from `dialer`: crossed offers keep the smaller key's, and a newer offer
    /// replaces an older inbound setup.
    fn admit_inbound(&mut self, me: PublicKey, dialer: PublicKey, sent_ms: u64, class: Class) -> io::Result<()> {
        let key = dialer.x25519();
        if let Some(setup) = self.links.get(&key).and_then(|e| e.setup.as_ref()) {
            if setup.dialed {
                if me.x25519() < key {
                    return Err(io::Error::new(io::ErrorKind::ResourceBusy, "crossed offer lost"));
                }
            } else if sent_ms <= setup.sent_ms {
                return Err(io::Error::other("older offer"));
            }
            self.end_setup(key);
        }
        let inbound = self
            .links
            .values()
            .filter(|e| e.setup.as_ref().is_some_and(|s| !s.dialed && s.class == class))
            .count();
        if inbound >= class.setups() {
            let oldest = self
                .links
                .iter()
                .filter_map(|(k, e)| e.setup.as_ref().filter(|s| !s.dialed && s.class == class).map(|s| (s.since, *k)))
                .min();
            if let Some((_, k)) = oldest {
                self.end_setup(k);
            }
        }
        self.make_room(class)
    }
}

struct Inner {
    key: SecretKey,
    signal: Arc<dyn Signal>,
    admit: Box<dyn Fn(&PublicKey) -> Admit + Send + Sync>,
    accepts: UnboundedSender<Stream>,
    accepted: AsyncMutex<UnboundedReceiver<Stream>>,
    state: Mutex<State>,
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).expect("clock is after 1970").as_millis() as u64
}

fn session_of(envelope: &[u8]) -> [u8; 16] {
    envelope[2..18].try_into().expect("envelopes have a session id")
}

fn expire_after(tx: UnboundedSender<Input>, after: Duration) {
    spawn(async move {
        sleep(after).await;
        let _ = tx.unbounded_send(Input::Expire);
    });
}

impl Inner {
    fn unlink(&self, key: PublicKey, session: [u8; 16]) {
        let mut st = self.state.lock().unwrap();
        st.sessions.remove(&session);
        let k = key.x25519();
        let Some(entry) = st.links.get_mut(&k) else {
            return;
        };
        if entry.setup.as_ref().is_some_and(|s| s.session == session) {
            entry.setup = None;
        }
        if entry.up.as_ref().is_some_and(|u| u.session == session) {
            entry.up = None;
        }
        if entry.up.is_none() && entry.setup.is_none() {
            st.links.remove(&k);
        }
    }

    fn set_connected(&self, key: PublicKey, session: [u8; 16], connected: bool) {
        let mut st = self.state.lock().unwrap();
        if let Some(up) = st.links.get_mut(&key.x25519()).and_then(|e| e.up.as_mut()).filter(|u| u.session == session) {
            up.connected = connected;
        }
    }

    fn confirm(&self, key: PublicKey, session: [u8; 16], tx: UnboundedSender<Input>, mux: Arc<Mux>, class: Class) {
        let mut st = self.state.lock().unwrap();
        let used = st.tick();
        let entry = st.links.entry(key.x25519()).or_default();
        if entry.setup.as_ref().is_some_and(|s| s.session == session) {
            entry.setup = None;
        }
        let old = entry.up.replace(Up { session, tx, mux: mux.clone(), class, used, connected: true });
        for waiter in entry.waiters.drain(..) {
            let _ = waiter.send(mux.clone());
        }
        if let Some(old) = old {
            let _ = old.tx.unbounded_send(Input::End);
        }
    }

    async fn dial(self: &Arc<Self>, to: PublicKey, class: Class) -> io::Result<()> {
        let peer = peer(&self.signal.ice_servers(), class == Class::Relayed).await?;
        let sdp = match peer.offer().await {
            Ok(sdp) => sdp,
            Err(e) => {
                peer.close().await;
                return Err(e);
            }
        };
        let sent_ms = now_ms();
        let (dialer, msg1) = Dialer::dial(&self.key, &to, sent_ms, sdp)?;
        let session = session_of(&msg1);
        let (tx, rx) = unbounded();
        {
            let mut st = self.state.lock().unwrap();
            if st.links.get(&to.x25519()).is_some_and(|e| e.setup.is_some()) {
                return Ok(());
            }
            let since = st.tick();
            st.links.entry(to.x25519()).or_default().setup =
                Some(Setup { session, tx: tx.clone(), dialed: true, sent_ms, class, since });
            st.sessions.insert(session, tx.clone());
        }
        let mut link = Link::new(self.clone(), to, session, class, true, peer, tx.clone());
        link.dialer = Some(dialer);
        expire_after(tx.clone(), DIAL_TIMEOUT);
        link.start(rx);
        if let Err(e) = self.signal.send(to, msg1).await {
            let _ = tx.unbounded_send(Input::End);
            return Err(e);
        }
        Ok(())
    }

    async fn link_to(self: &Arc<Self>, to: PublicKey) -> io::Result<Arc<Mux>> {
        let class = Class::of((self.admit)(&to))?;
        let (rx, dial) = {
            let mut st = self.state.lock().unwrap();
            if st.closed {
                return Err(io::Error::new(io::ErrorKind::NotConnected, "endpoint closed"));
            }
            let used = st.tick();
            let entry = st.links.entry(to.x25519()).or_default();
            if let Some(up) = entry.up.as_mut().filter(|u| u.connected) {
                up.used = used;
                return Ok(up.mux.clone());
            }
            let (tx, rx) = oneshot::channel();
            entry.waiters.push(tx);
            let dial = entry.setup.is_none();
            if dial {
                st.make_room(class)?;
            }
            (rx, dial)
        };
        if dial {
            self.dial(to, class).await?;
        }
        match timeout(DIAL_TIMEOUT, rx).await {
            Ok(Ok(mux)) => Ok(mux),
            _ => Err(io::Error::new(io::ErrorKind::TimedOut, "no link formed")),
        }
    }

    async fn answer(self: &Arc<Self>, envelope: Vec<u8>) -> io::Result<()> {
        let offer = Offer::receive(&self.key, &self.state.lock().unwrap().replay, &envelope, now_ms())?;
        let class = Class::of((self.admit)(&offer.dialer))?;
        let peer = peer(&self.signal.ice_servers(), class == Class::Relayed).await?;
        let sdp = peer.answer(&offer.sdp).await?;
        let (dialer, sent_ms) = (offer.dialer, offer.sent_ms);
        let (reply, transport) = {
            let mut st = self.state.lock().unwrap();
            st.admit_inbound(self.key.public(), dialer, sent_ms, class)?;
            let now = now_ms();
            offer.answer(&mut st.replay, now, &sdp)?
        };
        let session = session_of(&envelope);
        let (tx, rx) = unbounded();
        {
            let mut st = self.state.lock().unwrap();
            let since = st.tick();
            st.links.entry(dialer.x25519()).or_default().setup =
                Some(Setup { session, tx: tx.clone(), dialed: false, sent_ms, class, since });
            st.sessions.insert(session, tx.clone());
        }
        let mut link = Link::new(self.clone(), dialer, session, class, false, peer, tx.clone());
        link.key_up(transport).await?;
        expire_after(tx.clone(), INBOUND_TIMEOUT);
        link.start(rx);
        if let Err(e) = self.signal.send(dialer, reply).await {
            let _ = tx.unbounded_send(Input::End);
            return Err(e);
        }
        Ok(())
    }

    fn end(&self, peer: PublicKey) {
        let mut st = self.state.lock().unwrap();
        let k = peer.x25519();
        let Some(entry) = st.links.get_mut(&k) else {
            return;
        };
        if let Some(up) = entry.up.take() {
            let _ = up.tx.unbounded_send(Input::End);
        }
        if let Some(setup) = entry.setup.take() {
            let _ = setup.tx.unbounded_send(Input::End);
        }
        entry.waiters.clear();
        st.links.remove(&k);
    }
}

async fn route_all(inner: Arc<Inner>) {
    loop {
        let Some(envelope) = inner.signal.recv().await else {
            return;
        };
        let Some((kind, session)) = route(&envelope) else {
            continue;
        };
        match kind {
            Kind::Offer => {
                let inner = inner.clone();
                spawn(async move {
                    let _ = inner.answer(envelope).await;
                });
            }
            Kind::Answer | Kind::Candidates => {
                let tx = inner.state.lock().unwrap().sessions.get(&session).cloned();
                if let Some(tx) = tx {
                    let input = if kind == Kind::Answer { Input::Answer(envelope) } else { Input::Candidates(envelope) };
                    let _ = tx.unbounded_send(input);
                }
            }
        }
    }
}

async fn flush(inner: Arc<Inner>, mux: Arc<Mux>, key: PublicKey, session: [u8; 16], mut rx: UnboundedReceiver<String>) {
    let mut index = 0;
    while let Some(first) = rx.next().await {
        let mut batch = vec![first];
        sleep(CANDIDATE_BATCH).await;
        while let Ok(candidate) = rx.try_recv() {
            batch.push(candidate);
        }
        let mut bytes = Vec::new();
        ciborium::into_writer(&batch, &mut bytes).expect("CBOR into a Vec");
        let envelope = mux.transport().seal_candidates(&session, index, &bytes).expect("candidates fit the cipher");
        index += 1;
        if inner.signal.send(key, envelope).await.is_err() {
            return;
        }
    }
}

/// One link's setup and life: the handshake, candidates, confirmation and then its streams.
struct Link {
    inner: Arc<Inner>,
    key: PublicKey,
    session: [u8; 16],
    class: Class,
    dialed: bool,
    peer: Arc<dyn Peer>,
    tx: UnboundedSender<Input>,
    dialer: Option<Dialer>,
    candidates: UnboundedSender<String>,
    candidates_rx: Option<UnboundedReceiver<String>>,
    held: Vec<Vec<u8>>,
    mux: Option<Arc<Mux>>,
    confirmed: bool,
}

impl Link {
    fn new(
        inner: Arc<Inner>,
        key: PublicKey,
        session: [u8; 16],
        class: Class,
        dialed: bool,
        peer: Arc<dyn Peer>,
        tx: UnboundedSender<Input>,
    ) -> Link {
        let (candidates, candidates_rx) = unbounded();
        Link {
            inner,
            key,
            session,
            class,
            dialed,
            peer,
            tx,
            dialer: None,
            candidates,
            candidates_rx: Some(candidates_rx),
            held: Vec::new(),
            mux: None,
            confirmed: false,
        }
    }

    fn start(self, rx: UnboundedReceiver<Input>) {
        let peer = self.peer.clone();
        let tx = self.tx.clone();
        spawn(async move {
            while let Some(event) = peer.next().await {
                if tx.unbounded_send(Input::Event(event)).is_err() {
                    return;
                }
            }
        });
        spawn(self.run(rx));
    }

    async fn run(mut self, mut rx: UnboundedReceiver<Input>) {
        while let Some(input) = rx.next().await {
            let Ok(true) = self.step(input).await else {
                break;
            };
        }
        self.inner.unlink(self.key, self.session);
        self.peer.close().await;
        if let Some(mux) = &self.mux {
            mux.kill();
        }
    }

    async fn step(&mut self, input: Input) -> io::Result<bool> {
        match input {
            Input::End => Ok(false),
            Input::Expire => Ok(self.confirmed),
            Input::Answer(envelope) => {
                if let Some(dialer) = self.dialer.take() {
                    match dialer.finish(&envelope) {
                        Ok((transport, sdp)) => {
                            self.peer.accept(&sdp).await?;
                            self.key_up(transport).await?;
                        }
                        Err((dialer, _)) => self.dialer = Some(dialer),
                    }
                }
                Ok(true)
            }
            Input::Candidates(envelope) => {
                if self.mux.is_some() {
                    self.apply_candidates(&envelope).await?;
                } else {
                    self.held.push(envelope);
                }
                Ok(true)
            }
            Input::Event(event) => self.event(event).await,
        }
    }

    async fn key_up(&mut self, transport: Transport) -> io::Result<()> {
        let mux = Mux::new(self.peer.clone(), transport, self.key, self.dialed, self.class.budget());
        let rx = self.candidates_rx.take().expect("keyed once");
        spawn(flush(self.inner.clone(), mux.clone(), self.key, self.session, rx));
        self.mux = Some(mux);
        for envelope in std::mem::take(&mut self.held) {
            self.apply_candidates(&envelope).await?;
        }
        Ok(())
    }

    async fn apply_candidates(&self, envelope: &[u8]) -> io::Result<()> {
        let mux = self.mux.as_ref().expect("candidates are applied once keyed");
        let Ok((_, bytes)) = mux.transport().open_candidates(envelope) else {
            return Ok(());
        };
        let batch: Vec<String> = ciborium::from_reader(bytes.as_slice()).map_err(io::Error::other)?;
        for candidate in batch {
            self.peer.candidate(candidate).await?;
        }
        Ok(())
    }

    async fn event(&mut self, event: Event) -> io::Result<bool> {
        match event {
            Event::Candidate(candidate) => {
                let _ = self.candidates.unbounded_send(candidate);
                Ok(true)
            }
            Event::Connected => {
                self.inner.set_connected(self.key, self.session, true);
                Ok(true)
            }
            Event::Disconnected => {
                self.inner.set_connected(self.key, self.session, false);
                Ok(true)
            }
            Event::Failed => Ok(false),
            event => {
                let mux = self.mux.clone().ok_or_else(|| io::Error::other("stream event before the handshake"))?;
                match mux.handle(event)? {
                    Some(Incoming::Hello) if !self.confirmed => {
                        self.confirmed = true;
                        self.inner.confirm(self.key, self.session, self.tx.clone(), mux, self.class);
                    }
                    Some(Incoming::Stream(stream)) => {
                        if (self.inner.admit)(&self.key) == Admit::Refuse {
                            return Ok(false);
                        }
                        let _ = self.inner.accepts.unbounded_send(stream);
                    }
                    _ => {}
                }
                Ok(true)
            }
        }
    }
}

/// A local identity that dials keys by name and accepts streams from them.
#[derive(Clone)]
pub struct Endpoint(Arc<Inner>);

impl Endpoint {
    pub fn new(
        key: SecretKey,
        signal: impl Signal,
        admit: impl Fn(&PublicKey) -> Admit + Send + Sync + 'static,
    ) -> Endpoint {
        let (accepts, accepted) = unbounded();
        let inner = Arc::new(Inner {
            key,
            signal: Arc::new(signal),
            admit: Box::new(admit),
            accepts,
            accepted: AsyncMutex::new(accepted),
            state: Mutex::new(State::default()),
        });
        spawn(route_all(inner.clone()));
        Endpoint(inner)
    }

    pub fn key(&self) -> PublicKey {
        self.0.key.public()
    }

    pub async fn connect(&self, to: PublicKey, protocol: &str) -> io::Result<Stream> {
        let mux = self.0.link_to(to).await?;
        mux.open(protocol).await
    }

    pub async fn accept(&self) -> Option<Stream> {
        let mut accepted = self.0.accepted.lock().await;
        let stream = accepted.next().await?;
        stream.accept();
        Some(stream)
    }

    /// Closes the link to `peer`, and so its streams.
    pub fn disconnect(&self, peer: PublicKey) {
        self.0.end(peer);
    }

    pub async fn close(&self) {
        {
            let mut st = self.0.state.lock().unwrap();
            st.closed = true;
            for entry in st.links.values_mut() {
                if let Some(up) = entry.up.take() {
                    let _ = up.tx.unbounded_send(Input::End);
                }
                if let Some(setup) = entry.setup.take() {
                    let _ = setup.tx.unbounded_send(Input::End);
                }
            }
            st.links.clear();
        }
        self.0.accepts.close_channel();
    }
}
