//! Endpoints and links: setting up a link to a key, confirming it, and ending it.

use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use futures::FutureExt;
use futures::StreamExt;
use futures::channel::mpsc::{UnboundedReceiver, UnboundedSender, unbounded};
use futures::channel::oneshot;
use futures::future::{Either, select};
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
const KICK: Duration = Duration::from_millis(5);
const LINKS: usize = 256;
const RELAYED_LINKS: usize = 64;
const DIRECT_SETUPS: usize = 16;
const RELAYED_SETUPS: usize = 8;
const DIRECT_BUDGET: usize = 4 << 20;
const RELAYED_BUDGET: usize = 256 << 10;
const MAX_HELD: usize = 16;

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

    /// Reserves the setup of a dial to `to`, before its peer exists, so that no second dial starts meanwhile.
    fn reserve_dial(
        &mut self,
        to: PublicKey,
        class: Class,
    ) -> io::Result<([u8; 16], UnboundedSender<Input>, UnboundedReceiver<Input>)> {
        self.make_room(class)?;
        let mut session = [0; 16];
        getrandom::fill(&mut session).expect("OS randomness");
        let (tx, rx) = unbounded();
        let since = self.tick();
        let setup = Setup { session, tx: tx.clone(), dialed: true, sent_ms: now_ms(), class, since };
        self.links.entry(to.x25519()).or_default().setup = Some(setup);
        self.sessions.insert(session, tx.clone());
        Ok((session, tx, rx))
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
    stop: Mutex<Option<oneshot::Sender<()>>>,
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).expect("clock is after 1970").as_millis() as u64
}

impl Inner {
    /// Forgets a setup or link of `session`, and the waiters of a key left without one.
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
        if entry.setup.is_none() {
            entry.waiters.clear();
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

    /// Makes the setup of `session` a link, and replaces the old one. False if that setup has since ended.
    fn confirm(&self, key: PublicKey, session: [u8; 16], tx: UnboundedSender<Input>, mux: Arc<Mux>, class: Class) -> bool {
        let mut st = self.state.lock().unwrap();
        let used = st.tick();
        let Some(entry) = st
            .links
            .get_mut(&key.x25519())
            .filter(|e| e.setup.as_ref().is_some_and(|s| s.session == session))
        else {
            return false;
        };
        entry.setup = None;
        let old = entry.up.replace(Up { session, tx, mux: mux.clone(), class, used, connected: true });
        for waiter in entry.waiters.drain(..) {
            let _ = waiter.send(mux.clone());
        }
        if let Some(old) = old {
            let _ = old.tx.unbounded_send(Input::End);
        }
        true
    }

    async fn new_peer(&self, class: Class) -> io::Result<Arc<dyn Peer>> {
        let ice = self.signal.ice_servers();
        if class == Class::Relayed && ice.is_empty() {
            return Err(io::Error::new(io::ErrorKind::Unsupported, "no relay server to relay through"));
        }
        peer(&ice, class == Class::Relayed).await
    }

    async fn dial(
        self: &Arc<Self>,
        to: PublicKey,
        class: Class,
        session: [u8; 16],
        tx: UnboundedSender<Input>,
        rx: UnboundedReceiver<Input>,
    ) -> io::Result<()> {
        let peer = self.new_peer(class).await.inspect_err(|_| self.unlink(to, session))?;
        let mut link = Link::new(self.clone(), to, session, class, true, peer, tx);
        let msg1 = match link.make_offer().await {
            Ok(msg1) => msg1,
            Err(e) => {
                link.close().await;
                return Err(e);
            }
        };
        if let Err(e) = self.signal.send(to, msg1).await {
            link.close().await;
            return Err(e);
        }
        link.start(rx);
        Ok(())
    }

    async fn link_to(self: &Arc<Self>, to: PublicKey) -> io::Result<Arc<Mux>> {
        let class = Class::of((self.admit)(&to))?;
        let (rx, setup) = {
            let mut st = self.state.lock().unwrap();
            if st.closed {
                return Err(io::Error::new(io::ErrorKind::NotConnected, "endpoint closed"));
            }
            let used = st.tick();
            if let Some(up) = st.links.get_mut(&to.x25519()).and_then(|e| e.up.as_mut()).filter(|u| u.connected) {
                up.used = used;
                return Ok(up.mux.clone());
            }
            let dial = st.links.get(&to.x25519()).is_none_or(|e| e.setup.is_none());
            let setup = if dial { Some(st.reserve_dial(to, class)?) } else { None };
            let (tx, rx) = oneshot::channel();
            st.links.entry(to.x25519()).or_default().waiters.push(tx);
            (rx, setup)
        };
        if let Some((session, tx, setup_rx)) = setup {
            self.dial(to, class, session, tx, setup_rx).await?;
        }
        match timeout(DIAL_TIMEOUT, rx).await {
            Ok(Ok(mux)) => Ok(mux),
            _ => Err(io::Error::new(io::ErrorKind::TimedOut, "no link formed")),
        }
    }

    /// Answers an offer. Nothing is built until `admit` and the setup limits have accepted it, all under one lock.
    async fn answer(self: &Arc<Self>, envelope: Vec<u8>, session: [u8; 16]) -> io::Result<()> {
        let (offer, class, tx, rx) = {
            let mut st = self.state.lock().unwrap();
            if st.closed {
                return Err(io::Error::new(io::ErrorKind::NotConnected, "endpoint closed"));
            }
            let offer = Offer::receive(&self.key, &st.replay, &envelope, now_ms())?;
            let class = Class::of((self.admit)(&offer.dialer))?;
            if st.sessions.contains_key(&session) {
                return Err(io::Error::other("session in use"));
            }
            st.admit_inbound(self.key.public(), offer.dialer, offer.sent_ms, class)?;
            let (tx, rx) = unbounded();
            let since = st.tick();
            let setup = Setup { session, tx: tx.clone(), dialed: false, sent_ms: offer.sent_ms, class, since };
            st.links.entry(offer.dialer.x25519()).or_default().setup = Some(setup);
            st.sessions.insert(session, tx.clone());
            (offer, class, tx, rx)
        };
        let dialer = offer.dialer;
        let peer = self.new_peer(class).await.inspect_err(|_| self.unlink(dialer, session))?;
        let mut link = Link::new(self.clone(), dialer, session, class, false, peer, tx);
        let reply = match link.accept_offer(offer).await {
            Ok(reply) => reply,
            Err(e) => {
                link.close().await;
                return Err(e);
            }
        };
        if let Err(e) = self.signal.send(dialer, reply).await {
            link.close().await;
            return Err(e);
        }
        link.start(rx);
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

/// Routes what the carrier delivers until the endpoint closes or is dropped. It holds the endpoint only weakly.
async fn route_all(signal: Arc<dyn Signal>, inner: Weak<Inner>, mut stopped: oneshot::Receiver<()>) {
    loop {
        let envelope = match select(signal.recv(), &mut stopped).await {
            Either::Left((Some(envelope), _)) => envelope,
            _ => return,
        };
        let Some(inner) = inner.upgrade() else {
            return;
        };
        let Some((kind, session)) = route(&envelope) else {
            continue;
        };
        match kind {
            Kind::Offer => {
                let inner = inner.clone();
                spawn(async move {
                    let _ = inner.answer(envelope, session).await;
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

/// Keeps the peer connection's driver awake until the link is confirmed, so that what it queues while handling a
/// packet goes out at once.
async fn kick(peer: Arc<dyn Peer>, stopped: oneshot::Receiver<()>) {
    let mut stopped = stopped.fuse();
    loop {
        futures::select! {
            _ = stopped => return,
            _ = sleep(KICK).fuse() => peer.kick().await,
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
    kicker: Option<oneshot::Sender<()>>,
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
            kicker: None,
        }
    }

    /// Runs the link's task. Until then nothing reads the peer's events, which wait in its queue.
    fn start(mut self, rx: UnboundedReceiver<Input>) {
        let (done, stopped) = oneshot::channel();
        self.kicker = Some(done);
        spawn(kick(self.peer.clone(), stopped));
        spawn(self.run(rx));
    }

    async fn run(mut self, mut rx: UnboundedReceiver<Input>) {
        let mut expire = Box::pin(sleep(if self.dialed { DIAL_TIMEOUT } else { INBOUND_TIMEOUT })).fuse();
        loop {
            let input = match select(select(rx.next(), self.peer.next()), &mut expire).await {
                Either::Left((Either::Left((input, _)), _)) => input,
                Either::Left((Either::Right((event, _)), _)) => event.map(Input::Event),
                Either::Right(_) => Some(Input::Expire),
            };
            let Some(input) = input else {
                break;
            };
            let Ok(true) = self.step(input).await else {
                break;
            };
        }
        self.close().await;
    }

    /// Ends the link's setup or link, and closes its peer connection.
    async fn close(&self) {
        self.inner.unlink(self.key, self.session);
        self.peer.close().await;
        if let Some(mux) = &self.mux {
            mux.kill();
        }
    }

    async fn make_offer(&mut self) -> io::Result<Vec<u8>> {
        let sdp = self.peer.offer().await?;
        let (dialer, msg1) = Dialer::dial(&self.inner.key, &self.key, self.session, now_ms(), sdp)?;
        self.dialer = Some(dialer);
        Ok(msg1)
    }

    async fn accept_offer(&mut self, offer: Offer) -> io::Result<Vec<u8>> {
        let sdp = self.peer.answer(&offer.sdp).await?;
        let (reply, transport) = offer.answer(&mut self.inner.state.lock().unwrap().replay, now_ms(), &sdp)?;
        self.key_up(transport).await?;
        Ok(reply)
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
                } else if self.held.len() < MAX_HELD {
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
        let Ok(bytes) = mux.transport().open_candidates(envelope) else {
            return Ok(());
        };
        let batch: Vec<String> = ciborium::from_reader(bytes.as_slice()).map_err(io::Error::other)?;
        for candidate in batch {
            let _ = self.peer.candidate(candidate).await;
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
                        if !self.inner.confirm(self.key, self.session, self.tx.clone(), mux, self.class) {
                            return Ok(false);
                        }
                        self.confirmed = true;
                        self.kicker = None;
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
        let (stop, stopped) = oneshot::channel();
        let inner = Arc::new(Inner {
            key,
            signal: Arc::new(signal),
            admit: Box::new(admit),
            accepts,
            accepted: AsyncMutex::new(accepted),
            state: Mutex::new(State::default()),
            stop: Mutex::new(Some(stop)),
        });
        spawn(route_all(inner.signal.clone(), Arc::downgrade(&inner), stopped));
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

    /// The route of the link to `peer`, if one is up.
    #[cfg(feature = "stats")]
    pub async fn path(&self, peer: PublicKey) -> Option<crate::Path> {
        let mux = self.0.state.lock().unwrap().links.get(&peer.x25519())?.up.as_ref()?.mux.clone();
        mux.path().await
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
        self.0.stop.lock().unwrap().take();
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use crate::fake;
    use crate::backend::Peer;
    use crate::handshake::{Dialer, Offer, Replay};

    /// A live, idle link of `class`: a mux over a real handshake and a fake peer. The fake's other end is returned
    /// too, since the fake fails once it is dropped.
    async fn live_link(class: Class, used: u64) -> (Up, Arc<dyn Peer>) {
        let (a, b) = (SecretKey::generate(), SecretKey::generate());
        let (dialer, msg1) = Dialer::dial(&a, &b.public(), [1; 16], now_ms(), String::new()).unwrap();
        let offer = Offer::receive(&b, &Replay::default(), &msg1, now_ms()).unwrap();
        let (msg2, _) = offer.answer(&mut Replay::default(), now_ms(), "").unwrap();
        let (transport, _) = dialer.finish(&msg2).map_err(|(_, e)| e).unwrap();
        let (peer, other) = fake::pair();
        let mux = Mux::new(peer, transport, b.public(), true, class.budget());
        let (tx, _) = unbounded();
        (Up { session: [used as u8; 16], tx, mux, class, used, connected: true }, other)
    }

    fn setup(class: Class, dialed: bool, since: u64) -> Setup {
        let (tx, _) = unbounded();
        Setup { session: [since as u8; 16], tx, dialed, sent_ms: now_ms(), class, since }
    }

    #[tokio::test]
    async fn full_links_evict_the_least_recent_idle_one_then_refuse() {
        let mut st = State::default();
        let mut keys = Vec::new();
        let mut others = Vec::new();
        for used in 1..=LINKS as u64 {
            let key = SecretKey::generate().public();
            let (up, other) = live_link(Class::Direct, used).await;
            st.links.entry(key.x25519()).or_default().up = Some(up);
            others.push(other);
            keys.push(key);
        }
        st.make_room(Class::Direct).unwrap();
        assert!(st.links[&keys[0].x25519()].up.is_none());
        assert!(st.links[&keys[1].x25519()].up.is_some());

        let key = SecretKey::generate().public();
        let (up, other) = live_link(Class::Direct, LINKS as u64 + 1).await;
        st.links.entry(key.x25519()).or_default().up = Some(up);
        others.push(other);
        let mut busy = Vec::new();
        for entry in st.links.values() {
            if let Some(up) = &entry.up {
                busy.push(up.mux.open("busy").await.unwrap());
            }
        }
        assert_eq!(st.make_room(Class::Direct).unwrap_err().kind(), io::ErrorKind::ResourceBusy);
        assert_eq!(st.make_room(Class::Relayed).unwrap_err().kind(), io::ErrorKind::ResourceBusy);
    }

    #[tokio::test]
    async fn relayed_offers_from_fresh_keys_evict_no_direct_setup_or_link() {
        let me = SecretKey::generate().public();
        let mut st = State::default();
        let direct_setup = SecretKey::generate().public();
        st.links.entry(direct_setup.x25519()).or_default().setup = Some(setup(Class::Direct, false, 1));
        let direct_link = SecretKey::generate().public();
        let (up, _direct_other) = live_link(Class::Direct, 1).await;
        st.links.entry(direct_link.x25519()).or_default().up = Some(up);
        let mut others = Vec::new();
        for used in 0..LINKS as u64 - 3 {
            let key = SecretKey::generate().public();
            let (up, other) = live_link(Class::Relayed, used).await;
            st.links.entry(key.x25519()).or_default().up = Some(up);
            others.push(other);
        }

        for _ in 0..50 {
            let key = SecretKey::generate().public();
            if st.admit_inbound(me, key, now_ms(), Class::Relayed).is_ok() {
                let since = st.tick();
                st.links.entry(key.x25519()).or_default().setup = Some(setup(Class::Relayed, false, since));
            }
        }
        assert!(st.links[&direct_setup.x25519()].setup.is_some());
        assert!(st.links[&direct_link.x25519()].up.is_some());
    }
}
