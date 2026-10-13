//! The stream layer over one peer connection: numbers, sealing, messages and credit.

use std::collections::{BTreeSet, HashMap};
use std::io;
use std::sync::{Arc, Mutex};

use futures::StreamExt;
use futures::channel::mpsc::{UnboundedReceiver, UnboundedSender, unbounded};
use futures::channel::oneshot;
use n0_future::task::spawn;

use crate::backend::{Event, Peer};
use crate::handshake::Transport;
use crate::keys::PublicKey;
use crate::stream::{Io, IoState, Stream};

pub(crate) const CONTROL: u32 = 0;
const LAST: u32 = (1 << 24) - 1;
const WINDOW: u32 = 1024;
pub(crate) const CHUNK: usize = 16 * 1024;
pub(crate) const FIRST_CREDIT: usize = 16 * 1024;
pub(crate) const ACCEPTED_CREDIT: usize = 1 << 20;
const MAX_STREAMS: usize = 128;
const MAX_WAITING: usize = 16;
const MAX_PROTOCOL: usize = 255;

pub(crate) enum Plain {
    Open(String),
    Data(Vec<u8>),
    Finish,
    Hello,
    Credit(u32, u32),
    Reset(u32),
}

impl Plain {
    fn encode(&self) -> Vec<u8> {
        match self {
            Plain::Open(protocol) => [&[1][..], protocol.as_bytes()].concat(),
            Plain::Data(data) => [&[2][..], data].concat(),
            Plain::Finish => vec![3],
            Plain::Hello => vec![4],
            Plain::Credit(n, bytes) => [&[5][..], &n.to_be_bytes(), &bytes.to_be_bytes()].concat(),
            Plain::Reset(n) => [&[6][..], &n.to_be_bytes()].concat(),
        }
    }

    fn decode(mut bytes: Vec<u8>) -> io::Result<Plain> {
        let bad = || io::Error::other("bad message");
        let kind = *bytes.first().ok_or_else(bad)?;
        Ok(match (kind, bytes.len()) {
            (1, 1..=256) => Plain::Open(String::from_utf8(bytes[1..].to_vec()).map_err(io::Error::other)?),
            (2, _) => {
                bytes.drain(..1);
                Plain::Data(bytes)
            }
            (3, 1) => Plain::Finish,
            (4, 1) => Plain::Hello,
            (5, 9) => Plain::Credit(be32(&bytes[1..5]), be32(&bytes[5..9])),
            (6, 5) => Plain::Reset(be32(&bytes[1..5])),
            _ => return Err(bad()),
        })
    }
}

fn be32(bytes: &[u8]) -> u32 {
    u32::from_be_bytes(bytes.try_into().expect("four bytes"))
}

fn reset() -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionReset, "stream reset")
}

/// The stream numbers a peer has opened. Each must have the peer's parity and be new, within a window of
/// 1,024 below the highest one seen.
#[derive(Default)]
struct Numbers {
    highest: u32,
    seen: BTreeSet<u32>,
}

impl Numbers {
    fn admit(&mut self, number: u32, parity: u32) -> io::Result<()> {
        if number == CONTROL || number >= LAST || number % 2 != parity {
            return Err(io::Error::other("bad stream number"));
        }
        if number + WINDOW <= self.highest || !self.seen.insert(number) {
            return Err(io::Error::other("stream number reused"));
        }
        self.highest = self.highest.max(number);
        self.seen.retain(|&n| n + WINDOW > self.highest);
        Ok(())
    }
}

pub(crate) enum Incoming {
    Hello,
    Stream(Stream),
}

struct State {
    streams: HashMap<u32, Arc<Io>>,
    numbers: Numbers,
    next: u32,
    control_index: u64,
    control_open: bool,
    dead: bool,
}

pub(crate) struct Mux {
    peer: Arc<dyn Peer>,
    transport: Arc<Transport>,
    pub(crate) remote: PublicKey,
    dialer: bool,
    budget: usize,
    control: UnboundedSender<Plain>,
    state: Mutex<State>,
}

async fn control_loop(peer: Arc<dyn Peer>, transport: Arc<Transport>, mut rx: UnboundedReceiver<Plain>) {
    let mut index = 0;
    while let Some(plain) = rx.next().await {
        let sealed = transport.seal(index, &plain.encode()).expect("messages fit the cipher");
        index += 1;
        if peer.send(CONTROL, sealed).await.is_err() {
            return;
        }
    }
}

async fn send_loop(mux: Arc<Mux>, number: u32, start: oneshot::Receiver<()>, mut outbox: UnboundedReceiver<Plain>) {
    if start.await.is_err() {
        return;
    }
    let mut index = 0u64;
    while let Some(plain) = outbox.next().await {
        let finish = matches!(plain, Plain::Finish);
        let nonce = (number as u64) << 40 | index;
        index += 1;
        let sealed = mux.transport.seal(nonce, &plain.encode()).expect("messages fit the cipher");
        if mux.peer.send(number, sealed).await.is_err() {
            mux.fail_stream(number, true);
            mux.close_later(number);
            return;
        }
        if finish {
            mux.finished(number, true);
        }
    }
}

impl Mux {
    pub(crate) fn new(
        peer: Arc<dyn Peer>,
        transport: Transport,
        remote: PublicKey,
        dialer: bool,
        budget: usize,
    ) -> Arc<Mux> {
        let (control, rx) = unbounded();
        let transport = Arc::new(transport);
        spawn(control_loop(peer.clone(), transport.clone(), rx));
        Arc::new(Mux {
            peer,
            transport,
            remote,
            dialer,
            budget,
            control,
            state: Mutex::new(State {
                streams: HashMap::new(),
                numbers: Numbers::default(),
                next: if dialer { 2 } else { 1 },
                control_index: 0,
                control_open: false,
                dead: false,
            }),
        })
    }

    pub(crate) fn transport(&self) -> &Transport {
        &self.transport
    }

    pub(crate) fn streams(&self) -> usize {
        self.state.lock().unwrap().streams.len()
    }

    fn peer_parity(&self) -> u32 {
        u32::from(self.dialer)
    }

    pub(crate) async fn open(self: &Arc<Self>, protocol: &str) -> io::Result<Stream> {
        if protocol.len() > MAX_PROTOCOL {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "protocol name longer than 255 bytes"));
        }
        let (number, io) = {
            let mut st = self.state.lock().unwrap();
            if st.dead {
                return Err(reset());
            }
            let own = st.streams.values().filter(|io| io.own()).count();
            if own >= MAX_STREAMS || st.next >= LAST {
                return Err(io::Error::new(io::ErrorKind::ResourceBusy, "no stream slot free"));
            }
            let number = st.next;
            st.next += 2;
            let (ready, start) = oneshot::channel();
            let (outbox, rx) = unbounded();
            let io = Arc::new(Io::new(number, true, Some(ready), outbox));
            io.state().outbox.unbounded_send(Plain::Open(protocol.to_string())).expect("fresh outbox");
            st.streams.insert(number, io.clone());
            spawn(send_loop(self.clone(), number, start, rx));
            self.grant(&mut st);
            (number, io)
        };
        if let Err(e) = self.peer.open(number).await {
            self.fail_stream(number, false);
            return Err(e);
        }
        Ok(Stream::new(self.clone(), io, protocol.to_string()))
    }

    /// Handles one event of the peer connection that concerns streams or the control channel.
    pub(crate) fn handle(self: &Arc<Self>, event: Event) -> io::Result<Option<Incoming>> {
        match event {
            Event::Ready(CONTROL) => {
                self.send_control(Plain::Hello)?;
                Ok(None)
            }
            Event::Opened(CONTROL) => {
                if std::mem::replace(&mut self.state.lock().unwrap().control_open, true) {
                    return Err(io::Error::other("control channel opened twice"));
                }
                self.send_control(Plain::Hello)?;
                Ok(None)
            }
            Event::Ready(n) => {
                self.ready(n);
                Ok(None)
            }
            Event::Opened(n) => {
                self.opened(n)?;
                Ok(None)
            }
            Event::Message(CONTROL, data) => self.control_message(data),
            Event::Message(n, data) => self.stream_message(n, data),
            Event::Closed(CONTROL) => Err(reset()),
            Event::Closed(n) => {
                self.closed(n);
                Ok(None)
            }
            _ => Ok(None),
        }
    }

    fn send_control(&self, plain: Plain) -> io::Result<()> {
        self.control.unbounded_send(plain).map_err(|_| reset())
    }

    fn ready(&self, n: u32) {
        let st = self.state.lock().unwrap();
        if let Some(ready) = st.streams.get(&n).and_then(|io| io.state().ready.take()) {
            let _ = ready.send(());
        }
    }

    fn opened(self: &Arc<Self>, n: u32) -> io::Result<()> {
        let mut st = self.state.lock().unwrap();
        if st.dead {
            return Ok(());
        }
        st.numbers.admit(n, self.peer_parity())?;
        let peers = st.streams.values().filter(|io| !io.own()).count();
        if peers >= MAX_STREAMS {
            self.send_control(Plain::Reset(n))?;
            self.close_later(n);
            return Ok(());
        }
        let (outbox, rx) = unbounded();
        let io = Arc::new(Io::new(n, false, None, outbox));
        st.streams.insert(n, io);
        let (started, start) = oneshot::channel();
        let _ = started.send(());
        spawn(send_loop(self.clone(), n, start, rx));
        Ok(())
    }

    fn control_message(self: &Arc<Self>, data: Vec<u8>) -> io::Result<Option<Incoming>> {
        let mut st = self.state.lock().unwrap();
        let index = st.control_index;
        st.control_index += 1;
        let plain = self.transport.open(index, &data).and_then(Plain::decode)?;
        match plain {
            Plain::Hello => Ok(Some(Incoming::Hello)),
            Plain::Credit(n, bytes) => {
                if let Some(io) = st.streams.get(&n).cloned() {
                    let mut s = io.state();
                    if s.credit + bytes as usize > ACCEPTED_CREDIT {
                        return Err(io::Error::other("credit past the window"));
                    }
                    s.credit += bytes as usize;
                    if let Some(waker) = s.write_waker.take() {
                        waker.wake();
                    }
                }
                Ok(None)
            }
            Plain::Reset(n) => {
                self.fail(&mut st, n, false);
                self.close_later(n);
                Ok(None)
            }
            _ => Err(io::Error::other("bad control message")),
        }
    }

    fn stream_message(self: &Arc<Self>, n: u32, data: Vec<u8>) -> io::Result<Option<Incoming>> {
        let mut st = self.state.lock().unwrap();
        let Some(io) = st.streams.get(&n).cloned() else {
            return Ok(None);
        };
        let opened = {
            let mut s = io.state();
            let nonce = (n as u64) << 40 | s.recv_index;
            s.recv_index += 1;
            self.transport.open(nonce, &data).and_then(Plain::decode).map(|plain| (plain, s.opened))
        };
        let (plain, was_open) = match opened {
            Ok(pair) => pair,
            Err(_) => {
                self.fail(&mut st, n, true);
                self.close_later(n);
                return Ok(None);
            }
        };
        match plain {
            Plain::Open(protocol) => {
                if was_open {
                    return Err(io::Error::other("stream opened twice"));
                }
                let waiting = st.streams.values().filter(|io| !io.own() && io.is_waiting()).count();
                if waiting >= MAX_WAITING {
                    self.fail(&mut st, n, true);
                    self.close_later(n);
                    return Ok(None);
                }
                io.state().opened = true;
                Ok(Some(Incoming::Stream(Stream::new(self.clone(), io, protocol))))
            }
            _ if !was_open => Err(io::Error::other("data before open")),
            Plain::Data(bytes) => {
                let mut s = io.state();
                if s.received + bytes.len() > s.granted {
                    return Err(io::Error::other("sent past its credit"));
                }
                s.received += bytes.len();
                if s.discard {
                    s.read += bytes.len();
                    drop(s);
                    self.grant(&mut st);
                    return Ok(None);
                }
                s.inbox.extend(bytes);
                if let Some(waker) = s.read_waker.take() {
                    waker.wake();
                }
                Ok(None)
            }
            Plain::Finish => {
                let both = {
                    let mut s = io.state();
                    s.remote_finished = true;
                    if let Some(waker) = s.read_waker.take() {
                        waker.wake();
                    }
                    s.local_finished
                };
                if both {
                    self.close_later(n);
                }
                self.reap(&mut st, n);
                Ok(None)
            }
            _ => Err(io::Error::other("bad stream message")),
        }
    }

    fn closed(&self, n: u32) {
        let mut st = self.state.lock().unwrap();
        let done = st.streams.get(&n).is_some_and(|io| io.is_done());
        if !done {
            self.fail(&mut st, n, false);
        }
    }

    /// Records that this side sent or received its `Finish`. Once both have, the channel closes.
    pub(crate) fn finished(&self, n: u32, local: bool) {
        let mut st = self.state.lock().unwrap();
        let Some(io) = st.streams.get(&n).cloned() else {
            return;
        };
        let both = {
            let mut s = io.state();
            if local {
                s.local_finished = true;
            } else {
                s.remote_finished = true;
            }
            if let Some(waker) = s.read_waker.take() {
                waker.wake();
            }
            s.local_finished && s.remote_finished
        };
        if both {
            self.close_later(n);
        }
        self.reap(&mut st, n);
    }

    /// Removes a finished stream once the app has read all of it.
    fn reap(&self, st: &mut State, n: u32) {
        if st.streams.get(&n).is_some_and(|io| io.is_drained()) {
            st.streams.remove(&n);
        }
    }

    /// Removes a stream and fails its app-side handle. The channel is left as it is.
    fn fail(&self, st: &mut State, n: u32, notify: bool) {
        if let Some(io) = st.streams.remove(&n) {
            io.fail();
        }
        if notify {
            let _ = self.send_control(Plain::Reset(n));
        }
    }

    pub(crate) fn fail_stream(&self, n: u32, notify: bool) {
        let mut st = self.state.lock().unwrap();
        self.fail(&mut st, n, notify);
    }

    /// Ends the link: every stream fails, and the state drops its streams.
    pub(crate) fn kill(&self) {
        let mut st = self.state.lock().unwrap();
        st.dead = true;
        for (_, io) in st.streams.drain() {
            io.fail();
        }
    }

    fn close_later(&self, n: u32) {
        let peer = self.peer.clone();
        spawn(async move { peer.close_channel(n).await });
    }

    /// Grants credit to each stream. Each keeps its first 16 KiB outside the budget; above that, streams share what
    /// the link's budget has free. A grant goes out only once the shortfall is a full chunk.
    fn grant(&self, st: &mut State) {
        let above = |s: &IoState| s.outstanding().saturating_sub(FIRST_CREDIT);
        let used: usize = st.streams.values().map(|io| above(&io.state())).sum();
        let mut free = self.budget.saturating_sub(used);
        for (&n, io) in &st.streams {
            let mut s = io.state();
            if s.failed || s.remote_finished {
                continue;
            }
            let want = if s.accepted { ACCEPTED_CREDIT } else { FIRST_CREDIT };
            if want.saturating_sub(s.outstanding()) < CHUNK {
                continue;
            }
            let floor = FIRST_CREDIT.saturating_sub(s.outstanding());
            let extra = want.saturating_sub(s.outstanding() + floor).min(free);
            free -= extra;
            let grant = floor + extra;
            if grant > 0 {
                s.granted += grant;
                let _ = self.control.unbounded_send(Plain::Credit(n, grant as u32));
            }
        }
    }

    /// Called when the app reads from, or accepts, a stream.
    pub(crate) fn consumed(&self, n: u32) {
        let mut st = self.state.lock().unwrap();
        self.grant(&mut st);
        self.reap(&mut st, n);
    }

    pub(crate) fn accept(&self, n: u32) {
        let mut st = self.state.lock().unwrap();
        if let Some(io) = st.streams.get(&n).cloned() {
            io.state().accepted = true;
            self.grant(&mut st);
        }
    }

    /// Called when a stream's handle drops. A stream that finished sending keeps discarding what the peer
    /// still sends, so the peer can finish. Any other stream is reset.
    pub(crate) fn dropped(&self, n: u32) {
        let mut st = self.state.lock().unwrap();
        let Some(io) = st.streams.get(&n).cloned() else {
            return;
        };
        let (done, shut) = {
            let s = io.state();
            (s.local_finished && s.remote_finished, s.queued_finish)
        };
        if done {
            st.streams.remove(&n);
        } else if shut {
            {
                let mut s = io.state();
                s.discard = true;
                s.read = s.received;
                s.inbox.clear();
            }
            self.grant(&mut st);
        } else {
            self.fail(&mut st, n, true);
            self.close_later(n);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use futures::StreamExt;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::fake;
    use crate::handshake::{Dialer, Offer, Replay};
    use crate::keys::SecretKey;

    const BUDGET: usize = 4 << 20;
    const RELAYED_BUDGET: usize = 256 << 10;
    const MIB: usize = 1 << 20;

    fn now_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }

    fn transports() -> (Transport, Transport) {
        let a = SecretKey::generate();
        let b = SecretKey::generate();
        let mut replay = Replay::default();
        let (dialer, msg1) = Dialer::dial(&a, &b.public(), [1; 16], now_ms(), "offer".into()).unwrap();
        let offer = Offer::receive(&b, &replay, &msg1, now_ms()).unwrap();
        let (msg2, accepter) = offer.answer(&mut replay, now_ms(), "answer").unwrap();
        let (dialed, _) = dialer.finish(&msg2).map_err(|(_, e)| e).unwrap();
        (dialed, accepter)
    }

    /// Feeds one side's events to its mux. Accepted streams come out of the receiver. An error ends the task.
    fn serve(
        mux: Arc<Mux>,
        peer: Arc<dyn Peer>,
    ) -> (UnboundedReceiver<Stream>, n0_future::task::JoinHandle<io::Result<()>>) {
        let (tx, rx) = unbounded();
        let task = spawn(async move {
            while let Some(event) = peer.next().await {
                if let Some(Incoming::Stream(stream)) = mux.handle(event)? {
                    let _ = tx.unbounded_send(stream);
                }
            }
            Ok(())
        });
        (rx, task)
    }

    /// A dialer mux (A) and an accepter mux (B) over a fake pair. Both sides are served.
    struct Pair {
        a: Arc<Mux>,
        b: Arc<Mux>,
        a_peer: Arc<dyn Peer>,
        b_peer: Arc<dyn Peer>,
        accepts: UnboundedReceiver<Stream>,
        a_task: n0_future::task::JoinHandle<io::Result<()>>,
        b_task: n0_future::task::JoinHandle<io::Result<()>>,
    }

    fn pair() -> Pair {
        pair_with(BUDGET)
    }

    fn pair_with(budget: usize) -> Pair {
        let (ta, tb) = transports();
        let (pa, pb) = fake::pair();
        let a = Mux::new(pa.clone(), ta, SecretKey::generate().public(), true, budget);
        let b = Mux::new(pb.clone(), tb, SecretKey::generate().public(), false, budget);
        let (_, a_task) = serve(a.clone(), pa.clone());
        let (accepts, b_task) = serve(b.clone(), pb.clone());
        Pair { a, b, a_peer: pa, b_peer: pb, accepts, a_task, b_task }
    }

    /// Sends a message on stream `n` from A as the dialer would, sealed at `index`.
    async fn send_raw(p: &Pair, n: u32, index: u64, plain: Plain) {
        let sealed = p.a.transport.seal((n as u64) << 40 | index, &plain.encode()).unwrap();
        p.a_peer.send(n, sealed).await.unwrap();
    }

    #[test]
    fn numbers_need_the_peers_parity_and_must_be_new() {
        let mut numbers = Numbers::default();
        assert!(numbers.admit(CONTROL, 0).is_err());
        assert!(numbers.admit(3, 0).is_err());
        assert!(numbers.admit(LAST, 1).is_err());
        assert!(numbers.admit(LAST + 1, 0).is_err());
        assert!(numbers.admit(u32::MAX - 1, 0).is_err());
        numbers.admit(2, 0).unwrap();
        assert!(numbers.admit(2, 0).is_err());
        numbers.admit(2 + 2 * WINDOW, 0).unwrap();
        assert!(numbers.admit(2, 0).is_err());
        assert!(numbers.admit(4, 0).is_err());
        assert!(numbers.admit(2 + WINDOW, 0).is_err());
        numbers.admit(2 + 2 * WINDOW - 2, 0).unwrap();
    }

    #[tokio::test]
    async fn echo_and_finish_both_ways() {
        let p = pair();
        let mut a = p.a.open("echo").await.unwrap();
        let mut accepts = p.accepts;
        let mut b = accepts.next().await.unwrap();
        b.accept();
        assert_eq!(b.protocol(), "echo");
        a.write_all(b"ping").await.unwrap();
        let mut buf = [0; 4];
        b.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
        b.write_all(b"pong").await.unwrap();
        a.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong");
        a.shutdown().await.unwrap();
        let mut rest = Vec::new();
        b.read_to_end(&mut rest).await.unwrap();
        assert!(rest.is_empty());
        b.shutdown().await.unwrap();
        a.read_to_end(&mut rest).await.unwrap();
        assert!(rest.is_empty());
    }

    #[tokio::test]
    async fn replayed_message_fails_its_stream() {
        let mut p = pair();
        let _a = p.a.open("raw").await.unwrap();
        let mut b = p.accepts.next().await.unwrap();
        b.accept();
        let sealed = p.a.transport.seal(2 << 40 | 1, &Plain::Data(b"one".to_vec()).encode()).unwrap();
        p.a_peer.send(2, sealed.clone()).await.unwrap();
        let mut buf = [0; 3];
        b.read_exact(&mut buf).await.unwrap();
        p.a_peer.send(2, sealed).await.unwrap();
        assert_eq!(b.read(&mut buf).await.unwrap_err().kind(), io::ErrorKind::ConnectionReset);
    }

    #[tokio::test]
    async fn reordered_message_fails_its_stream() {
        let mut p = pair();
        let _a = p.a.open("raw").await.unwrap();
        let mut b = p.accepts.next().await.unwrap();
        b.accept();
        send_raw(&p, 2, 2, Plain::Data(b"two".to_vec())).await;
        send_raw(&p, 2, 1, Plain::Data(b"one".to_vec())).await;
        let mut buf = [0; 3];
        assert_eq!(b.read(&mut buf).await.unwrap_err().kind(), io::ErrorKind::ConnectionReset);
    }

    #[tokio::test]
    async fn dropped_message_fails_its_stream() {
        let mut p = pair();
        let _a = p.a.open("raw").await.unwrap();
        let mut b = p.accepts.next().await.unwrap();
        b.accept();
        send_raw(&p, 2, 2, Plain::Data(b"two".to_vec())).await;
        let mut buf = [0; 3];
        assert_eq!(b.read(&mut buf).await.unwrap_err().kind(), io::ErrorKind::ConnectionReset);
    }

    #[tokio::test]
    async fn moved_message_fails_its_stream() {
        let mut p = pair();
        let _a = p.a.open("first").await.unwrap();
        let _c = p.a.open("second").await.unwrap();
        let mut first = p.accepts.next().await.unwrap();
        let mut second = p.accepts.next().await.unwrap();
        first.accept();
        second.accept();
        let sealed = p.a.transport.seal(2 << 40 | 1, &Plain::Data(b"one".to_vec()).encode()).unwrap();
        p.a_peer.send(4, sealed).await.unwrap();
        let mut buf = [0; 3];
        assert_eq!(second.read(&mut buf).await.unwrap_err().kind(), io::ErrorKind::ConnectionReset);
        let quiet = n0_future::time::timeout(Duration::from_millis(100), first.read(&mut buf)).await;
        assert!(quiet.is_err());
    }

    #[tokio::test]
    async fn opening_a_used_number_fails_the_link() {
        let mut p = pair();
        let _a = p.a.open("used").await.unwrap();
        let _b = p.accepts.next().await.unwrap();
        p.a_peer.open(2).await.unwrap();
        assert!(p.b_task.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn opening_a_number_of_our_parity_fails_the_link() {
        let p = pair();
        p.a_peer.open(3).await.unwrap();
        assert!(p.b_task.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn opening_a_number_past_the_range_fails_the_link() {
        for number in [(1 << 24) + 2, u32::MAX - 1] {
            let p = pair();
            p.a_peer.open(number).await.unwrap();
            assert!(p.b_task.await.unwrap().is_err());
        }
        let p = pair();
        p.b_peer.open(LAST).await.unwrap();
        assert!(p.a_task.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn opening_the_control_channel_twice_fails_the_link() {
        let p = pair();
        p.a_peer.open(CONTROL).await.unwrap();
        p.a_peer.open(CONTROL).await.unwrap();
        assert!(p.b_task.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn sending_past_credit_fails_the_link() {
        let mut p = pair();
        let _a = p.a.open("greedy").await.unwrap();
        let _b = p.accepts.next().await.unwrap();
        send_raw(&p, 2, 1, Plain::Data(vec![0; FIRST_CREDIT + 1])).await;
        assert!(p.b_task.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn credit_past_the_window_fails_the_link() {
        let p = pair();
        let _a = p.a.open("greedy").await.unwrap();
        let sealed = p.b.transport.seal(0, &Plain::Credit(2, ACCEPTED_CREDIT as u32 + 1).encode()).unwrap();
        p.b_peer.send(CONTROL, sealed).await.unwrap();
        assert!(p.a_task.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn unaccepted_stream_takes_16_kib_then_waits_for_accept() {
        let mut p = pair();
        let mut a = p.a.open("slow").await.unwrap();
        let mut b = p.accepts.next().await.unwrap();
        let writer = spawn(async move {
            a.write_all(&vec![1; 2 * FIRST_CREDIT]).await.unwrap();
            a
        });
        n0_future::time::sleep(Duration::from_millis(100)).await;
        assert!(!writer.is_finished());
        let mut buf = vec![0; 2 * FIRST_CREDIT];
        b.read_exact(&mut buf[..FIRST_CREDIT]).await.unwrap();
        b.accept();
        b.read_exact(&mut buf[FIRST_CREDIT..]).await.unwrap();
        writer.await.unwrap();
    }

    #[tokio::test]
    async fn accept_queue_holds_sixteen() {
        let mut p = pair();
        let mut opened = Vec::new();
        for _ in 0..=MAX_WAITING {
            opened.push(p.a.open("queued").await.unwrap());
        }
        for _ in 0..MAX_WAITING {
            p.accepts.next().await.unwrap();
        }
        let last = opened.last_mut().unwrap();
        let mut buf = [0; 1];
        assert_eq!(last.read(&mut buf).await.unwrap_err().kind(), io::ErrorKind::ConnectionReset);
        assert!(n0_future::time::timeout(Duration::from_millis(100), p.accepts.next()).await.is_err());
    }

    #[tokio::test]
    async fn reset_during_a_backlog_fails_the_writer() {
        let mut p = pair();
        let mut a = p.a.open("backlog").await.unwrap();
        let b = p.accepts.next().await.unwrap();
        b.accept();
        let writer = spawn(async move {
            let chunk = vec![2; MIB];
            let mut result = Ok(());
            for _ in 0..4 {
                result = a.write_all(&chunk).await;
                if result.is_err() {
                    break;
                }
            }
            result
        });
        n0_future::time::sleep(Duration::from_millis(100)).await;
        assert!(!writer.is_finished());
        drop(b);
        let err = writer.await.unwrap().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::ConnectionReset);
    }

    #[tokio::test]
    async fn stalled_stream_on_a_relayed_link_does_not_starve_another() {
        let mut p = pair_with(RELAYED_BUDGET);
        let mut stalled = p.a.open("stalled").await.unwrap();
        let mut live = p.a.open("live").await.unwrap();
        let b_stalled = p.accepts.next().await.unwrap();
        let mut b_live = p.accepts.next().await.unwrap();
        b_stalled.accept();
        b_live.accept();
        let flood = spawn(async move { stalled.write_all(&vec![3; 4 * MIB]).await });
        let send = spawn(async move {
            live.write_all(&vec![5; 256 * 1024]).await.unwrap();
            live
        });
        let mut buf = vec![0; 256 * 1024];
        n0_future::time::timeout(Duration::from_secs(2), b_live.read_exact(&mut buf))
            .await
            .expect("the live stream got 256 KiB in 2 s")
            .unwrap();
        send.await.unwrap();
        let held: usize = p.b.state.lock().unwrap().streams.values().map(|io| io.state().outstanding()).sum();
        assert!(held <= RELAYED_BUDGET + 2 * FIRST_CREDIT, "receiver granted {held} bytes");
        assert!(!flood.is_finished());
        drop(b_stalled);
        assert_eq!(flood.await.unwrap().unwrap_err().kind(), io::ErrorKind::ConnectionReset);
    }

    #[tokio::test]
    async fn stalled_reader_does_not_stall_other_streams() {
        let mut p = pair();
        let mut a1 = p.a.open("stalled").await.unwrap();
        let mut a2 = p.a.open("echo").await.unwrap();
        let b1 = p.accepts.next().await.unwrap();
        let mut b2 = p.accepts.next().await.unwrap();
        b1.accept();
        b2.accept();
        let flood = spawn(async move { a1.write_all(&vec![3; 4 * MIB]).await });
        a2.write_all(b"ping").await.unwrap();
        let mut buf = [0; 4];
        b2.read_exact(&mut buf).await.unwrap();
        b2.write_all(&buf).await.unwrap();
        a2.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
        assert!(!flood.is_finished());
        drop(b1);
        let err = flood.await.unwrap().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::ConnectionReset);
    }

    #[tokio::test]
    async fn stream_cap_refuses_the_129th_open() {
        let p = pair();
        let mut held = Vec::new();
        for _ in 0..MAX_STREAMS {
            held.push(p.a.open("many").await.unwrap());
        }
        let err = p.a.open("one too many").await.err().unwrap();
        assert_eq!(err.kind(), io::ErrorKind::ResourceBusy);
    }

    #[tokio::test]
    async fn bulk_to_a_slow_reader_stays_within_its_window() {
        let mut p = pair();
        let mut a = p.a.open("bulk").await.unwrap();
        let mut b = p.accepts.next().await.unwrap();
        b.accept();
        let total = 256 * MIB;
        let writer = spawn(async move {
            let chunk = vec![4; CHUNK];
            for _ in 0..total / CHUNK {
                a.write_all(&chunk).await.unwrap();
            }
            a.shutdown().await.unwrap();
        });
        let mut buf = vec![0; MIB];
        let mut got = 0;
        let mut most = 0;
        while got < total {
            most = most.max(b.io.state().inbox.len());
            n0_future::time::sleep(Duration::from_millis(1)).await;
            got += b.read(&mut buf).await.unwrap();
        }
        writer.await.unwrap();
        assert!(most <= ACCEPTED_CREDIT, "inbox held {most} bytes");
    }
}
