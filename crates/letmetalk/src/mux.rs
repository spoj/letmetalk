//! The stream layer over one peer connection: the control channel, the lanes, numbers, frames and credit.

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::future::poll_fn;
use std::io;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use futures::StreamExt;
use futures::channel::mpsc::{UnboundedReceiver, UnboundedSender, unbounded};
use n0_future::task::spawn;

use crate::backend::{CHANNELS, Event, LANES, Peer};
use crate::handshake::Transport;
use crate::keys::PublicKey;
use crate::stream::{Io, IoState, Stream};

pub(crate) const CHUNK: usize = 16 * 1024;
pub(crate) const FIRST_CREDIT: usize = 16 * 1024;
pub(crate) const ACCEPTED_CREDIT: usize = 1 << 20;
const MAX_STREAMS: usize = 128;
const MAX_WAITING: usize = 16;
const MAX_PROTOCOL: usize = 255;

pub(crate) const OPEN: u8 = 1;
const DATA: u8 = 2;
const FINISH: u8 = 3;
const RESET: u8 = 4;
const CREDIT: u8 = 5;

/// The lane that carries stream `n`.
pub(crate) fn lane_of(n: u32) -> u32 {
    1 + (n / 2) % LANES
}

pub(crate) fn frame(kind: u8, n: u32, body: &[u8]) -> Vec<u8> {
    [&[kind][..], &n.to_be_bytes(), body].concat()
}

pub(crate) fn data_frame(n: u32, body: &[u8]) -> Vec<u8> {
    frame(DATA, n, body)
}

fn unframe(bytes: &[u8]) -> io::Result<(u8, u32, &[u8])> {
    if bytes.len() < 5 {
        return Err(io::Error::other("short frame"));
    }
    let n = u32::from_be_bytes(bytes[1..5].try_into().expect("four bytes"));
    Ok((bytes[0], n, &bytes[5..]))
}

pub(crate) fn reset() -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionReset, "stream reset")
}

pub(crate) enum Incoming {
    Hello,
    Stream(Stream),
}

#[derive(Default)]
struct Lane {
    ready: VecDeque<Arc<Io>>,
    waker: Option<Waker>,
}

struct State {
    streams: HashMap<u32, Arc<Io>>,
    /// The last stream number the peer opened on each lane. A lane is in order, so its numbers rise.
    last: [Option<u32>; LANES as usize],
    next: u64,
    channels: BTreeSet<u32>,
    hello_sent: bool,
    hello_seen: bool,
    lanes: [Lane; LANES as usize],
    dead: bool,
}

impl State {
    /// Queues a frame on the stream's outbox. A stream with frames waiting is in its lane's ready queue, so its
    /// lane sends one frame from each waiting stream in turn.
    fn queue(&mut self, io: &Arc<Io>, bytes: Vec<u8>) {
        let was_empty = {
            let mut s = io.state();
            let empty = s.outbox.is_empty();
            s.outbox.push_back(bytes);
            empty
        };
        if was_empty {
            let lane = &mut self.lanes[lane_of(io.number) as usize - 1];
            lane.ready.push_back(io.clone());
            if let Some(waker) = lane.waker.take() {
                waker.wake();
            }
        }
    }
}

/// Ends a stream once both sides have sent their Finish. Its handles keep what they hold.
fn settle(st: &mut State, n: u32) {
    let done = st.streams.get(&n).is_some_and(|io| {
        let s = io.state();
        s.local_finished && s.remote_finished
    });
    if done {
        st.streams.remove(&n);
    }
}

pub(crate) struct Mux {
    peer: Arc<dyn Peer>,
    transport: Transport,
    pub(crate) remote: PublicKey,
    dialer: bool,
    budget: usize,
    control: UnboundedSender<Vec<u8>>,
    state: Mutex<State>,
}

/// Sends control messages in order. One that cannot be sent fails the link.
async fn control_loop(peer: Arc<dyn Peer>, mut rx: UnboundedReceiver<Vec<u8>>) {
    while let Some(bytes) = rx.next().await {
        if peer.send(0, bytes).await.is_err() {
            peer.close().await;
            return;
        }
    }
}

async fn lane_loop(mux: Arc<Mux>, channel: u32) {
    while let Some(bytes) = poll_fn(|cx| mux.next_frame(channel, cx)).await {
        if mux.peer.send(channel, bytes).await.is_err() {
            mux.peer.close().await;
            return;
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
        let mux = Arc::new(Mux {
            peer: peer.clone(),
            transport,
            remote,
            dialer,
            budget,
            control,
            state: Mutex::new(State {
                streams: HashMap::new(),
                last: [None; LANES as usize],
                next: u64::from(!dialer),
                channels: BTreeSet::new(),
                hello_sent: false,
                hello_seen: false,
                lanes: Default::default(),
                dead: false,
            }),
        });
        spawn(control_loop(peer, rx));
        for channel in 1..CHANNELS {
            spawn(lane_loop(mux.clone(), channel));
        }
        mux
    }

    pub(crate) fn transport(&self) -> &Transport {
        &self.transport
    }

    #[cfg(feature = "stats")]
    pub(crate) async fn path(&self) -> Option<crate::backend::Path> {
        self.peer.path().await
    }

    pub(crate) fn streams(&self) -> usize {
        self.state.lock().unwrap().streams.len()
    }

    /// The next frame of a lane, from the streams waiting on it in turn.
    fn next_frame(&self, channel: u32, cx: &mut Context<'_>) -> Poll<Option<Vec<u8>>> {
        let mut st = self.state.lock().unwrap();
        if st.dead {
            return Poll::Ready(None);
        }
        let lane = &mut st.lanes[channel as usize - 1];
        let Some(io) = lane.ready.pop_front() else {
            lane.waker = Some(cx.waker().clone());
            return Poll::Pending;
        };
        let mut s = io.state();
        let bytes = s.outbox.pop_front().expect("a ready stream has a frame");
        let more = !s.outbox.is_empty();
        drop(s);
        if more {
            lane.ready.push_back(io);
        }
        Poll::Ready(Some(bytes))
    }

    pub(crate) fn open(self: &Arc<Self>, protocol: &str) -> io::Result<Stream> {
        if protocol.len() > MAX_PROTOCOL {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "protocol name longer than 255 bytes"));
        }
        let mut st = self.state.lock().unwrap();
        if st.dead {
            return Err(reset());
        }
        let own = st.streams.values().filter(|io| io.own()).count();
        if own >= MAX_STREAMS || st.next > u64::from(u32::MAX) {
            return Err(io::Error::new(io::ErrorKind::ResourceBusy, "no stream slot free"));
        }
        let number = st.next as u32;
        st.next += 2;
        let io = Arc::new(Io::new(number, true));
        st.streams.insert(number, io.clone());
        st.queue(&io, frame(OPEN, number, protocol.as_bytes()));
        self.grant(&mut st);
        Ok(Stream::new(self.clone(), io, protocol.to_string()))
    }

    /// Handles one event of the peer connection that concerns streams or the control channel.
    pub(crate) fn handle(self: &Arc<Self>, event: Event) -> io::Result<Option<Incoming>> {
        match event {
            Event::Ready(channel) if self.dialer => self.channel_open(channel),
            Event::Opened(channel) if !self.dialer => self.channel_open(channel),
            Event::Opened(_) => Err(io::Error::other("the dialer's channel opened")),
            // The accepter's own channels are the ones the peer opened, so their readiness is not awaited.
            Event::Ready(_) => Ok(None),
            Event::Message(0, data) => self.control_message(data),
            Event::Message(channel, data) => self.lane_message(channel, data),
            Event::Closed => Err(reset()),
            _ => Ok(None),
        }
    }

    /// Once all channels are open, sends this side's Hello. The link is confirmed once both Hellos are through, so
    /// each side has every channel open before the other sends on one.
    fn channel_open(&self, channel: u32) -> io::Result<Option<Incoming>> {
        let mut st = self.state.lock().unwrap();
        if channel >= CHANNELS || !st.channels.insert(channel) {
            return Err(io::Error::other("unknown or repeated channel"));
        }
        if st.channels.len() < CHANNELS as usize {
            return Ok(None);
        }
        st.hello_sent = true;
        let hello = self.transport.seal(0, &[])?;
        self.control.unbounded_send(hello).map_err(|_| reset())?;
        Ok(st.hello_seen.then_some(Incoming::Hello))
    }

    fn control_message(&self, data: Vec<u8>) -> io::Result<Option<Incoming>> {
        let mut st = self.state.lock().unwrap();
        if !st.hello_seen {
            self.transport.open(0, &data)?;
            st.hello_seen = true;
            return Ok(st.hello_sent.then_some(Incoming::Hello));
        }
        let (kind, n, body) = unframe(&data)?;
        if kind != CREDIT {
            return Err(io::Error::other("bad control message"));
        }
        let bytes: [u8; 4] = body.try_into().map_err(io::Error::other)?;
        if let Some(io) = self.lookup(&st, n)? {
            let mut s = io.state();
            let bytes = u32::from_be_bytes(bytes) as usize;
            if bytes > ACCEPTED_CREDIT - s.credit {
                return Err(io::Error::other("credit past the window"));
            }
            s.credit += bytes;
            if let Some(waker) = s.write_waker.take() {
                waker.wake();
            }
        }
        Ok(None)
    }

    fn lane_message(self: &Arc<Self>, channel: u32, data: Vec<u8>) -> io::Result<Option<Incoming>> {
        let (kind, n, body) = unframe(&data)?;
        let valid = match kind {
            OPEN => body.len() <= MAX_PROTOCOL,
            DATA => body.len() <= CHUNK,
            FINISH | RESET => body.is_empty(),
            _ => false,
        };
        if !valid || lane_of(n) != channel {
            return Err(io::Error::other("bad lane frame"));
        }
        let mut st = self.state.lock().unwrap();
        if kind == OPEN {
            return self.open_from_peer(&mut st, n, body);
        }
        let Some(io) = self.lookup(&st, n)? else {
            return Ok(None);
        };
        match kind {
            DATA => self.received(&mut st, &io, body)?,
            FINISH => {
                {
                    let mut s = io.state();
                    s.remote_finished = true;
                    if let Some(waker) = s.read_waker.take() {
                        waker.wake();
                    }
                }
                settle(&mut st, n);
            }
            _ => {
                st.streams.remove(&n);
                io.fail();
            }
        }
        Ok(None)
    }

    /// The stream of a frame: live, or ended (`None`, which ignores the frame). A number never opened fails the
    /// link. Ours are opened in order, and the peer's are judged by its lane's last Open.
    fn lookup(&self, st: &State, n: u32) -> io::Result<Option<Arc<Io>>> {
        if let Some(io) = st.streams.get(&n) {
            return Ok(Some(io.clone()));
        }
        let ours = n % 2 != u32::from(self.dialer);
        let opened = if ours {
            u64::from(n) < st.next
        } else {
            st.last[lane_of(n) as usize - 1].is_some_and(|last| n <= last)
        };
        if opened {
            Ok(None)
        } else {
            Err(io::Error::other("frame for a stream never opened"))
        }
    }

    fn open_from_peer(self: &Arc<Self>, st: &mut State, n: u32, body: &[u8]) -> io::Result<Option<Incoming>> {
        let protocol = String::from_utf8(body.to_vec()).map_err(io::Error::other)?;
        if n % 2 != u32::from(self.dialer) {
            return Err(io::Error::other("stream number of our parity"));
        }
        let last = &mut st.last[lane_of(n) as usize - 1];
        if last.is_some_and(|last| n <= last) {
            return Err(io::Error::other("stream number reused"));
        }
        *last = Some(n);
        let peers = st.streams.values().filter(|io| !io.own()).count();
        let waiting = st.streams.values().filter(|io| !io.own() && !io.state().accepted).count();
        if peers >= MAX_STREAMS || waiting >= MAX_WAITING {
            let refused = Arc::new(Io::new(n, false));
            st.queue(&refused, frame(RESET, n, &[]));
            return Ok(None);
        }
        let io = Arc::new(Io::new(n, false));
        st.streams.insert(n, io.clone());
        Ok(Some(Incoming::Stream(Stream::new(self.clone(), io, protocol))))
    }

    fn received(&self, st: &mut State, io: &Arc<Io>, body: &[u8]) -> io::Result<()> {
        let mut s = io.state();
        if s.remote_finished {
            return Err(io::Error::other("data after finish"));
        }
        if s.received + body.len() as u64 > s.granted {
            return Err(io::Error::other("sent past its credit"));
        }
        s.received += body.len() as u64;
        if s.discard {
            s.read += body.len() as u64;
            drop(s);
            self.grant(st);
            return Ok(());
        }
        s.inbox.extend(body);
        if let Some(waker) = s.read_waker.take() {
            waker.wake();
        }
        Ok(())
    }

    /// Grants credit to each stream. Each keeps its first 16 KiB outside the budget; above that, streams share what
    /// the link's budget has free. A grant goes out only once the shortfall is a full chunk.
    fn grant(&self, st: &mut State) {
        let above = |s: &IoState| s.outstanding().saturating_sub(FIRST_CREDIT);
        let used: usize = st.streams.values().map(|io| above(&io.state())).sum();
        let mut free = self.budget.saturating_sub(used);
        for (&n, io) in &st.streams {
            let mut s = io.state();
            // Control and lanes are not ordered against each other, so a grant must not outrun the Open of a stream
            // this side opened. The peer's first frame on it shows that the Open arrived.
            if s.failed || s.remote_finished || (io.own() && s.received == 0) {
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
                s.granted += grant as u64;
                let _ = self.control.unbounded_send(frame(CREDIT, n, &(grant as u32).to_be_bytes()));
            }
        }
    }

    /// Queues a frame of a stream on its lane.
    pub(crate) fn push(&self, io: &Arc<Io>, bytes: Vec<u8>) {
        self.state.lock().unwrap().queue(io, bytes);
    }

    /// Queues the stream's Finish, and ends the stream if the peer's has come.
    pub(crate) fn finish(&self, io: &Arc<Io>) {
        let mut st = self.state.lock().unwrap();
        st.queue(io, frame(FINISH, io.number, &[]));
        settle(&mut st, io.number);
    }

    /// Called when the app reads from a stream.
    pub(crate) fn consumed(&self) {
        let mut st = self.state.lock().unwrap();
        self.grant(&mut st);
    }

    pub(crate) fn accept(&self, n: u32) {
        let mut st = self.state.lock().unwrap();
        if let Some(io) = st.streams.get(&n).cloned() {
            io.state().accepted = true;
            self.grant(&mut st);
        }
    }

    /// Called when a stream's handle drops. A stream that has shut down keeps discarding what the peer still sends,
    /// so the peer can finish. Any other stream is reset.
    pub(crate) fn dropped(&self, n: u32) {
        let mut st = self.state.lock().unwrap();
        let Some(io) = st.streams.get(&n).cloned() else {
            return;
        };
        if io.state().local_finished {
            {
                let mut s = io.state();
                s.discard = true;
                s.read = s.received;
                s.inbox.clear();
            }
            self.grant(&mut st);
        } else {
            st.streams.remove(&n);
            st.queue(&io, frame(RESET, n, &[]));
        }
    }

    /// Ends the link: every stream fails, and the lanes stop.
    pub(crate) fn kill(&self) {
        let mut st = self.state.lock().unwrap();
        st.dead = true;
        for (_, io) in st.streams.drain() {
            io.fail();
        }
        for lane in st.lanes.iter_mut() {
            lane.ready.clear();
            if let Some(waker) = lane.waker.take() {
                waker.wake();
            }
        }
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use std::time::Duration;

    use futures::StreamExt;
    use futures::channel::oneshot;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::backend::Peer;
    use crate::fake::{self, Fake};
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

    /// Feeds one side's events to its mux. Accepted streams come out of the receiver, and the Hello that confirms
    /// the link is reported once. An error ends the task.
    fn serve(
        mux: Arc<Mux>,
        peer: Arc<dyn Peer>,
    ) -> (UnboundedReceiver<Stream>, oneshot::Receiver<()>, n0_future::task::JoinHandle<io::Result<()>>) {
        let (tx, rx) = unbounded();
        let (confirmed, hello) = oneshot::channel();
        let task = spawn(async move {
            let mut confirmed = Some(confirmed);
            while let Some(event) = peer.next().await {
                match mux.handle(event)? {
                    Some(Incoming::Stream(stream)) => {
                        let _ = tx.unbounded_send(stream);
                    }
                    Some(Incoming::Hello) => {
                        if let Some(confirmed) = confirmed.take() {
                            let _ = confirmed.send(());
                        }
                    }
                    None => {}
                }
            }
            Ok(())
        });
        (rx, hello, task)
    }

    /// A dialer mux (A) and an accepter mux (B) over a fake pair, with all channels open. Both sides are served.
    struct Pair {
        a: Arc<Mux>,
        b: Arc<Mux>,
        a_peer: Arc<Fake>,
        b_peer: Arc<Fake>,
        accepts: UnboundedReceiver<Stream>,
        a_task: n0_future::task::JoinHandle<io::Result<()>>,
        b_task: n0_future::task::JoinHandle<io::Result<()>>,
    }

    /// A confirmed link: both Hellos have passed, so streams may open.
    async fn pair() -> Pair {
        pair_with(BUDGET).await
    }

    async fn pair_with(budget: usize) -> Pair {
        let (ta, tb) = transports();
        let (pa, pb) = fake::pair();
        let a = Mux::new(pa.clone(), ta, SecretKey::generate().public(), true, budget);
        let b = Mux::new(pb.clone(), tb, SecretKey::generate().public(), false, budget);
        let (_, a_hello, a_task) = serve(a.clone(), pa.clone());
        let (accepts, b_hello, b_task) = serve(b.clone(), pb.clone());
        a_hello.await.unwrap();
        b_hello.await.unwrap();
        Pair { a, b, a_peer: pa, b_peer: pb, accepts, a_task, b_task }
    }

    /// Sends a frame from A on `channel`, as the dialer's peer connection would.
    async fn send_raw(p: &Pair, channel: u32, bytes: Vec<u8>) {
        p.a_peer.send(channel, bytes).await.unwrap();
    }

    /// Sends a frame from B on `channel`.
    async fn send_back(p: &Pair, channel: u32, bytes: Vec<u8>) {
        p.b_peer.send(channel, bytes).await.unwrap();
    }

    #[tokio::test]
    async fn echo_and_finish_both_ways() {
        let p = pair().await;
        let mut a = p.a.open("echo").unwrap();
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
    async fn stream_leaves_the_link_once_both_sides_finish() {
        let mut p = pair().await;
        let mut a = p.a.open("echo").unwrap();
        let mut b = p.accepts.next().await.unwrap();
        b.accept();
        a.shutdown().await.unwrap();
        let mut rest = Vec::new();
        b.read_to_end(&mut rest).await.unwrap();
        b.shutdown().await.unwrap();
        a.read_to_end(&mut rest).await.unwrap();
        n0_future::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(p.a.streams() + p.b.streams(), 0);
    }

    #[tokio::test]
    async fn opening_a_used_number_fails_the_link() {
        let p = pair().await;
        let _a = p.a.open("used").unwrap();
        send_raw(&p, lane_of(0), frame(OPEN, 0, b"used")).await;
        assert!(p.b_task.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn opening_a_number_of_our_parity_fails_the_link() {
        let p = pair().await;
        send_raw(&p, lane_of(1), frame(OPEN, 1, b"odd")).await;
        assert!(p.b_task.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn opens_arriving_out_of_order_across_lanes_are_all_accepted() {
        let mut p = pair().await;
        send_raw(&p, lane_of(4), frame(OPEN, 4, b"four")).await;
        send_raw(&p, lane_of(2), frame(OPEN, 2, b"two")).await;
        let four = p.accepts.next().await.unwrap();
        let mut two = p.accepts.next().await.unwrap();
        assert_eq!((four.protocol(), two.protocol()), ("four", "two"));
        four.accept();
        two.accept();
        send_raw(&p, lane_of(2), frame(DATA, 2, b"hi")).await;
        let mut buf = [0; 2];
        two.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hi");
    }

    #[tokio::test]
    async fn late_open_on_a_stalled_lane_is_accepted_after_the_others_run_ahead() {
        let mut p = pair().await;
        for n in [4000, 4004, 4006] {
            send_raw(&p, lane_of(n), frame(OPEN, n, b"ahead")).await;
        }
        send_raw(&p, lane_of(2), frame(OPEN, 2, b"late")).await;
        let mut streams = Vec::new();
        for _ in 0..4 {
            streams.push(p.accepts.next().await.unwrap());
        }
        let protocols: Vec<&str> = streams.iter().map(|s| s.protocol()).collect();
        assert_eq!(protocols, ["ahead", "ahead", "ahead", "late"]);
        assert!(!p.b_task.is_finished());
    }

    #[tokio::test]
    async fn open_at_or_below_its_lanes_last_fails_the_link() {
        let p = pair().await;
        send_raw(&p, lane_of(4000), frame(OPEN, 4000, b"ahead")).await;
        send_raw(&p, lane_of(0), frame(OPEN, 0, b"behind")).await;
        assert!(p.b_task.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn frame_for_an_unseen_number_that_is_not_an_open_fails_the_link() {
        let p = pair().await;
        send_raw(&p, lane_of(6), frame(DATA, 6, b"x")).await;
        assert!(p.b_task.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn frame_on_the_wrong_lane_fails_the_link() {
        let p = pair().await;
        send_raw(&p, lane_of(0), frame(OPEN, 2, b"two")).await;
        assert!(p.b_task.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn repeated_lane_label_fails_the_link() {
        let p = pair().await;
        p.a_peer.tell(Event::Opened(1));
        assert!(p.b_task.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn unknown_lane_label_fails_the_link() {
        let p = pair().await;
        p.a_peer.tell(Event::Opened(CHANNELS));
        assert!(p.b_task.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn credit_for_an_ended_stream_is_ignored() {
        let mut p = pair().await;
        let mut a = p.a.open("echo").unwrap();
        let mut b = p.accepts.next().await.unwrap();
        b.accept();
        a.shutdown().await.unwrap();
        let mut rest = Vec::new();
        b.read_to_end(&mut rest).await.unwrap();
        b.shutdown().await.unwrap();
        a.read_to_end(&mut rest).await.unwrap();
        send_raw(&p, 0, frame(CREDIT, 0, &5u32.to_be_bytes())).await;
        n0_future::time::sleep(Duration::from_millis(50)).await;
        assert!(!p.b_task.is_finished());
    }

    #[tokio::test]
    async fn data_after_finish_fails_the_link() {
        let mut p = pair().await;
        let _a = p.a.open("raw").unwrap();
        let b = p.accepts.next().await.unwrap();
        b.accept();
        send_raw(&p, lane_of(0), frame(FINISH, 0, &[])).await;
        send_raw(&p, lane_of(0), frame(DATA, 0, b"late")).await;
        assert!(p.b_task.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn a_lane_frame_on_the_control_channel_fails_the_link() {
        let p = pair().await;
        send_raw(&p, 0, frame(DATA, 0, b"x")).await;
        assert!(p.b_task.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn hello_from_another_session_fails_the_link() {
        let (_, tb) = transports();
        let (other, _) = transports();
        let (pa, pb) = fake::pair();
        let b = Mux::new(pb.clone(), tb, SecretKey::generate().public(), false, BUDGET);
        let (_, _, b_task) = serve(b, pb.clone());
        pa.send(0, other.seal(0, &[]).unwrap()).await.unwrap();
        assert!(b_task.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn hello_sealed_under_the_wrong_nonce_fails_the_link() {
        let (ta, tb) = transports();
        let (pa, pb) = fake::pair();
        let b = Mux::new(pb.clone(), tb, SecretKey::generate().public(), false, BUDGET);
        let (_, _, b_task) = serve(b, pb.clone());
        let hello = ta.seal(1, &[]).unwrap();
        pa.send(0, hello).await.unwrap();
        assert!(b_task.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn hello_reflected_from_the_accepters_own_direction_fails_the_link() {
        let p = pair().await;
        p.a_peer.tell(Event::Message(0, p.b.transport().seal(0, &[]).unwrap()));
        assert!(p.b_task.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn credit_past_the_window_fails_the_link() {
        let p = pair().await;
        let _a = p.a.open("greedy").unwrap();
        send_back(&p, 0, frame(CREDIT, 0, &(ACCEPTED_CREDIT as u32 + 1).to_be_bytes())).await;
        assert!(p.a_task.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn credit_of_u32_max_fails_the_link_without_overflow() {
        let p = pair().await;
        let _a = p.a.open("greedy").unwrap();
        send_back(&p, 0, frame(CREDIT, 0, &u32::MAX.to_be_bytes())).await;
        assert!(p.a_task.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn sending_past_credit_fails_the_link() {
        let mut p = pair().await;
        let _a = p.a.open("greedy").unwrap();
        let _b = p.accepts.next().await.unwrap();
        for _ in 0..2 {
            send_raw(&p, lane_of(0), frame(DATA, 0, &vec![0; CHUNK])).await;
        }
        assert!(p.b_task.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn unaccepted_stream_takes_16_kib_then_waits_for_accept() {
        let mut p = pair().await;
        let mut a = p.a.open("slow").unwrap();
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
        let mut p = pair().await;
        let mut opened = Vec::new();
        for _ in 0..=MAX_WAITING {
            opened.push(p.a.open("queued").unwrap());
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
        let mut p = pair().await;
        let mut a = p.a.open("backlog").unwrap();
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
        let mut p = pair_with(RELAYED_BUDGET).await;
        let mut stalled = p.a.open("stalled").unwrap();
        let mut live = p.a.open("live").unwrap();
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
        let mut p = pair().await;
        let mut a1 = p.a.open("stalled").unwrap();
        let mut a2 = p.a.open("echo").unwrap();
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
        let p = pair().await;
        let mut held = Vec::new();
        for _ in 0..MAX_STREAMS {
            held.push(p.a.open("many").unwrap());
        }
        let err = p.a.open("one too many").err().unwrap();
        assert_eq!(err.kind(), io::ErrorKind::ResourceBusy);
    }
}
