# letmetalk: dial a key over WebRTC

Draft 3, for review.
- **Changes since draft 2:** the second review's findings and the second validation's corrections.
- **Owner's decisions so far:**
  - webrtc-rs;
  - streams only;
  - the guarantees below;
  - these thresholds;
  - letmeknow's VPS for the real-world runs.
- **What this is:** the contract for a trial. letmetalk is a small library that connects to an Ed25519 public key over
  WebRTC, natively and in browsers. The trial's measurements decide whether letmeknow moves its networking onto it.
- letmeknow does not change during the trial.

## Why

- letmeknow connects by key over iroh. Browsers cannot send raw UDP, so every browser byte goes through iroh's relay.
  WebRTC is the only way a browser connects directly, to another browser or to an agent.
- Plugging WebRTC into iroh as a custom transport would stack two connection stacks: QUIC over ICE, DTLS and SCTP.
  iroh's transport API also has no channel for signaling, and iroh marks it unstable.
- Existing Rust WebRTC wrappers don't fit:
  - matchbox, wasm-peers and just-webrtc address peers by IDs their signaling server hands out, so that server can
    impersonate anyone.
  - rings has keys, but it is a whole DHT overlay.
  - libp2p has keys and browser WebRTC, but only inside libp2p.
- The goal: iroh's ease of use with an even smaller API, built on WebRTC from the start. It is not compatible with
  iroh. Keys are still Ed25519, so letmeknow's keys would carry over.

## Guarantees

What letmetalk promises, whatever app uses it and whichever WebRTC stack carries it:

1. **Authenticated.** A stream's `remote_key()` is held by the other end: on `connect`, the key dialed; on `accept`,
   the key that opened the stream. The proof is bound to the link, so nobody can splice two links into one.
2. **Private and tamper-proof, end to end.**
   - Only the two endpoints can read a stream.
   - Any change, replay, reordering or injection fails the stream.
   - This holds against the carrier, TURN servers and the network.
   - It does not rest on WebRTC's DTLS: letmetalk encrypts every message itself. A flaw in a stack's DTLS could break
     links, but not read or alter them.
3. **Forward secret and post-quantum.** Everything after the dialer's first message uses keys made from both X25519 and
   ML-KEM-768. That covers streams, the answer and later candidates. Recorded traffic stays closed even if a key is
   stolen later, or a quantum computer arrives later.
4. **Deniable.** letmetalk signs nothing, and neither does a forwarder login. So a record of a session proves nothing
   to a third party about who talked to whom.
   - The limit, which no design avoids: a peer or forwarder that colludes with a third party while the session happens
     can convince that party.
5. **Addresses only to admitted keys.**
   - Peers learn this endpoint's IP addresses only if `admit` says `Direct`. With `Relayed`, they see only TURN's.
   - Envelopes carry no addresses. The forwarder does see the IP address each key connects from.

Not promised:
- **Metadata.**
  - The carrier sees who signals whom, when, and how much.
  - From envelope sizes and counts, the carrier can tell an answer from a silent refusal, and a direct link from a
    relayed one.
  - A forwarder also knows who is logged in, and from which IP address.
  - Any key logged in to a forwarder can ask whether another key is online, unless the forwarder runs an allowlist.
  - TURN servers see both ends' addresses and how much they send.
- **Traffic shape.** Encryption hides what streams carry, not how many there are, their sizes or their timing. Anyone
  who breaks a link's DTLS sees that. So would a later quantum attack on recorded DTLS 1.2.
- **Delivery.** A sender is not told what arrived. A reader sees a stream cut short as a reset, but a stream that never
  arrived is invisible to it.
- **Availability.** A carrier can drop or delay signaling, so links may fail to form.
- **The first exchange.**
  - The dialer's first message is protected by X25519 only: it is not post-quantum, and not forward secret if the
    recipient's key is stolen later. It carries the dialer's key and the send time, which the forwarder knows anyway,
    plus session parameters that are worthless once the session ends. No addresses travel in it.
  - Until the dialer's `Hello` arrives, the accepter's answer and candidates are only weakly forward secret (Noise
    §7.5). An attacker who already holds the accepter's key can pose as the dialer, and could read them if it later
    steals the dialer's key too.
- **Post-quantum authentication.** Authentication only has to hold while a link forms, so it matters only once quantum
  attacks run live.
- **Healing.** If a live link's keys leak, that link stays exposed until it ends. Every new link starts afresh.
- **The endpoints themselves.** A compromised device or key is out of scope.

## Model

- **Keys are addresses.** An endpoint holds an Ed25519 secret key, and peers are named by their 32-byte public keys.
  There are no server-assigned IDs and no addresses.
- **A carrier moves envelopes.**
  - WebRTC needs offers, answers and candidates swapped before any packet flows. letmetalk puts them into envelopes and
    hands those to a carrier the app supplies (`Signal`), which delivers bytes to a key.
  - The carrier is untrusted: it can delay or drop envelopes, but cannot read them, forge them or sit in the middle.
  - letmetalk ships one carrier: a WebSocket client (`WsSignal`) for its forwarder, `letmetalk-signal`. The forwarder
    also issues TURN credentials, because its login already proves the key.
- **letmetalk's own handshake and encryption.**
  - The offer and the answer are the two messages of a Noise handshake: WireGuard's, with an ML-KEM secret mixed in.
  - Every message on every data channel is then encrypted with its keys.
  - WebRTC's DTLS still runs, because WebRTC requires it, but no guarantee rests on it.
- **One link per peer.** An endpoint keeps at most one WebRTC peer connection (a "link") per remote key. A link is
  made on first use, and kept until one of these happens:
  - it fails;
  - either side disconnects;
  - the endpoint, at its cap, evicts it as the least recently used link with no streams.
- **Streams are the API.** `connect(key, protocol)` opens a reliable, ordered, two-way byte stream on its own data
  channel of the link. The peer's `accept()` yields it. On a live link, opening a stream costs one round trip from a
  native endpoint (webrtc-rs waits for the peer's ack), and none from a browser.
- **Admission.** The app's `admit(key)` decides, per key, whether it gets no link, a relayed one, or a direct one.
  - A relayed link uses only TURN candidates, so the peer never learns this endpoint's addresses.
  - letmeknow would give members direct links, and joiners it does not know yet relayed ones.
- **Relays are TURN:** coturn, or any server that accepts the forwarder's credentials. letmetalk never runs one.

## API

The whole public surface:

```rust
pub struct SecretKey;  // generate(), from_bytes(), to_bytes(), public()
pub struct PublicKey;  // 32 bytes; Display and FromStr as hex

pub enum Admit { Refuse, Relayed, Direct }

pub trait Signal: Send + Sync + 'static {
    /// Delivers an envelope toward `to`. Fails with HostUnreachable if the carrier knows `to` is offline.
    fn send(&self, to: PublicKey, envelope: Vec<u8>) -> BoxFuture<'static, io::Result<()>>;
    /// The next envelope for this endpoint; None once the carrier has stopped.
    fn recv(&self) -> BoxFuture<'_, Option<Vec<u8>>>;
    /// STUN and TURN servers for a new link, with current credentials.
    fn ice_servers(&self) -> Vec<IceServer>;
}

pub struct IceServer { pub urls: Vec<String>, pub username: String, pub credential: String }

impl Endpoint {  // Clone
    pub fn new(key: SecretKey, signal: impl Signal, admit: impl Fn(&PublicKey) -> Admit + Send + Sync + 'static) -> Endpoint;
    pub fn key(&self) -> PublicKey;
    pub async fn connect(&self, to: PublicKey, protocol: &str) -> io::Result<Stream>;
    pub async fn accept(&self) -> Option<Stream>;
    /// Closes the link to `peer`, and so its streams.
    pub fn disconnect(&self, peer: PublicKey);
    /// Feature `stats`, for the bench only: the selected candidate pair of the link to `peer`.
    #[cfg(feature = "stats")]
    pub async fn path(&self, peer: PublicKey) -> Option<Path>;
    pub async fn close(&self);
}

impl Stream {  // tokio AsyncRead + AsyncWrite; shutdown finishes the sending side
    pub fn remote_key(&self) -> PublicKey;
    pub fn protocol(&self) -> &str;
}

impl WsSignal {  // feature "ws"
    /// Logs in in the background, and again after a drop.
    pub fn new(url: &str, key: &SecretKey) -> WsSignal;
}
```
- `letmetalk::ws::wire` (feature `ws`) is `#[doc(hidden)]`: the frames and login that `letmetalk-signal` shares with the
  client. It is internal, not API.

- **Admission rules.**
  - `admit` is checked when a link forms. Once a key is refused, its link closes at its next incoming stream.
  - It also sets what this endpoint reveals when it dials. A key it would refuse cannot be dialed.
- **Errors** are `io::Error`:
  - `HostUnreachable`: the carrier says the key is offline.
  - `NotConnected`: the carrier itself is down.
  - `PermissionDenied`: `admit` refuses the key.
  - `TimedOut`: no link formed within 15 s. A refusal looks the same, since refusals are silent.
  - `ResourceBusy`: no new link fits, because every link at the cap holds streams.
  - `ConnectionReset`: the stream, or its link, died, was reset, or failed to decrypt.
  - `Unsupported`: a relayed link was asked for, and the carrier gave no TURN server.
- **Streams.** Dropping a stream before `shutdown` resets it; after `shutdown`, it discards what the peer still sends until
  the peer finishes, so the peer can finish. To refuse an unknown protocol, the accepter drops the
  stream.
- **Same types on both targets.**
  - On wasm, JS objects are held in `SendWrapper`, which is safe because wasm32-unknown-unknown has one thread.
  - With the `futures` crate's `BoxFuture`, the types and the `Signal` bound are then the same on both targets.
  - n0-future's `BoxFuture` would not do: it isn't `Send` on wasm.
- **For the bench only,** behind the feature `stats`: `Endpoint::path(peer)` gives the selected candidate pair of the
  link to `peer`. `Path` holds each side's candidate type (`host`, `srflx`, `prflx` or `relay`), `relayed()`, and the RTT
  of the checks, which is zero until one is answered: the latest check on native, and the mean of the answered checks in a
  browser, where Chrome leaves the latest at zero. It is None until the link is up. A remote candidate that
  webrtc-rs learnt from a check, and so has no stats entry, is reported as `prflx`.

## Design

### Handshake

- **Noise pattern.** `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s`, WireGuard's handshake.
  - Prologue: `letmetalk/1 ‖ session id`.
  - IK fits keys as addresses: the dialer knows the peer's key, and the peer learns the dialer's from message 1.
- **Static keys.**
  - Both sides' Ed25519 keys are mapped to X25519 (`SigningKey::to_scalar_bytes`, `VerifyingKey::to_montgomery`).
  - letmetalk itself only ever does X25519 with the key, in Noise and in the forwarder login, though apps may also sign
    with it. eprint 2021/509 shows that Ed25519 signing and an X25519 KEM can share a key. It does not cover those two
    uses, so the outside review (Risks) does.
  - Message 1 carries the dialer's Ed25519 key, and the peer checks that it maps to the dialer's Noise static key.
  - letmetalk refuses keys of small order (`is_weak`) or with a torsion part, in the handshake and in the forwarder
    login. snow checks neither: in the validation, a forger with no secret at all completed a handshake with a
    small-order key.
  - One secret then still passes as two Ed25519 keys, A and −A, which map to the same X25519 key. Per-key limits
    therefore count the X25519 key. Holding A's secret already gives −A, so nobody else is exposed.
  - snow does not check ephemeral keys either, but a bad one only weakens its sender's own session.
- **Post-quantum.**
  - The dialer puts a fresh ML-KEM-768 encapsulation key in message 1.
  - The peer encapsulates to it and sends the ciphertext beside message 2.
  - Before writing message 2, it puts `BLAKE2s(letmetalk/1 pq ‖ shared secret ‖ ciphertext)` in Noise's PSK slot,
    which binds the ciphertext into the handshake as PQNoise and Rosenpass do. snow allows setting the PSK mid-handshake.
  - So every key after message 1 mixes X25519 and ML-KEM. Rosenpass makes WireGuard post-quantum through the same slot,
    with two differences:
    - Rosenpass runs its own exchange beforehand, with static post-quantum keys, so its PSK also protects message 1
      and authenticates.
    - Here the PSK comes from a fresh exchange inside the handshake, and protects only what follows message 1.
- **Envelopes.** `version (1) ‖ kind (1) ‖ session id (16) ‖ body`. The session id is chosen at random by the dialer.
  - `Offer`: Noise message 1. Its payload (CBOR) holds:
    - the dialer's Ed25519 key;
    - the send time (Unix ms);
    - the ML-KEM encapsulation key;
    - the offer SDP, without candidates.
  - `Answer`: the ML-KEM ciphertext, then Noise message 2. Its payload holds the answer SDP.
  - `Candidates`: an index (5 bytes, below 2⁴⁰−1), then candidates sealed with the session keys (see Streams for
    nonces). Each side sends these once it holds those keys: the peer after writing message 2, the dialer after reading
    it.
- **Nothing for a forger.**
  - The peer's answer and candidates are sealed to the dialer's live ephemeral and static keys.
  - The dialer's candidates come only after message 2, sealed with keys that need both of those.
  - So a replayed message 1, or one forged with a stolen copy of the peer's key, learns nothing and draws no ICE checks
    from the peer's addresses.
  - Holding the dialer's candidates back costs about one carrier leg, against the 100 ms the offer no longer waits.
- **What the carrier sees:**
  - the recipient, the session id, and each envelope's kind, size and time;
  - for a forwarder, also each sender (from its login), and so both ends of every session.

  It never sees an address inside an envelope, or any SDP.
- **Freshness.**
  - A message 1 more than 10 minutes old or ahead is dropped and logged.
  - So is one whose session id was seen within that window. A session id enters that cache only when the offer is
    answered, after `admit`. The cache expires entries in order and holds at most 100,000, refusing to answer when full.
  - Answers count only for a session in progress. A garbled answer is dropped, and the dialer keeps waiting: snow
    keeps its state after a failed read.
  - Candidates are idempotent, so a replayed one does no harm.
  - An offer whose session id is already in progress is refused, so it cannot take over that session's routing.
- **Libraries:** snow (RustCrypto resolver) and ml-kem (RustCrypto). Both build for wasm32.
- **Why not HPKE envelopes and signatures:** they would be neither deniable nor forward secret for the answer.
  One Noise handshake gives authentication, deniability, forward secrecy after message 1, and resistance to
  key-compromise impersonation once the link confirms.

### Links

- **Setup.**
  - The dialer creates a peer connection with the carrier's ICE servers, plus the relay-only policy if `admit` says
    `Relayed`.
  - It creates the control channel (in band, labelled `0`, before the offer, so the offer has an SCTP section) and an
    offer. The accepter sees the channel as an open. A negotiated channel would lose its first message: webrtc-rs drops
    data that reaches a channel its peer has not opened yet.
  - The offer goes in message 1 at once, with no candidates.
  - Once the dialer has read message 2, its candidates follow as they are gathered, each send taking what has gathered
    by then, until gathering ends. A batch timer of 50 ms in front of each send cost about 50 ms of setup per side.
  - Until the link is confirmed, letmetalk wakes the peer connection's driver every 5 ms. webrtc-rs sends what a packet
    or event queues only when its driver next wakes, and an idle link wakes only on its 200 ms ACK timer. The DTLS
    start (SCTP's INIT) and the DCEP open then each waited up to 200 ms, and ICE's responses waited too. The wake is
    `set_configuration` with the configuration already in place, the cheapest driver event webrtc-rs offers. Cold setup
    on native loopback fell from about 606 ms to about 60 ms.
  - On native, letmetalk lists interfaces itself (`netdev`) and binds only up, physical ones, skipping docker, veth and
    bridges, one socket per address (IPv6 link-local excluded). With no such address, it binds loopback, so peers on
    one machine still connect. webrtc-rs's interface filter is stored but never read.
  - The accepter:
    - drops anything it cannot open;
    - applies `admit`, and a refusal gets no reply;
    - does the same with an answer in message 2, then its own candidates.
  - Candidates that arrive early are held, up to 16, until they can be applied.
- **Connect.** `connect` uses a confirmed link if one is live. Otherwise it waits for the setup already under way to
  that key, or starts one. A setup that ends without a link fails the waiting `connect` with `TimedOut`.
- **Confirmation.** When its control channel opens (the dialer's own open, the accepter's when the dialer's arrives),
  each side sends `Hello` on it, encrypted with the session keys. The
  link is up when the peer's `Hello` opens. It has two jobs:
  - Nothing waits on an unconfirmed link: neither streams, nor the replacement of an older link.
  - From the dialer, `Hello` is the first message that proves the dialer even to a peer whose own key was stolen.
    Noise IK's message 1 can't do that.

  Relaying two peers' offer and answer between them (identity misbinding) gets nowhere: the two ends would hold
  different keys, so nothing between them opens.
- **Crossed offers.** If offers cross between two keys, the link offered by the smaller key survives. Pending
  `connect`s move to it.
- **Replacement.**
  - A fresh, unseen message 1 from a key with a live link starts a new link.
  - The old link closes only once the new one is confirmed, so a carrier holding back or replaying an old offer cannot
    tear down a working link.
  - If replacements cross, the smaller-key rule applies.
- **Liveness.** A link whose ICE state reads `disconnected` takes no new streams. `connect` starts a new link instead,
  which replaces the old one once confirmed.
- **End.** A link ends when:
  - its control channel closes, which is how a peer's close arrives;
  - its peer connection fails (ICE consent lost: 30 s by RFC 7675 and in webrtc-rs; Chrome may give up sooner);
  - either side disconnects or closes;
  - it is evicted at the cap.

  There is no idle timer, so a new stream never races an idle close. The trial has no ICE restart: a network change
  ends the link, and the app reconnects.
- **Limits.** Relayed keys (strangers, in letmeknow) are kept apart, so that they cannot crowd out admitted ones.
  - 256 links in all, of which at most 64 are Relayed.
  - At a cap, the least recently used link with no streams in the same class is evicted. If none is free, `connect`
    fails with `ResourceBusy`, and offers get no reply.
  - One link in setup per key that this endpoint did not dial. A newer offer replaces it only if its authenticated send
    time is later.
  - Inbound setups: 16 Direct and 8 Relayed. When a class is full, its oldest unconfirmed setup is evicted, so Relayed
    offers never evict Direct ones.
  - An unconfirmed inbound link is dropped after 10 s.
  - The handshake itself costs little: a few X25519 operations and one ML-KEM encapsulation. What these limits bound is
    the peer connection, its gathering and its TURN allocation, which each offer costs.

### Streams

- **Channels.** Each stream is one data channel, reliable and ordered, opened in band (DCEP).
  - The opener closes its channel, and only the opener does, once the stream is done (Messages: `Closed`). The
    accepter's channel closes with the opener's reset, and a close that comes before the stream is done fails it at
    once. A browser's close flushes what was queued; webrtc-rs drops a channel's queued messages when its close is
    processed, which is why nothing is closed before the peer has read everything.
  - webrtc-rs frees a closed channel's SCTP stream id at once, but the reset the peer sends in reply arrives about one
    round trip later, and it closes whatever channel holds the id by then. So after a close, the opener opens no channel
    until the accepter acknowledges the close with `Closed`, which it sends once its channel has closed. Without the
    wait, native streams opened right after a close failed in every run of `many_streams`; a 5 ms pause before each open
    also cured it.
  - Streams open only once the link is confirmed. That also avoids a webrtc-rs bug: a channel the answering side opens
    just after ICE connects, before SCTP is up, never opens.
  - A browser opener writes at once. A native opener waits for the peer's DCEP ack.
  - At most 128 streams are open per link in each direction, and at most 16 wait for `accept`. Further peer opens are
    reset; a local open beyond 128 fails with `ResourceBusy`.
- **Numbers.** Streams are numbered by letmetalk, not by channel id, since webrtc-rs's `id()` is only a local handle.
  - The link's dialer opens even numbers and its accepter odd ones. Numbers are never reused on a link, and an open
    past the 24-bit range fails with `ResourceBusy` (about 2²³ streams from one side).
  - Stream 0 is the control channel, and it opens once: a second open fails the link. Number 2²⁴−1 is reserved for
    `Candidates` envelopes.
  - The DCEP label carries the number. The protocol name travels encrypted in the stream's first message, which also
    sidesteps web-sys having no getter for a channel's protocol.
  - **Checks on each open by the peer.** The number must:
    - have the peer's parity;
    - be neither 0 nor 2²⁴−1;
    - never have been seen on this link.

    A sliding window over the highest number seen (1,024 wide, as DTLS does for records in RFC 6347) enforces the last.
    Any failure fails the link. Without these checks, someone who broke DTLS could re-open a used number and replay its
    messages, and our replies would reuse nonces.
- **Encryption.**
  - Every message on every channel, the control channel included, is sealed with ChaCha20-Poly1305 under the session
    key of its direction.
  - Its nonce is the stream's number (24 bits) and the message's index on that stream (40 bits). Channels deliver in
    order and lose nothing, so the nonce is implicit.
  - A replayed, reordered, dropped or moved message fails to open, and fails its stream. A sender whose index would
    pass 2⁴⁰ fails the stream, or the link on the control channel.
  - Since numbers are never reused, and the peer's are checked, no nonce repeats under a key.
- **Messages.** Plaintexts start with a type:
  - on a stream: `Open(protocol)` (the first message), `Data`, `Finish`;
  - on the control channel: `Hello`, `Credit(stream, bytes)`, `Reset(stream)`, `Closed(stream)`.
  - A `Data` after the peer's `Finish`, and a `Reset` of the control channel, fail the link.
  - `Closed(stream)` is sent once a side has sent its `Finish` and received the peer's. Once a side has sent and received
    `Closed`, the stream is done. The peer sends `Closed` only after our `Finish`, so it has read everything we sent.
  - The accepter also sends `Closed(stream)` once its channel has closed, as the acknowledgement described under
    Channels. The opener takes it as one, since the stream is already gone on its side.

  Data goes in messages of at most 16 KiB, so a small message on one stream never waits behind a large one on another.
  Data channels have no half-close, so `Finish` stands in for one.
- **Flow control.** SCTP has one receive window per link, not one per stream (RFC 9260). So on native, one slow reader
  would stall every stream, the control channel included. And browsers deliver messages as events, with no back-pressure
  at all. So each stream gets its own window, under a budget for its link:
  - **Credit.**
    - Every stream starts with 16 KiB of credit on both sides, with no message. Only `Data` bytes count; `Open` is
      not counted, and its protocol name is at most 255 bytes.
    - The reader grants more: up to 16 KiB until the app accepts a stream, then up to 1 MiB, and more as the app reads.
      A grant goes out only once it is at least 16 KiB, so small reads don't flood the control channel.
    - Each stream keeps its first 16 KiB outside the budget, so every stream can always progress. Above that, streams
      share the link's budget: 4 MiB for a Direct link, 256 KiB for a Relayed one.
  - **Enforcement.** The sender never sends past its credit. A message past it fails the link, so what a peer can make
    an endpoint hold is bounded by budget + 16 KiB × open streams. A peer whose credit would pass 1 MiB fails the link.
  - So no sender watches a send buffer: credit bounds what each channel holds, on both sides.
  - **Draining.** Every stream's unread data stays within its window, so letmetalk always drains the link at once.
  - **Throughput limit.** A window caps a stream at window ÷ RTT. 1 MiB covers about 80 Mbit/s at 100 ms; quinn's
    default is 1.25 MB. The bench records whether a run was limited by its window.
- **Reset.** A reset sends `Reset`, then closes the channel. The reader discards what it holds and fails with
  `ConnectionReset`.
  - A channel the peer closes fails a stream the peer has not finished, at once. The peer closes only after the
    `Closed` exchange, so the channel has carried everything the stream needs.

### Backends

- **Native: webrtc-rs (`webrtc` 0.21).**
  - It is an async peer connection over a Sans-I/O core (`rtc`).
  - It gathers host, server-reflexive and TURN relay candidates itself, and resolves browsers' mDNS (`.local`)
    candidates.
  - It supports the relay-only policy, ICE-TCP and ICE restart.
  - **Socket buffers.** webrtc-rs binds its UDP sockets with the OS defaults, which drop packets under bulk load. So
    every socket gets 4 MiB send and receive buffers, through a `Runtime` wrapper (`with_runtime`). Linux caps the
    request at `net.core.rmem_max`, which is 208 KiB on stock kernels, so a host that keeps the default gets smaller
    buffers. Spike 2 measured the drops and the 1 s stalls that this removes.
  - **SCTP MTU stays at webrtc-rs's default.** MTU 1400 gained 13% on loopback in spike 2. It is unvalidated on real
    paths and risks black holes on tunnels (WireGuard 1420, tailscale 1280) and TURN, so it is rejected for the trial.
  - **TURN over UDP only.** It skips `turns:` and TCP TURN URLs. TURN over TCP is planned for after its 1.0
    (webrtc#848; PR #907 is open), and nothing tracks TLS. So a native endpoint on a network that blocks UDP has no
    relay.
  - It is Rust plus ring's C and assembly. letmeknow already builds ring for all its targets: Linux, macOS, Windows
    and Android.
  - Its DTLS is 1.2 only, and DTLS 1.3 waits until after its 1.0 (webrtc#801). That doesn't touch the guarantees.
  - 0.21 (September 2026) is its pre-1.0 line, the run-up to 1.0. It is weeks old, so step 0 tests it before anything
    is built on it.
- **Why not str0m:** at equal settings it was 2.2–2.8× slower in spike 2 (106 vs 233 MB/s with MTU 1400; 74 vs 206
  MB/s with 4 MiB buffers), with worse latency under load (9–14 ms p50 against 3–4 ms). Its single event queue gives no
  per-channel isolation, so it would need the same credit layer. Its per-SACK cost is sctp-proto's, not a setting. It
  also leaves NIC enumeration, STUN and TURN outside its scope, so we would write candidate gathering and a TURN client.
  - It remains the fallback, so letmetalk reaches the native stack through a narrow seam that str0m could also sit
    behind: create a link, set the remote description, add candidates, open, send, receive and close channels, and
    events.
  - The stream layer's tests also run over a fake backend at this seam.
- **Browser: the browser's own WebRTC,** through web-sys (`RtcPeerConnection`, `RtcDataChannel`).
  - The browser runs ICE, DTLS and SCTP. letmetalk adds the handshake, encryption, flow control and link management.
  - Browsers expose `RTCPeerConnection` in windows, not in workers. letmeknow's node already runs in the window.
  - The peer connection gets the carrier's ICE servers, and `iceTransportPolicy: relay` for Relayed keys. Candidates
    go in with mid `0` and index 0, as on native.
  - web-sys lacks a few getters (`pc.sctp`) and `restartIce`. `js_sys::Reflect` reaches them if needed.
  - On wasm:
    - snow runs with its default features off, since they pull in ring and getrandom 0.2, which fail there.
    - snow uses getrandom 0.3 and ml-kem uses 0.4. Both need the `wasm_js` feature.
- **Shared link logic.** The link logic is written once, over the two backends. Spawning and timers go through
  n0-future.
- **Node and Deno** have no WebRTC. Agents use the native build, as now.

### `letmetalk-signal`

A forwarder for envelopes over WebSocket. It has a library entry (an axum router), so that letmeknow's `serve` can embed
it later.

- **Login, deniable.**
  - The server sends a fresh X25519 key.
  - The client answers with its Ed25519 key and a MAC: keyed BLAKE2s over `letmetalk-signal/1 ‖ Ed25519 ‖ host`. The MAC
    key is derived, through a labelled KDF, from the Diffie–Hellman of the client's X25519-mapped key and the server's
    fresh key.
  - The server checks the MAC with its side of the same Diffie–Hellman. A record of the login proves nothing to
    anyone else, since the server could have computed the MAC itself.
  - The host is in the MAC, so a login cannot be relayed to another server. The host is lowercased first. The MAC covers
    the Ed25519 key too, so a login claiming −A fails unless its holder can make the MAC for −A.
  - All-zero Diffie–Hellman results are refused. Small-order and torsioned keys are refused before the Diffie–Hellman.
  - Wire, in `letmetalk::ws::wire`: the challenge is 32 raw bytes, the first message from the server. The client
    answers with `Ed25519 (32) ‖ MAC (32)`. The MAC is BLAKE2s-MAC, keyed with `BLAKE2s("letmetalk-signal/1 key" ‖
    DH)`, over `letmetalk-signal/1 ‖ Ed25519 ‖ host`. The host is the URL's host name without port, lowercased. The socket
    is `/ws`. A bad login gets no reply: the server closes the socket.
  - Sessions and routing are keyed by the X25519 key, so A and −A are one login.
  - `WsSignal` connects over `wss://` only, except to loopback. Any other URL stops it at once: `recv` returns None
    and `send` fails with `NotConnected`.
- **Liveness.**
  - The server pings every 5 s and sends frame `6` with each ping. Browsers answer pings without showing them to JS, so
    a browser sees only `6`. Both clients count any binary frame as traffic. Either side treats a socket silent for 15 s as
    dead: the server closes it, and `WsSignal` reconnects.
  - Every server write times out after 10 s, so a client that never reads cannot pin its task.
  - Connect and login each have a 10 s timeout on the client, which reconnects after one.
  - `WsSignal` reconnects after 2 s plus 0–2 s of jitter, so clients do not stampede a restarted forwarder.
- **Sockets.** Upgrades get a 16 KiB read buffer. A frame or message over 8 KiB + 36 bytes closes the socket. Each IP,
  with IPv6 taken by its /64, may hold 64 sockets. The 65th upgrade gets HTTP 429.
- **TURN credentials.**
  - The login's reply carries the ICE servers, with TURN credentials in the TURN REST form, valid for 24 h
    (`--turn-ttl`). They are renewed over the socket at half their life.
  - Two coturn instances, each with its own secret. `member` gives full credentials, and only to keys on the allowlist.
    Every other key gets `stranger`, even when there is no allowlist. `stranger` has a low `user-quota`, `total-quota`
    and `max-bps`. Under REST auth coturn can't tell users apart, so the quota is per instance: `total-quota` bounds the
    instance, and a stranger that logs in again gets a fresh token and so a fresh per-user quota.
  - Member limits: `total-quota=1000`, `max-bps` and `bps-capacity` 12500000 bytes/s. Stranger limits: `user-quota=2`,
    `total-quota=100`, `max-bps=125000` bytes/s.
  - A stranger dialing a member needs no TURN of its own, since the member's relay candidate reaches it.
  - The username is `expiry:token`, with a random 128-bit token (hex) per credential. The forwarder logs one line per
    credential it mints, `token <hex> key <key>`, which attributes coturn's usage logs. It keeps nothing. TURN sends
    usernames in the clear, so a key never goes in one.
  - The password is base64 of HMAC-SHA1 over the username, under the secret of the instance it is for. The forwarder
    shares that secret with coturn.
- **coturn hardening.** `crates/letmetalk-signal/coturn/member.conf` and `stranger.conf` are the trial's coturn configs,
  without secrets. Both set `no-multicast-peers`, `no-tcp-relay` and `no-cli`. Both deny peers in loopback, private,
  link-local, shared-address, multicast, cloud-metadata, and IPv4-mapped, NAT64 (`64:ff9b::/96`, `64:ff9b:1::/48`) and
  6to4 ranges by explicit ranges, so the configs rely on no coturn version decoding mapped addresses. Without these, a
  peer's candidates could aim the TURN server at internal addresses (the known TURN SSRF class). A deployment also denies
  the host's own IPv4 and IPv6 addresses: a relay to them reaches the forwarder and the other coturn. In coturn 4.18 a
  denied `::`, even alone, refuses every IPv4 peer, so the configs leave the unspecified IPv6 address out. The configs
  were run on coturn 4.18, and CI prints the version it runs.
- **One login per key.** A new login replaces the old one. The replaced socket is sent `5` and closed, and `WsSignal`
  does not reconnect it, so two processes with one key don't evict each other in a loop.
- **Frames.** Integers are big-endian.
  - Client to server: `id (u32) ‖ to (32) ‖ envelope`.
  - Server to client:
    - `0 ‖ envelope`: a delivery;
    - `1 ‖ id`: passed to the recipient's socket;
    - `2 ‖ id`: the recipient isn't connected;
    - `3 ‖ id`: over a limit;
    - `4 ‖ ICE servers`: the login reply, and renewed credentials (CBOR);
    - `5`: this key logged in elsewhere. The socket closes after it.
    - `6`: alive. Sent with each server ping, so that browsers, which see no pings, see traffic every 5 s.
  - Ping and pong frames count against the login's bucket, and close the socket when it is empty. A text frame closes it.
  - `WsSignal::send` resolves on `1`, `2` or `3`. `2` becomes `HostUnreachable`, `3` becomes `ResourceBusy`, and a
    socket lost before its ack becomes `NotConnected`.
  - `send` refuses an envelope over 8 KiB with `InvalidInput`.
- **Limits.**
  - Envelopes of up to 8 KiB. An offer or answer is about 3 KB, ML-KEM included.
  - Token-bucket rates, sized from a measured startup: one endpoint dialing 20 peers through the forwarder, on loopback
    (`tests/endpoints.rs`). The dialer sent 40 envelopes and the 20 peers 40, all within 0.7 s. The busiest 100 ms held
    20 from the dialer and 38 from the peers. Nothing was refused.
    - per login, which is per socket: 50/s, burst 200. The dialer's busiest second is 40, so the burst is 5× it, and
      the rate exceeds the 40 it sends per second;
    - per IP (IPv6 by its /64): 200/s, burst 800, charged for each login and each message. The startup's 80 sends
      are a tenth of the burst, and the rate covers them within a second;
    - for a non-member only, per login and recipient: 1/s, burst 5. The per-IP bucket bounds the total across a host's
      logins.
  - Over a limit the sender gets `3`. A login over the per-IP bucket gets no reply, and its socket closes.
  - Nothing is stored.
- **Presence.** `2 ‖ id` tells any logged-in key whether another key is online. Run with an allowlist to keep that
  among known keys. Embedded in letmeknow's service, it would forward only between members of a group.
  - Members are the keys on the allowlist. Without one, every key is a routing member: an open forwarder, which gives
    every key stranger TURN only.
  - A non-member gets `1` for every recipient, online or not, so it never learns presence. Its envelopes to offline
    members are dropped.

## Trial

### Step 0: spike

2–3 days of throwaway code, before anything else is built. webrtc-rs 0.21 talks to Chromium through hand-carried SDP,
to measure:
- throughput;
- what a stalled reader does to another channel;
- `turns:` on port 443;
- mDNS resolution of a browser on the same host;
- 256 MiB with memory.

Throughput comes first: in the validation, a single 4 MiB burst between two webrtc-rs peers on loopback ran at only
3–18 MB/s. If that holds, the spike also measures str0m. Its SCTP is a separate crate (sctp-proto), but a
sibling of webrtc-rs's rtc-sctp by the same lead developer, so the two may share a flaw. If webrtc-rs fails here, the
plan switches to str0m before step 1.

### Measurements

Each run records:
- **Connection:** whether the pair connected, and its path (relayed or direct, with the candidate types).
- **Setup time:**
  - cold: `connect` with no link, until the first echoed byte;
  - warm: a new stream on a live link, until the first echoed byte.
- **Throughput:** 256 MiB on one stream, and on four at once.
- **Encryption cost:** sealing and opening 16 KiB messages, natively and in wasm, against the link's throughput.
- **Latency under load:** a 100-byte echo on one stream while another carries bulk data.
- **Recovery:** time until a peer whose network changed is reachable again.
- **Churn:** 10,000 stream opens and closes on one link, and 1,000 links made and closed. Memory and handles must stay
  flat.
- **Credential expiry:** in the lab the TURN TTL is set to 5 minutes, and a relayed link is held for 10.
- **Background:** a backgrounded tab, and iOS Safari and Android Chrome in the background for 5 minutes.
- **wasm size:** letmetalk's share of a web build, recorded but not a criterion.

Pairs and baselines:
- Pairs are native↔native, native↔browser and browser↔browser, with Chromium.
- Firefox and WebKit run against native through Playwright. There they are relay-only, with Firefox's loopback setting,
  because direct paths in Playwright's WebKit are unproven. Safari runs for real on the phone.
- Native pairs are compared with iroh 1.3, measured the same way.
- Pairs with a browser are compared with today's path for them: iroh through iroh-relay.
- `TRIAL.md` also estimates what replacing iroh-blobs would take, since "go" commits to rewriting letmeknow's file
  fetch.

### Lab

`lab/` holds a Docker Compose setup, run locally and in a GitHub Actions workflow started by hand.
- **Network:** an "internet" bridge carrying `letmetalk-signal`, coturn (UDP and TCP on 3478, TLS on 443) and
  iroh-relay. Each peer sits behind its own router container.
- **NAT types** on the routers (nftables):
  - none (a public address);
  - endpoint-independent filtering, by forwarding all inbound UDP to the LAN's one peer;
  - port-restricted, which is masquerade's default;
  - symmetric (masquerade `random`);
  - UDP blocked, with only TCP 443 out.

  Each router's behaviour is checked with an RFC 5780 probe before every run, so a mislabelled NAT fails the run.
- **Pairs,** each listed explicitly:
  - every NAT type against none, port-restricted and symmetric;
  - symmetric↔symmetric, which must use TURN;
  - UDP blocked against anything. A browser there must use TURN over TLS. A native peer there has no relay until
    webrtc-rs has TURN over TCP, so that pair is recorded, not required;
  - the same host;
  - the same LAN with multicast blocked;
  - two peers behind one NAT (hairpinning).
- **Profiles,** shaped in both directions (`tc netem` with ifb):
  - LAN;
  - WAN, at 50 ms RTT with 1% loss;
  - constrained, at 10 Mbit/s with a deep buffer.
- **Browsers:** headless Chromium (Playwright) containers.
- **Realisation** (`lab/`):
  - The internet is 203.0.113.0/24 (TEST-NET-3), which coturn's denied ranges leave open. LANs are 10.20.x.0/24, each
    with its router at .254.
  - `none` is the peer on the internet with its own address and no router: a router that does no NAT would not make
    its LAN reachable.
  - The forwarder listens on plain `ws` at 443, so the signaling crosses a UDP-blocked NAT. Peers reach it through a
    loopback tunnel at `127.0.0.1:8787`, since `WsSignal` refuses `ws://` off loopback and the lab has no public
    certificate. The login's host is then `127.0.0.1`. The forwarder's TLS is not measured in the lab; the real-world
    runs cover `wss`.
  - coturn runs the repo's member and stranger configs, each with two listening addresses: the second is the RFC 5780
    alternate. `bps-capacity` is 125000000, as deployed, since coturn 4.6 refuses every allocation when it equals
    `max-bps`. iroh-relay serves plain HTTP on 443.
  - Profiles shape each peer's access link in both directions (netem on egress, `ifb0` for ingress), after the NAT
    probes, so loss cannot change what a probe reports. `lan` is unshaped. `wan` adds 12.5 ms and 0.5% loss per link, so two peers see 50 ms RTT and about 1% loss; the servers are
    unshaped. `constrained` is netem at 10 Mbit/s with a 5000-packet queue, about 6 s deep.
  - The NAT probe is `turnutils_natdiscovery -m -f` against the member coturn, run from the peer behind its NAT. Each
    label must probe as: `none` and `eif`, endpoint-independent mapping and filtering; `pr`, endpoint-independent
    mapping and address-and-port-dependent filtering; `sym`, address-and-port-dependent mapping and filtering; `blk`,
    no UDP reply, with TCP 443 open.
  - `lab/pairs.txt` lists the pairs. The NAT types are `none`, `eif`, `pr`, `sym` and `blk`. `eif`, `pr` and `sym` meet
    `none`, `pr` and `sym`, `sym` among them, which must use TURN. `blk` meets `none`, `eif`, `pr` and `sym`. Browser
    rows repeat NAT rows with a browser on one side.
  - Same-host runs both roles in one peer. Same-LAN puts two peers on one LAN with multicast blocked, as a blackhole
    route for 224.0.0.0/4.
  - Hairpin puts two peers on separate LANs behind one router, which forwards only LAN to WAN. Without hairpin NAT,
    the pair has no direct path, so it must relay or fail. Both stacks run it, so iroh is the comparison.

Real-world runs use the owner's devices:
- a laptop on home Wi-Fi;
- a phone on mobile data (behind carrier-grade NAT), in Chrome and Safari;
- letmeknow's VPS;
- one restrictive network, if one is available.

The forwarder and coturn for these runs go on letmeknow's VPS, beside `serve`; it is pre-alpha, so sharing it is
fine.
- `serve` holds 443, so coturn takes 3478 (UDP and TCP) and 5349 (TLS), and the forwarder its own TLS port. The VPS
  firewall opens those ports for the trial.
- TURN over TLS on 443 is therefore tested only in the lab.

**Deployed,** by `deploy/signal.sh root@129.212.227.207` (rerun to update). The VPS runs Ubuntu 24.04 with coturn 4.6.1
from apt; the repo's tests run 4.18.
- **Ports:**
  - forwarder: TCP 8443, `wss://relay.letmeknow.dev:8443/ws`;
  - member: TCP and UDP 3478, TLS 5349; relays UDP 49152–50151;
  - stranger: TCP and UDP 3479, TLS 5350; relays UDP 50152–50351.
  - coturn also binds its alternate ports, 3488/5358 (member) and 3489/5359 (stranger). Clients never use them.
- **Units:** `letmetalk-forwarder`, `letmetalk-turn@member`, `letmetalk-turn@stranger`, all as user `letmetalk`, and
  `letmetalk-tls-sync.timer`, which runs daily.
- **Files:** `/usr/local/bin/letmetalk-signal`; `/etc/letmetalk/{member,stranger}.secret` (made once, root only);
  `coturn/{member,stranger}.conf` (the repo's configs, plus ports, relays, cert, secret, `bps-capacity` and the host's
  own addresses as denied peers); `forwarder.env` (the secrets, as `MEMBER_SECRET` and `STRANGER_SECRET`);
  `allowlist`, seeded with `deploy/check.pub` once, then owned by the owner; `tls/{cert,key}.pem`, split from letmeknow's
  cached ACME PEM by `/usr/local/sbin/letmetalk-tls-sync`, which restarts ours when the certificate changed.
- **Deviations:** `bps-capacity` is 125000000 on both instances, not 12500000. On coturn 4.6.1, an allocation reserves
  `max-bps`, so a capacity equal to it refused every allocation. The member instance now takes 10 relays at once.
- **Open in the cloud firewall:** TCP 8443, 3478, 3479, 5349 and 5350; UDP 3478, 3479 and 49152–50351. Relays need
  their UDP range open to peers, not only the listeners.

Each pair runs both letmetalk and iroh.

### Bench

`crates/bench` runs one scenario set over three transports: letmetalk natively (`bench`), letmetalk in a browser page
(the same code as `letmetalk_bench.wasm`, behind `crates/bench/web/index.html`), and iroh 1.3 natively (feature `iroh`,
direct and relay-only). Decisions:
- **Roles.** `serve` answers streams by protocol name: `echo` echoes until the peer finishes, `sink` reads to the end and
  then writes one byte, and `source:<bytes>` writes that many and finishes. It logs in as its key and reports it.
  `dial` runs every scenario against one peer and prints one JSON object per line: `pair`, `scenario` and the metrics.
- **Scenarios.**
  - cold: a fresh login and link, 5 times, timed from opening a stream to its first echoed byte.
  - warm: after the link is up, 20 more streams, timed the same way.
  - path: `Endpoint::path`, after the warm streams.
  - 256 MiB up and down on one stream, and 4 × 64 MiB up at once. Throughput is decimal MB/s, timed until the peer's
    acknowledgement.
  - 1,000 100-byte echoes, paced 5 ms apart, idle and then while a sink takes 64 KiB chunks on another stream.
  - 1 s of ChaCha20-Poly1305 sealing and opening 16 KiB blocks.
- **One link per measurement.** Each measurement gets a link of its own, formed by an echo before it starts, so that
  setup is not in its timing.
- **Peak RSS.** Each native process reports its own `VmHWM`; a server's is read before the harness stops it. Browsers
  have no RSS figure.
- **Environment.** `bench-local.sh` records the load average (1, 5, 15 minutes) before and after each run, and
  `net.core.rmem_max`. Socket buffers matter (spike 2), so the report states them.
- **Browser.** The page prints its lines into `#out` and sets `#status` to `done` or `failed`. Playwright reads them. The
  `.wasm` is recorded as wasm-bindgen writes it, raw and gzipped. Nothing shrinks it with `wasm-opt`, so the number is
  the untuned build.
- **Encryption.** chacha20poly1305 0.10.1 with the default features off, which is the version and feature set snow
  uses. The bench times the crate directly. It does not time snow's transport.

### Decision

The criteria:
- **Connectivity:** every lab pair connects, except a native peer on a UDP-blocked network.
  - Native pairs connect directly wherever iroh does, and pairs with a browser do so under the same NAT types.
  - Same-host and same-LAN pairs connect directly.
  - In real-world runs, browser pairs connect directly wherever native iroh pairs do on the same networks.
- **Setup time,** on the WAN profile:
  - cold: at most 1 s at the median and 3 s at the 95th percentile;
  - warm: at most two RTTs plus 10 ms. One RTT is the native opener's DCEP ack.
- **Latency under load:** at most one RTT plus 100 ms at the 95th percentile, on the WAN profile.
- **Throughput,** with letmetalk's encryption on, as always, on the LAN and WAN profiles:
  - native↔native reaches at least half of iroh's;
  - pairs with a browser reach at least 50 Mbit/s on the LAN profile, and beat today's iroh-relay path on the WAN
    profile.
- **Recovery:** a peer whose network changed is reachable again within 10 s.
- **Stability:**
  - an idle stream holds its link for an hour;
  - churn leaves memory and handles flat;
  - 256 MiB transfers stay within bounded memory on both targets.

Outcomes:
- **Go:** a separate adoption plan for letmeknow, replacing iroh and iroh-blobs.
- **Browser links only:** pairs with a browser pass, but native pairs lose to iroh. Browsers move to letmetalk, and
  agents run both: iroh among themselves, letmetalk toward browsers.
- **No-go:** `TRIAL.md` records why, and letmeknow stays on iroh.

## Work

Each step lands with its tests and keeps the checks in AGENTS.md green.

0. **Spike,** throwaway (above).
1. **Keys and handshake,** with CI: native clippy and tests, and wasm32 clippy. Tests:
   - a full handshake, with the ML-KEM secret in the PSK slot;
   - a tampered message 1, message 2 and ML-KEM ciphertext (the ciphertext is bound through the PSK);
   - a message 1 for the wrong key;
   - a message 1 whose Ed25519 key does not map to its Noise static key;
   - a replayed, stale and future message 1;
   - forged message 1s, which must not enter the replay cache;
   - small-order static keys;
   - `Candidates` envelopes replayed and out of order, and indexes of 2⁴⁰ or more.
2. **Native links and streams** over an in-memory carrier on loopback, with the stream layer also run over a fake
   backend. Tests:
   - echo, and finishing in each direction;
   - a replayed, reordered, dropped or moved message fails its stream;
   - a peer opening a used number, a number of our parity, 0 or 2²⁴−1 fails the link;
   - a peer sending past its credit fails the link; streams not yet accepted get 16 KiB; the accept queue holds 16;
   - a reset during a 1 MiB backlog;
   - crossed connects;
   - replacement, which a held-back or replayed offer cannot cause;
   - each `admit` outcome, including a key refused after its link formed;
   - an offline peer, a timeout, eviction at the cap, and `ResourceBusy` when nothing can be evicted;
   - a flood of Relayed offers from fresh keys, which evicts no Direct setup or link;
   - the stream cap;
   - identity misbinding: a key holder relaying two peers' offer and answer as its own gets no link;
   - a stalled reader on one stream while another stream and the control channel keep moving;
   - 256 MiB to a slow reader, in bounded memory.
3. **`letmetalk-signal` and native `WsSignal`.** Tests:
   - login with a bad MAC, a wrong host, an all-zero Diffie–Hellman, a small-order or torsioned key, and a negated key;
   - a 65th socket from one IP refused;
   - `ws://` refused except to loopback;
   - TURN credentials against a coturn the test starts: tokens, not keys, in usernames; member credentials only for
     allowlisted keys; the small quota for keys outside the allowlist; `total-quota`; a peer address in a private
     range, a mapped or a NAT64 one refused;
   - routing and its acks;
   - an offline recipient;
   - limits;
   - a new login replacing an old one;
   - two endpoints connecting through it.

   The limits are sized from a measured startup (see Limits).
4. **Browser backend and wasm `WsSignal`.** wasm-bindgen tests in headless Chromium, run in CI by
   `scripts/browser-tests.sh`. The script starts a forwarder and a native echo endpoint on loopback, and builds the tests
   with their URL and key in `LETMETALK_TEST_SIGNAL` and `LETMETALK_TEST_ECHO`.
   - browser↔browser within one page, with 8 MiB one way, and a relayed dial with no relay forms no link;
   - browser↔native through the forwarder, in both directions;
   - a plain `ws://` to a remote host is refused.
5. **Bench** (`crates/bench`): a native binary and a browser page. They:
   - echo, time setup, and measure bulk throughput and latency under load;
   - micro-benchmark the encryption;
   - cover the iroh baselines.
6. **Lab:** the Compose setup, its runner and the manual workflow.
7. **Real-world runs, `TRIAL.md` and the decision.**

## Later

Not in the trial:
- **ICE restart:** on a network change, and to renew TURN credentials on a live link.
- **Unordered and unreliable streams.**
- **Routing across forwarders,** for groups that span deployments. `WsSignal` would learn the forwarder each key's
  envelopes came through, and take hints (`route(key, url)`). The API stays the same.
- **More carriers,** which the app composes into one `Signal`:
  - a local carrier for sessions on one device, as letmeknow's `LETMEKNOW_HOME`, so they need no forwarder;
  - signaling through peers already connected.
- **Browser to a public native host without signaling,** as in libp2p's WebRTC Direct.
- **Post-quantum first messages.** These would need each peer's ML-KEM key in advance, and a key here is only Ed25519.
- **Credit windows that grow** with the path's bandwidth-delay product.
- **Spare channels,** opened ahead of time, so that native opens cost no round trip either.
- **TURN over TCP and TLS for webrtc-rs:** upstream, if not there by adoption.
- **Stream I/O in a worker.** `RTCDataChannel` can be transferred to dedicated workers: Chrome 130, Firefox 144,
  Safari 15.
- **Audio and video.**
- **Publishing** to crates.io and npm.
- **Embedding the forwarder in letmeknow's `serve`.** TURN over TLS on 443 would then need an SNI split beside
  `serve`'s HTTPS.

## Risks

- **webrtc-rs can lose a stream's last messages, and reuse a stream id too soon.** Found by the bench. A channel's close,
  when processed, drops the messages still queued on that channel, so a channel closes only after the `Closed` exchange
  (Channels). Its SCTP stream id is freed at once, and the peer's reset for it can close a new channel that takes the id,
  so the opener waits for the acknowledgement before opening another. Before the handshake, sequential streams on one
  native loopback link failed after about 40 to 75 of them; with it, `many_streams.rs` passes. That is loopback evidence
  only. Report both causes upstream.
- **Our own protocol.**
  - The Noise pattern, the ML-KEM secret in the PSK slot and the nonce layout are ours to get right. The primitives
    come from snow and RustCrypto, not from us.
  - The long-term key does X25519 in two places: Noise (`es`, `se`, `ss`) and the forwarder login, with a point the
    server chooses. eprint 2021/509 covers neither.
  - Deniability rests on reasoning, not on a formal analysis: nothing is signed, and the recipient could have forged any
    message 1 itself. The Noise specification makes no deniability claim.
  - Before adoption, the protocol gets a written specification and an outside review that covers all of this.
- **Double encryption.** Every message is encrypted by letmetalk and again by DTLS. The bench measures what that costs,
  above all in wasm.
- **webrtc-rs in peer-to-peer use.** It has one lead maintainer, and its 0.21 rewrite is weeks old: 0.21.1 fixed lost
  data-channel events. The spike and the lab exist to find such bugs before letmeknow would.
- **Slower cold setup than iroh.** WebRTC sends nothing until gathering, ICE checks, DTLS and SCTP are done. iroh sends
  through its relay at once and moves to a direct path later.
- **No path migration.** A network change costs a reconnect, which hurts phones most.
- **Networks that block UDP.** These need TURN over TLS on 443. iroh's relay works there today over HTTPS.
  - Browsers can do it.
  - Native peers can't until webrtc-rs has TURN over TCP (and TLS).
  - Agents would keep iroh until then, which is the "browser links only" outcome.
- **Native throughput.** The first sign from validation is low (above). The spike measures it first.
- **The forwarder is required for new links** until the app composes other carriers. It also tells logged-in keys who
  is online.
- **TURN.**
  - Relay bandwidth moves from iroh-relay to coturn. Most of today's relay traffic is browsers, though, and letmetalk
    aims to make them direct.
  - A relayed link may die when its 24-hour credentials expire, until ICE restart exists. The lab's run with 5-minute
    credentials shows whether it does.
