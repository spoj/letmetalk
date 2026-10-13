# letmetalk: dial a key over WebRTC

Draft 1, for review. This plan is the contract for a trial: a small library that connects to an Ed25519 public key over
WebRTC, natively and in browsers, plus the measurements that decide whether letmeknow moves its networking onto it.
letmeknow does not change during the trial.

## Why

- letmeknow connects by key over iroh. Browsers cannot send raw UDP, so every browser byte goes through iroh's relay.
  WebRTC is the only way a browser connects directly, whether to another browser or to an agent.
- Plugging WebRTC into iroh as a custom transport would stack two connection stacks (QUIC over ICE, DTLS and SCTP). iroh's
  transport API has no channel for signaling, and iroh marks it unstable.
- Existing Rust WebRTC wrappers don't fit:
  - matchbox, wasm-peers and just-webrtc address peers by IDs their signaling server hands out, so that server can
    impersonate anyone.
  - rings has keys, but it is a whole DHT overlay.
  - libp2p has keys and browser WebRTC, but only inside libp2p.
- **Goal:** iroh's ease of use (a secret key, `connect(key, protocol)`, `accept()`) with an even smaller surface, built on
  WebRTC from the start. Not compatible with iroh. Keys are still Ed25519, so letmeknow's existing keys would carry over.

## Model

- **Keys are addresses.** An endpoint holds an Ed25519 secret key, and peers are named by their 32-byte public keys.
  Nothing else names a peer: no server-assigned IDs, no addresses.
- **A carrier moves envelopes.** WebRTC needs offers, answers and candidates exchanged before any packet flows.
  letmetalk seals them into envelopes and hands them to a carrier that the app supplies (`Signal`): "deliver these bytes
  to key K".
  - The carrier is untrusted. It can delay or drop envelopes, and it sees who signals whom and when. It cannot read
    them, forge them or sit in the middle.
  - letmetalk ships one carrier: a WebSocket client for its small forwarder, `letmetalk-signal`.
- **One link per peer.** An endpoint keeps at most one WebRTC peer connection (a "link") per remote key. A link is
  made on first use and closed 60 s after its last stream ends.
- **Streams are the API.** `connect(key, protocol)` opens a stream to the key: a reliable, ordered, two-way byte stream
  on its own data channel of the link, tagged with the protocol name. The peer's `accept()` yields it.
  - There are no connection objects, ALPN or router.
  - Opening a stream on a live link costs no round trip.
- **Relays are TURN.** Pairs that cannot connect directly go through a TURN server: coturn or any provider, with
  short-lived credentials (the TURN REST convention). letmetalk takes ICE servers as config and never runs one.

## API

The whole public surface:

```rust
pub struct SecretKey;  // generate(), from_bytes(), to_bytes(), public()
pub struct PublicKey;  // 32 bytes; Display and FromStr as hex

pub struct IceServer { pub urls: Vec<String>, pub username: String, pub credential: String }

#[derive(Default)]
pub struct Config {
    pub ice_servers: Vec<IceServer>,
    /// Use TURN only, so that peers never learn this endpoint's addresses.
    pub relay_only: bool,
    /// The keys that may open links to this endpoint, checked before answering. All keys if none.
    pub allow: Option<Arc<dyn Fn(&PublicKey) -> bool + Send + Sync>>,
}

pub trait Signal: Send + Sync + 'static {
    /// Delivers an envelope toward `to`; fails with HostUnreachable if the carrier knows `to` is offline.
    fn send(&self, to: PublicKey, envelope: Vec<u8>) -> BoxFuture<'static, io::Result<()>>;
    /// The next envelope for this endpoint; None once the carrier has stopped.
    fn recv(&self) -> BoxFuture<'_, Option<Vec<u8>>>;
}

impl Endpoint {  // Clone
    pub fn new(key: SecretKey, config: Config, signal: impl Signal) -> Endpoint;
    pub fn key(&self) -> PublicKey;
    pub async fn connect(&self, to: PublicKey, protocol: &str) -> io::Result<Stream>;
    pub async fn accept(&self) -> Option<Stream>;
    /// For links made from now on, since TURN credentials expire.
    pub fn set_ice_servers(&self, servers: Vec<IceServer>);
    /// The live link's route: whether it is relayed, and its round-trip time.
    pub async fn path(&self, peer: PublicKey) -> Option<Path>;
    pub async fn close(&self);
}

impl Stream {  // tokio AsyncRead + AsyncWrite; shutdown finishes the sending side
    pub fn remote_key(&self) -> PublicKey;
    pub fn protocol(&self) -> &str;
}

impl WsSignal {  // feature "ws"
    pub async fn connect(url: &str, key: &SecretKey) -> io::Result<WsSignal>;
}
```

- **Errors** are `io::Error`, as with `TcpStream`:
  - `HostUnreachable`: the carrier says the key is offline.
  - `ConnectionRefused`: the peer refused the link.
  - `TimedOut`: no link formed within 15 s.
  - `ConnectionReset`: a stream or its link died.
- **Streams.** Dropping a stream without finishing it resets it, and the peer's reads fail. To refuse an unknown
  protocol, the accepter drops the stream.
- **Same types on both targets.** On wasm, JS objects are held in `SendWrapper`; wasm32-unknown-unknown runs on one
  thread. So handles and the `Signal` bound are the same on both targets.
- **With no ICE servers,** links are only possible between hosts on the same network or with public addresses.

## Design

### Envelopes

- **Format.** `version (1 byte) ‖ sender key (32) ‖ HPKE encapsulated key (32) ‖ ciphertext`.
  - The plaintext is CBOR: a session id (16 random bytes, chosen by the offerer), the send time (Unix ms), and one
    message: `Offer(sdp)`, `Answer(sdp)`, `Candidate(candidate, mid)` or `Bye`.
- **Sealing.** HPKE (RFC 9180) in auth mode, with info `letmetalk/1`:
  - Suite: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and ChaCha20-Poly1305.
  - Keys: both sides' Ed25519 keys mapped to X25519 (`SigningKey::to_scalar_bytes`, `VerifyingKey::to_montgomery`).
  - Library: hpke-rs with its RustCrypto provider, which letmeknow already builds through openmls.
  - What auth mode gives: the recipient knows the sender, and the key schedule binds both keys. So an envelope opens
    only at its recipient, and only as coming from its sender; a reflected or redirected one fails.
  - Small-order keys are refused.
- **Freshness.**
  - An offer more than 2 minutes old, or more than 2 minutes in the future, is dropped.
  - So is an offer whose session id was already seen within that window.
  - Answers, candidates and byes count only for a session in progress.
- **Why not separate signing and encryption keys:** a dialer knows only the peer's Ed25519 key. Auth-mode HPKE gives
  sender authentication and confidentiality from that key in one standard step.
- **Why not Noise:** its one-way K pattern is the same construction, with less library support. HPKE fits a single
  sealed message through a store-and-forward carrier.

### Links

- **Setup.**
  - The dialer creates a peer connection with the endpoint's ICE servers, then the control channel (`letmetalk/1`,
    negotiated with id 0, so it needs no in-band open). It sends an offer at once, and then its candidates as they are
    gathered (trickle ICE).
  - The accepter checks `allow`, then does the same with an answer.
  - A candidate that arrives before its offer or answer is held until it can be applied.
- **Confirmation.**
  - The problem: the SDP carries each side's DTLS certificate fingerprint, and the WebRTC stack refuses a peer whose
    certificate differs. That isn't enough. A dishonest key holder M could pass A's offer to B as its own, and B's
    answer back to A. A and B would then connect directly, each believing it reached M (identity misbinding).
  - The fix: once the control channel opens, each side sends an Ed25519 signature over `letmetalk/1 confirm ‖ role ‖
    session ‖ offerer key ‖ answerer key ‖ offerer fingerprints ‖ answerer fingerprints`.
  - A link is up only when the peer's signature verifies under the key it was dialed or accepted as. Only the holder of
    the DTLS key can be at the other end, and only the holder of the Ed25519 key can sign, so the two are bound.
  - Streams wait for confirmation.
- **Crossed offers.** If offers cross between two keys, the link offered by the smaller key survives. The other side
  drops its own offer and answers. Pending `connect`s move to the surviving link.
- **Replacement.** A peer that restarted or lost its link sends a new offer. It replaces the live link only if it was
  sent later than that link's offer, and the old link closes only once the new one is confirmed. So a carrier
  replaying or holding back an old offer cannot tear down a working link.
- **End.** A link ends when:
  - its control channel closes, which is how a peer's close arrives;
  - its peer connection fails (ICE consent lost for 30 s, RFC 7675);
  - 60 s have passed since its last stream ended.

  The trial has no ICE restart. A network change ends the link, and the app reconnects, as letmeknow does today.
- **Limits.**
  - 256 links per endpoint.
  - 16 links in setup that this endpoint did not dial.
  - An offer beyond either limit, or refused by `allow`, gets a `Bye`, so the dialer fails fast with
    `ConnectionRefused`.

### Streams

- **Channels.** Each stream is one data channel, reliable and ordered.
  - It is opened in band (DCEP), with the protocol name as its DCEP protocol.
  - The opener can write at once.
  - The peer surfaces it only on a confirmed link.
- **Messages.**
  - Data goes in binary messages of at most 64 KiB, and at most the peer's `max-message-size`.
  - Data channels have no half-close, so finishing sends one text message.
  - A channel closes once both sides have finished, or at once on a reset.
- **Sending back-pressure.** A write waits while the channel buffers more than 1 MiB, until the buffer drains to
  256 KiB. Browsers signal this with `bufferedAmount` and `bufferedamountlow`, and webrtc-rs has equivalents.
- **No receiving back-pressure in browsers.** Browsers deliver data-channel messages as events, so a slow reader in a
  browser buffers them in memory. The trial measures this. If it matters, the fix is a per-stream credit window on the
  control channel.

### Backends

- **Native: webrtc-rs (`webrtc` 0.21).**
  - It is an async peer connection over a Sans-I/O core (`rtc`).
  - It gathers host, server-reflexive and TURN relay candidates itself, and resolves browsers' mDNS (`.local`)
    candidates.
  - It supports the relay-only policy, ICE-TCP and ICE restart.
  - 0.21, its 1.0 release candidate (September 2026), fixed data-channel back-pressure.
  - It is pure Rust (ring), so it cross-compiles to letmeknow's targets: Linux, macOS, Windows and Android.
- **Why not str0m:** it leaves NIC enumeration, STUN and TURN outside its scope, so we would write candidate gathering
  and a TURN client. Its README also says peer-to-peer "has received less testing" than its SFU use. It is the fallback
  if webrtc-rs fails the trial.
- **Why not libdatachannel:** being C++ with OpenSSL, it complicates letmeknow's cross-builds.
- **Browser: the browser's own WebRTC,** through web-sys (`RtcPeerConnection`, `RtcDataChannel`).
  - The browser runs ICE, DTLS and SCTP. letmetalk adds only envelopes, confirmation and link management, so its wasm
    stays small.
  - Browsers expose `RTCPeerConnection` in windows, not in workers. letmeknow's node already runs in the window.
- **Shared link logic.** Both backends follow the W3C peer-connection shape. So the link logic is written once, over
  two thin modules chosen by target, which have the same functions. Spawning and timers go through n0-future.
- **Node and Deno** have no WebRTC. Agents use the native build, as now.

### `letmetalk-signal`

A forwarder for envelopes over WebSocket, with a library entry (an axum router) so that letmeknow's `serve` can embed it
later.

- **Login.**
  - The server sends a 32-byte nonce.
  - The client answers with its key and an Ed25519 signature over `letmetalk-signal/1 ‖ host ‖ nonce`. The host is
    signed so that a login can't be replayed to another server.
  - There is one socket per key; a new login replaces the old.
- **Frames.**
  - Client to server: `id (u32) ‖ to (32) ‖ envelope`.
  - Server to client: `0 ‖ envelope` for a delivery; `1 ‖ id` once an envelope is passed to its recipient's socket;
    `2 ‖ id` if the recipient isn't connected.
  - `WsSignal::send` resolves on `1` or `2`; `2` becomes `HostUnreachable`.
  - The server drops an envelope whose sender key isn't the login's key.
- **Limits.** Envelopes of up to 8 KiB, 50 a second per key with bursts of 200, and an optional allowlist of keys.
  Nothing is stored.
- **Reconnecting.** `WsSignal` reconnects with backoff. Meanwhile, sends fail with `NotConnected`.

## Trial

### Measurements

Each run records:
- **Connection:** whether the pair connected, its path (relayed or direct, with the candidate types).
- **Setup time:**
  - cold: `connect` with no link, to the first echoed byte;
  - warm: a new stream on a live link, to the first echoed byte.
- **Throughput:** 256 MiB on one stream, and on four streams at once.
- **Browser memory** with a slow reader.
- **Stability:** a link left idle for an hour; 50 links on one agent.
- **wasm size:** letmetalk's share of a web build, against iroh's in letmeknow's.

Pairs are native↔native, native↔browser and browser↔browser, with Chromium on each. Firefox and WebKit run against
native on one NAT pair. The baseline is iroh 1.3, native↔native, with a local iroh-relay, measured the same way.

### Lab

`lab/` holds a Docker Compose setup that runs locally and in a GitHub Actions workflow started by hand:
- **Network:** an "internet" bridge carrying `letmetalk-signal`, coturn (UDP, TCP and TLS) and iroh-relay. Each peer
  sits behind its own router container.
- **NAT types** on the routers (nftables):
  - none (a public address);
  - endpoint-independent mapping and filtering;
  - endpoint-independent mapping with address-and-port-dependent filtering;
  - endpoint-dependent mapping (symmetric);
  - UDP blocked, with only TCP 443 out.
- **Path profiles** (`tc netem` on the routers): LAN, and WAN at 50 ms RTT with 1% loss.
- **Browsers:** headless Chromium (Playwright) containers on each side.

Real-world runs, using the owner's devices: a laptop on home Wi-Fi, a phone on mobile data (behind carrier-grade NAT)
in Chrome and Safari, a cloud VM, and one restrictive network if available. Each pair runs both letmetalk and iroh.

### Decision

Proposed thresholds, which the owner sets:
- **Connectivity:** every lab pair connects. Native pairs connect directly wherever iroh does, and pairs with browsers
  connect directly under the same NAT types.
- **Setup time:** on the WAN profile, a cold connect takes at most 1 s at the median and 3 s at the 95th percentile. A
  warm one takes at most one RTT plus 10 ms.
- **Throughput:** native↔native reaches at least half of iroh's on the same path. Any pair with a browser reaches at
  least 50 Mbit/s on the LAN profile.
- **Stability:** idle links survive an hour, and native memory stays bounded through 256 MiB transfers.
- **Size:** letmetalk adds less to the web build than iroh does.

**Go** means a separate adoption plan for letmeknow, replacing iroh and iroh-blobs. **No-go** means `TRIAL.md`
records why, and letmeknow stays on iroh.

## Work

Each step lands with its tests and keeps the checks in AGENTS.md green.

1. **Keys and envelopes,** with CI: native clippy and tests, and wasm32 clippy. Tests:
   - round trip;
   - a tampered envelope;
   - a wrong recipient;
   - an envelope from A to B fed back to A;
   - replayed, stale and future offers;
   - small-order keys.
2. **Native links and streams** over an in-memory carrier, on loopback. Tests:
   - echo, and finishing in each direction;
   - reset;
   - crossed connects;
   - replacement after a restart, but not by an older offer;
   - refusal by `allow`;
   - an offline peer;
   - a timeout and an idle close;
   - a key holder re-sealing two peers' offer and answer as its own gets no link;
   - 256 MiB to a slow reader.
3. **`letmetalk-signal` and native `WsSignal`.** Tests:
   - login with a bad signature, and with the wrong host;
   - routing and its acks;
   - an offline recipient;
   - the sender-key check;
   - limits;
   - a new login replacing an old one;
   - two endpoints connecting through the forwarder.
4. **Browser backend and wasm `WsSignal`.** wasm-bindgen tests in headless Chromium, run in CI:
   - browser↔browser within one page;
   - browser↔native through a forwarder that the test starts.
5. **Bench** (`crates/bench`): a native binary and a browser page, which echo, time setup and measure bulk throughput.
   It also covers the iroh baseline.
6. **Lab:** the Compose setup and its runner, and the manual workflow.
7. **Real-world runs, `TRIAL.md` and the decision.**

## Later

Not in the trial:
- ICE restart on network change.
- Unordered and unreliable streams.
- A receive credit window for browsers.
- Signaling through peers already connected (an app-level `Signal`).
- Browser to public native host without signaling, as in libp2p's WebRTC Direct.
- Audio and video.
- Publishing to crates.io and npm.
- Embedding the forwarder in letmeknow's `serve`.

## Risks

- **webrtc-rs in peer-to-peer use:** it has one lead maintainer and a fresh 1.0 release candidate. The lab exists to
  find its ICE and TURN bugs before letmeknow would.
- **Slower cold setup than iroh:** WebRTC sends nothing until gathering, ICE checks, DTLS and SCTP are done. iroh sends
  through its relay at once and moves to a direct path later.
- **No path migration:** without ICE restart, a network change costs a reconnect.
- **Networks that block UDP:** these need TURN over TCP or TLS on port 443. iroh's relay works there today over HTTPS.
  Browsers support `turns:`; whether webrtc-rs does is still to be checked.
- **Browser receive buffering,** as above.
- **TURN costs:** relay bandwidth moves from iroh-relay to coturn. Most of today's relay traffic is browsers, which
  letmetalk aims to make direct.
- **Metadata:** the carrier sees who dials whom and when, as iroh's relay does today. Envelopes hide addresses.
