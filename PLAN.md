# letmetalk: dial a key over WebRTC

Draft 2, for review.
- **Changes since draft 1:**
  - the owner's decisions: webrtc-rs, streams only, the guarantees below, these thresholds, and a throwaway VM;
  - the review's findings;
  - the validation's corrections.
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
4. **Deniable.** letmetalk signs nothing. No message it sends proves to a third party who talked to whom, and neither
   does a forwarder login.
5. **Addresses only to admitted keys.**
   - Peers learn this endpoint's IP addresses only if `admit` says `Direct`. With `Relayed`, they see only TURN's.
   - The carrier sees no addresses.

Not promised:
- **Metadata.**
  - The carrier sees who signals whom, when, and how much.
  - A forwarder also knows who is logged in.
  - TURN servers see both ends' addresses and how much they send.
- **Availability.** A carrier can drop or delay signaling, so links may fail to form.
- **The first message.** The dialer's first message carries its key, its offer and its first candidates. It is
  protected by X25519 only: it is not post-quantum, and not forward secret if the recipient's key is stolen later.
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

- **Admission rules.**
  - `admit` is checked when a link forms. Once a key is refused, its link closes at its next incoming stream.
  - It also sets what this endpoint reveals when it dials. A key it would refuse cannot be dialed.
- **Errors** are `io::Error`:
  - `HostUnreachable`: the carrier says the key is offline.
  - `NotConnected`: the carrier itself is down.
  - `PermissionDenied`: `admit` refuses the key.
  - `TimedOut`: no link formed within 15 s. A refusal looks the same, since refusals are silent.
  - `ConnectionReset`: the stream, or its link, died, was reset, or failed to decrypt.
- **Streams.** Dropping a stream without finishing it resets it. To refuse an unknown protocol, the accepter drops the
  stream.
- **Same types on both targets.**
  - On wasm, JS objects are held in `SendWrapper`, which is safe because wasm32-unknown-unknown has one thread.
  - With the `futures` crate's `BoxFuture`, the types and the `Signal` bound are then the same on both targets.
  - n0-future's `BoxFuture` would not do: it isn't `Send` on wasm.
- **For the bench only,** behind the feature `stats`: `Endpoint::path(peer)` gives the link's route (relayed or direct)
  and its RTT.

## Design

### Handshake

- **Noise pattern.** `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s`, WireGuard's handshake.
  - Prologue: `letmetalk/1 ‖ session id`.
  - IK fits keys as addresses: the dialer knows the peer's key, and the peer learns the dialer's from message 1.
- **Static keys.**
  - Both sides' Ed25519 keys are mapped to X25519 (`SigningKey::to_scalar_bytes`, `VerifyingKey::to_montgomery`).
  - letmetalk itself only ever does X25519 with the key, though apps may also sign with it. eprint 2021/509 shows that
    Ed25519 signing and an X25519 KEM can share a key. The outside review (Risks) covers Noise's static-key use.
  - Message 1 carries the dialer's Ed25519 key, and the peer checks that it maps to the dialer's Noise static key.
  - Small-order keys are refused.
- **Post-quantum.**
  - The dialer puts a fresh ML-KEM-768 encapsulation key in message 1.
  - The peer encapsulates to it, puts the shared secret in Noise's PSK slot before writing message 2, and sends the
    ciphertext beside message 2.
  - So every key after message 1 mixes X25519 and ML-KEM. This is how Rosenpass makes WireGuard post-quantum through
    the same slot, except that here the exchange rides inside the handshake's two messages.
- **Envelopes.** `version (1) ‖ kind (1) ‖ session id (16) ‖ body`. The session id is chosen at random by the dialer.
  - `Offer`: Noise message 1. Its payload (CBOR) holds:
    - the dialer's Ed25519 key;
    - the send time (Unix ms);
    - the ML-KEM encapsulation key;
    - the offer SDP.
  - `Answer`: the ML-KEM ciphertext, then Noise message 2. Its payload holds the answer SDP.
  - `Candidates`: an index (8 bytes), then candidates sealed with the session keys (see Streams for nonces). Either
    side sends these once it holds those keys: the peer after writing message 2, the dialer after reading it.
- **What the carrier sees:** the recipient, the session id, and each envelope's kind, size and time. It does not see
  the dialer's key (Noise encrypts it), any address, or any SDP. A forwarder does know the dialer from its login.
- **Freshness.**
  - A message 1 more than 10 minutes old or ahead is dropped and logged.
  - So is one whose session id was seen within that window.
  - Answers count only for a session in progress.
  - Candidates are idempotent, so a replayed one does no harm.
- **Libraries:** snow (RustCrypto resolver) and ml-kem (RustCrypto). Both build for wasm32.
- **Why not HPKE envelopes and signatures:** they would be neither deniable nor forward secret for the answer.
  One Noise handshake gives authentication, deniability, forward secrecy after message 1, and resistance to
  key-compromise impersonation once the link confirms.

### Links

- **Setup.**
  - The dialer creates a peer connection with the carrier's ICE servers, plus the relay-only policy if `admit` says
    `Relayed`.
  - It creates the control channel (`letmetalk/1`, negotiated with id 0, so no in-band open is needed) and an offer.
  - The offer, carrying the candidates gathered within 100 ms, goes in message 1.
  - Later candidates follow in batches every 50 ms until gathering ends, once the dialer holds the session keys. On
    native, virtual interfaces (docker, veth, bridges) are skipped.
  - The accepter:
    - drops anything it cannot open;
    - applies `admit`, and a refusal gets no reply;
    - does the same with an answer in message 2, then its own candidates.
  - Candidates that arrive early are held until they can be applied.
- **Confirmation.**
  - Once the control channel opens, each side sends `Hello` on it, encrypted with the session keys. The link is up when
    the peer's `Hello` opens.
  - A peer without the session keys cannot produce one. That includes a key holder M that tries to pass A's offer to B
    as its own, and B's answer back to A, so that A and B connect directly, each believing it reached M (identity
    misbinding).
  - Streams wait for confirmation.
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
- **Limits.**
  - 256 links. At the cap, the least recently used link with no streams is evicted.
  - One link in setup per key that this endpoint did not dial. A newer offer replaces it.
  - 16 such links in all. When that pool is full, the oldest unconfirmed one is evicted.
  - An unconfirmed inbound link is dropped after 10 s.

### Streams

- **Channels.** Each stream is one data channel, reliable and ordered, opened in band (DCEP).
  - Streams open only once the link is confirmed. That also avoids a webrtc-rs bug: a channel the answering side opens
    between ICE connecting and SCTP coming up never opens.
  - A browser opener writes at once. A native opener waits for the peer's DCEP ack.
  - At most 128 streams are open per link in each direction; further opens are reset.
- **Numbers.** Streams are numbered by letmetalk, not by channel id, since webrtc-rs's `id()` is only a local handle.
  - The link's dialer opens even numbers and its accepter odd ones. Numbers are never reused on a link.
  - Stream 0 is the control channel. Number 2²⁴−1 is reserved for `Candidates` envelopes.
  - The DCEP label carries the number. The protocol name travels encrypted in the stream's first message, which also
    sidesteps web-sys having no getter for a channel's protocol.
- **Encryption.**
  - Every message on every channel, the control channel included, is sealed with ChaCha20-Poly1305 under the session
    key of its direction.
  - Its nonce is the stream's number (24 bits) and the message's index on that stream (40 bits). Channels deliver in
    order and lose nothing, so the nonce is implicit.
  - A replayed, reordered, dropped or moved message fails to open, and fails its stream.
  - Since numbers are never reused, no nonce repeats under a key. A link that runs out of numbers is replaced.
- **Messages.** Plaintexts start with a type:
  - on a stream: `Open(protocol)` (the first message), `Data`, `Finish`;
  - on the control channel: `Hello`, `Credit(stream, bytes)`, `Reset(stream)`.

  Data goes in messages of at most 16 KiB, so a small message on one stream never waits behind a large one on another.
  Data channels have no half-close, so `Finish` stands in for one, and a channel closes once both sides have finished.
- **Flow control.** SCTP has one receive window per link, not one per stream (RFC 9260). So on native, one slow reader
  would stall every stream, the control channel included. And browsers deliver messages as events, with no back-pressure
  at all. So each stream gets its own window:
  - The reader grants 256 KiB of credit, and grants more as the app reads.
  - The sender never sends past its credit.
  - On native, the sender also caps each channel's send buffer and waits on `writable()`, because webrtc-rs's
    `OnBufferedAmountLow` proved unreliable: it fired with 3 MB still queued.
  - Every stream's unread data stays within its window, so letmetalk always drains the link at once, and memory is
    bounded on both targets.
- **Reset.** A reset sends `Reset`, then closes the channel. The reader discards what it holds and fails with
  `ConnectionReset`.

### Backends

- **Native: webrtc-rs (`webrtc` 0.21).**
  - It is an async peer connection over a Sans-I/O core (`rtc`).
  - It gathers host, server-reflexive and TURN relay candidates itself, and resolves browsers' mDNS (`.local`)
    candidates.
  - It supports the relay-only policy, ICE-TCP and ICE restart.
  - **TURN over UDP only.** It skips `turns:` and TCP TURN URLs. TURN over TCP is planned for after its 1.0
    (webrtc#848; PR #907 is open), and nothing tracks TLS. So a native endpoint on a network that blocks UDP has no
    relay.
  - It is Rust plus ring's C and assembly. letmeknow already builds ring for all its targets: Linux, macOS, Windows
    and Android.
  - Its DTLS is 1.2 only, and DTLS 1.3 waits until after its 1.0 (webrtc#801). That doesn't touch the guarantees.
  - 0.21 (September 2026) is its pre-1.0 line, the run-up to 1.0. It is weeks old, so step 0 tests it before anything
    is built on it.
- **Why not str0m:** it leaves NIC enumeration, STUN and TURN outside its scope, so we would write candidate gathering
  and a TURN client. Its README also says peer-to-peer "has received less testing" than its SFU use.
  - It remains the fallback, so letmetalk reaches the native stack through a narrow seam that str0m could also sit
    behind: create a link, set the remote description, add candidates, open, send, receive and close channels, and
    events.
  - The stream layer's tests also run over a fake backend at this seam.
- **Browser: the browser's own WebRTC,** through web-sys (`RtcPeerConnection`, `RtcDataChannel`).
  - The browser runs ICE, DTLS and SCTP. letmetalk adds the handshake, encryption, flow control and link management.
  - Browsers expose `RTCPeerConnection` in windows, not in workers. letmeknow's node already runs in the window.
  - web-sys lacks a few getters (`pc.sctp`) and `restartIce`. `js_sys::Reflect` reaches them if needed.
  - On wasm, snow and ml-kem need `getrandom` with its `wasm_js` feature.
- **Shared link logic.** The link logic is written once, over the two backends. Spawning and timers go through
  n0-future.
- **Node and Deno** have no WebRTC. Agents use the native build, as now.

### `letmetalk-signal`

A forwarder for envelopes over WebSocket. It has a library entry (an axum router), so that letmeknow's `serve` can embed
it later.

- **Login, deniable.**
  - The server sends a fresh X25519 key.
  - The client answers with its Ed25519 key and a MAC: keyed BLAKE2s over `letmetalk-signal/1 ‖ host`, with the key
    being the Diffie–Hellman of the client's X25519-mapped key and the server's fresh key.
  - The server checks the MAC with its side of the same Diffie–Hellman. That proves the key to the server, and to
    nobody else, since the server could have computed the MAC itself.
  - The host is in the MAC, so a login cannot be relayed to another server. All-zero Diffie–Hellman results are
    refused.
- **TURN credentials.**
  - The login's reply carries the ICE servers, with TURN credentials in the TURN REST form (username `expiry:key`,
    valid for 24 h).
  - They are minted from a secret the forwarder shares with coturn, and renewed every 12 h over the socket.
  - So coturn can attribute usage to keys, and refuse anyone without a login.
- **One login per key.** A new login replaces the old one. The replaced socket is told so, and `WsSignal` does not
  reconnect it, so two processes with one key don't evict each other in a loop.
- **Frames.**
  - Client to server: `id (u32) ‖ to (32) ‖ envelope`.
  - Server to client:
    - `0 ‖ envelope`: a delivery;
    - `1 ‖ id`: passed to the recipient's socket;
    - `2 ‖ id`: the recipient isn't connected;
    - `3 ‖ id`: over a limit;
    - `4 ‖ ICE servers`: renewed credentials.
  - `WsSignal::send` resolves on `1`, `2` or `3`; `2` becomes `HostUnreachable`.
- **Limits.**
  - Envelopes of up to 8 KiB. An offer or answer is about 3 KB, ML-KEM included.
  - Rates per login, per socket and per IP, sized in step 3 from a measured startup of an endpoint dialing 20 peers.
  - An optional allowlist of keys.
  - Nothing is stored.
- **Presence.** `2 ‖ id` tells any logged-in key whether another key is online. Run with an allowlist to keep that
  among known keys. Embedded in letmeknow's service, it would forward only between members of a group.

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
3–18 MB/s. If that holds, the spike also measures str0m, whose SCTP is a separate crate (sctp-proto, against
webrtc-rs's rtc-sctp). If webrtc-rs fails here, the plan switches to str0m before step 1.

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

Real-world runs use the owner's devices:
- a laptop on home Wi-Fi;
- a phone on mobile data (behind carrier-grade NAT), in Chrome and Safari;
- a cloud VM;
- one restrictive network, if one is available.

The forwarder and coturn for these runs go on a separate small VM, not letmeknow's server. It is made for step 7 and
deleted afterwards. Each pair runs both letmetalk and iroh.

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
- **Throughput,** with letmetalk's encryption on, as always:
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
   - a tampered message 1, message 2 and ML-KEM ciphertext;
   - a message 1 for the wrong key;
   - a message 1 whose Ed25519 key does not map to its Noise static key;
   - a replayed, stale and future message 1;
   - small-order keys;
   - `Candidates` envelopes replayed and out of order.
2. **Native links and streams** over an in-memory carrier on loopback, with the stream layer also run over a fake
   backend. Tests:
   - echo, and finishing in each direction;
   - a replayed, reordered, dropped or moved message fails its stream;
   - a reset during a 1 MiB backlog;
   - crossed connects;
   - replacement, which a held-back or replayed offer cannot cause;
   - each `admit` outcome, including a key refused after its link formed;
   - an offline peer, a timeout, and eviction at the cap;
   - the stream cap;
   - identity misbinding: a key holder relaying two peers' offer and answer as its own gets no link;
   - a stalled reader on one stream while another stream and the control channel keep moving;
   - 256 MiB to a slow reader, in bounded memory.
3. **`letmetalk-signal` and native `WsSignal`.** Tests:
   - login with a bad MAC, a wrong host and an all-zero Diffie–Hellman;
   - TURN credentials, against a coturn the test starts;
   - routing and its acks;
   - an offline recipient;
   - limits;
   - a new login replacing an old one;
   - two endpoints connecting through it.

   The limits are sized here.
4. **Browser backend and wasm `WsSignal`.** wasm-bindgen tests in headless Chromium, run in CI:
   - browser↔browser within one page;
   - browser↔native through a forwarder the test starts.
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

- **Our own protocol.**
  - The Noise pattern, the ML-KEM secret in the PSK slot and the nonce layout are ours to get right. The primitives
    come from snow and RustCrypto, not from us.
  - Before adoption, the protocol gets a written specification and an outside review.
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
  - A relayed link dies when its 24-hour credentials expire, until ICE restart exists.
