# letmetalk

Dial a public key over WebRTC, natively and in browsers. It has iroh's ease of use: a secret key,
`connect(key, protocol)` and `accept()`. Underneath is WebRTC, so browsers connect directly. Signaling goes over any
carrier the app has, and nothing in the middle is trusted.

Status: a trial is being planned; see [PLAN.md](PLAN.md). Nothing works yet.

The planned API:

```rust
let signal = WsSignal::connect("wss://signal.example", &key).await?;
let endpoint = Endpoint::new(key, Config { ice_servers, ..Default::default() }, signal);
let mut stream = endpoint.connect(bob, "chat/1").await?;
stream.write_all(b"hi").await?;
```

MIT licensed.
