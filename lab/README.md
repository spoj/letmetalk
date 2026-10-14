# Lab

The Compose setup for the Lab step of PLAN.md. `run.sh` runs each pair in `pairs.txt`, keeps raw output in `results/`,
and writes `trial/2-lab.md`.

- `compose.yml`: the internet network (203.0.113.0/24) with `letmetalk-signal`, coturn (member and stranger) and
  iroh-relay; a router per NAT'd slot (a, b, h); and peers behind them. Peers are named by slot: `native-a`,
  `browser-a2` and so on, one native and one browser variant each.
- `Containerfile`: one target per image. Build with `podman build -f lab/Containerfile --target <name> .` from the
  repo root.
- `nat/*.nft`: `pr` (masquerade), `sym` (masquerade random), `eif` (inbound UDP DNATed to the LAN peer) and `blk`
  (only TCP 443 out). `none` has no router.
- `peer.sh`: moves a peer behind its router (or onto the internet, for `none`), shapes its access link and tunnels
  loopback port 8787 to the forwarder.
- `nat-check.sh`: RFC 5780 probe from a peer. `run.sh` fails a pair whose probe differs from its NAT label.
- `standin-bench.sh`: stands in for the bench's roles until `crates/bench` lands. It logs in and, for a dial, relays
  over UDP and TLS on 443.
- `keys/`: lab-only seeds and the forwarder's allowlist. They protect nothing.

Run locally with `COMPOSE=podman-compose lab/run.sh`, or `COMPOSE="docker compose"` (the default). The wan and
constrained profiles need the `sch_netem` and `ifb` kernel modules. CI runs the lab by hand from
`.github/workflows/lab.yml`.
