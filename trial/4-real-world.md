# Real-world runs (partial, 2026-10-14)

Raw lines in `trial/real-world/`. Peers:
- the VPS: DigitalOcean Singapore, 1 vCPU, running `bench serve` and `bench iroh-serve --direct` next to the forwarder
  and coturn;
- `pc`: Windows 11 on a home ISP, native `bench.exe` and Chrome 154 through Playwright;
- this Linux machine: its internet goes through a Tailscale exit node (Mullvad, Tokyo).

The RTT between `pc` and the VPS is 36 ms, and every pair below ran direct: host to host over IPv6, or host to srflx.

| pair | cold median ms | warm median ms | up / down / 4 streams MB/s | echo p95 idle / under bulk ms |
|---|---|---|---|---|
| pc native → VPS, 16 MiB | 477 | 36 | 18.6 / 7.6 / 4.2 | 38 / 167 |
| pc native → VPS, 64 MiB | 664 | – | 7.5 / 0.5 / 5.4 | 41 / – |
| pc native → VPS, 64 MiB | – | – | 4.2 / 1.4 / 4.8 | 37 / 135 |
| pc iroh direct → VPS, 16 MiB | 532 | 36 | 19.9 / 18.6 / 26.3 | 36 / 39 |
| pc iroh relay-only → VPS, 16 MiB | 483 | 87 | 1.0 / 1.0 / 1.0 | 38 / – |
| pc Chrome → VPS native, 64 MiB | 452 | 40 | 5.9 / 3.2 / 7.1 | 38 / 128 |
| VPS native → pc Chrome, 16 MiB | 1090 | 36 | 8.9 / 5.0 / 0.5 | 40 / 217 |

So far:
- **Setup** passes: warm is about one RTT.
- **Browser pairs** beat today's iroh-relay path, which letmeknow's relay holds near 1 MB/s.
- **Native throughput** trails iroh badly, and four streams can collapse. Latency under load misses RTT + 100 ms.
  - A capture of VPS → pc at 1.4 MB/s shows 57,601 datagrams of 1,225 bytes for 64 MiB, so almost nothing was
    retransmitted. They leave in bursts of 20–40 within about 1 ms, then the sender idles for an RTT.
  - The sender is window-limited, not loss- or CPU-limited. Branch `wan` investigates.
- **This machine → VPS forms no link.**
  - This machine is behind the Mullvad exit, which is likely an endpoint-dependent NAT, and the VPS's DigitalOcean
    firewall drops unsolicited UDP.
  - Its relay candidate can't reach a peer on the TURN server's own address, since coturn has
    `denied-peer-ip=129.212.227.207`. So a peer colocated with coturn is unreachable from behind such a NAT.
  - Real peers are never on the TURN host, so this is a quirk of this setup, not a finding about letmetalk.

Not yet run: the phone on mobile data (as server, dialed from the VPS and `pc`, then 5 minutes in the background).
