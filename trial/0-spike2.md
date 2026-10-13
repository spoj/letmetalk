# letmetalk spike 2: native backend, webrtc-rs vs str0m vs iroh

Loopback only, no relay, one 32-core box shared with other agents. Throughput is decimal MB/s. Every number is the median of 3 runs. Load average (1 min, at each run's start) medians are 1.5–4.5 across configs. Raw output and `uptime` are in `results/`. `scripts/summarize.py` writes `results/summary.md`.
Drops are `drops` from `/proc/net/udp` for this process's own UDP sockets, so they are per socket.
Tests: **t1** = 1 channel × 256 MiB; **t4** = 4 × 64 MiB; **lc** = 100-byte echo every 100 ms on channel B while 10 s of bulk runs on A and A is drained; **ls** = the same, but A is never read.

## Q1. Bigger UDP buffers: yes, they fix the drops, the stalls and most of the throughput

Where: webrtc-rs 0.21.1 `peer_connection/driver.rs::bind_transports` calls `std::net::UdpSocket::bind`, then `Runtime::wrap_udp_socket`. `SettingEngine` has no socket option. So `SockBufs` (src/bin/peer.rs) wraps the tokio runtime with `with_runtime` and calls SO_RCVBUF/SO_SNDBUF there. The kernel doubles the requested size.

| webrtc-rs config | t1 send | t4 send | lc ping p50 / p95 ms | lc max gap s | lc receiver drops |
|---|---|---|---|---|---|
| wd0: default (rcvbuf 208 KiB) | 155.0 | 169.6 | 4.9 / 107.5 | 0.31 | 553 |
| wu1: 1 MiB | 200.3 | 194.5 | 4.3 / 8.2 | 0.11 | 0 |
| wu4: 4 MiB | 206.3 | 198.9 | 4.0 / 7.8 | 0.11 | 0 |

Send-limit sweep with 4 MiB buffers (t1 / t4 send): 256 KiB 198.6 / 197.6; 1 MiB 206.3 / 198.9; 4 MiB 209.9 / 195.7; 16 MiB 208.7 / 193.2. The spike's "bigger limit is slower" was UDP drops. With the buffers fixed, the limit has no effect.

## Q2. Other SCTP limits in webrtc-rs

Exposed: `sctp_max_receive_buffer_size` (a_rwnd), `sctp_mtu`, `sctp_max_message_size`, and letmetalk's send limit. Not exposed: RTO_MIN (a 1000 ms constant in `rtc-sctp` `association/timer.rs`) and congestion control (RFC 4960 slow start and AIMD, no knob).

| config (all with 4 MiB UDP buffers) | t1 send | t4 send | lc p95 ms |
|---|---|---|---|
| wu4 (baseline) | 206.3 | 198.9 | 7.8 |
| + a_rwnd 4 MiB (wu4r) | 206.9 | 198.8 | 7.9 |
| + SCTP MTU 1400 (wu4m) | 232.9 | 224.2 | 7.1 |
| + max message 256 KiB (wu4mm, t1 only) | 177.0 | – | – |

- a_rwnd and message size make no difference. MTU 1400 gives about +13%. It does not fit relayed paths: the spike's 1191 budget is the TURN-over-IPv6 minimum, so use it on direct paths only.
- RTO_MIN, diagnostic only: `vendor/rtc-sctp` with 200 ms, built to `peer-rto200`. With default buffers, lc p95 drops 107 → 36 ms and the median max gap 0.31 → 0.26 s, but 172 drops remain. With 4 MiB buffers it changes nothing (p95 7.8 ms). So the 1 s minimum RTO makes each drop cost more, but the drops cause the stall.

## Q3. str0m 0.24.1, native, in-band DCEP

Harness: `src/bin/str0m_peer.rs`, one thread and one socket. The loop pumps `poll_output`, then drains every queued datagram.
Two traps:
- A channel that an answerer adds out-of-band is dropped by `accept_offer` and never opens. So channels are in-band, as PLAN specifies.
- The DTLS receive queue holds 30 records between `poll_output` calls. The loop pumps every 16 datagrams.

| str0m config | t1 send | t4 send | lc ping p50 / p95 ms | lc receiver drops | ls echoes (of 100) |
|---|---|---|---|---|---|
| s0: default (rcvbuf 208 KiB, MTU 1150) | 57.9 | 75.4 | 10.9 / 12.9 | 0 | 100 |
| s4: 4 MiB buffers | 74.2 | 70.5 | 13.6 / 14.4 | 0 | 100 |
| s4m: 4 MiB + MTU 1400 | 105.7 | 99.9 | 9.1 / 9.8 | 0 | 100 |

- **Stalled reader.** str0m delivers every channel through one `poll_output` queue, so an app cannot pause one channel. Parking A's data in the app leaves B at 100/100 echoes, but A's data piles up with no bound: 775 MB to 1 GB in 10 s. That needs letmetalk's credit.
- **Shared budget.** `sctp_max_buffered_amount` is one budget across all channels. Bulk that fills it first starves the pings, so the harness sends pings first.
- **Throughput.** `perf` on the sender: 43% in sctp-proto `gather_data_packets_to_retransmit` and 30% in hash lookups of TSNs. The cost per SACK grows with the packets in flight, which caps one core at 60–105 MB/s.

## Q4. iroh 1.3 baseline (same box, same method)

- Throughput, one stream, 256 MiB: client 792.6, server 793.2 MB/s. The spike measured 717 under other load.
- lc, bulk on one stream at 883 MB/s, echoes on another: ping p50 0.2 ms, p95 0.6 ms, max gap 0.10 s (the ping interval).

## Limits

- Loopback only. No WAN, TURN, NAT or real NIC. The MTU 1400 result is not validated on a path.
- str0m runs single-threaded. webrtc-rs and iroh use multi-thread tokio, so the comparison is not per core.
- The box was loaded (1-min load 1.5–4.5). Runs vary about 2× (spike 1), so 3-run medians are rough.
- webrtc-rs `ls` writes stop after the stall (11 MB), so the stall number is about the reader, not the sender.
- `wu4mm`, `wu4park` and `rto*` are diagnostics, not configs.
- s0 t4 run 1 hung twice (240 s timeout). The sender waited for the receiver's final app-level ack, which was lost, and the receiver had exited 1 s after finishing. The receiver now lingers 5 s, and the reported run is the rerun. Attempts are kept as `results/s0-t4-1-timeout-attempt*.txt`.

Files: `results/` (raw), `results/summary.md`, `scripts/*.sh`, `vendor/rtc-sctp` (RTO diagnostic), `src/bin/{peer,str0m_peer,iroh_bench,iroh_latency}.rs`.

## Recommendation: stay on webrtc-rs, with these settings

1. Set SO_RCVBUF and SO_SNDBUF to 4 MiB on every UDP socket, through a `Runtime` wrapper. This is what removes the drops and the 1 s stall.
2. Keep the per-channel send limit at 1 MiB. Once the buffers are fixed, 256 KiB to 16 MiB is flat.
3. Set SCTP MTU 1400 on direct paths only. Keep a_rwnd and message size at their defaults.
4. Keep the always-drain design. With an unread channel, webrtc-rs still kills the association: `ls` gave 1 of 101 echoes, with or without buffers. Draining A into memory (`--park`) gave 101/101 at p95 8.7 ms over 10 s, with about 2.1 GB held and no credit to bound it.

Why not str0m: at equal settings it is 2.2–2.8× slower (106 vs 233 MB/s with MTU 1400; 74 vs 206 with 4 MiB buffers). Its latency under load is worse (9–14 ms p50 vs 3–4 ms). Its shared budget and single event queue give no per-channel isolation, so it would need the same credit layer. Its SCTP throughput is limited by sctp-proto's per-SACK cost, which is not a setting.

The native throughput bar (at least half of iroh, about 397 MB/s) is still missed. Best webrtc-rs is 233 MB/s, 29% of iroh. These settings do not close that gap, so per PLAN the native pairs fail throughput and the trial outcome is "browser links only", unless webrtc-rs's per-packet SCTP cost is fixed upstream.
