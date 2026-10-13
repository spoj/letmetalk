# letmetalk step 0 spike: webrtc-rs 0.21.1 vs iroh 1.3

Scratch code, not a design. Raw logs are in `results/`. Throughput is decimal MB/s (10^6 bytes). RSS is `VmHWM` (peak) read from `/proc/self/status` at the end of each process. Medians are over 3 runs unless noted.

## Setup

- `src/bin/peer.rs`: native webrtc-rs 0.21.1 peer. Signalling is JSON lines on stdin/stdout. Scenarios: `send`, `recv`, `stall-send`, `stall-recv`. Channels use `negotiated` ids 0..N-1. Send-side back-pressure is `with_data_channel_send_buffer_limit` plus `writable()`. The sender waits until `outstanding_bytes()==0`, so its time includes the final ack.
- `scripts/run.mjs`: Node harness, using the Playwright library. It relays signalling between two native processes (`native` mode), or between a native process and headless Chromium (`chrome` mode). No STUN servers anywhere, so Chromium offers only mDNS `.local` host candidates.
- `src/bin/iroh_bench.rs` and `scripts/iroh.sh`: iroh 1.3.0, `=1.3.0` with default features off, as in letmeknow. Relay disabled, two processes on loopback, one bidirectional stream, 16 KiB writes, and a 1-byte ack from the server to stop the clock.
- Build: `CARGO_TARGET_DIR=/tmp/letmetalk-validate/target cargo build --release`, reusing `Cargo.lock` from validate.
- Chromium: Playwright's bundled build is 1247, but only 1243 is cached, so `executablePath` points at the 1243 `chrome-headless-shell` (Chrome 153 UA).

## 1. Native↔native throughput (webrtc-rs, loopback)

Limit 1 MiB per channel (default in the harness).

| run | 1 ch × 256 MiB, sender | 1 ch, receiver | 4 ch × 64 MiB, sender | 4 ch, receiver |
|---|---|---|---|---|
| 1 | 153.2 | 173.4 | 172.3 | 172.8 |
| 2 | 177.3 | 177.5 | 170.9 | 171.2 |
| 3 | 98.7 | 98.8 | 195.8 | 196.2 |
| **median** | **153.2** | **173.4** | **172.3** | **172.8** |
| peak RSS, sender | 19.5 MB (median) | | 36.9 MB (median) | |
| peak RSS, receiver | | 11.4 MB (median) | | 17.4 MB (median) |

Sensitivity, 1 channel, sender MB/s, 3 runs each: 256 KiB: 92 / 162 / 183 (median 162). 4 MiB: 116 / 204 / 172 (median 172). 16 MiB: 33 / 42 / 55 (median 42, RSS 66 MB). Bigger limits hurt on loopback, which is surprising. Runs are noisy (about 2×).

Surprise: the validation's "3–18 MB/s for a 4 MiB burst" did not reproduce. Those numbers came from an unlimited buffer with `OnBufferedAmountLow`, so the setups differ.

## 2. Native↔Chromium throughput

Native binds `0.0.0.0` (mDNS-only Chromium, no STUN), 1 channel, 256 MiB, limit 16 MiB, LAN path forced with `--bind 192.168.50.22:0`.

| direction | run 1 | run 2 | run 3 | median | native peak RSS |
|---|---|---|---|---|---|
| Chromium → native (native receives) | 112.5 | 98.2 | 116.5 | **112.5** | 11.2–11.4 MB |
| native → Chromium (native sends) | 58.3 | 81.1 | 59.9 | **59.9** | 57–62 MB |

Selected pair in every run is host↔host. Native-side view: local host on the LAN, remote = Chromium's `<uuid>.local` name. Chromium-side view (`getStats`): local host with the address hidden behind mDNS, remote = the native's address.

Earlier runs bound to all interfaces (no `--bind`) picked the tailscale address (100.96.16.76) and varied from 29 to 118 MB/s. Two of the earlier native→Chromium runs failed (see surprises).

The 50 Mbit/s bar is 6.25 MB/s. Every browser run here is at least 9× that.

## 3. Stalled reader (native↔native)

Two channels on one link. The sender writes 1 MiB-limited bulk to A and sends a 100-byte ping on B every 100 ms for 10 s. The receiver echoes B. In the stall run it never polls A, but keeps the handle alive.

| run | pings / echoes | RTT p50 / p95 / max | longest gap between echoes | bulk written to A |
|---|---|---|---|---|
| control, reader drains A (1 MiB) | 101 / 101 | 84.8 / 923 / 1125 ms | 1.22 s | 519 MB |
| control, drains A (1 MiB), repeat | 101 / 101 | 5.8 / 493 / 993 ms | 1.09 s | 1.38 GB |
| control, drains A (1 MiB), repeat | 101 / 101 | 5.9 / 443 / 944 ms | 1.04 s | 1.35 GB |
| control, drains A (256 KiB) | 101 / 101 | 2.4 / 835 / 948 ms | 1.05 s | 1.05 GB |
| **stall: A never polled** | **101 / 1** | 8.4 (one echo) | **B dead for the rest of the run** | 10.5 MB |

Stall result: B delivered one echo, at 9 ms, then nothing for 10 s. The stalled reader's queue fills and webrtc-rs stops reading the whole association. Mechanism, from the code: each channel's event queue holds 256 messages (`DRIVER_TO_DATA_CHANNEL_EVENT_CHANNEL_CAPACITY`). When a registered queue is full, `data_channel_delivery_blocked` makes `poll_reads` stop draining the core, so every channel on the connection stops.

Control (not stalled) surprise: even with no stall, B has about 1 s gaps. In the control run the kernel reported `RcvbufErrors` rising by 1,899 datagrams during the 10 s run (`/proc/net/snmp`). Those drops are the likely source of the gaps, since SCTP's minimum RTO is 1 s. This is an inference, not confirmed.

Not done: Chromium as the stalled receiver. A browser always dispatches `onmessage`, so there is no way to leave a channel unread.

## 4. mDNS (native↔Chromium, no STUN)

Yes. webrtc-rs in its default `QueryOnly` mode connected directly to Chromium's `.local` host candidates, with no relay and no srflx. Data flowed in both directions over the selected pair.

- Native offers, Chromium answers: selected pair = local `host` (native, tailscale 100.96.16.76 or LAN 192.168.50.22) ↔ remote `host <uuid>.local`. The `.local` name stays unresolved in the stats, but the pair was nominated and carried data.
- Chromium offers, native answers: selected pair = local `host` (Chromium, mDNS-hidden) ↔ remote `host` (native). The native-side stats report has no entry for the remote candidate, so it prints `remote=[?]`. The remote is probably a peer-reflexive candidate. I did not verify that.

## 5. iroh 1.3 baseline (loopback, no relay)

256 MiB, one bidirectional stream, two processes.

| run | client MB/s | server MB/s |
|---|---|---|
| 1 | 794.3 | 795.2 |
| 2 | 690.6 | 691.8 |
| 3 | 717.0 | 718.1 |
| **median** | **717.0** | **718.1** |

Server peak RSS about 17 MB, client about 16 MB.

## 6. str0m

Not run. Measurement 1 is 153 MB/s (median) against a 50 MB/s trigger. Its SCTP is also `sctp-proto`, which PLAN says may share a flaw with webrtc-rs's.

## Surprises

- The stalled reader stops every channel on the association. That is the shared-queue design in webrtc-rs's driver, not just one channel's problem.
- A bigger send limit on loopback made webrtc-rs slower (16 MiB: median 42 MB/s, against about 160 MB/s at 256 KiB–4 MiB). The limit matters, and a browser-like 16 MiB is a bad choice for native.
- Kernel UDP receive-buffer drops (`RcvbufErrors`) during bulk loopback transfers. This is the likely cause of the ~1 s gaps in control runs.
- Native→Chromium failures:
  - Run 3 of the first batch died with `page.evaluate: Target page, context or browser has been closed`. Chromium logged `Remapping ICE state failed to disconnected` about 8 s in. The native side never reached connected, and the harness crashed. I did not find the cause.
  - Native→Chromium 256 MiB over the tailscale path gave 48 MB/s in one run and 29 MB/s in another. Those runs are noisy, not failures.
- Harness bugs fixed during the run, both recorded in the code: the native processes did not exit (blocking stdin read at runtime shutdown, fixed with `process::exit`), and the stall sender blocked on `writer.await` (now counts bytes atomically).
- The Playwright bundle wanted Chromium 1247 and only 1243 was cached. Handled with `executablePath`.

## Verdict (PLAN "Decision" thresholds)

- Native↔native at least half of iroh: **fails.** webrtc-rs reaches 153–172 MB/s (median), about 21–24% of iroh's 717 MB/s. The best of the limit sweep is about 24%.
- Browser pairs at least 50 Mbit/s: **passes** on the LAN profile, 60–113 MB/s (480–900 Mbit/s).
- Stall isolation (PLAN's latency-under-load criterion is WAN-only, so this is a separate issue): **fails.** One stalled channel silenced a second channel for the whole 10 s. Even the unstalled control had p95 of 0.4–0.9 s on loopback.

**Is webrtc-rs fit for the trial?** No, not as configured. It fails the native throughput bar and the stall isolation. It passes the browser throughput bar. This matches PLAN's "Browser links only" outcome, unless the stall problem can be fixed in the driver.

**Should str0m replace it?** Undecided, and the data here doesn't decide it. str0m was not measured. The stall failure comes from webrtc-rs's shared per-connection drain gate, so str0m may or may not behave the same. Run measurement 3 on str0m before deciding. Do not switch on throughput alone, because str0m's SCTP is a sibling of the one in question.
