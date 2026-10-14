"""Medians of bench-local's JSON lines, one table with a column per pair. Usage: bench-summary.py <dir>"""

import glob
import json
import os
import statistics
import sys
from collections import defaultdict

PAIRS = ["native-native", "native-chromium", "chromium-chromium", "iroh-direct", "iroh-relay"]
HEADS = {
    "native-native": "letmetalk native↔native",
    "native-chromium": "letmetalk native↔Chromium",
    "chromium-chromium": "letmetalk Chromium↔Chromium",
    "iroh-direct": "iroh direct",
    "iroh-relay": "iroh relay-only",
}

# runs[pair][run] -> {(scenario, field): value}
runs = defaultdict(lambda: defaultdict(dict))
routes = defaultdict(dict)
for path in sorted(glob.glob(os.path.join(sys.argv[1], "*.jsonl"))):
    run = int(os.path.basename(path).rsplit("-", 1)[1].split(".")[0])
    for line in open(path):
        record = json.loads(line)
        pair, scenario = record["pair"], record["scenario"]
        values = runs[pair][run]
        if scenario == "path":
            routes[pair][run] = record["route"]
        elif scenario == "crypto":
            values[("crypto", "seal")] = record["seal_mb_s"]
            values[("crypto", "open")] = record["open_mb_s"]
        elif scenario in ("cold", "warm"):
            values[(scenario, "ms")] = record["median_ms"]
        elif scenario in ("bulk_up", "bulk_down", "bulk_4x64"):
            values[(scenario, "mb_s")] = record["mb_s"]
        elif scenario == "latency_idle":
            for p in ("p50", "p95", "p99"):
                values[("idle", p)] = record[f"{p}_ms"]
        elif scenario == "latency_load":
            values[("bulk_under_echo", "mb_s")] = record["bulk_mb_s"]
            for p in ("p50", "p95", "p99"):
                values[("loaded", p)] = record["echo"][f"{p}_ms"]
        elif scenario == "rss":
            values[("rss", "dial")] = record["peak_rss_kib"] / 1024
        elif scenario == "serve_rss":
            values[("rss", "serve")] = record["peak_rss_kib"] / 1024


def median_of(pair, key):
    values = [run[key] for run in runs[pair].values() if key in run]
    return statistics.median(values) if values else None


def cell(pair, key, fmt="{:.1f}"):
    value = median_of(pair, key)
    return "–" if value is None else fmt.format(value)


def route(pair):
    first = routes[pair].get(min(routes[pair])) if routes[pair] else None
    if first is None:
        return "none"
    if first["relayed"]:
        return "relayed"
    return f"direct {first['local']} → {first['remote']}"


rows = [
    ("Cold setup, median ms", lambda p: cell(p, ("cold", "ms"))),
    ("Warm stream, median ms", lambda p: cell(p, ("warm", "ms"), "{:.2f}")),
    ("Route, first run", route),
    ("Route RTT, median ms", lambda p: "–" if not routes[p] else "{:.2f}".format(statistics.median(r["rtt_ms"] for r in routes[p].values()))),
    ("256 MiB up, one stream, MB/s", lambda p: cell(p, ("bulk_up", "mb_s"))),
    ("256 MiB down, one stream, MB/s", lambda p: cell(p, ("bulk_down", "mb_s"))),
    ("4 × 64 MiB up, MB/s", lambda p: cell(p, ("bulk_4x64", "mb_s"))),
    ("Echo p50 / p95 / p99 idle, ms", lambda p: " / ".join(cell(p, ("idle", k), "{:.2f}") for k in ("p50", "p95", "p99"))),
    ("Echo p50 / p95 / p99 under bulk, ms", lambda p: " / ".join(cell(p, ("loaded", k), "{:.2f}") for k in ("p50", "p95", "p99"))),
    ("Bulk MB/s while echoing", lambda p: cell(p, ("bulk_under_echo", "mb_s"))),
    ("Seal 16 KiB, MB/s", lambda p: cell(p, ("crypto", "seal"), "{:.0f}")),
    ("Open 16 KiB, MB/s", lambda p: cell(p, ("crypto", "open"), "{:.0f}")),
    ("Peak RSS dialer, MiB", lambda p: cell(p, ("rss", "dial"), "{:.1f}")),
    ("Peak RSS server, MiB", lambda p: cell(p, ("rss", "serve"), "{:.1f}")),
]
print("| | " + " | ".join(HEADS[p] for p in PAIRS) + " |")
print("|---|" + "---|" * len(PAIRS))
for name, fn in rows:
    print(f"| {name} | " + " | ".join(fn(p) for p in PAIRS) + " |")
