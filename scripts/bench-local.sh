#!/bin/bash
# Runs the bench on this machine, three times each: letmetalk native and in Chromium, and iroh 1.3 direct and through
# a relay only. Raw JSON lines go to trial/bench-local/, and the report to trial/1-bench-local.md.
# Needs Chromium at $CHROME (default: /opt/google/chrome/chrome) and Playwright at $PLAYWRIGHT.
set -eu
cd "$(dirname "$0")/.."
RUNS=3
OUT=trial/bench-local
WEB=target/bench-web
BIN=target/release/bench
WS=ws://127.0.0.1:18790/ws
WS_URL=http://127.0.0.1:18790/
PAGE=http://127.0.0.1:18791/index.html
RELAY=http://127.0.0.1:18792
keys=$(mktemp -d)
trap 'rm -rf "$keys"' EXIT

cargo build -q --release -p bench -p letmetalk-signal
cargo build -q --release -p bench --lib --target wasm32-unknown-unknown --no-default-features
rm -rf "$OUT" "$WEB"
mkdir -p "$OUT" "$WEB"
wasm-bindgen --target web --out-dir "$WEB/pkg" target/wasm32-unknown-unknown/release/letmetalk_bench.wasm
cp crates/bench/web/index.html "$WEB/"

for role in serve dial; do
  head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$keys/$role.key"
done
SERVE=$(cat "$keys/serve.key")
DIAL=$(cat "$keys/dial.key")
SERVE_PUB=$($BIN pubkey --key "$keys/serve.key")

wait_for() {
  for _ in $(seq 300); do
    grep -q "$1" "$2" 2>/dev/null && return 0
    sleep 0.2
  done
  echo "timed out waiting for $1 in $2" >&2
  exit 1
}

target/release/letmetalk-signal --listen 127.0.0.1:18790 --host 127.0.0.1 \
  --member-turn 'turn:127.0.0.1:3478?transport=udp' --member-secret unused \
  --stranger-turn 'turn:127.0.0.1:3479?transport=udp' --stranger-secret unused > "$OUT/forwarder.log" 2>&1 &
forwarder=$!
(cd "$WEB" && exec python3 -m http.server 18791 --bind 127.0.0.1) > "$OUT/http.log" 2>&1 &
http=$!
$BIN iroh-relay --listen 127.0.0.1:18792 > "$OUT/relay.log" 2>&1 &
relay=$!
trap 'kill "$forwarder" "$http" "$relay" 2>/dev/null || true; rm -rf "$keys"' EXIT
for _ in $(seq 100); do
  curl -s -o /dev/null "$PAGE" && curl -s -o /dev/null "$WS_URL" && curl -s -o /dev/null "$RELAY/" && break
  sleep 0.2
done

# Each file starts with the load before its run, and ends with the load after it and, for a native server, the
# server's peak RSS, read before the server is stopped.
env_line() {
  printf '{"pair":"%s","scenario":"env","run":%s,"loadavg_start":"%s","rmem_max":%s}\n' \
    "$1" "$2" "$(cut -d' ' -f1-3 /proc/loadavg)" "$(sysctl -n net.core.rmem_max)"
}
end_line() {
  printf '{"pair":"%s","scenario":"env","run":%s,"loadavg_end":"%s"}\n' "$1" "$2" "$(cut -d' ' -f1-3 /proc/loadavg)"
}
server_rss() {
  printf '{"pair":"%s","scenario":"serve_rss","peak_rss_kib":%s}\n' "$1" "$(awk '/VmHWM/ {print $2}' "/proc/$2/status")"
}
start_browser_server() {
  node scripts/bench-browser.mjs serve "$PAGE#role=serve&url=$WS&key=$SERVE&pair=chromium" > "$keys/server.out" 2>&1 &
  browser_server=$!
  wait_for ready "$keys/server.out"
}
stop() {
  kill "$1"
  wait "$1" 2>/dev/null || true
}

for run in $(seq "$RUNS"); do
  f="$OUT/native-native-$run.jsonl"
  env_line native-native "$run" > "$f"
  $BIN serve --url "$WS" --key "$keys/serve.key" > "$keys/serve.out" 2> "$OUT/serve-native.err" &
  server=$!
  wait_for '"role":"serve"' "$keys/serve.out"
  $BIN dial --url "$WS" --key "$keys/dial.key" --peer "$SERVE_PUB" --pair native-native >> "$f" 2> "$OUT/dial-native.err"
  server_rss native-native "$server" >> "$f"
  end_line native-native "$run" >> "$f"
  stop "$server"

  f="$OUT/native-chromium-$run.jsonl"
  env_line native-chromium "$run" > "$f"
  start_browser_server
  $BIN dial --url "$WS" --key "$keys/dial.key" --peer "$SERVE_PUB" --pair native-chromium >> "$f" 2> "$OUT/dial-native.err"
  end_line native-chromium "$run" >> "$f"
  stop "$browser_server"

  f="$OUT/chromium-chromium-$run.jsonl"
  env_line chromium-chromium "$run" > "$f"
  start_browser_server
  node scripts/bench-browser.mjs dial "$PAGE#role=dial&url=$WS&key=$DIAL&peer=$SERVE_PUB&pair=chromium-chromium" "$keys/dial.out"
  cat "$keys/dial.out" >> "$f"
  end_line chromium-chromium "$run" >> "$f"
  stop "$browser_server"

  f="$OUT/iroh-direct-$run.jsonl"
  env_line iroh-direct "$run" > "$f"
  $BIN iroh-serve --key "$keys/serve.key" > "$keys/addr.json" 2> "$OUT/iroh-serve.err" &
  server=$!
  wait_for '"id"' "$keys/addr.json"
  $BIN iroh-dial --key "$keys/dial.key" --addr "$keys/addr.json" --pair iroh-direct >> "$f" 2> "$OUT/iroh-dial.err"
  server_rss iroh-direct "$server" >> "$f"
  end_line iroh-direct "$run" >> "$f"
  stop "$server"

  f="$OUT/iroh-relay-$run.jsonl"
  env_line iroh-relay "$run" > "$f"
  $BIN iroh-serve --key "$keys/serve.key" --relay "$RELAY" > "$keys/addr.json" 2> "$OUT/iroh-serve.err" &
  server=$!
  wait_for '"id"' "$keys/addr.json"
  $BIN iroh-dial --key "$keys/dial.key" --addr "$keys/addr.json" --relay "$RELAY" --pair iroh-relay >> "$f" 2> "$OUT/iroh-dial.err"
  server_rss iroh-relay "$server" >> "$f"
  end_line iroh-relay "$run" >> "$f"
  stop "$server"
done

scripts/bench-report.sh
