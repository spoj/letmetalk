#!/bin/sh
# Runs the wasm tests in headless Chrome, against a forwarder and a native echo endpoint that this script starts.
set -eu
cd "$(dirname "$0")/.."
cargo build -q -p letmetalk-signal --example browser_helper
helper_out=$(mktemp)
"${CARGO_TARGET_DIR:-target}/debug/examples/browser_helper" > "$helper_out" &
helper=$!
trap 'kill "$helper"; rm -f "$helper_out"' EXIT
until [ -s "$helper_out" ] || ! kill -0 "$helper" 2>/dev/null; do sleep 0.1; done
read -r port key < "$helper_out"
export CHROMEDRIVER="$(command -v chromedriver)" WASM_BINDGEN_TEST_TIMEOUT=180
LETMETALK_TEST_SIGNAL="ws://127.0.0.1:$port/ws" LETMETALK_TEST_ECHO="$key" \
cargo test -p letmetalk --target wasm32-unknown-unknown --features ws --lib --test browser
