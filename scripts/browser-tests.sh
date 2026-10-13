#!/bin/sh
# Runs the wasm tests in headless Chrome, against a forwarder and a native echo endpoint that this script starts.
set -eu
cd "$(dirname "$0")/.."
cargo build -q -p letmetalk-signal --example browser_helper
target/debug/examples/browser_helper 8787 >/dev/null &
helper=$!
trap 'kill "$helper"' EXIT
LETMETALK_TEST_SIGNAL=ws://127.0.0.1:8787/ws \
LETMETALK_TEST_ECHO=2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12 \
cargo test -p letmetalk --target wasm32-unknown-unknown --features ws --test browser
