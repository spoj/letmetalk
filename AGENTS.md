# Agents working on letmetalk

PLAN.md is the contract for the trial: when a decision changes, change it there in the same commit as the code.
Commit subjects read `Area: what changed`.

## Checks

    cargo clippy --workspace --all-targets -- -D warnings
    cargo test --workspace
    cargo clippy -p letmetalk --target wasm32-unknown-unknown -- -D warnings
    cargo clippy -p letmetalk --features ws --target wasm32-unknown-unknown -- -D warnings
    LETMETALK_TEST_SIGNAL=ws://127.0.0.1:1/ws LETMETALK_TEST_ECHO=0000000000000000000000000000000000000000000000000000000000000000 \
    cargo clippy -p letmetalk --features ws --target wasm32-unknown-unknown --test browser -- -D warnings
    scripts/browser-tests.sh
