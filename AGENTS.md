# Agents working on letmetalk

PLAN.md is the contract for the trial: when a decision changes, change it there in the same commit as the code.
Commit subjects read `Area: what changed`.

## Checks

    cargo clippy --workspace --all-targets -- -D warnings
    cargo test --workspace
    cargo clippy -p letmetalk --target wasm32-unknown-unknown -- -D warnings
