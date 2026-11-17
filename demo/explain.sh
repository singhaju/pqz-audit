#!/bin/bash
# Step-by-step terminal demo with a real tiny example (16 records, then N = 2000). Pauses at "press Enter".
# Usage: bash demo/explain.sh           (pauses)      bash demo/explain.sh --no-pause   (prints everything at once)
# Uses only the existing library functions through the new binary demo_explain; no network needed after `cargo fetch`.
set -e
cd "$(dirname "$0")/../pqz-integrated-w46"
cargo build --release --locked --bin demo_explain 2>&1 | tail -1
./target/release/demo_explain "$@"
