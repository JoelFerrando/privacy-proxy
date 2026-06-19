#!/usr/bin/env bash
set -euo pipefail

CONFIG="${1:-examples/privacy-proxy.toml}"
INPUT="${2:-examples/logs.jsonl}"
OUTPUT="${3:-clean.jsonl}"

cargo build --release -p privacy-proxy
/usr/bin/time -v target/release/privacy-proxy \
  --config "$CONFIG" \
  redact \
  --input "$INPUT" \
  --output "$OUTPUT"
