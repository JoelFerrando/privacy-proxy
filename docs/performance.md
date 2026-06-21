# Performance

The MVP is designed for streaming JSONL: the CLI reads one line, redacts or scans it, writes the result, then moves on. Memory use is therefore dominated by the largest single line plus temporary JSON/string allocations, not by the full input file.

## Benchmarking

Run the core benchmark suite with:

```sh
cargo bench -p privacy_proxy_core --bench redaction
```

For a faster local smoke test:

```sh
cargo bench -p privacy_proxy_core --bench redaction -- --warm-up-time 1 --measurement-time 3
```

The benchmarks cover:

- `text/redact_mixed_text`: plain text with email, IP, bearer token, URL token, card and IBAN.
- `text/scan_mixed_text`: same input, counts only.
- `json/redact_nested_json`: recursive `serde_json::Value` redaction.
- `json/scan_nested_json`: recursive scan without output value construction.
- `jsonl/*_100_lines`: small JSONL parse, redact and serialize.
- `jsonl/*_1000_lines`: medium JSONL parse, redact and serialize.
- `jsonl/*_10000_lines`: larger JSONL parse, redact and serialize.
- `jsonl/Mask_*`, `jsonl/Hash_*`, and `jsonl/Drop_*`: mode comparison with the same input corpus.

Criterion reports throughput and timing on the current machine. Treat the numbers as comparative, not absolute: CPU, allocator, regex cache warmth, detector config and log shape all matter.

## Local Baseline

Smoke benchmark run on 2026-06-19 with Rust 1.92.0 on an AMD Ryzen 7 7800X3D, using:

```sh
cargo bench -p privacy_proxy_core --bench redaction -- --warm-up-time 1 --measurement-time 3
```

| Benchmark | Median-ish Time | Throughput |
| --- | ---: | ---: |
| `text/redact_mixed_text` | 13.91 us | 15.64 MiB/s |
| `text/scan_mixed_text` | 13.79 us | 15.77 MiB/s |
| `json/redact_nested_json` | 44.26 us | 11.20 MiB/s |
| `json/scan_nested_json` | 37.91 us | 13.08 MiB/s |

JSONL mode and size comparison from the same smoke run:

| Benchmark | Median-ish Time | Throughput | Approx Lines/s |
| --- | ---: | ---: | ---: |
| `jsonl/Mask_100_lines` | 2.62 ms | 11.54 MiB/s | 38,213 |
| `jsonl/Hash_100_lines` | 4.61 ms | 6.55 MiB/s | 21,698 |
| `jsonl/Drop_100_lines` | 2.18 ms | 13.88 MiB/s | 45,947 |
| `jsonl/Mask_1000_lines` | 21.44 ms | 14.20 MiB/s | 46,640 |
| `jsonl/Hash_1000_lines` | 27.00 ms | 11.28 MiB/s | 37,040 |
| `jsonl/Drop_1000_lines` | 21.64 ms | 14.07 MiB/s | 46,204 |
| `jsonl/Mask_10000_lines` | 213.57 ms | 14.35 MiB/s | 46,823 |
| `jsonl/Hash_10000_lines` | 271.52 ms | 11.29 MiB/s | 36,829 |
| `jsonl/Drop_10000_lines` | 198.04 ms | 15.47 MiB/s | 50,495 |

This is a synthetic benchmark corpus, not a production claim. The main value is regression tracking as detectors and config grow. Re-run the command above after detector changes.

## Current Expectations

The current implementation is optimized for correctness and maintainability before raw throughput. It should be fast enough for local preprocessing, CI checks and moderate log pipelines, but production collector throughput should be measured with representative logs before relying on it inline.

Performance characteristics:

- Engine reuse matters. Build `Engine` once and reuse it across lines.
- `scan` is generally cheaper than `redact` because it avoids producing a redacted JSON value.
- JSON redaction costs include parse/serialize if used through the CLI.
- `hash` mode is more expensive than `mask` because every detection computes HMAC-SHA256.
- `drop` can be cheaper for sensitive JSON fields, but strings still need replacement placeholders.
- Large free-form text fields cost more than structured fields because multiple detectors scan the same string.
- HTTP proxy mode buffers each request body up to `max_body_bytes` before redaction. This keeps the MVP simple and bounded, but high-volume collectors should measure latency, payload sizes and peak memory with their real traffic shape.

## End-to-End CLI Check

Generate a synthetic JSONL corpus with fake emails, bearer tokens, cookies,
cards, IPs and safe trace/request IDs:

```sh
cargo run -p privacy-proxy -- generate-corpus --lines 100000 --output synthetic.jsonl
```

All generated values are fake and deterministic, using reserved `.test` domains
and documentation IP ranges. Increase or decrease `--lines` to change the file
size.

To measure the generated file:

```sh
cargo build --release -p privacy-proxy
Measure-Command {
  target/release/privacy-proxy redact --config examples/privacy-proxy.toml --input synthetic.jsonl --output clean.jsonl
}
```

On Unix shells:

```sh
cargo build --release -p privacy-proxy
time target/release/privacy-proxy redact --config examples/privacy-proxy.toml --input synthetic.jsonl --output clean.jsonl
```

Use a synthetic file large enough to drown out startup time when comparing versions.

## HTTP Proxy Check

Start a local upstream and proxy, then send representative JSON or JSONL payloads through the proxy:

```sh
cargo build --release -p privacy-proxy
target/release/privacy-proxy --config examples/privacy-proxy.toml serve \
  --target http://127.0.0.1:9000 \
  --listen 127.0.0.1:8080
```

Watch aggregate counts without exposing sensitive values:

```sh
curl http://127.0.0.1:8080/metrics
curl http://127.0.0.1:8080/metrics/prometheus
```

For proxy benchmarks, track:

- request latency at p50/p95/p99
- payload size distribution
- rejected payloads from `max_body_bytes`
- redactions per detector type
- process peak RSS under concurrent sends
- upstream error count

To estimate lines/sec manually:

```text
lines_per_second = input_lines / elapsed_seconds
```

To estimate MiB/sec manually:

```text
mib_per_second = input_bytes / 1048576 / elapsed_seconds
```

## Memory Checks

The CLI is line-oriented, so peak memory should scale with the largest line and JSON temporary allocations, not total file size. Measure this with a representative file.

Windows PowerShell:

```powershell
scripts/measure-memory.ps1 -Config examples/privacy-proxy.toml -Input examples/logs.jsonl -Output clean.jsonl
```

Linux:

```sh
scripts/measure-memory.sh examples/privacy-proxy.toml examples/logs.jsonl clean.jsonl
```

macOS:

```sh
cargo build --release -p privacy-proxy
/usr/bin/time -l target/release/privacy-proxy --config examples/privacy-proxy.toml redact --input examples/logs.jsonl --output clean.jsonl
```

## Obvious Optimization Paths

- Compile detector sets from config so disabled detectors skip both setup and execution.
- Collapse compatible string detectors into fewer passes, especially email/IP/JWT/token scans.
- Add `aho-corasick` for field-name and URL parameter keyword matching.
- Avoid JSON reserialization churn where a caller can accept `serde_json::Value` directly.
- Add optional metrics around lines/sec, bytes/sec and detections/sec without exposing values.
- Add proxy-level streaming for large HTTP bodies.
