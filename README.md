# privacy-proxy

[![CI](https://github.com/JoelFerrando/privacy-proxy/actions/workflows/ci.yml/badge.svg)](https://github.com/JoelFerrando/privacy-proxy/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![Rust](https://img.shields.io/badge/rust-stable-orange.svg)](https://www.rust-lang.org/)

`privacy-proxy` is **privacy tests for logs**: a Rust CLI, HTTP proxy and redaction engine that finds emails, tokens, secrets, cookies, cards, IBANs, IPs and sensitive URL parameters before logs reach Sentry, Datadog, Loki, Elastic, Honeycomb, or OpenTelemetry pipelines.

Use it in CI to fail fast when test logs leak secrets, or inline to redact JSONL streams before shipping them to your observability stack.

```sh
privacy-proxy assert --input test-logs.jsonl
privacy-proxy redact --input logs.jsonl --output clean.jsonl
privacy-proxy serve --target http://127.0.0.1:9000
```

This MVP reduces the chance of sensitive data leaving your process, but it does not guarantee legal compliance or complete removal of all personal data.

## Why

Most teams test code, API contracts and security headers. Very few test whether their logs accidentally contain user emails, bearer tokens, cookies, API keys, reset links, payment cards, or bank identifiers.

`privacy-proxy` makes that check boring and automatable:

- `assert` fails CI when supported sensitive data is detected.
- `scan` reports aggregate counts only, never samples or values.
- `redact` streams JSONL line by line without loading the full file.
- `serve` proxies UTF-8 JSON, JSONL and text bodies with payload limits and safe metrics.
- The core crate is pure Rust and reusable in other tooling.

## Install

```sh
cargo install --path crates/privacy_proxy_cli
```

Or run from the workspace:

```sh
cargo run -p privacy-proxy -- init
cargo run -p privacy-proxy -- redact --input examples/logs.jsonl --output clean.jsonl
```

After crates.io publication, the intended install command is:

```sh
cargo install privacy-proxy
```

## Usage

Try the built-in demo first:

```sh
privacy-proxy demo
```

It prints synthetic log lines, their redacted form, and aggregate scan statistics. No config file is needed.

Create a starter config:

```sh
privacy-proxy init
```

Redact a JSONL file:

```sh
privacy-proxy redact --input logs.jsonl --output clean.jsonl
```

Redact from stdin to stdout:

```sh
privacy-proxy redact < logs.jsonl > clean.jsonl
```

Scan for aggregate counts only:

```sh
privacy-proxy scan --input logs.jsonl
```

`scan` prints statistics like detector counts and line counts. It never prints matching values or samples.

Fail CI if logs contain sensitive values:

```sh
privacy-proxy assert --input test-logs.jsonl
```

`assert` is the "privacy tests for logs" mode: it exits successfully when no supported sensitive values are found and fails when detections are present. Output is still aggregate-only.

Run the HTTP proxy:

```sh
privacy-proxy --config examples/privacy-proxy.toml serve \
  --target http://127.0.0.1:9000 \
  --listen 127.0.0.1:8080
```

Then point a log sender at `http://127.0.0.1:8080`. Requests are forwarded to the target with:

- UTF-8 JSON objects redacted recursively
- JSONL/NDJSON bodies redacted line by line
- text bodies redacted as strings
- sensitive headers such as `authorization`, `cookie`, `set-cookie`, API key/token/secret/password/session headers replaced before forwarding
- request bodies capped by `max_body_bytes`
- aggregate JSON metrics at `GET /metrics`
- Prometheus metrics at `GET /metrics/prometheus`
- liveness at `GET /healthz`

The proxy intentionally does not print request bodies, headers, matched values or URL query strings in logs.

Example before:

```json
{"level":"error","email":"alice@example.test","authorization":"Bearer example-token-value-123456","url":"https://app.example.test/reset?token=reset-token","message":"card 4111 1111 1111 1111 from 203.0.113.10"}
```

Example after `mask`:

```json
{"authorization":"[REDACTED:bearer_token]","email":"[REDACTED:email]","level":"error","message":"card [REDACTED:credit_card] from [REDACTED:ip]","url":"https://app.example.test/reset?token=[REDACTED:url_sensitive_params]"}
```

## Configuration

The CLI reads `privacy-proxy.toml` by default. Use `--config FILE` to choose another path.

```toml
mode = "mask"

redact = [
  "email",
  "ip",
  "jwt",
  "bearer_token",
  "api_key",
  "cookie",
  "credit_card",
  "iban",
  "url_sensitive_params"
]

fields_deny = [
  "password",
  "token",
  "secret",
  "apiKey",
  "authorization",
  "cookie",
  "set-cookie"
]

fields_allow = [
  "trace_id",
  "span_id",
  "request_id"
]

hash_env = "PRIVACY_PROXY_HASH_KEY"
sample_limit = 10000
max_line_bytes = 1048576
max_body_bytes = 10485760
```

Modes:

- `mask`: replaces values with `[REDACTED:type]`.
- `hash`: replaces values with `[HASHED:type:hmac_sha256]`; set the environment variable named by `hash_env`.
- `drop`: removes sensitive JSON fields. Inline string matches become `[DROPPED:type]` because arbitrary text has no field boundary to remove safely.

## Detectors

The MVP supports:

- email addresses
- IPv4 and IPv6 addresses, validated with Rust's standard IP parsers
- JWT-like tokens
- Bearer tokens
- cookie header values and cookie fields
- API keys and secrets by JSON field name
- credit card candidates validated with Luhn
- IBAN candidates validated with mod-97
- sensitive URL query parameters: `token`, `key`, `secret`, `password`, `code`, and `session`

JSON objects and arrays are walked recursively. Non-JSON lines are treated as plain text. Processing is streaming and line-oriented, so the CLI does not load the whole log file into memory.

`max_line_bytes` limits each input line before redaction/scan work continues. `max_body_bytes` limits each HTTP proxy request body before redaction work starts.

## Rust API

```rust
use privacy_proxy_core::{redact_value, scan_value, Config};
use serde_json::json;

let config = Config::default();
let input = json!({"email": "alice@example.com"});

let result = redact_value(input, &config)?;
println!("{}", result.value);

let report = scan_value(&result.value, &config)?;
println!("{}", report.total);
# Ok::<(), privacy_proxy_core::Error>(())
```

For high-throughput paths, construct `privacy_proxy_core::Engine` once and reuse it across lines.

## Performance

The CLI processes input line by line and does not load the full file into memory. For real pipelines, benchmark with representative logs because detector mix and log shape matter a lot.

Core benchmarks are included:

```sh
cargo bench -p privacy_proxy_core --bench redaction
```

See [docs/performance.md](docs/performance.md) for what is measured, JSONL small/medium/large benchmark cases, `mask` vs `hash` vs `drop`, memory measurement, end-to-end CLI timing, and optimization notes.

## Limits

Redaction is best-effort. False positives and false negatives are possible, especially in unstructured text, custom token formats, nested encodings, compressed payloads, encrypted blobs, and application-specific identifiers.

Run `scan` in CI or staging to understand what the configured detectors see before enabling redaction in production pipelines. Keep configs reviewed like security-sensitive code.

## Integrations

- Dockerfile included for container builds.
- GitHub Action metadata included for `privacy-proxy assert` in CI.
- HTTP proxy mode included for JSON, JSONL/NDJSON and text log ingestion paths.
- See [docs/integrations.md](docs/integrations.md) for Sentry, Loki, Datadog, Elastic and OpenTelemetry-oriented examples.
- See [docs/releasing.md](docs/releasing.md) for the planned binary/crates.io release path.

## Roadmap

Near-term improvements:

- Add corpus-based benchmarks with realistic Sentry, Datadog, Loki and OpenTelemetry JSON shapes.
- Add proxy streaming for very large bodies instead of buffering up to `max_body_bytes`.
- Add gzip/zstd request body support with decompression limits.
- Add middleware helpers for common web frameworks.
- Add deeper OTLP/HTTP support for OpenTelemetry collector topologies.
- Add packaged releases and shell completions.

## Development

```sh
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo bench -p privacy_proxy_core --bench redaction
```

Optional fuzzing:

```sh
cargo install cargo-fuzz
cargo fuzz run redact_str
cargo fuzz run redact_json
```

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
