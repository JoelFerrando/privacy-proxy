# Integrations

## CI Privacy Tests

Use `assert` to fail a workflow when generated logs contain supported sensitive values:

```yaml
jobs:
  privacy-logs:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: your-org/privacy-proxy@v0
        with:
          config: privacy-proxy.toml
          input: test-logs.jsonl
```

The action prints aggregate counts only. It does not print matched values.

## Synthetic Fixture Examples

The `examples/observability/` directory contains small before/after fixtures for
common observability shapes. All values are synthetic and safe for
documentation.

Run the Sentry-shaped example:

```sh
privacy-proxy --config examples/privacy-proxy.toml redact \
  --input examples/observability/sentry.input.jsonl \
  --output /tmp/sentry.masked.jsonl
diff -u examples/observability/sentry.masked.jsonl /tmp/sentry.masked.jsonl
```

Run the Loki-shaped example:

```sh
privacy-proxy --config examples/privacy-proxy.toml redact \
  --input examples/observability/loki.input.jsonl \
  --output /tmp/loki.masked.jsonl
diff -u examples/observability/loki.masked.jsonl /tmp/loki.masked.jsonl
```

Use `assert` to demonstrate the CI failure mode against the intentionally leaky
inputs:

```sh
privacy-proxy --config examples/privacy-proxy.toml assert \
  --input examples/observability/sentry.input.jsonl
privacy-proxy --config examples/privacy-proxy.toml assert \
  --input examples/observability/loki.input.jsonl
```

Those commands should exit non-zero and print aggregate counts only. They should
not print matched values.

## Sentry

```sh
privacy-proxy redact --input sentry-events.jsonl --output sentry-events.clean.jsonl
privacy-proxy assert --input sentry-events.clean.jsonl
```

Common sensitive locations:

- `request.headers.authorization`
- `request.headers.cookie`
- `request.url` query parameters
- `user.email`

## Loki

```sh
privacy-proxy redact --input loki-lines.jsonl --output loki-lines.clean.jsonl
```

Loki often carries sensitive data inside the `line` string. Keep string detectors enabled.

## Datadog

```sh
privacy-proxy redact --input datadog-logs.jsonl --output datadog-logs.clean.jsonl
```

Keep `trace_id`, `span_id`, and request identifiers in `fields_allow` so correlation survives redaction.

## Elastic

```sh
privacy-proxy scan --input elastic-export.jsonl
privacy-proxy redact --input elastic-export.jsonl --output elastic-export.clean.jsonl
```

Field-name redaction is useful for `_source.apiKey`, `_source.password`, and similar application fields.

## OpenTelemetry OTLP/HTTP

For JSON or JSONL log export paths, run the HTTP proxy between the producer and collector/exporter:

```sh
privacy-proxy --config examples/privacy-proxy.toml serve \
  --target http://127.0.0.1:4318 \
  --listen 127.0.0.1:8080
```

Then configure the sender to use `http://127.0.0.1:8080`. The proxy redacts UTF-8 JSON, JSONL/NDJSON and text bodies, decodes gzip request bodies before redaction, replaces sensitive headers before forwarding, enforces `max_body_bytes`, and exposes aggregate JSON metrics at `/metrics` plus Prometheus metrics at `/metrics/prometheus`.

Gzip support is intended for UTF-8 JSON, JSONL/NDJSON and text request bodies. The proxy forwards the redacted body uncompressed and strips `Content-Encoding`/`Content-Length` before forwarding. Unsupported content encodings are rejected with `415`, and oversized decompressed bodies are rejected with `413`.

Deep protocol-aware OTLP protobuf support is still future work. Route JSON/HTTP logs through the proxy first.

## HTTP Proxy Metrics

```sh
curl http://127.0.0.1:8080/metrics
curl http://127.0.0.1:8080/metrics/prometheus
```

Metrics include request counts, rejected payload counts, byte counts and redaction counts by detector type. They never include matched values, header values, request bodies or samples.

Minimal local Prometheus scrape config:

```yaml
scrape_configs:
  - job_name: privacy-proxy
    metrics_path: /metrics/prometheus
    static_configs:
      - targets:
          - 127.0.0.1:8080
```

With the proxy listening on `127.0.0.1:8080`, Prometheus scrapes:

```text
http://127.0.0.1:8080/metrics/prometheus
```

Keep the target local unless the proxy metrics endpoint is intentionally exposed through your monitoring network.
