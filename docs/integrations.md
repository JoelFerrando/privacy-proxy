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

Then configure the sender to use `http://127.0.0.1:8080`. The proxy redacts UTF-8 JSON, JSONL/NDJSON and text bodies, replaces sensitive headers before forwarding, enforces `max_body_bytes`, and exposes aggregate JSON metrics at `/metrics`.

Deep protocol-aware OTLP support is still future work. In particular, compressed protobuf OTLP payloads are not decoded by this MVP; route JSON/HTTP logs through the proxy first.

## HTTP Proxy Metrics

```sh
curl http://127.0.0.1:8080/metrics
```

Metrics include request counts, rejected payload counts, byte counts and redaction counts by detector type. They never include matched values, header values, request bodies or samples.
