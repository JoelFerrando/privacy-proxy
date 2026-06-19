# Contributing

Thanks for helping make log privacy easier to test and enforce.

## Development Loop

```sh
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo bench --no-run -p privacy_proxy_core --bench redaction
```

Before changing detectors, add or update tests with fake but realistic log shapes. Do not put real tokens, customer emails, production URLs, or copied incident logs in fixtures.

## Detector Changes

Detector changes should include:

- unit tests for true positives and false positives
- at least one JSON fixture when field names are involved
- a note in `README.md` if behavior changes
- benchmark awareness if the change adds another full string pass

## Privacy Rules

- Errors must not include input lines, matched values, request bodies, headers, or samples.
- `scan` and `assert` must only report aggregate counts.
- Test snapshots and fixtures must use synthetic values.
- Prefer simple regexes with validation logic over clever high-risk patterns.

## Fuzzing

Optional longer-running fuzzing uses `cargo-fuzz`:

```sh
cargo install cargo-fuzz
cargo fuzz run redact_str
cargo fuzz run redact_json
```

