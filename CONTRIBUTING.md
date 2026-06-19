# Contributing

Thanks for helping make log privacy easier to test and enforce.

## Before Opening an Issue or PR

Use synthetic data only. Do not paste real logs, production URLs, customer emails, tokens, cookies, API keys, credentials, session identifiers or incident data into issues, pull requests, fixtures or screenshots.

If you found a leak, bypass, denial-of-service risk or other security-sensitive issue, follow [SECURITY.md](SECURITY.md) instead of opening a public issue.

## Development Loop

```sh
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo bench --no-run -p privacy_proxy_core --bench redaction
cargo audit --deny warnings
```

## Pull Requests

Keep PRs focused and easy to review. A good PR usually includes:

- a short explanation of the user-facing behavior
- tests or fixtures using fake data
- documentation updates when behavior changes
- benchmark awareness for detector or hot-path changes

Prefer small contributions over broad refactors. If you want to make a larger design change, open an issue first with the proposed direction.

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
