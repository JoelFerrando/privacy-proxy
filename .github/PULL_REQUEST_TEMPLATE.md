## Summary

- 

## Validation

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] `cargo test --workspace`
- [ ] `cargo bench --no-run -p privacy_proxy_core --bench redaction`

## Privacy checklist

- [ ] I used only synthetic test data.
- [ ] This PR does not add real logs, credentials, tokens, cookies, API keys or personal data.
- [ ] Errors, logs, metrics and reports do not print matched sensitive values.
- [ ] Detector changes include tests for true positives and likely false positives.

