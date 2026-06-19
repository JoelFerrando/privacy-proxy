# Releasing

Planned release path:

1. Tag a version such as `v0.1.0`.
2. Build signed binaries for Linux, macOS, and Windows.
3. Publish the Docker image.
4. Publish `privacy-proxy` to crates.io so users can run:

```sh
cargo install privacy-proxy
```

Until the crate is published, install from source:

```sh
cargo install --path crates/privacy_proxy_cli
```

Recommended future automation:

- the included `.github/workflows/release.yml` for tag-based binaries
- `cargo-dist` later if installers and richer release notes are needed
- GitHub Releases with checksums
- container image build on tags
- crates.io publish from a protected release workflow
