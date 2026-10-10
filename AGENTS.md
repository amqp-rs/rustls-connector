# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```sh
RUSTFLAGS="-D warnings" cargo hack check --each-feature --all-targets --locked  # check every feature, as CI does
cargo test                                                                      # run tests (default features)
cargo hack test --each-feature --all-targets                                    # run tests for every feature
cargo fmt --all                                                                 # format code
cargo fmt --all -- --check                                                      # check formatting
cargo hack clippy --each-feature --all-targets --locked -- -D warnings          # lint, as CI does
RUSTDOCFLAGS="-D warnings" cargo hack doc --each-feature --no-deps \
    --document-private-items --locked                                           # check docs, as CI does
cargo semver-checks                                                             # check semver compliance
cargo audit                                                                     # security audit
```

Unit tests that build a connector need a crypto provider feature, and live in the `tests::with_provider` module; `tests/installed_provider.rs`, which installs a process-level crypto provider, is a test binary of its own and runs with or without one.

## Architecture

This is a single-file library (`src/lib.rs`) that wraps `rustls` with a connector API modeled after `openssl` and `native-tls`.

**Core types:**
- `RustlsConnectorConfig` — builder for certificate roots and verification strategy; converts to a `RustlsConnector` via `connector_with_no_client_auth()` or `connector_with_single_cert()`
- `RustlsConnector` — thin `Arc<ClientConfig>` newtype; exposes `connect()` (sync, accepting non-`Send` streams) and `connect_async()` (async, behind `futures` feature, accepting borrowed and non-`Send` streams)
- `TlsStream<S>` / `AsyncTlsStream<S>` — type aliases for the underlying rustls stream types; `TlsStream` is rustls's `StreamOwned`, whose pitfalls with non-blocking and buffering transports are documented on the alias
- `HandshakeError<S>` — distinguishes `WouldBlock` (retryable) from `Failure` (fatal), mirroring the `native-tls` API

**Feature flags:**
- `platform-verifier` (default) — uses `rustls-platform-verifier` for OS-native certificate verification
- `native-certs` — loads system certificates via `rustls-native-certs`
- `webpki-root-certs` — bundles Mozilla root certificates via `webpki-root-certs`
- `futures` — enables async support via `futures-rustls` and `futures-io`
- `logging` — forwards to `rustls/logging` and `futures-rustls?/logging` (rustls log output through the `log` crate)
- `rustls--aws_lc_rs` (default) / `rustls--ring` — crypto backend selection, made by `crypto_provider()` and documented in the crate docs' feature flags section (`rustls--aws_lc_rs` also enables rustls's `prefer-post-quantum`, a rustls default that this crate otherwise loses by disabling rustls's default features)

`platform-verifier` can be combined with `webpki-root-certs` and explicitly added roots, which are passed to the platform verifier via `new_with_extra_roots` (plain `Verifier::new` when there are none). Native certs are kept in a separate field and only passed to it in some cases: `with_native_certs()` records that decision in `native_certs_needed` (`platform_verifier_needs_native_certs()` around the pure `needs_native_certs()`), and `with_platform_verifier` documents the rules, the Android refusal of extra roots and the JNI initialization Android needs.

Each synchronous `handshake()` call flushes the underlying stream, makes at most one `complete_io()` attempt through `HandshakeIo` (which retries `Interrupted` writes and flushes in place, records blocked writes, and fails zero-length ones with `WriteZero`), and returns `WouldBlock` with `MidHandshakeTlsStream` while negotiation or writes remain pending, or when the stream reports `WouldBlock` or `NotConnected`. `MidHandshakeTlsStream::wants_write()`/`wants_read()` tell callers which readiness to wait for.

**MSRV:** 1.85.0

## CI

The workflows in `.github/workflows/` delegate to shared composite actions in [`amqp-rs/actions`](https://github.com/amqp-rs/actions). They reference those actions as `@main` on purpose: that repository is ours, and it keeps action bumps in sync across all amqp-rs repositories. Do not pin them to a SHA or tag. For the same reason, `.github/dependabot.yml` only tracks `cargo`, and `amqp-rs/actions` bumps the third-party actions itself.

`build-and-test.yaml` passes extra feature sets to the shared build action (`test-features`) so the tests gated on non-default features run, including without a crypto provider feature (that set and the ring one only on Linux stable, as they test nothing OS- or toolchain-specific), and has an `android` job that checks the Android-only code paths for `aarch64-linux-android`, test targets included, as they hold compile-time pins of the platform-verifier constants. The shared build action cannot check another target, so that job only uses it to set up the toolchain, cache and `RUSTFLAGS`, and runs `cargo check` itself.
