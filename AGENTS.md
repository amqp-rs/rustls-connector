# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```sh
cargo check --all --bins --examples --tests --all-features   # check compilation
cargo test                                                    # run tests
cargo fmt --all                                               # format code
cargo fmt --all -- --check                                    # check formatting
cargo clippy --all-features -- -W clippy::all                 # lint
cargo semver-checks                                           # check semver compliance
cargo audit                                                   # security audit
```

Unit tests that build a connector need a crypto provider feature, and live in the `tests::with_provider` module; `tests/installed_provider.rs`, which installs a process-level crypto provider, is a test binary of its own and runs with or without one.

## Architecture

This is a single-file library (`src/lib.rs`) that wraps `rustls` with a connector API modeled after `openssl` and `native-tls`.

**Core types:**
- `RustlsConnectorConfig` — builder for certificate roots and verification strategy; converts to a `RustlsConnector` via `connector_with_no_client_auth()` or `connector_with_single_cert()`
- `RustlsConnector` — thin `Arc<ClientConfig>` newtype; exposes `connect()` (sync, accepting non-`Send` streams) and `connect_async()` (async, behind `futures` feature)
- `TlsStream<S>` / `AsyncTlsStream<S>` — type aliases for the underlying rustls stream types; `TlsStream` is rustls's `StreamOwned`, whose pitfalls with non-blocking and buffering transports are documented on the alias
- `HandshakeError<S>` — distinguishes `WouldBlock` (retryable) from `Failure` (fatal), mirroring the `native-tls` API

**Feature flags:**
- `platform-verifier` (default) — uses `rustls-platform-verifier` for OS-native certificate verification
- `native-certs` — loads system certificates via `rustls-native-certs`
- `webpki-root-certs` — bundles Mozilla root certificates via `webpki-root-certs`
- `futures` — enables async support via `futures-rustls` and `futures-io`
- `rustls--aws_lc_rs` (default) / `rustls--ring` — crypto backend selection, made by `crypto_provider()` and documented in the crate docs' feature flags section (`rustls--aws_lc_rs` also enables rustls's `prefer-post-quantum`, a rustls default that this crate otherwise loses by disabling rustls's default features)

`platform-verifier` and `webpki-root-certs`/`native-certs` can be combined: extra roots from the latter are passed to the platform verifier via `new_with_extra_roots`.

Each synchronous `handshake()` call flushes the underlying stream, makes at most one `complete_io()` attempt through `HandshakeIo` (which retries `Interrupted` writes and flushes in place, records blocked writes, and fails zero-length ones with `WriteZero`), and returns `WouldBlock` with `MidHandshakeTlsStream` while negotiation or writes remain pending, or when the stream reports `WouldBlock` or `NotConnected`. `MidHandshakeTlsStream::wants_write()`/`wants_read()` tell callers which readiness to wait for.

**MSRV:** 1.85.0

## CI

The workflows in `.github/workflows/` delegate to shared composite actions in [`amqp-rs/actions`](https://github.com/amqp-rs/actions). They reference those actions as `@main` on purpose: that repository is ours, and it keeps action bumps in sync across all amqp-rs repositories. Do not pin them to a SHA or tag. For the same reason, `.github/dependabot.yml` only tracks `cargo`, and `amqp-rs/actions` bumps the third-party actions itself.
