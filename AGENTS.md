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

## Architecture

This is a single-file library (`src/lib.rs`) that wraps `rustls` with a connector API modeled after `openssl` and `native-tls`.

**Core types:**
- `RustlsConnectorConfig` — builder for certificate roots and verification strategy; converts to a `RustlsConnector` via `connector_with_no_client_auth()` or `connector_with_single_cert()`
- `RustlsConnector` — thin `Arc<ClientConfig>` newtype; exposes `connect()` (sync) and `connect_async()` (async, behind `futures` feature)
- `TlsStream<S>` / `AsyncTlsStream<S>` — type aliases for the underlying rustls stream types
- `HandshakeError<S>` — distinguishes `WouldBlock` (retryable) from `Failure` (fatal), mirroring the `native-tls` API

**Feature flags:**
- `platform-verifier` (default) — uses `rustls-platform-verifier` for OS-native certificate verification
- `native-certs` — loads system certificates via `rustls-native-certs`
- `webpki-root-certs` — bundles Mozilla root certificates via `webpki-root-certs`
- `futures` — enables async support via `futures-rustls` and `futures-io`
- `rustls--aws_lc_rs` (default) / `rustls--ring` — crypto backend selection; an installed process default takes precedence, otherwise aws-lc-rs wins if both are enabled, and construction returns an error if neither is enabled

`platform-verifier` and `webpki-root-certs`/`native-certs` can be combined: extra roots from the latter are passed to the platform verifier via `new_with_extra_roots`.

Each synchronous `handshake()` call flushes the underlying stream, makes at most one `complete_io()` attempt, and returns `WouldBlock` with `MidHandshakeTlsStream` while negotiation or writes remain pending or I/O is interrupted.

**MSRV:** 1.87.0
