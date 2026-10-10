<div align="center">

[![API Docs](https://docs.rs/rustls-connector/badge.svg)](https://docs.rs/rustls-connector)
[![Build status](https://github.com/amqp-rs/rustls-connector/workflows/Build%20and%20test/badge.svg)](https://github.com/amqp-rs/rustls-connector/actions)
[![Downloads](https://img.shields.io/crates/d/rustls-connector.svg)](https://crates.io/crates/rustls-connector)
[![Dependency Status](https://deps.rs/repo/github/amqp-rs/rustls-connector/status.svg)](https://deps.rs/repo/github/amqp-rs/rustls-connector)
[![LICENSE](https://img.shields.io/crates/l/rustls-connector)](LICENSE)

**A TLS connector for rustls modelled after the `openssl` and `native-tls` APIs.**

</div>

Wraps `rustls` with a high-level `RustlsConnector` type that mirrors the
ergonomics of `native_tls::TlsConnector`, making it straightforward to swap
TLS backends in existing code. An async variant is available via the `futures`
feature.

## Feature flags

### Certificate store (pick at least one)

| Flag | Notes |
|------|-------|
| `platform-verifier` *(default)* | Platform trust store via rustls-platform-verifier |
| `native-certs` | Native root certificates via rustls-native-certs |
| `webpki-root-certs` | Bundled Mozilla root certificate set |

### Rustls crypto provider (one is used, see below)

| Flag | Notes |
|------|-------|
| `rustls--aws_lc_rs` *(default)* | Uses aws-lc-rs, preferring post-quantum key exchange |
| `rustls--ring` | Uses ring (more portable, e.g. builds on Windows) |

Connectors use the process-level rustls crypto provider when one is installed.
Otherwise they pick aws-lc-rs, or ring if only `rustls--ring` is enabled, and
install it as the process-level default when the first connector is built, so
install a provider early in `main` if other rustls users may start before
that. With neither feature, the choice is left to rustls's own crate features:
rustls installs the provider it picks as the default too, and building a
connector panics if it cannot pick one. Applications using a custom rustls
provider should disable this crate's provider features and install their
provider before building any connector.

To use ring without compiling aws-lc-rs, disable default features and select
a certificate store explicitly:

```toml
rustls-connector = { version = "0.23", default-features = false, features = ["platform-verifier", "rustls--ring"] }
```

### Miscellaneous

| Flag | Notes |
|------|-------|
| `futures` | Async connect via `futures-rustls` |
| `logging` | Enable rustls TLS logging |

## Example

To connect to a remote server:

```rust
use rustls_connector::RustlsConnector;

use std::{
    io::{Read, Write},
    net::TcpStream,
};

let connector = RustlsConnector::new_with_platform_verifier().unwrap();
let stream = TcpStream::connect("google.com:443").unwrap();
let mut stream = connector.connect("google.com", stream).unwrap();

stream.write_all(b"GET / HTTP/1.0\r\n\r\n").unwrap();
let mut res = vec![];
stream.read_to_end(&mut res).unwrap();
println!("{}", String::from_utf8_lossy(&res));
```
