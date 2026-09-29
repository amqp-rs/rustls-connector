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

Both connection methods accept borrowed I/O streams and streams that do not
implement `Send`; async streams must also implement `Unpin`.

## Feature flags

### Certificate store (pick at least one)

| Flag | Notes |
|------|-------|
| `platform-verifier` *(default)* | Platform trust store via rustls-platform-verifier |
| `native-certs` | Native root certificates via rustls-native-certs |
| `webpki-root-certs` | Bundled Mozilla root certificate set |

### Rustls crypto provider (at least one required)

| Flag | Notes |
|------|-------|
| `rustls--aws_lc_rs` *(default)* | Uses aws-lc-rs |
| `rustls--ring` | Uses ring (more portable, e.g. builds on Windows) |

An installed process-level rustls crypto provider takes precedence. If both
provider features are enabled, the connector uses aws-lc-rs unless a
process-level default has been installed. If neither is enabled, connector
construction returns an error.

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
