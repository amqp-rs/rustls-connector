<div align="center">

[![API Docs](https://docs.rs/rustls-connector/badge.svg)](https://docs.rs/rustls-connector)
[![Build status](https://github.com/amqp-rs/rustls-connector/workflows/Build%20and%20test/badge.svg)](https://github.com/amqp-rs/rustls-connector/actions)
[![Downloads](https://img.shields.io/crates/d/rustls-connector.svg)](https://crates.io/crates/rustls-connector)
[![Dependency Status](https://deps.rs/repo/github/amqp-rs/rustls-connector/status.svg)](https://deps.rs/repo/github/amqp-rs/rustls-connector)
[![LICENSE](https://img.shields.io/crates/l/rustls-connector)](LICENSE)

**A TLS connector for rustls modelled after the `openssl` and `native-tls` APIs.**

</div>

rustls-connector gives rustls the connector API of the `openssl` and
`native-tls` crates: build a `RustlsConnector` from a choice of root
certificates, call `connect` on a stream such as a `TcpStream`, and retry the
handshake on non-blocking streams the same way. It is the rustls backend of
`tcp-stream`, and the `futures` feature adds an async `connect_async`.

## Feature flags

### Certificate store (pick at least one)

| Flag | Notes |
|------|-------|
| `platform-verifier` *(default)* | Platform trust store via rustls-platform-verifier |
| `native-certs` | Native root certificates via rustls-native-certs |
| `webpki-root-certs` | Bundled Mozilla root certificate set |

On Android, the platform verifier must be initialized from Java before the
first connection (see the rustls-platform-verifier documentation), and it
cannot take any roots besides the platform's: extra root certificates, the
webpki roots, or native certificates while `SSL_CERT_FILE` or `SSL_CERT_DIR`
is set.

### Rustls crypto provider (one is used, see below)

| Flag | Notes |
|------|-------|
| `rustls--aws_lc_rs` *(default)* | Uses aws-lc-rs, preferring post-quantum key exchange |
| `rustls--ring` | Uses ring (more portable) |

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

To connect to several servers, build the connector once and reuse it:

```rust
use rustls_connector::RustlsConnector;

use std::{
    io::{Read, Write},
    net::TcpStream,
};

// Build it once: reusing it lets rustls resume TLS sessions, and on most Unix
// systems, building it loads the OS trust store.
let connector = RustlsConnector::new_with_platform_verifier().unwrap();

for host in ["rust-lang.org", "crates.io"] {
    let stream = TcpStream::connect((host, 443)).unwrap();
    let mut stream = connector.connect(host, stream).unwrap();
    let request = format!("GET / HTTP/1.0\r\nHost: {host}\r\n\r\n");
    stream.write_all(request.as_bytes()).unwrap();
    let mut res = vec![];
    stream.read_to_end(&mut res).unwrap();
    println!("{host}: {} bytes", res.len());
}
```
