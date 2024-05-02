# rustls-connector

[![API Docs](https://docs.rs/rustls-connector/badge.svg)](https://docs.rs/rustls-connector)
[![Build status](https://github.com/amqp-rs/rustls-connector/workflows/Build%20and%20test/badge.svg)](https://github.com/amqp-rs/rustls-connector/actions)
[![Downloads](https://img.shields.io/crates/d/rustls-connector.svg)](https://crates.io/crates/rustls-connector)

## Connector similar to openssl or native-tls for rustls

rustls-connector is a library aiming at simplifying using rustls as
an alternative to openssl and native-tls

## Warning about crypto backends

A crypto implementation must be enabled in rustls using feature flags.
We mimic what rustls does, providing one feature flag per implementation and enabling the same as rustls by default.
Available options are:
- `rustls--aws_lc_rs` (default)
- `rustls--ring`

## Examples

To connect to a remote server:

```rust
use rustls_connector::RustlsConnector;

use std::{
    io::{Read, Write},
    net::TcpStream,
};

let connector = RustlsConnector::new_with_native_certs().unwrap();
let stream = TcpStream::connect("google.com:443").unwrap();
let mut stream = connector.connect("google.com", stream).unwrap();

stream.write_all(b"GET / HTTP/1.0\r\n\r\n").unwrap();
let mut res = vec![];
stream.read_to_end(&mut res).unwrap();
println!("{}", String::from_utf8_lossy(&res));
```
