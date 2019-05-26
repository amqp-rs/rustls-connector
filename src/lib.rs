#![deny(missing_docs)]
#![warn(rust_2018_idioms)]
#![doc(html_root_url = "https://docs.rs/rustls-connector/0.1.0/")]

//! # Connector similar to openssl or native-tls for rustls
//!
//! tcp-stream is a library aiming at simplifying using rustls as
//! an alternative to openssl and native-tls

pub use rustls;
pub use webpki;
pub use webpki_roots;

use rustls::{ClientConfig, ClientSession, Session, StreamOwned as TlsStream};

use std::{
    io::{Read, Write},
    sync::Arc,
};

/// The connector
pub struct RustlsConnector {
    config: Arc<ClientConfig>,
}

impl Default for RustlsConnector {
    fn default() -> Self {
        let mut config = ClientConfig::new();
        config.root_store.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
        Self {
            config: Arc::new(config),
        }
    }
}

impl RustlsConnector {
    /// Connect to the given host
    pub fn connect<S: Read + Write>(&self, mut stream: S, domain: &str) -> Result<TlsStream<ClientSession, S>, ()> {
        let mut session = ClientSession::new(&self.config, webpki::DNSNameRef::try_from_ascii_str(domain)?);
        // FIXME: handle MidHandshake/WouldBlock
        while session.is_handshaking() {
            while session.is_handshaking() && session.wants_write() {
                session.write_tls(&mut stream).expect("FIXME");
            }
            while session.is_handshaking() && session.wants_read() {
                if session.read_tls(&mut stream).expect("FIXME") == 0 {
                    // FIXME
                    return Err(());
                }
                session.process_new_packets().expect("FIXME");
            }
        }
        Ok(TlsStream::new(session, stream))
    }
}
