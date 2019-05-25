#![deny(missing_docs)]
#![warn(rust_2018_idioms)]
#![doc(html_root_url = "https://docs.rs/rustls-connector/0.1.0/")]

//! # Connector similar to openssl or native-tls for rustls
//!
//! tcp-stream is a library aiming at simplifying using rustls as
//! an alternative to openssl and native-tls

use rustls::{ClientConfig, ClientSession};
use webpki::DNSNameRef;
use webpki_roots::TLS_SERVER_ROOTS;

use std::sync::Arc;

/// The connector
pub struct RustlsConnector {
    config: Arc<ClientConfig>,
}

impl Default for RustlsConnector {
    fn default() -> Self {
        let mut config = ClientConfig::new();
        config.root_store.add_server_trust_anchors(&TLS_SERVER_ROOTS);
        Self {
            config: Arc::new(config),
        }
    }
}

impl RustlsConnector {
    /// Connect to the given host
    pub fn connect(&self, domain: &str) -> Result<ClientSession, ()> {
        Ok(ClientSession::new(&self.config, DNSNameRef::try_from_ascii_str(domain)?))
    }
}
