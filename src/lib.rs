#![deny(missing_docs)]
#![warn(rust_2018_idioms)]
#![doc(html_root_url = "https://docs.rs/rustls-connector/0.6.0/")]

//! # Connector similar to openssl or native-tls for rustls
//!
//! tcp-stream is a library aiming at simplifying using rustls as
//! an alternative to openssl and native-tls

pub use rustls;
pub use webpki;
pub use webpki_roots;

use rustls::{ClientConfig, ClientSession, Session, StreamOwned};

use std::{
    fmt::{self, Debug},
    error::Error,
    io::{self, Read, Write},
    sync::Arc,
};

/// A TLS stream
pub type TlsStream<S> = StreamOwned<ClientSession, S>;

/// The connector
pub struct RustlsConnector {
    config: Arc<ClientConfig>,
}

impl Default for RustlsConnector {
    fn default() -> Self {
        let mut config = ClientConfig::new();
        config.root_store.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
        config.into()
    }
}

impl From<ClientConfig> for RustlsConnector {
    fn from(config: ClientConfig) -> Self {
        Arc::new(config).into()
    }
}

impl From<Arc<ClientConfig>> for RustlsConnector {
    fn from(config: Arc<ClientConfig>) -> Self {
        Self { config }
    }
}

impl RustlsConnector {
    /// Create a new RustlsConnector from the given ClientConfig
    pub fn new(config: ClientConfig) -> Self {
        config.into()
    }

    /// Connect to the given host
    pub fn connect<S: Debug + Read + Send + Sync + Write + 'static>(&self, domain: &str, stream: S) -> Result<TlsStream<S>, HandshakeError<S>> {
        let session = ClientSession::new(&self.config, webpki::DNSNameRef::try_from_ascii_str(domain).map_err(|()| HandshakeError::Failure(io::Error::new(io::ErrorKind::InvalidData, format!("Invalid domain name: {}", domain))))?);
        MidHandshakeTlsStream { session, stream }.handshake()
    }
}

/// A TLS stream which has been interrupted during the handshake
#[derive(Debug)]
pub struct MidHandshakeTlsStream<S: Read + Write> {
    session: ClientSession,
    stream:  S,
}

impl<S: Debug + Read + Send + Sync + Write + 'static> MidHandshakeTlsStream<S> {
    /// Get a reference to the inner stream
    pub fn get_ref(&self) -> &S {
        &self.stream
    }

    /// Get a mutable reference to the inner stream
    pub fn get_mut(&mut self) -> &S {
        &mut self.stream
    }

    /// Retry the handshake
    pub fn handshake(mut self) -> Result<TlsStream<S>, HandshakeError<S>> {
        if let Err(e) = self.session.complete_io(&mut self.stream) {
            if e.kind() == io::ErrorKind::WouldBlock {
                if self.session.is_handshaking() {
                    return Err(HandshakeError::WouldBlock(self));
                }
            } else {
                return Err(e.into());
            }
        }
        Ok(TlsStream::new(self.session, self.stream))
    }
}

impl<S: Read + Write> fmt::Display for MidHandshakeTlsStream<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MidHandshakeTlsStream")
    }
}

/// An error returned while performing the handshake
#[derive(Debug)]
pub enum HandshakeError<S: Read + Send + Sync + Write + 'static> {
    /// We hit WouldBlock during handshake
    WouldBlock(MidHandshakeTlsStream<S>),
    /// We hit a critical failure
    Failure(io::Error),
}

impl<S: Debug + Read + Send + Sync + Write + 'static> fmt::Display for HandshakeError<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HandshakeError::WouldBlock(_) => write!(f, "WouldBlock hit during handshake"),
            HandshakeError::Failure(err)  => write!(f, "IO error: {}", err),
        }
    }
}

impl<S: Debug + Read + Send + Sync + Write + 'static> Error for HandshakeError<S> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            HandshakeError::Failure(err) => Some(err),
            _                            => None,
        }
    }
}

impl<S: Debug + Read + Send + Sync + Write + 'static> From<io::Error> for HandshakeError<S> {
    fn from(err: io::Error) -> Self {
        HandshakeError::Failure(err)
    }
}
