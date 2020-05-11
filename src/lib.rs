#![deny(missing_docs)]
#![warn(rust_2018_idioms)]
#![doc(html_root_url = "https://docs.rs/rustls-connector/0.11.0/")]

//! # Connector similar to openssl or native-tls for rustls
//!
//! rustls-connector is a library aiming at simplifying using rustls as
//! an alternative to openssl and native-tls
//!
//! # Examples
//!
//! To connect to a remote server:
//!
//! ```rust, no_run
//! use rustls_connector::RustlsConnector;
//!
//! use std::{
//!     io::{Read, Write},
//!     net::TcpStream,
//! };
//!
//! let connector = RustlsConnector::new_with_native_certs().unwrap();
//! let stream = TcpStream::connect("google.com:443").unwrap();
//! let mut stream = connector.connect("google.com", stream).unwrap();
//!
//! stream.write_all(b"GET / HTTP/1.0\r\n\r\n").unwrap();
//! let mut res = vec![];
//! stream.read_to_end(&mut res).unwrap();
//! println!("{}", String::from_utf8_lossy(&res));
//! ```

pub use rustls;
#[cfg(feature = "native-certs")]
pub use rustls_native_certs;
pub use webpki;
#[cfg(feature = "webpki-roots-certs")]
pub use webpki_roots;

use log::warn;
use rustls::{ClientConfig, ClientSession, Session, StreamOwned};

use std::{
    error::Error,
    fmt::{self, Debug},
    io::{self, Read, Write},
    ops::{Deref, DerefMut},
    sync::Arc,
};

/// A TLS stream
pub type TlsStream<S> = StreamOwned<ClientSession, S>;

/// Configuration helper for RustlsConnector
pub struct RustlsConnectorConfig(ClientConfig);

impl RustlsConnectorConfig {
    /// Create a new RustlsConnector from the given ClientConfig
    pub fn new(config: ClientConfig) -> Self {
        config.into()
    }

    #[cfg(feature = "webpki-roots-certs")]
    /// Create a new RustlsConnector using the webpki-roots certs (requires webpki-roots-certs feature enabled)
    pub fn new_with_webpki_roots_certs() -> Self {
        let mut config = ClientConfig::new();
        config
            .root_store
            .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
        config.into()
    }

    #[cfg(feature = "native-certs")]
    /// Create a new RustlsConnector using the system certs (requires native-certs feature enabled)
    pub fn new_with_native_certs() -> io::Result<Self> {
        let mut config = ClientConfig::new();
        config.root_store =
            rustls_native_certs::load_native_certs().or_else(|(partial_root_store, error)| {
                partial_root_store
                    .map(|store| {
                        warn!(
                            "Got error while importing some native certificates: {:?}",
                            error
                        );
                        store
                    })
                    .ok_or(error)
            })?;
        Ok(config.into())
    }
}

impl Default for RustlsConnectorConfig {
    fn default() -> Self {
        ClientConfig::new().into()
    }
}

impl From<ClientConfig> for RustlsConnectorConfig {
    fn from(config: ClientConfig) -> Self {
        Self(config)
    }
}

impl Deref for RustlsConnectorConfig {
    type Target = ClientConfig;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for RustlsConnectorConfig {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// The connector
pub struct RustlsConnector(Arc<ClientConfig>);

impl Default for RustlsConnector {
    fn default() -> Self {
        RustlsConnectorConfig::default().into()
    }
}

impl From<RustlsConnectorConfig> for RustlsConnector {
    fn from(config: RustlsConnectorConfig) -> Self {
        config.0.into()
    }
}

impl From<ClientConfig> for RustlsConnector {
    fn from(config: ClientConfig) -> Self {
        Arc::new(config).into()
    }
}

impl From<Arc<ClientConfig>> for RustlsConnector {
    fn from(config: Arc<ClientConfig>) -> Self {
        Self(config)
    }
}

impl RustlsConnector {
    #[cfg(feature = "webpki-roots-certs")]
    /// Create a new RustlsConnector using the webpki-roots certs (requires webpki-roots-certs feature enabled)
    pub fn new_with_webpki_roots_certs() -> Self {
        RustlsConnectorConfig::new_with_webpki_roots_certs().into()
    }

    #[cfg(feature = "native-certs")]
    /// Create a new RustlsConnector using the system certs (requires native-certs feature enabled)
    pub fn new_with_native_certs() -> io::Result<Self> {
        Ok(RustlsConnectorConfig::new_with_native_certs()?.into())
    }

    /// Connect to the given host
    pub fn connect<S: Debug + Read + Send + Sync + Write + 'static>(
        &self,
        domain: &str,
        stream: S,
    ) -> Result<TlsStream<S>, HandshakeError<S>> {
        let session = ClientSession::new(
            &self.0,
            webpki::DNSNameRef::try_from_ascii_str(domain).map_err(|err| {
                HandshakeError::Failure(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Invalid domain name ({}): {}", err, domain),
                ))
            })?,
        );
        MidHandshakeTlsStream { session, stream }.handshake()
    }
}

/// A TLS stream which has been interrupted during the handshake
#[derive(Debug)]
pub struct MidHandshakeTlsStream<S: Read + Write> {
    session: ClientSession,
    stream: S,
}

impl<S: Debug + Read + Send + Sync + Write + 'static> MidHandshakeTlsStream<S> {
    /// Get a reference to the inner stream
    pub fn get_ref(&self) -> &S {
        &self.stream
    }

    /// Get a mutable reference to the inner stream
    pub fn get_mut(&mut self) -> &mut S {
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
        f.write_str("MidHandshakeTlsStream")
    }
}

/// An error returned while performing the handshake
#[derive(Debug)]
pub enum HandshakeError<S: Read + Send + Sync + Write + 'static> {
    /// We hit WouldBlock during handshake.
    /// Note that this is not a critical failure, you should be able to call handshake again once the stream is ready to perform I/O.
    WouldBlock(MidHandshakeTlsStream<S>),
    /// We hit a critical failure.
    Failure(io::Error),
}

impl<S: Debug + Read + Send + Sync + Write + 'static> fmt::Display for HandshakeError<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HandshakeError::WouldBlock(_) => f.write_str("WouldBlock hit during handshake"),
            HandshakeError::Failure(err) => f.write_fmt(format_args!("IO error: {}", err)),
        }
    }
}

impl<S: Debug + Read + Send + Sync + Write + 'static> Error for HandshakeError<S> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            HandshakeError::Failure(err) => Some(err),
            _ => None,
        }
    }
}

impl<S: Debug + Read + Send + Sync + Write + 'static> From<io::Error> for HandshakeError<S> {
    fn from(err: io::Error) -> Self {
        HandshakeError::Failure(err)
    }
}
