#![deny(missing_docs)]

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
pub use rustls_pki_types;
pub use webpki;
#[cfg(feature = "webpki-roots-certs")]
pub use webpki_roots;

use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};

use std::{
    error::Error,
    fmt::{self, Debug},
    io::{self, Read, Write},
    sync::Arc,
};

/// A TLS stream
pub type TlsStream<S> = StreamOwned<ClientConnection, S>;

/// Configuration helper for [`RustlsConnector`]
#[derive(Clone)]
pub struct RustlsConnectorConfig(RootCertStore);

impl RustlsConnectorConfig {
    #[cfg(feature = "webpki-roots-certs")]
    /// Create a new [`RustlsConnectorConfig`] using the webpki-roots certs (requires webpki-roots-certs feature enabled)
    pub fn new_with_webpki_roots_certs() -> Self {
        Self(RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect(),
        })
    }

    #[cfg(feature = "native-certs")]
    /// Create a new [`RustlsConnectorConfig`] using the system certs (requires native-certs feature enabled)
    ///
    /// # Errors
    ///
    /// Returns an error if we fail to load the native certs.
    pub fn new_with_native_certs() -> io::Result<Self> {
        let mut root_store = RootCertStore::empty();
        for cert in rustls_native_certs::load_native_certs()?
        {
            if let Err(err) = root_store.add(cert) {
                log::warn!(
                    "Got error while importing some native certificates: {:?}",
                    err
                );
            }
        }
        Ok(Self(root_store))
    }

    /// Parse the given DER-encoded certificates and add all that can be parsed in a best-effort fashion.
    ///
    /// This is because large collections of root certificates often include ancient or syntactically invalid certificates.
    ///
    /// Returns the number of certificates added, and the number that were ignored.
    pub fn add_parsable_certificates(
        &mut self,
        der_certs: Vec<CertificateDer<'_>>,
    ) -> (usize, usize) {
        self.0.add_parsable_certificates(der_certs)
    }

    /// Create a new [`RustlsConnector`] from this config and no client certificate
    pub fn connector_with_no_client_auth(self) -> RustlsConnector {
        ClientConfig::builder()
            .with_root_certificates(self.0)
            .with_no_client_auth()
            .into()
    }

    /// Create a new [`RustlsConnector`] from this config and the given client certificate
    ///
    /// cert_chain is a vector of DER-encoded certificates. key_der is a DER-encoded RSA, ECDSA, or
    /// Ed25519 private key.
    ///
    /// This function fails if key_der is invalid.
    pub fn connector_with_single_cert(
        self,
        cert_chain: Vec<CertificateDer<'static>>,
        key_der: PrivateKeyDer<'static>,
    ) -> io::Result<RustlsConnector> {
        Ok(ClientConfig::builder()
            .with_root_certificates(self.0)
            .with_client_auth_cert(cert_chain, key_der)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?
            .into())
    }
}

impl Default for RustlsConnectorConfig {
    fn default() -> Self {
        Self(RootCertStore::empty())
    }
}

/// The connector
#[derive(Clone)]
pub struct RustlsConnector(Arc<ClientConfig>);

impl Default for RustlsConnector {
    fn default() -> Self {
        RustlsConnectorConfig::default().connector_with_no_client_auth()
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
        RustlsConnectorConfig::new_with_webpki_roots_certs().connector_with_no_client_auth()
    }

    #[cfg(feature = "native-certs")]
    /// Create a new [`RustlsConnector`] using the system certs (requires native-certs feature enabled)
    ///
    /// # Errors
    ///
    /// Returns an error if we fail to load the native certs.
    pub fn new_with_native_certs() -> io::Result<Self> {
        Ok(RustlsConnectorConfig::new_with_native_certs()?.connector_with_no_client_auth())
    }

    /// Connect to the given host
    ///
    /// # Errors
    ///
    /// Returns a [`HandshakeError`] containing either the current state of the handshake or the
    /// failure when we couldn't complete the hanshake
    pub fn connect<S: Debug + Read + Send + Sync + Write + 'static>(
        &self,
        domain: &str,
        stream: S,
    ) -> Result<TlsStream<S>, HandshakeError<S>> {
        let session = ClientConnection::new(
            self.0.clone(),
            ServerName::try_from(domain)
                .map_err(|err| {
                    HandshakeError::Failure(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("Invalid domain name ({:?}): {}", err, domain),
                    ))
                })?
                .to_owned(),
        )
        .map_err(|err| io::Error::new(io::ErrorKind::ConnectionAborted, err))?;
        MidHandshakeTlsStream { session, stream }.handshake()
    }
}

/// A TLS stream which has been interrupted during the handshake
#[derive(Debug)]
pub struct MidHandshakeTlsStream<S: Read + Write> {
    session: ClientConnection,
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
    ///
    /// # Errors
    ///
    /// Returns a [`HandshakeError`] containing either the current state of the handshake or the
    /// failure when we couldn't complete the hanshake
    pub fn handshake(mut self) -> Result<TlsStream<S>, HandshakeError<S>> {
        if let Err(e) = self.session.complete_io(&mut self.stream) {
            if e.kind() == io::ErrorKind::WouldBlock {
                if self.session.is_handshaking() {
                    return Err(HandshakeError::WouldBlock(Box::new(self)));
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
    WouldBlock(Box<MidHandshakeTlsStream<S>>),
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
