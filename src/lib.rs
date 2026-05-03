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
//! let connector = RustlsConnector::new_with_platform_verifier().unwrap();
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
#[cfg(feature = "platform-verifier")]
pub use rustls_platform_verifier;
pub use webpki;
#[cfg(feature = "webpki-root-certs")]
pub use webpki_root_certs;

#[cfg(feature = "futures")]
use futures_io::{AsyncRead, AsyncWrite};
use rustls::{
    ClientConfig, ClientConnection, ConfigBuilder, RootCertStore, StreamOwned,
    client::WantsClientCert,
};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};

use std::{
    error::Error,
    fmt,
    io::{self, Read, Write},
    sync::Arc,
};

/// A TLS stream
pub type TlsStream<S> = StreamOwned<ClientConnection, S>;

#[cfg(feature = "futures")]
/// An async TLS stream
pub type AsyncTlsStream<S> = futures_rustls::client::TlsStream<S>;

/// Configuration helper for [`RustlsConnector`]
#[derive(Clone, Default)]
pub struct RustlsConnectorConfig {
    store: Vec<CertificateDer<'static>>,
    #[cfg(feature = "platform-verifier")]
    platform_verifier: bool,
}

impl RustlsConnectorConfig {
    #[cfg(feature = "webpki-root-certs")]
    /// Create a new [`RustlsConnectorConfig`] using the webpki-root-certs (requires webpki-root-certs feature enabled)
    pub fn new_with_webpki_root_certs() -> Self {
        Self::default().with_webpki_root_certs()
    }

    #[cfg(feature = "platform-verifier")]
    /// Create a new [`RustlsConnectorConfig`] using the rustls-platform-verifier mechanism (requires platform-verifier feature enabled)
    pub fn new_with_platform_verifier() -> Self {
        Self::default().with_platform_verifier()
    }

    #[cfg(feature = "native-certs")]
    /// Create a new [`RustlsConnectorConfig`] using the system certs (requires native-certs feature enabled)
    ///
    /// # Errors
    ///
    /// Returns an error if we fail to load the native certs.
    pub fn new_with_native_certs() -> io::Result<Self> {
        Self::default().with_native_certs()
    }

    /// Parse the given DER-encoded certificates and add all that can be parsed in a best-effort fashion.
    ///
    /// This is because large collections of root certificates often include ancient or syntactically invalid certificates.
    pub fn add_parsable_certificates(&mut self, mut der_certs: Vec<CertificateDer<'static>>) {
        self.store.append(&mut der_certs)
    }

    /// Parse the given DER-encoded certificates and add all that can be parsed in a best-effort fashion.
    ///
    /// This is because large collections of root certificates often include ancient or syntactically invalid certificates.
    pub fn with_parsable_certificates(mut self, der_certs: Vec<CertificateDer<'static>>) -> Self {
        self.add_parsable_certificates(der_certs);
        self
    }

    #[cfg(feature = "webpki-root-certs")]
    /// Add certs from webpki-root-certs (requires webpki-root-certs feature enabled)
    pub fn with_webpki_root_certs(mut self) -> Self {
        self.add_parsable_certificates(webpki_root_certs::TLS_SERVER_ROOT_CERTS.to_vec());
        self
    }

    #[cfg(feature = "platform-verifier")]
    /// Use the rustls-platform-verifier mechanism (requires platform-verifier feature enabled)
    pub fn with_platform_verifier(mut self) -> Self {
        self.platform_verifier = true;
        self
    }

    #[cfg(feature = "native-certs")]
    /// Add the system certs (requires native-certs feature enabled)
    ///
    /// # Errors
    ///
    /// Returns an error if we fail to load the native certs.
    pub fn with_native_certs(mut self) -> io::Result<Self> {
        let certs_result = rustls_native_certs::load_native_certs();
        for err in certs_result.errors {
            log::warn!("Got error while loading some native certificates: {err:?}");
        }
        if certs_result.certs.is_empty() {
            return Err(io::Error::other(
                "Could not load any valid native certificates",
            ));
        }
        self.add_parsable_certificates(certs_result.certs);
        Ok(self)
    }

    fn builder(self) -> io::Result<ConfigBuilder<ClientConfig, WantsClientCert>> {
        let builder = ClientConfig::builder();
        #[cfg(feature = "platform-verifier")]
        {
            if self.platform_verifier {
                let verifier = rustls_platform_verifier::Verifier::new_with_extra_roots(
                    self.store,
                    builder.crypto_provider().clone(),
                )
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
                return Ok(builder
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(verifier)));
            }
        }
        let mut store = RootCertStore::empty();
        let (_, ignored) = store.add_parsable_certificates(self.store);
        if ignored > 0 {
            log::warn!("{ignored} platform CA root certificates were ignored due to errors");
        }
        if store.is_empty() {
            return Err(io::Error::other("Could not load any valid certificates"));
        }
        Ok(builder.with_root_certificates(store))
    }

    /// Create a new [`RustlsConnector`] from this config and no client certificate
    ///
    /// # Errors
    ///
    /// Returns an error if we fail to init our verifier
    pub fn connector_with_no_client_auth(self) -> io::Result<RustlsConnector> {
        Ok(self.builder()?.with_no_client_auth().into())
    }

    /// Create a new [`RustlsConnector`] from this config and the given client certificate
    ///
    /// cert_chain is a vector of DER-encoded certificates. key_der is a DER-encoded RSA, ECDSA, or
    /// Ed25519 private key.
    ///
    /// # Errors
    ///
    /// Returns an error if we fail to init our verifier or if key_der is invalid.
    pub fn connector_with_single_cert(
        self,
        cert_chain: Vec<CertificateDer<'static>>,
        key_der: PrivateKeyDer<'static>,
    ) -> io::Result<RustlsConnector> {
        Ok(self
            .builder()?
            .with_client_auth_cert(cert_chain, key_der)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?
            .into())
    }
}


/// The connector
#[derive(Clone)]
pub struct RustlsConnector(Arc<ClientConfig>);

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
    #[cfg(feature = "webpki-root-certs")]
    /// Create a new RustlsConnector using the webpki-root certs (requires webpki-root-certs feature enabled)
    ///
    /// # Errors
    ///
    /// Returns an error if we fail to init our verifier
    pub fn new_with_webpki_root_certs() -> io::Result<Self> {
        RustlsConnectorConfig::new_with_webpki_root_certs().connector_with_no_client_auth()
    }

    #[cfg(feature = "platform-verifier")]
    /// Create a new [`RustlsConnector`] using the rustls-platform-verifier mechanism (requires platform-verifier feature enabled)
    ///
    /// # Errors
    ///
    /// Returns an error if we fail to init our verifier
    pub fn new_with_platform_verifier() -> io::Result<Self> {
        RustlsConnectorConfig::new_with_platform_verifier().connector_with_no_client_auth()
    }

    #[cfg(feature = "native-certs")]
    /// Create a new [`RustlsConnector`] using the system certs (requires native-certs feature enabled)
    ///
    /// # Errors
    ///
    /// Returns an error if we fail to load the native certs.
    pub fn new_with_native_certs() -> io::Result<Self> {
        RustlsConnectorConfig::new_with_native_certs()?.connector_with_no_client_auth()
    }

    /// Connect to the given host
    ///
    /// # Errors
    ///
    /// Returns a [`HandshakeError`] containing either the current state of the handshake or the
    /// failure when we couldn't complete the hanshake
    #[allow(clippy::result_large_err)]
    pub fn connect<S: Read + Write + Send + 'static>(
        &self,
        domain: &str,
        stream: S,
    ) -> Result<TlsStream<S>, HandshakeError<S>> {
        let session = ClientConnection::new(
            self.0.clone(),
            server_name(domain).map_err(HandshakeError::Failure)?,
        )
        .map_err(|err| io::Error::new(io::ErrorKind::ConnectionAborted, err))?;
        MidHandshakeTlsStream { session, stream }.handshake()
    }

    #[cfg(feature = "futures")]
    /// Connect to the given host asynchronously
    ///
    /// # Errors
    ///
    /// Returns a [`io::Error`] containing the failure when we couldn't complete the TLS hanshake
    pub async fn connect_async<S: AsyncRead + AsyncWrite + Send + Unpin + 'static>(
        &self,
        domain: &str,
        stream: S,
    ) -> io::Result<AsyncTlsStream<S>> {
        futures_rustls::TlsConnector::from(self.0.clone())
            .connect(server_name(domain)?, stream)
            .await
    }
}

fn server_name(domain: &str) -> io::Result<ServerName<'static>> {
    Ok(ServerName::try_from(domain)
        .map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Invalid domain name ({err:?}): {domain}"),
            )
        })?
        .to_owned())
}

/// A TLS stream which has been interrupted during the handshake
#[derive(Debug)]
pub struct MidHandshakeTlsStream<S: Read + Write> {
    session: ClientConnection,
    stream: S,
}

impl<S: Read + Send + Write + 'static> MidHandshakeTlsStream<S> {
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
    #[allow(clippy::result_large_err)]
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
#[allow(clippy::large_enum_variant)]
pub enum HandshakeError<S: Read + Write + Send + 'static> {
    /// We hit WouldBlock during handshake.
    /// Note that this is not a critical failure, you should be able to call handshake again once the stream is ready to perform I/O.
    WouldBlock(MidHandshakeTlsStream<S>),
    /// We hit a critical failure.
    Failure(io::Error),
}

impl<S: Read + Write + Send + 'static> fmt::Display for HandshakeError<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HandshakeError::WouldBlock(_) => f.write_str("WouldBlock hit during handshake"),
            HandshakeError::Failure(err) => f.write_fmt(format_args!("IO error: {err}")),
        }
    }
}

impl<S: Read + Write + Send + 'static> fmt::Debug for HandshakeError<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut d = f.debug_tuple("HandshakeError");
        match self {
            HandshakeError::WouldBlock(_) => d.field(&"WouldBlock"),
            HandshakeError::Failure(err) => d.field(&err),
        }
        .finish()
    }
}

impl<S: Read + Write + Send + 'static> Error for HandshakeError<S> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            HandshakeError::Failure(err) => Some(err),
            _ => None,
        }
    }
}

impl<S: Read + Send + Write + 'static> From<io::Error> for HandshakeError<S> {
    fn from(err: io::Error) -> Self {
        HandshakeError::Failure(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_config_fails() {
        assert!(RustlsConnectorConfig::default()
            .connector_with_no_client_auth()
            .is_err());
    }

    #[test]
    #[cfg(feature = "webpki-root-certs")]
    fn webpki_root_certs_connector_builds() {
        RustlsConnector::new_with_webpki_root_certs().unwrap();
    }

    #[test]
    #[cfg(feature = "platform-verifier")]
    fn platform_verifier_connector_builds() {
        RustlsConnector::new_with_platform_verifier().unwrap();
    }

    #[test]
    fn handshake_error_failure_display() {
        let err: HandshakeError<std::net::TcpStream> =
            HandshakeError::Failure(io::Error::other("test error"));
        assert!(err.to_string().contains("test error"));
        assert!(format!("{err:?}").contains("test error"));
        assert!(err.source().is_some());
    }
}
