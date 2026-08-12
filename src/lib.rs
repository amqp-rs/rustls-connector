#![deny(missing_docs, missing_debug_implementations, unsafe_code)]
#![warn(unreachable_pub, unused_qualifications, unused_lifetimes)]
#![warn(
    clippy::must_use_candidate,
    clippy::unwrap_in_result,
    clippy::panic_in_result_fn
)]

//! A TLS connector for rustls modelled after the `openssl` and `native-tls` APIs.
//!
//! Wraps [`rustls`] with a high-level [`RustlsConnector`] type that mirrors the
//! ergonomics of `native_tls::TlsConnector`, making it straightforward to swap
//! TLS backends in existing code.
//!
//! # Feature flags
//!
//! ## Certificate store (pick at least one)
//!
//! | Flag | Notes |
//! |------|-------|
//! | `platform-verifier` *(default)* | Platform trust store via rustls-platform-verifier |
//! | `native-certs` | Native root certificates via rustls-native-certs |
//! | `webpki-root-certs` | Bundled Mozilla root certificate set |
//!
//! ## Rustls crypto provider (at least one must be enabled)
//!
//! | Flag | Notes |
//! |------|-------|
//! | `rustls--aws_lc_rs` *(default)* | Uses aws-lc-rs |
//! | `rustls--ring` | Uses ring (more portable) |
//!
//! Enabling *both* providers (which cargo feature unification can do behind your
//! back) leaves rustls unable to pick one on its own. In that case install a
//! process-level default with
//! [`CryptoProvider::install_default`](rustls::crypto::CryptoProvider::install_default)
//! before building a connector, otherwise every constructor below panics.
//!
//! ## Miscellaneous
//!
//! | Flag | Notes |
//! |------|-------|
//! | `futures` | Async connect via `futures-rustls` |
//! | `logging` | Enable rustls TLS logging |
//!
//! # Example
//!
// The example needs the `platform-verifier` feature to compile; keep it visible in the rendered
// docs either way, but don't let `cargo test --no-default-features` trip over it.
#![cfg_attr(feature = "platform-verifier", doc = "```rust, no_run")]
#![cfg_attr(not(feature = "platform-verifier"), doc = "```rust, ignore")]
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

/// Reexport of the [`rustls`](https://docs.rs/rustls) crate.
pub use rustls;
#[cfg(feature = "native-certs")]
/// Reexport of the [`rustls_native_certs`](https://docs.rs/rustls-native-certs) crate.
pub use rustls_native_certs;
/// Reexport of the [`rustls_pki_types`](https://docs.rs/rustls-pki-types) crate.
pub use rustls_pki_types;
#[cfg(feature = "platform-verifier")]
/// Reexport of the [`rustls_platform_verifier`](https://docs.rs/rustls-platform-verifier) crate.
pub use rustls_platform_verifier;
/// Reexport of the [`rustls_webpki`](https://docs.rs/rustls-webpki) crate.
pub use webpki;
#[cfg(feature = "webpki-root-certs")]
/// Reexport of the [`webpki_root_certs`](https://docs.rs/webpki-root-certs) crate.
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

/// A rustls client TLS stream wrapping an underlying synchronous I/O stream `S`.
pub type TlsStream<S> = StreamOwned<ClientConnection, S>;

#[cfg(feature = "futures")]
/// A rustls client TLS stream wrapping an underlying async I/O stream `S`.
pub type AsyncTlsStream<S> = futures_rustls::client::TlsStream<S>;

/// Configuration helper for [`RustlsConnector`]
#[derive(Clone, Default, Debug)]
pub struct RustlsConnectorConfig {
    store: Vec<CertificateDer<'static>>,
    #[cfg(feature = "platform-verifier")]
    platform_verifier: bool,
}

impl RustlsConnectorConfig {
    #[cfg(feature = "webpki-root-certs")]
    /// Create a new [`RustlsConnectorConfig`] using the webpki-root-certs (requires webpki-root-certs feature enabled)
    #[must_use]
    pub fn new_with_webpki_root_certs() -> Self {
        Self::default().with_webpki_root_certs()
    }

    #[cfg(feature = "platform-verifier")]
    /// Create a new [`RustlsConnectorConfig`] using the rustls-platform-verifier mechanism (requires platform-verifier feature enabled)
    #[must_use]
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

    /// Queue the given DER-encoded certificates as additional roots.
    ///
    /// Parsing is deferred until the connector is built. Certificates that fail to parse are then
    /// skipped in a best-effort fashion, because large collections of root certificates often
    /// include ancient or syntactically invalid certificates.
    ///
    /// The one exception is [`with_platform_verifier`](Self::with_platform_verifier): the platform
    /// verifier rejects unparsable extra roots outright, so a single bad certificate makes
    /// building the connector fail.
    pub fn add_parsable_certificates(&mut self, mut der_certs: Vec<CertificateDer<'static>>) {
        self.store.append(&mut der_certs)
    }

    /// Queue the given DER-encoded certificates as additional roots.
    ///
    /// Chainable variant of [`add_parsable_certificates`](Self::add_parsable_certificates); see it
    /// for the parsing semantics.
    #[must_use]
    pub fn with_parsable_certificates(mut self, der_certs: Vec<CertificateDer<'static>>) -> Self {
        self.add_parsable_certificates(der_certs);
        self
    }

    #[cfg(feature = "webpki-root-certs")]
    /// Add certs from webpki-root-certs (requires webpki-root-certs feature enabled)
    #[must_use]
    pub fn with_webpki_root_certs(mut self) -> Self {
        self.add_parsable_certificates(webpki_root_certs::TLS_SERVER_ROOT_CERTS.to_vec());
        self
    }

    #[cfg(feature = "platform-verifier")]
    /// Use the rustls-platform-verifier mechanism (requires platform-verifier feature enabled)
    #[must_use]
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
                let provider = builder.crypto_provider().clone();
                // `rustls-platform-verifier` has no `new_with_extra_roots` on Android: its trust
                // decisions are delegated to the platform and cannot be augmented from Rust.
                // Refuse rather than silently trusting fewer roots than the caller asked for.
                #[cfg(target_os = "android")]
                let verifier = {
                    if !self.store.is_empty() {
                        return Err(io::Error::other(
                            "extra root certificates cannot be combined with the platform verifier on Android",
                        ));
                    }
                    rustls_platform_verifier::Verifier::new(provider)
                };
                #[cfg(not(target_os = "android"))]
                let verifier =
                    rustls_platform_verifier::Verifier::new_with_extra_roots(self.store, provider);
                let verifier =
                    verifier.map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
                // `.dangerous()` is the rustls API for supplying a custom verifier;
                // it does not bypass verification — `Verifier` delegates to the OS store.
                return Ok(builder
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(verifier)));
            }
        }
        let mut store = RootCertStore::empty();
        let (_, ignored) = store.add_parsable_certificates(self.store);
        if ignored > 0 {
            log::warn!("{ignored} CA root certificates were ignored due to errors");
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
    /// Returns an error if we fail to init our verifier or if no valid root certificate could be
    /// loaded
    ///
    /// # Panics
    ///
    /// Panics if rustls cannot determine a crypto provider, i.e. if no process-level default has
    /// been installed and the enabled crate features select zero or more than one provider.
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
    /// Returns an error if we fail to init our verifier, if no valid root certificate could be
    /// loaded, or if key_der is invalid.
    ///
    /// # Panics
    ///
    /// Panics if rustls cannot determine a crypto provider, i.e. if no process-level default has
    /// been installed and the enabled crate features select zero or more than one provider.
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

/// A rustls TLS connector ready to perform TLS handshakes.
///
/// Wraps an [`Arc<ClientConfig>`] and can be built from a [`RustlsConnectorConfig`] via
/// [`connector_with_no_client_auth`](RustlsConnectorConfig::connector_with_no_client_auth) or
/// [`connector_with_single_cert`](RustlsConnectorConfig::connector_with_single_cert), or
/// directly from a `ClientConfig` via the [`From`] impl.
#[derive(Clone, Debug)]
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
    ///
    /// # Panics
    ///
    /// See [`connector_with_no_client_auth`](RustlsConnectorConfig::connector_with_no_client_auth).
    pub fn new_with_webpki_root_certs() -> io::Result<Self> {
        RustlsConnectorConfig::new_with_webpki_root_certs().connector_with_no_client_auth()
    }

    #[cfg(feature = "platform-verifier")]
    /// Create a new [`RustlsConnector`] using the rustls-platform-verifier mechanism (requires platform-verifier feature enabled)
    ///
    /// # Errors
    ///
    /// Returns an error if we fail to init our verifier
    ///
    /// # Panics
    ///
    /// See [`connector_with_no_client_auth`](RustlsConnectorConfig::connector_with_no_client_auth).
    pub fn new_with_platform_verifier() -> io::Result<Self> {
        RustlsConnectorConfig::new_with_platform_verifier().connector_with_no_client_auth()
    }

    #[cfg(feature = "native-certs")]
    /// Create a new [`RustlsConnector`] using the system certs (requires native-certs feature enabled)
    ///
    /// # Errors
    ///
    /// Returns an error if we fail to load the native certs or to init our verifier.
    ///
    /// # Panics
    ///
    /// See [`connector_with_no_client_auth`](RustlsConnectorConfig::connector_with_no_client_auth).
    pub fn new_with_native_certs() -> io::Result<Self> {
        RustlsConnectorConfig::new_with_native_certs()?.connector_with_no_client_auth()
    }

    /// Connect to the given host
    ///
    /// # Errors
    ///
    /// Returns a [`HandshakeError`] containing either the current state of the handshake or the
    /// failure when we couldn't complete the handshake
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
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        MidHandshakeTlsStream { session, stream }.handshake()
    }

    #[cfg(feature = "futures")]
    /// Connect to the given host asynchronously
    ///
    /// # Errors
    ///
    /// Returns a [`io::Error`] containing the failure when we couldn't complete the TLS handshake
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
                format!("Invalid domain name: {err:?}"),
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

impl<S: Read + Write> MidHandshakeTlsStream<S> {
    /// Get a reference to the inner stream
    pub fn get_ref(&self) -> &S {
        &self.stream
    }

    /// Get a mutable reference to the inner stream
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.stream
    }
}

impl<S: Read + Write + Send + 'static> MidHandshakeTlsStream<S> {
    /// Retry the handshake
    ///
    /// # Errors
    ///
    /// Returns a [`HandshakeError`] containing either the current state of the handshake or the
    /// failure when we couldn't complete the handshake
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
        assert!(
            RustlsConnectorConfig::default()
                .connector_with_no_client_auth()
                .is_err()
        );
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
    #[cfg(feature = "webpki-root-certs")]
    fn invalid_certificates_are_skipped() {
        let mut certs = vec![CertificateDer::from(vec![0x00, 0x01, 0x02])];
        certs.extend(webpki_root_certs::TLS_SERVER_ROOT_CERTS.iter().cloned());
        RustlsConnectorConfig::default()
            .with_parsable_certificates(certs)
            .connector_with_no_client_auth()
            .unwrap();
    }

    #[test]
    #[cfg(feature = "platform-verifier")]
    fn platform_verifier_rejects_invalid_extra_roots() {
        assert!(
            RustlsConnectorConfig::new_with_platform_verifier()
                .with_parsable_certificates(vec![CertificateDer::from(vec![0x00, 0x01, 0x02])])
                .connector_with_no_client_auth()
                .is_err()
        );
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
