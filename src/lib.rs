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
//! ## Rustls crypto provider (one is used, see below)
//!
//! | Flag | Notes |
//! |------|-------|
//! | `rustls--aws_lc_rs` *(default)* | Uses aws-lc-rs, preferring post-quantum key exchange |
//! | `rustls--ring` | Uses ring (more portable) |
//!
//! A process-level default installed with
//! [`CryptoProvider::install_default`](rustls::crypto::CryptoProvider::install_default)
//! takes precedence. Otherwise, the first connector build selects aws-lc-rs when both
//! provider features are enabled, and ring when only `rustls--ring` is enabled, and
//! installs it as the process-level default, like rustls's own `ClientConfig::builder()`
//! does. From then on, other rustls users in the process work even when cargo feature
//! unification enables both of rustls's providers, and `install_default` returns an
//! error. If they may run before the first connector build, or your application installs
//! its own provider, install one early in `main` instead.
//!
//! If neither feature is enabled, rustls selects the provider from its own crate
//! features, which other crates in the dependency graph may enable, and installs it as
//! the process-level default too; building a connector panics if rustls cannot select
//! exactly one. If your application relies on rustls's `custom-provider` feature, or
//! must otherwise never fall back to a built-in provider, disable this crate's provider
//! features and install your provider before building any connector.
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
/// Reexport of the [`rustls_pki_types`](https://docs.rs/rustls-pki-types) crate.
pub use rustls::pki_types as rustls_pki_types;
#[cfg(feature = "native-certs")]
/// Reexport of the [`rustls_native_certs`](https://docs.rs/rustls-native-certs) crate.
pub use rustls_native_certs;
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
    crypto::CryptoProvider,
    pki_types::{CertificateDer, PrivateKeyDer, ServerName},
};

use std::{
    error::Error,
    fmt,
    io::{self, Read, Write},
    sync::Arc,
};

/// The crypto provider for new connectors: the process-level default, installing the one
/// selected by this crate's features if there is none yet.
#[cfg(any(feature = "rustls--aws_lc_rs", feature = "rustls--ring"))]
fn crypto_provider() -> io::Result<Arc<CryptoProvider>> {
    if let Some(provider) = CryptoProvider::get_default() {
        return Ok(provider.clone());
    }

    #[cfg(feature = "rustls--aws_lc_rs")]
    let provider = rustls::crypto::aws_lc_rs::default_provider();

    #[cfg(not(feature = "rustls--aws_lc_rs"))]
    let provider = rustls::crypto::ring::default_provider();

    // If another thread installed a default in the meantime, use that one.
    let _ = provider.install_default();
    CryptoProvider::get_default()
        .cloned()
        .ok_or_else(|| io::Error::other("Failed to install a rustls crypto provider"))
}

/// The crypto provider for new connectors, as selected by rustls itself.
///
/// Panics if no process-level default is installed and rustls cannot select a provider from its
/// own crate features.
#[cfg(not(any(feature = "rustls--aws_lc_rs", feature = "rustls--ring")))]
fn crypto_provider() -> io::Result<Arc<CryptoProvider>> {
    // `ClientConfig::builder()` panics if the installed provider lacks the default protocol
    // versions; `builder()` reports that as an error instead.
    if let Some(provider) = CryptoProvider::get_default() {
        return Ok(provider.clone());
    }
    Ok(ClientConfig::builder().crypto_provider().clone())
}

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
        let builder = ClientConfig::builder_with_provider(crypto_provider()?)
            .with_safe_default_protocol_versions()
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
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
    /// Returns an error if the crypto provider does not support the default protocol versions, the
    /// verifier cannot be initialized, or no valid root certificate could be loaded.
    ///
    /// # Panics
    ///
    /// Panics if neither `rustls--aws_lc_rs` nor `rustls--ring` is enabled, no process-level
    /// crypto provider is installed, and rustls cannot select one from its own crate features.
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
    /// Returns an error if the crypto provider does not support the default protocol versions, the
    /// verifier cannot be initialized, no valid root certificate could be loaded, or key_der is
    /// invalid.
    ///
    /// # Panics
    ///
    /// See [`connector_with_no_client_auth`](Self::connector_with_no_client_auth).
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
    /// Returns an error if the crypto provider or verifier cannot be initialized.
    ///
    /// # Panics
    ///
    /// See [`RustlsConnectorConfig::connector_with_no_client_auth`].
    pub fn new_with_webpki_root_certs() -> io::Result<Self> {
        RustlsConnectorConfig::new_with_webpki_root_certs().connector_with_no_client_auth()
    }

    #[cfg(feature = "platform-verifier")]
    /// Create a new [`RustlsConnector`] using the rustls-platform-verifier mechanism (requires platform-verifier feature enabled)
    ///
    /// # Errors
    ///
    /// Returns an error if the crypto provider or verifier cannot be initialized.
    ///
    /// # Panics
    ///
    /// See [`RustlsConnectorConfig::connector_with_no_client_auth`].
    pub fn new_with_platform_verifier() -> io::Result<Self> {
        RustlsConnectorConfig::new_with_platform_verifier().connector_with_no_client_auth()
    }

    #[cfg(feature = "native-certs")]
    /// Create a new [`RustlsConnector`] using the system certs (requires native-certs feature enabled)
    ///
    /// # Errors
    ///
    /// Returns an error if native certificates cannot be loaded, or the crypto provider or
    /// verifier cannot be initialized.
    ///
    /// # Panics
    ///
    /// See [`RustlsConnectorConfig::connector_with_no_client_auth`].
    pub fn new_with_native_certs() -> io::Result<Self> {
        RustlsConnectorConfig::new_with_native_certs()?.connector_with_no_client_auth()
    }

    /// Connect to the given host
    ///
    /// # Errors
    ///
    /// Returns a [`HandshakeError`] containing either the current state of the handshake or the
    /// failure when we couldn't complete the handshake
    // FIXME: The `Send + 'static` bounds here, in `connect_async`, and on
    // `HandshakeError<S>` exclude borrowed and non-`Send` streams. Removing the
    // public `'static` bound can break downstream code that relies on its implied
    // lifetime constraint, so supporting those streams needs a compatible API.
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
        MidHandshakeTlsStream {
            session,
            stream,
            write_blocked: false,
        }
        .handshake()
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
    write_blocked: bool,
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

    /// Whether the handshake is waiting for the inner stream to accept or flush data.
    ///
    /// After a [`HandshakeError::WouldBlock`], wait for the inner stream to become writable before
    /// retrying the handshake when this returns `true`, and for it to become readable otherwise.
    #[must_use]
    pub fn wants_write(&self) -> bool {
        self.write_blocked || self.session.wants_write()
    }

    /// Whether the handshake is waiting for data from the peer.
    ///
    /// See [`wants_write`](Self::wants_write).
    #[must_use]
    pub fn wants_read(&self) -> bool {
        !self.wants_write() && self.session.wants_read()
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
        let mut io = HandshakeIo {
            stream: &mut self.stream,
            write_blocked: false,
        };
        let result = drive_handshake_io(&mut self.session, &mut io);
        self.write_blocked = io.write_blocked;
        match result {
            Ok(()) => Ok(TlsStream::new(self.session, self.stream)),
            Err(e) if is_retryable_handshake_io(&e) => Err(HandshakeError::WouldBlock(self)),
            Err(e) => Err(e.into()),
        }
    }
}

/// Make one attempt at the pending handshake I/O, returning `Ok` once the handshake is complete
/// and all of it has been flushed to the inner stream.
fn drive_handshake_io<IO: Read + Write>(
    session: &mut ClientConnection,
    io: &mut IO,
) -> io::Result<()> {
    let pending = |session: &ClientConnection| session.is_handshaking() || session.wants_write();

    // A previous attempt may have handed data over to a buffering stream that then failed to
    // flush it. rustls does not track data it handed over, so flush unconditionally.
    io.flush()?;
    if !pending(session) {
        return Ok(());
    }
    // `complete_io` gives up without an error when the peer closes the connection while we still
    // have data to send.
    if session.complete_io(io)? == (0, 0) && pending(session) {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    if pending(session) {
        Err(io::ErrorKind::WouldBlock.into())
    } else {
        Ok(())
    }
}

/// Whether the handshake can be retried after this error, once the stream is ready.
///
/// `NotConnected` is what macOS and the BSDs return while a non-blocking connect is in progress,
/// which openssl and native-tls treat as `WouldBlock` too. `Interrupted` never gets here: rustls
/// retries interrupted reads, and `HandshakeIo` interrupted writes and flushes.
fn is_retryable_handshake_io(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::NotConnected
    )
}

/// The inner stream as seen by the handshake: interrupted writes and flushes are retried in place,
/// as rustls already does for reads, blocked writes are recorded, and zero-length writes fail.
struct HandshakeIo<'a, S> {
    stream: &'a mut S,
    write_blocked: bool,
}

impl<S> HandshakeIo<'_, S> {
    fn retry_write<T>(&mut self, mut op: impl FnMut(&mut S) -> io::Result<T>) -> io::Result<T> {
        let result = retry_interrupted(|| op(self.stream));
        if let Err(err) = &result {
            self.write_blocked |= is_retryable_handshake_io(err);
        }
        result
    }
}

/// Run an I/O operation again for as long as it is interrupted, as std's helpers do.
fn retry_interrupted<T>(mut op: impl FnMut() -> io::Result<T>) -> io::Result<T> {
    loop {
        match op() {
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
            result => return result,
        }
    }
}

/// Fail writes that accept no bytes, as `write_all` does: rustls would otherwise stop writing
/// without an error, and leave the rest of the handshake unsent.
fn fail_zero_write(written: io::Result<usize>, len: usize) -> io::Result<usize> {
    match written {
        Ok(0) if len > 0 => Err(io::ErrorKind::WriteZero.into()),
        written => written,
    }
}

impl<S: Read> Read for HandshakeIo<'_, S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.stream.read(buf)
    }
}

impl<S: Write> Write for HandshakeIo<'_, S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        fail_zero_write(self.retry_write(|stream| stream.write(buf)), buf.len())
    }

    fn write_vectored(&mut self, bufs: &[io::IoSlice<'_>]) -> io::Result<usize> {
        let len = bufs.iter().map(|buf| buf.len()).sum();
        fail_zero_write(self.retry_write(|stream| stream.write_vectored(bufs)), len)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.retry_write(|stream| stream.flush())
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
    /// The inner stream is not ready: it returned `WouldBlock`, or `NotConnected` while a
    /// non-blocking connect is in progress. The handshake state is preserved so it can be retried
    /// once [`MidHandshakeTlsStream::wants_write`] tells which readiness to wait for.
    /// `Interrupted` errors are retried right away instead.
    WouldBlock(MidHandshakeTlsStream<S>),
    /// We hit a critical failure.
    Failure(io::Error),
}

impl<S: Read + Write + Send + 'static> fmt::Display for HandshakeError<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HandshakeError::WouldBlock(_) => f.write_str("Handshake needs another I/O attempt"),
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
    #[cfg(feature = "rustls--aws_lc_rs")]
    fn aws_lc_rs_prefers_post_quantum_key_exchange() {
        // Also when both provider features are enabled.
        let provider = crypto_provider().unwrap();
        assert_eq!(
            provider.kx_groups[0].name(),
            rustls::NamedGroup::X25519MLKEM768
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

    // Everything below needs a crypto provider to build a connector, or shares the scripted
    // transport of the tests that do.
    #[cfg(any(feature = "rustls--aws_lc_rs", feature = "rustls--ring"))]
    mod with_provider {
        use super::*;

        use std::collections::VecDeque;

        /// A connector for tests that never reach certificate verification.
        fn test_connector() -> RustlsConnector {
            ClientConfig::builder_with_provider(crypto_provider().unwrap())
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(RootCertStore::empty())
                .with_no_client_auth()
                .into()
        }

        #[test]
        fn selected_provider_becomes_process_default() {
            let provider = crypto_provider().unwrap();
            let default = CryptoProvider::get_default().unwrap();
            assert!(Arc::ptr_eq(&provider, default));
        }

        /// The outcome of one call on a [`ScriptedIo`].
        #[derive(Debug)]
        enum Step {
            /// Reads yield these bytes; writes accept as many bytes; flushes succeed.
            Ok(&'static [u8]),
            /// Reads report EOF; writes accept no bytes.
            Zero,
            /// The call fails with this error kind.
            Err(io::ErrorKind),
        }

        impl Step {
            /// The outcome of a write of `len` bytes.
            fn write(self, len: usize) -> io::Result<usize> {
                match self {
                    Step::Ok(data) => Ok(data.len().min(len)),
                    Step::Zero => Ok(0),
                    Step::Err(kind) => Err(kind.into()),
                }
            }

            /// The outcome of a flush.
            fn flush(self) -> io::Result<()> {
                match self {
                    Step::Err(kind) => Err(kind.into()),
                    Step::Ok(_) | Step::Zero => Ok(()),
                }
            }
        }

        #[derive(Debug, Default)]
        struct Calls {
            reads: usize,
            flushes: usize,
        }

        /// A transport following a per-call script. Once a script runs out, reads return
        /// `WouldBlock` while writes and flushes succeed.
        #[derive(Debug, Default)]
        struct ScriptedIo {
            reads: VecDeque<Step>,
            writes: VecDeque<Step>,
            flushes: VecDeque<Step>,
            calls: Calls,
        }

        impl ScriptedIo {
            fn reads(mut self, steps: impl IntoIterator<Item = Step>) -> Self {
                self.reads.extend(steps);
                self
            }

            fn writes(mut self, steps: impl IntoIterator<Item = Step>) -> Self {
                self.writes.extend(steps);
                self
            }

            fn flushes(mut self, steps: impl IntoIterator<Item = Step>) -> Self {
                self.flushes.extend(steps);
                self
            }
        }

        impl Read for ScriptedIo {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                self.calls.reads += 1;
                match self.reads.pop_front() {
                    Some(Step::Ok(data)) => {
                        buf[..data.len()].copy_from_slice(data);
                        Ok(data.len())
                    }
                    Some(Step::Zero) => Ok(0),
                    Some(Step::Err(kind)) => Err(kind.into()),
                    None => Err(io::ErrorKind::WouldBlock.into()),
                }
            }
        }

        impl Write for ScriptedIo {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                let step = self.writes.pop_front();
                step.map_or(Ok(buf.len()), |step| step.write(buf.len()))
            }

            fn flush(&mut self) -> io::Result<()> {
                self.calls.flushes += 1;
                self.flushes.pop_front().map_or(Ok(()), Step::flush)
            }
        }

        fn expect_would_block<S: Read + Write + Send + 'static>(
            result: Result<TlsStream<S>, HandshakeError<S>>,
        ) -> MidHandshakeTlsStream<S> {
            match result {
                Err(HandshakeError::WouldBlock(mid)) => mid,
                Err(HandshakeError::Failure(err)) => panic!("expected WouldBlock, got {err:?}"),
                Ok(_) => panic!("expected WouldBlock, got a TLS stream"),
            }
        }

        fn expect_failure<S: Read + Write + Send + 'static>(
            result: Result<TlsStream<S>, HandshakeError<S>>,
        ) -> io::Error {
            match result {
                Err(HandshakeError::Failure(err)) => err,
                Err(HandshakeError::WouldBlock(_)) => panic!("expected a failure, got WouldBlock"),
                Ok(_) => panic!("expected a failure, got a TLS stream"),
            }
        }

        #[test]
        fn empty_config_fails() {
            let err = RustlsConnectorConfig::default()
                .connector_with_no_client_auth()
                .unwrap_err();
            assert!(
                err.to_string().contains("valid certificates"),
                "unexpected error: {err}"
            );
        }

        #[test]
        fn partial_read_remains_mid_handshake() {
            let io = ScriptedIo::default().reads([Step::Ok(&[0x16])]);
            let mid = expect_would_block(test_connector().connect("example.com", io));
            assert!(mid.session.is_handshaking());
            // The partial record was consumed, and the next read blocked.
            assert!(mid.stream.reads.is_empty());
            assert!(mid.stream.calls.reads >= 2);
            expect_would_block(mid.handshake());
        }

        #[test]
        fn interrupted_io_is_retried_in_place() {
            let io = ScriptedIo::default()
                .reads([Step::Err(io::ErrorKind::Interrupted)])
                .writes([Step::Err(io::ErrorKind::Interrupted)])
                .flushes([Step::Err(io::ErrorKind::Interrupted)]);
            let mid = expect_would_block(test_connector().connect("example.com", io));
            // Only the read blocked: the ClientHello went out despite the interruptions, and the
            // interrupted read was retried.
            assert!(mid.stream.reads.is_empty());
            assert!(mid.stream.writes.is_empty() && mid.stream.flushes.is_empty());
            assert!(mid.session.is_handshaking());
            assert!(!mid.wants_write());
            assert!(mid.wants_read());
        }

        #[test]
        fn not_connected_is_retried() {
            let io = ScriptedIo::default().writes([Step::Err(io::ErrorKind::NotConnected)]);
            let mid = expect_would_block(test_connector().connect("example.com", io));
            assert!(mid.wants_write());

            let mid = expect_would_block(mid.handshake());
            assert!(!mid.wants_write());
            assert!(mid.wants_read());
        }

        #[test]
        fn zero_length_write_fails() {
            let io = ScriptedIo::default().writes([Step::Zero]);
            let err = expect_failure(test_connector().connect("example.com", io));
            assert_eq!(err.kind(), io::ErrorKind::WriteZero);
        }

        #[test]
        fn zero_length_write_after_partial_write_fails() {
            let io = ScriptedIo::default().writes([Step::Ok(&[0; 10]), Step::Zero]);
            let err = expect_failure(test_connector().connect("example.com", io));
            assert_eq!(err.kind(), io::ErrorKind::WriteZero);
        }

        // rustls writes through `write_vectored`: exercise `write` directly.
        #[test]
        fn handshake_io_write_retries_interrupted_and_fails_zero() {
            let mut stream =
                ScriptedIo::default().writes([Step::Err(io::ErrorKind::Interrupted), Step::Zero]);
            let mut adapter = HandshakeIo {
                stream: &mut stream,
                write_blocked: false,
            };
            let err = adapter.write(b"data").unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::WriteZero);
            assert!(!adapter.write_blocked);
        }

        #[test]
        fn handshake_io_write_records_blocked_writes() {
            let mut stream = ScriptedIo::default().writes([Step::Err(io::ErrorKind::WouldBlock)]);
            let mut adapter = HandshakeIo {
                stream: &mut stream,
                write_blocked: false,
            };
            let err = adapter.write(b"data").unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
            assert!(adapter.write_blocked);
        }

        #[test]
        fn peer_closing_fails() {
            let io = ScriptedIo::default().reads([Step::Zero]);
            let err = expect_failure(test_connector().connect("example.com", io));
            assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
        }

        #[test]
        fn not_connected_flush_is_retried() {
            let io = ScriptedIo::default()
                .flushes([Step::Ok(&[]), Step::Err(io::ErrorKind::NotConnected)]);
            let mid = expect_would_block(test_connector().connect("example.com", io));
            // The ClientHello left rustls, but the transport has yet to flush it.
            assert!(!mid.session.wants_write());
            assert!(mid.wants_write());
            assert!(!mid.wants_read());
        }

        #[test]
        fn blocked_flush_is_retried() {
            let io = ScriptedIo::default()
                .flushes([Step::Ok(&[]), Step::Err(io::ErrorKind::WouldBlock)]);
            let mid = expect_would_block(test_connector().connect("example.com", io));
            // The ClientHello left rustls, but the transport has yet to flush it.
            assert!(mid.stream.flushes.is_empty());
            assert!(!mid.session.wants_write());
            assert!(mid.wants_write());
            assert!(!mid.wants_read());

            let flushes = mid.stream.calls.flushes;
            let mid = expect_would_block(mid.handshake());
            assert!(mid.stream.calls.flushes > flushes);
            assert!(mid.wants_read());
        }

        #[cfg(feature = "futures")]
        #[test]
        fn async_connect_starts_handshake() {
            use std::{
                pin::{Pin, pin},
                sync::{
                    Arc,
                    atomic::{AtomicUsize, Ordering},
                },
                task::{Context, Poll, Waker},
            };

            /// Accepts every write, never yields data.
            #[derive(Debug, Default)]
            struct SilentPeer(Arc<AtomicUsize>);

            impl AsyncRead for SilentPeer {
                fn poll_read(
                    self: Pin<&mut Self>,
                    _: &mut Context<'_>,
                    _: &mut [u8],
                ) -> Poll<io::Result<usize>> {
                    Poll::Pending
                }
            }

            impl AsyncWrite for SilentPeer {
                fn poll_write(
                    self: Pin<&mut Self>,
                    _: &mut Context<'_>,
                    buf: &[u8],
                ) -> Poll<io::Result<usize>> {
                    self.0.fetch_add(buf.len(), Ordering::Relaxed);
                    Poll::Ready(Ok(buf.len()))
                }

                fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
                    Poll::Ready(Ok(()))
                }

                fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
                    Poll::Ready(Ok(()))
                }
            }

            let written = Arc::default();
            let connector = test_connector();
            let mut future =
                pin!(connector.connect_async("example.com", SilentPeer(Arc::clone(&written))));
            let mut cx = Context::from_waker(Waker::noop());
            assert!(future.as_mut().poll(&mut cx).is_pending());
            // The ClientHello went out.
            assert!(written.load(Ordering::Relaxed) > 0);
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
            let err = RustlsConnectorConfig::new_with_platform_verifier()
                .with_parsable_certificates(vec![CertificateDer::from(vec![0x00, 0x01, 0x02])])
                .connector_with_no_client_auth()
                .unwrap_err();
            assert_eq!(
                err.kind(),
                io::ErrorKind::InvalidData,
                "unexpected error: {err}"
            );
        }
    }
}
