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
//! let stream = TcpStream::connect("rust-lang.org:443").unwrap();
//! let mut stream = connector.connect("rust-lang.org", stream).unwrap();
//!
//! stream.write_all(b"GET / HTTP/1.0\r\nHost: rust-lang.org\r\n\r\n").unwrap();
//! let mut res = vec![];
//! stream.read_to_end(&mut res).unwrap();
//! println!("{}", String::from_utf8_lossy(&res));
//! ```

/// Reexport of the [`rustls`](https://docs.rs/rustls) crate.
pub use rustls;
/// Reexport of the [`rustls_pki_types`](https://docs.rs/rustls-pki-types) crate.
pub use rustls::pki_types as rustls_pki_types;
#[cfg(feature = "native-certs")]
/// Reexport of the [`rustls_native_certs`](https://docs.rs/rustls-native-certs) crate (requires native-certs feature enabled)
pub use rustls_native_certs;
#[cfg(feature = "platform-verifier")]
/// Reexport of the [`rustls_platform_verifier`](https://docs.rs/rustls-platform-verifier) crate (requires platform-verifier feature enabled)
pub use rustls_platform_verifier;
/// Reexport of the [`rustls_webpki`](https://docs.rs/rustls-webpki) crate.
pub use webpki;
#[cfg(feature = "webpki-root-certs")]
/// Reexport of the [`webpki_root_certs`](https://docs.rs/webpki-root-certs) crate (requires webpki-root-certs feature enabled)
pub use webpki_root_certs;

#[cfg(feature = "futures")]
use futures_io::{AsyncRead, AsyncWrite};
use rustls::{
    ClientConfig, ClientConnection, ConfigBuilder, RootCertStore, StreamOwned,
    client::WantsClientCert,
    crypto::CryptoProvider,
    pki_types::{CertificateDer, PrivateKeyDer, ServerName},
};
#[cfg(feature = "futures")]
use std::{pin::Pin, task::Poll};

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
///
/// This is rustls's [`StreamOwned`], whose `write` hands the data over to `S` but ignores errors
/// while doing so, including a `WouldBlock` from flushing `S`. If `S` buffers writes (a buffered
/// wrapper around a non-blocking socket, for instance), call `flush`, which also flushes `S`,
/// until that succeeds.
///
/// Its `write` returns `Ok(0)` when rustls's buffer is full and `S` blocks while data from the
/// peer, or the end of its stream, is waiting: treat that as a `WouldBlock`, which `write_all`
/// does not. If `conn.wants_write()` is false, sending the buffer emptied it after rustls refused
/// the data: write again, `Ok(0)` then meaning a zero buffer limit. Over an `S` that accepts no
/// bytes, `write` keeps buffering until rustls's buffer is full and then returns `Ok(0)`, while
/// `flush` fails with `WriteZero` right away.
///
/// While sending pending data fails with an error other than `WouldBlock`, its `read` fails with
/// that error too, even with data from the peer waiting at `S`.
pub type TlsStream<S> = StreamOwned<ClientConnection, S>;

#[cfg(feature = "futures")]
/// A rustls client TLS stream wrapping an underlying async I/O stream `S` (requires futures feature enabled)
pub type AsyncTlsStream<S> = futures_rustls::client::TlsStream<S>;

/// Configuration helper for [`RustlsConnector`]
#[derive(Clone, Default)]
pub struct RustlsConnectorConfig {
    store: Vec<CertificateDer<'static>>,
    // Kept apart from `store`: the platform verifier only needs them in some cases.
    #[cfg(feature = "native-certs")]
    native_certs: Vec<CertificateDer<'static>>,
    // Whether the platform verifier needs `native_certs`, decided from the environment they were
    // loaded with.
    #[cfg(all(feature = "platform-verifier", feature = "native-certs"))]
    native_certs_needed: bool,
    // A flag rather than certificates in `store`, so that without the platform verifier, which
    // gets their DER, they are only parsed once per process.
    #[cfg(feature = "webpki-root-certs")]
    webpki_root_certs: bool,
    #[cfg(feature = "platform-verifier")]
    platform_verifier: bool,
}

// Certificates would be dumped byte by byte; only count them.
impl fmt::Debug for RustlsConnectorConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut d = f.debug_struct("RustlsConnectorConfig");
        d.field("extra_roots", &self.store.len());
        #[cfg(feature = "native-certs")]
        d.field("native_certs", &self.native_certs.len());
        #[cfg(all(feature = "platform-verifier", feature = "native-certs"))]
        d.field("native_certs_needed", &self.native_certs_needed);
        #[cfg(feature = "webpki-root-certs")]
        d.field("webpki_root_certs", &self.webpki_root_certs);
        #[cfg(feature = "platform-verifier")]
        d.field("platform_verifier", &self.platform_verifier);
        d.finish()
    }
}

/// The certificates rustls-native-certs loaded from the OS store, or an error if there are none:
/// see [`RustlsConnectorConfig::with_native_certs`].
#[cfg(feature = "native-certs")]
fn native_certs(
    result: rustls_native_certs::CertificateResult,
) -> io::Result<Vec<CertificateDer<'static>>> {
    let mut errors = result.errors.into_iter();
    if result.certs.is_empty() {
        let Some(err) = errors.next() else {
            return Err(io::Error::other(
                "Could not load any valid native certificates",
            ));
        };
        for err in errors {
            log::warn!("Got error while loading native certificates: {err}");
        }
        let kind = match &err.kind {
            rustls_native_certs::ErrorKind::Io { inner, .. } => inner.kind(),
            _ => io::ErrorKind::Other,
        };
        return Err(io::Error::new(kind, err));
    }
    for err in errors {
        log::warn!("Got error while loading some native certificates: {err}");
    }
    Ok(result.certs)
}

/// Whether the platform verifier loads the native certificates itself, with rustls-native-certs.
#[cfg(all(feature = "platform-verifier", feature = "native-certs"))]
const PLATFORM_VERIFIER_LOADS_NATIVE_CERTS: bool = cfg!(all(
    unix,
    not(target_os = "android"),
    not(target_vendor = "apple"),
    not(target_arch = "wasm32"),
));

/// Whether the platform verifier trusts the OS certificate store: on wasm32, it only trusts the
/// webpki roots.
#[cfg(all(feature = "platform-verifier", feature = "native-certs"))]
const PLATFORM_VERIFIER_TRUSTS_OS_STORE: bool = cfg!(not(target_arch = "wasm32"));

/// Whether the platform verifier needs the native certificates as extra roots.
#[cfg(all(feature = "platform-verifier", feature = "native-certs"))]
fn platform_verifier_needs_native_certs() -> bool {
    needs_native_certs(
        PLATFORM_VERIFIER_LOADS_NATIVE_CERTS,
        PLATFORM_VERIFIER_TRUSTS_OS_STORE,
        std::env::var_os("SSL_CERT_FILE").as_deref(),
        std::env::var_os("SSL_CERT_DIR").as_deref(),
    )
}

/// Whether a platform verifier needs the native certificates, given whether it loads them itself,
/// whether it trusts the OS certificate store, and the values of `SSL_CERT_FILE` and
/// `SSL_CERT_DIR`, without which rustls-native-certs loads them from the OS store.
#[cfg(all(feature = "platform-verifier", feature = "native-certs"))]
fn needs_native_certs(
    loads_them_itself: bool,
    trusts_os_store: bool,
    cert_file: Option<&std::ffi::OsStr>,
    cert_dirs: Option<&std::ffi::OsStr>,
) -> bool {
    // rustls-native-certs skips empty `SSL_CERT_DIR` entries.
    let elsewhere = cert_file.is_some()
        || cert_dirs
            .is_some_and(|dirs| std::env::split_paths(dirs).any(|dir| !dir.as_os_str().is_empty()));
    !loads_them_itself && (!trusts_os_store || elsewhere)
}

/// The native certificates that webpki can parse, skipping the others as the platform verifier
/// does with the OS store where it loads it itself. Where this is used, the platform verifier
/// still parses the remaining ones, with the OS's own parser on Apple platforms and Windows and
/// with webpki on wasm32; on Android, `builder()` refuses them.
#[cfg(all(feature = "platform-verifier", feature = "native-certs"))]
fn parsable_native_certs(mut certs: Vec<CertificateDer<'static>>) -> Vec<CertificateDer<'static>> {
    let len = certs.len();
    certs.retain(|cert| webpki::anchor_from_trusted_cert(cert).is_ok());
    warn_ignored_roots(len - certs.len(), "native");
    certs
}

/// Log how many root certificates from the given origin could not be parsed.
fn warn_ignored_roots(ignored: usize, origin: &str) {
    if ignored > 0 {
        log::warn!("{ignored} {origin} root certificates were ignored due to errors");
    }
}

/// The webpki-root-certs set as trust anchors, parsed on first use.
///
/// They borrow the static certificates, so adding them to a store copies no certificate data.
#[cfg(feature = "webpki-root-certs")]
fn webpki_trust_anchors() -> &'static [rustls::pki_types::TrustAnchor<'static>] {
    static ANCHORS: std::sync::OnceLock<Vec<rustls::pki_types::TrustAnchor<'static>>> =
        std::sync::OnceLock::new();
    static WARNED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    let anchors = ANCHORS.get_or_init(|| {
        webpki_root_certs::TLS_SERVER_ROOT_CERTS
            .iter()
            .filter_map(|cert| webpki::anchor_from_trusted_cert(cert).ok())
            .collect()
    });
    // Outside `get_or_init`, which a logger that builds a connector would re-enter.
    if !WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
        let ignored = webpki_root_certs::TLS_SERVER_ROOT_CERTS.len() - anchors.len();
        warn_ignored_roots(ignored, "webpki");
    }
    anchors
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
    /// See [`with_native_certs`](Self::with_native_certs).
    pub fn new_with_native_certs() -> io::Result<Self> {
        Self::default().with_native_certs()
    }

    /// Queue the given DER-encoded certificates as additional roots.
    ///
    /// Parsing is deferred until the connector is built. Certificates that fail to parse are then
    /// skipped in a best-effort fashion, because large collections of root certificates often
    /// include ancient or syntactically invalid certificates.
    ///
    /// The exception is the platform verifier (`with_platform_verifier`, with the
    /// `platform-verifier` feature): it rejects unparsable extra roots outright, so a single bad
    /// certificate makes building the connector fail. On Android, it cannot use extra roots at
    /// all, so building the connector fails if any were added.
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
        self.webpki_root_certs = true;
        self
    }

    #[cfg(feature = "platform-verifier")]
    /// Use the rustls-platform-verifier mechanism (requires platform-verifier feature enabled)
    ///
    /// Except on wasm32, where it only trusts the webpki roots, the platform verifier trusts the OS
    /// certificate store, so roots from `with_native_certs` are only passed to it, skipping those
    /// that fail to parse, when `SSL_CERT_FILE` or `SSL_CERT_DIR` pointed rustls-native-certs
    /// elsewhere during a call to it (and then all of them are), and not even then on Unix systems
    /// other than Apple platforms and Android, such as Linux and the BSDs, where it loads them
    /// itself. On wasm32, they are always passed to it. Other roots are passed to it as extra
    /// roots: see [`add_parsable_certificates`](Self::add_parsable_certificates) for how it
    /// handles them.
    ///
    /// On Android, the platform verifier cannot take any roots besides the platform's, so building
    /// the connector fails if it would pass it some: extra roots, the webpki roots, or roots from
    /// `with_native_certs` when `SSL_CERT_FILE` or `SSL_CERT_DIR` pointed rustls-native-certs
    /// elsewhere. rustls-platform-verifier must also be initialized from Java first (see
    /// [`rustls_platform_verifier::android`](https://docs.rs/rustls-platform-verifier/0.7/rustls_platform_verifier/android/index.html));
    /// otherwise the first handshake panics.
    #[must_use]
    pub fn with_platform_verifier(mut self) -> Self {
        self.platform_verifier = true;
        self
    }

    #[cfg(feature = "native-certs")]
    /// Add the system certs (requires native-certs feature enabled)
    ///
    /// With the platform verifier, they are only used in some cases, as it trusts the OS
    /// certificate store itself except on wasm32 (see `with_platform_verifier`). Whether
    /// `SSL_CERT_FILE` or `SSL_CERT_DIR` point rustls-native-certs elsewhere is checked here, as
    /// the certificates are loaded.
    ///
    /// # Errors
    ///
    /// Returns an error if the OS certificate store yielded no certificate. If it could not be
    /// read, the error carries the underlying error, and its kind when that is an I/O error.
    /// Certificates that fail to load individually are logged and skipped.
    pub fn with_native_certs(mut self) -> io::Result<Self> {
        #[cfg(feature = "platform-verifier")]
        {
            self.native_certs_needed |= platform_verifier_needs_native_certs();
        }
        self.native_certs
            .extend(native_certs(rustls_native_certs::load_native_certs())?);
        Ok(self)
    }

    /// The roots to pass to the platform verifier on top of those it trusts itself.
    #[cfg(feature = "platform-verifier")]
    fn platform_verifier_extra_roots(self) -> Vec<CertificateDer<'static>> {
        // Unlike native certificates, these are not pre-filtered: the caller asked for each of
        // them, so one the verifier cannot parse fails the build rather than being dropped, and
        // webpki would also drop some that the platform's own parser, used on Apple platforms and
        // Windows, accepts.
        #[allow(unused_mut)]
        let mut extra_roots = self.store;
        #[cfg(feature = "native-certs")]
        if self.native_certs_needed {
            extra_roots.extend(parsable_native_certs(self.native_certs));
        }
        #[cfg(feature = "webpki-root-certs")]
        if self.webpki_root_certs {
            extra_roots.extend(webpki_root_certs::TLS_SERVER_ROOT_CERTS.iter().cloned());
        }
        extra_roots
    }

    fn builder(self) -> io::Result<ConfigBuilder<ClientConfig, WantsClientCert>> {
        let builder = ClientConfig::builder_with_provider(crypto_provider()?)
            .with_safe_default_protocol_versions()
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
        #[cfg(feature = "platform-verifier")]
        if self.platform_verifier {
            let provider = builder.crypto_provider().clone();
            let extra_roots = self.platform_verifier_extra_roots();
            let verifier = if extra_roots.is_empty() {
                rustls_platform_verifier::Verifier::new(provider)
            } else {
                // `rustls-platform-verifier` has no `new_with_extra_roots` on Android: its
                // trust decisions are delegated to the platform and cannot be augmented from
                // Rust. Refuse rather than silently trusting fewer roots than the caller asked
                // for.
                #[cfg(target_os = "android")]
                return Err(io::Error::other(
                    "extra root certificates cannot be combined with the platform verifier on Android",
                ));
                #[cfg(not(target_os = "android"))]
                rustls_platform_verifier::Verifier::new_with_extra_roots(extra_roots, provider)
            };
            let verifier =
                verifier.map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
            // `.dangerous()` is the rustls API for supplying a custom verifier;
            // it does not bypass verification — `Verifier` delegates to the OS store.
            return Ok(builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(verifier)));
        }
        let mut store = RootCertStore::empty();
        #[cfg(feature = "webpki-root-certs")]
        if self.webpki_root_certs {
            store.extend(webpki_trust_anchors().iter().cloned());
        }
        let roots = self.store.into_iter();
        #[cfg(feature = "native-certs")]
        let roots = roots.chain(self.native_certs);
        let (_, ignored) = store.add_parsable_certificates(roots);
        warn_ignored_roots(ignored, "CA");
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
    /// verifier cannot be initialized, or no valid root certificate could be loaded.
    ///
    /// Also returns an error with kind [`InvalidData`](io::ErrorKind::InvalidData) if key_der is
    /// invalid. When the crypto provider exposes the public key of key_der, as the built-in ones
    /// do, it also does if cert_chain is empty, its first certificate cannot be parsed, or that
    /// certificate does not match key_der. rustls words some of these errors as if the peer had
    /// sent the certificate.
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
///
/// Building a connector can load and parse root certificates, which takes milliseconds with the
/// OS certificate store: native certificates load it, and so does the platform verifier on Unix
/// systems other than Apple platforms and Android. Build one and clone it, which only shares the
/// configuration, rather than building one per connection: reusing a connector also lets rustls
/// resume TLS sessions.
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

    /// Connect to the given host, over a stream that does not need to be `Send`
    ///
    /// # Errors
    ///
    /// Returns a [`HandshakeError`] containing either the current state of the handshake or the
    /// failure when we couldn't complete the handshake
    ///
    /// # Panics
    ///
    /// On Android, panics when using the platform verifier before rustls-platform-verifier was
    /// initialized (see `RustlsConnectorConfig::with_platform_verifier`).
    // FIXME: The `'static` bounds here and on `MidHandshakeTlsStream::handshake` exclude borrowed
    // streams. Lifting them is a breaking change: downstream code may rely on the `'static` bound
    // of `HandshakeError<S>` as an implied bound.
    #[allow(clippy::result_large_err)]
    pub fn connect<S: Read + Write + 'static>(
        &self,
        domain: &str,
        stream: S,
    ) -> Result<TlsStream<S>, HandshakeError<S>> {
        let session = ClientConnection::new(self.0.clone(), server_name(domain)?)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        MidHandshakeTlsStream {
            session,
            stream,
            write_blocked: false,
        }
        .handshake()
    }

    #[cfg(feature = "futures")]
    /// Connect to the given host asynchronously, over an owned or borrowed stream that does not
    /// need to be `Send` (requires futures feature enabled)
    ///
    /// The returned future borrows neither the connector nor `domain`, and is `Send` and `'static`
    /// when the stream is, so with an owned stream it can be spawned. The TLS connection is set up
    /// right away, generating key shares and taking a session resumption ticket from the
    /// connector, so the future only drives the handshake.
    ///
    /// futures-rustls drives the handshake and the returned stream. Unlike
    /// [`connect`](Self::connect), it keeps polling a stream whose writes accept no bytes: the
    /// handshake, and flushing or closing the returned stream, then spin, and writes to that
    /// stream end up pending forever. The handshake also stalls if the stream buffers its data and
    /// returns `Pending` from a flush. And with a zero buffer limit, writes to the returned stream
    /// spin.
    ///
    /// # Errors
    ///
    /// The future resolves to an [`io::Error`] containing the failure when we couldn't complete
    /// the TLS handshake. TLS errors have kind [`InvalidData`](io::ErrorKind::InvalidData), as
    /// with [`connect`](Self::connect).
    ///
    /// # Panics
    ///
    /// The future panics in the same case as [`connect`](Self::connect).
    pub fn connect_async<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        domain: &str,
        stream: S,
    ) -> impl Future<Output = io::Result<AsyncTlsStream<S>>> + use<S> {
        // Not an async block, which would keep its inputs next to the handshake they moved into.
        let mut connect = server_name(domain)
            .map(|domain| {
                futures_rustls::TlsConnector::from(self.0.clone()).connect(domain, stream)
            })
            .map_err(Some);
        std::future::poll_fn(move |cx| match &mut connect {
            Ok(connect) => Pin::new(connect)
                .poll(cx)
                .map_err(tls_errors_as_invalid_data),
            Err(err) => Poll::Ready(Err(err.take().expect("polled after completion"))),
        })
    }
}

/// futures-rustls reports a failure to create the TLS connection with kind `Other`, where
/// [`RustlsConnector::connect`] and rustls's own I/O helpers use `InvalidData`.
#[cfg(feature = "futures")]
fn tls_errors_as_invalid_data(err: io::Error) -> io::Error {
    if err.kind() != io::ErrorKind::Other {
        return err;
    }
    match err.downcast::<rustls::Error>() {
        Ok(err) => io::Error::new(io::ErrorKind::InvalidData, err),
        Err(err) => err,
    }
}

fn server_name(domain: &str) -> io::Result<ServerName<'static>> {
    Ok(ServerName::try_from(domain)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?
        .to_owned())
}

/// A TLS stream which has been interrupted during the handshake
#[derive(Debug)]
pub struct MidHandshakeTlsStream<S> {
    session: ClientConnection,
    stream: S,
    write_blocked: bool,
}

impl<S> MidHandshakeTlsStream<S> {
    /// Get a reference to the inner stream
    #[must_use]
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

impl<S: Read + Write + 'static> MidHandshakeTlsStream<S> {
    /// Retry the handshake
    ///
    /// # Errors
    ///
    /// Returns a [`HandshakeError`] containing either the current state of the handshake or the
    /// failure when we couldn't complete the handshake
    ///
    /// # Panics
    ///
    /// See [`RustlsConnector::connect`]: on a non-blocking stream, the server certificate is
    /// verified by a later call to this method.
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

impl<S> fmt::Display for MidHandshakeTlsStream<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MidHandshakeTlsStream")
    }
}

/// An error returned while performing the handshake
#[allow(clippy::large_enum_variant)]
// The definition does not need the `'static` bound, but downstream signatures may rely on it as an
// implied bound, so removing it would be a breaking change.
pub enum HandshakeError<S: 'static> {
    /// The inner stream is not ready: it returned `WouldBlock`, or `NotConnected` while a
    /// non-blocking connect is in progress. The handshake state is preserved so it can be retried
    /// once [`MidHandshakeTlsStream::wants_write`] tells which readiness to wait for.
    /// `Interrupted` errors are retried right away instead.
    WouldBlock(MidHandshakeTlsStream<S>),
    /// We hit a critical failure.
    Failure(io::Error),
}

impl<S: 'static> fmt::Display for HandshakeError<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HandshakeError::WouldBlock(_) => f.write_str("Handshake needs another I/O attempt"),
            // The error itself is the source, so that error reporters don't print it twice.
            HandshakeError::Failure(_) => f.write_str("TLS handshake failed"),
        }
    }
}

impl<S: 'static> fmt::Debug for HandshakeError<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut d = f.debug_tuple("HandshakeError");
        match self {
            HandshakeError::WouldBlock(_) => d.field(&"WouldBlock"),
            HandshakeError::Failure(err) => d.field(&err),
        }
        .finish()
    }
}

impl<S: 'static> Error for HandshakeError<S> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            HandshakeError::Failure(err) => Some(err),
            _ => None,
        }
    }
}

impl<S: 'static> From<io::Error> for HandshakeError<S> {
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
        assert_eq!(err.to_string(), "TLS handshake failed");
        assert!(format!("{err:?}").contains("test error"));
        assert_eq!(err.source().unwrap().to_string(), "test error");
    }

    #[test]
    #[cfg(feature = "native-certs")]
    fn empty_native_store_is_an_error() {
        let err = native_certs(rustls_native_certs::CertificateResult::default()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Other);
    }

    #[test]
    #[cfg(feature = "native-certs")]
    fn unreadable_native_store_keeps_its_error() {
        let mut result = rustls_native_certs::CertificateResult::default();
        result.errors.push(rustls_native_certs::Error {
            context: "test",
            kind: rustls_native_certs::ErrorKind::Io {
                inner: io::ErrorKind::NotFound.into(),
                path: "no/such/file".into(),
            },
        });
        let err = native_certs(result).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        assert!(err.get_ref().unwrap().is::<rustls_native_certs::Error>());
    }

    #[test]
    #[cfg(all(feature = "platform-verifier", feature = "native-certs"))]
    fn native_certs_are_needed_where_redirected_or_untrusted() {
        let file = Some(std::ffi::OsStr::new("ca.pem"));
        let dirs = Some(std::ffi::OsStr::new("certs"));
        let empty_dirs = std::env::join_paths(["", ""]).unwrap();
        assert!(!needs_native_certs(false, true, None, None));
        assert!(needs_native_certs(false, true, file, None));
        assert!(needs_native_certs(false, true, None, dirs));
        assert!(!needs_native_certs(false, true, None, Some(&empty_dirs)));
        assert!(!needs_native_certs(true, true, file, dirs));
        assert!(needs_native_certs(false, false, None, None));
    }

    // Tests set the native-certificates decision directly, so pin the constants it is made of on
    // known targets (an item, so that `cargo check --tests` evaluates it).
    #[cfg(all(
        feature = "platform-verifier",
        feature = "native-certs",
        not(target_arch = "wasm32")
    ))]
    const _: () = {
        assert!(PLATFORM_VERIFIER_TRUSTS_OS_STORE);
        #[cfg(any(target_os = "linux", target_os = "freebsd"))]
        assert!(PLATFORM_VERIFIER_LOADS_NATIVE_CERTS);
        #[cfg(any(windows, target_vendor = "apple", target_os = "android"))]
        assert!(!PLATFORM_VERIFIER_LOADS_NATIVE_CERTS);
    };

    #[test]
    #[cfg(all(
        feature = "platform-verifier",
        feature = "native-certs",
        feature = "webpki-root-certs"
    ))]
    fn unparsable_native_certs_are_skipped() {
        let valid = webpki_root_certs::TLS_SERVER_ROOT_CERTS[0].clone();
        let invalid = CertificateDer::from(vec![0x00, 0x01, 0x02]);
        assert_eq!(parsable_native_certs(vec![invalid, valid.clone()]), [valid]);
    }

    #[test]
    #[cfg(feature = "webpki-root-certs")]
    fn webpki_trust_anchors_clone_without_copying() {
        let anchors = webpki_trust_anchors();
        assert_eq!(
            anchors.len(),
            webpki_root_certs::TLS_SERVER_ROOT_CERTS.len()
        );
        // Clones of borrowed anchors share their data; owned ones would copy it.
        for anchor in anchors {
            let clone = anchor.clone();
            assert_eq!(clone.subject.as_ptr(), anchor.subject.as_ptr());
        }
    }

    #[test]
    #[cfg(feature = "webpki-root-certs")]
    fn config_debug_output_stays_small() {
        let config = RustlsConnectorConfig::new_with_webpki_root_certs()
            .with_parsable_certificates(vec![CertificateDer::from(vec![0x00; 1024])]);
        let debug = format!("{config:?}");
        assert!(debug.len() < 200, "{debug}");
        assert!(debug.contains("extra_roots: 1"), "{debug}");
    }

    #[test]
    #[cfg(all(feature = "platform-verifier", feature = "webpki-root-certs"))]
    fn platform_verifier_gets_webpki_roots() {
        let roots = RustlsConnectorConfig::new_with_platform_verifier()
            .with_webpki_root_certs()
            .platform_verifier_extra_roots();
        assert_eq!(roots, webpki_root_certs::TLS_SERVER_ROOT_CERTS);
    }

    // Everything below needs a crypto provider to build a connector, or shares the scripted
    // transport of the tests that do.
    #[cfg(any(feature = "rustls--aws_lc_rs", feature = "rustls--ring"))]
    mod with_provider {
        use super::*;

        use std::collections::VecDeque;
        #[cfg(feature = "futures")]
        use std::{
            pin::pin,
            task::{Context, Waker},
        };

        /// A config trusting the test CA, which signed the end-to-end server's certificate.
        fn test_config() -> RustlsConnectorConfig {
            RustlsConnectorConfig::default().with_parsable_certificates(vec![test_ca()])
        }

        /// A connector built from [`test_config`].
        fn test_connector() -> RustlsConnector {
            test_config().connector_with_no_client_auth().unwrap()
        }

        /// The test CA, which signed the end-to-end server's certificate.
        fn test_ca() -> CertificateDer<'static> {
            CertificateDer::from(&include_bytes!("../test-data/ca.der")[..])
        }

        /// The end-to-end server's certificate, for `example.com`.
        fn test_cert() -> CertificateDer<'static> {
            CertificateDer::from(&include_bytes!("../test-data/example.com.der")[..])
        }

        /// The end-to-end server's private key.
        fn test_key() -> PrivateKeyDer<'static> {
            PrivateKeyDer::try_from(&include_bytes!("../test-data/example.com.key.der")[..])
                .unwrap()
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
            writes: usize,
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
                self.calls.writes += 1;
                let step = self.writes.pop_front();
                step.map_or(Ok(buf.len()), |step| step.write(buf.len()))
            }

            fn flush(&mut self) -> io::Result<()> {
                self.calls.flushes += 1;
                self.flushes.pop_front().map_or(Ok(()), Step::flush)
            }
        }

        /// Polls `future` once, with a waker that does nothing.
        #[cfg(feature = "futures")]
        fn poll_once<F: Future>(future: F) -> Poll<F::Output> {
            pin!(future).poll(&mut Context::from_waker(Waker::noop()))
        }

        /// Adapts a synchronous test transport to async I/O, where it would block.
        #[cfg(feature = "futures")]
        fn pending_on_would_block<T>(result: io::Result<T>) -> Poll<io::Result<T>> {
            match result {
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
                result => Poll::Ready(result),
            }
        }

        /// Implements async I/O for a synchronous test transport with `pending_on_would_block`.
        #[cfg(feature = "futures")]
        macro_rules! impl_async_io {
            ($io:ty) => {
                impl AsyncRead for $io {
                    fn poll_read(
                        self: Pin<&mut Self>,
                        _: &mut std::task::Context<'_>,
                        buf: &mut [u8],
                    ) -> Poll<io::Result<usize>> {
                        pending_on_would_block(self.get_mut().read(buf))
                    }
                }

                impl AsyncWrite for $io {
                    fn poll_write(
                        self: Pin<&mut Self>,
                        _: &mut std::task::Context<'_>,
                        buf: &[u8],
                    ) -> Poll<io::Result<usize>> {
                        pending_on_would_block(self.get_mut().write(buf))
                    }

                    fn poll_flush(
                        self: Pin<&mut Self>,
                        _: &mut std::task::Context<'_>,
                    ) -> Poll<io::Result<()>> {
                        pending_on_would_block(self.get_mut().flush())
                    }

                    fn poll_close(
                        self: Pin<&mut Self>,
                        _: &mut std::task::Context<'_>,
                    ) -> Poll<io::Result<()>> {
                        Poll::Ready(Ok(()))
                    }
                }
            };
        }

        fn expect_would_block<S: Read + Write + 'static>(
            result: Result<TlsStream<S>, HandshakeError<S>>,
        ) -> MidHandshakeTlsStream<S> {
            match result {
                Err(HandshakeError::WouldBlock(mid)) => mid,
                Err(HandshakeError::Failure(err)) => panic!("expected WouldBlock, got {err:?}"),
                Ok(_) => panic!("expected WouldBlock, got a TLS stream"),
            }
        }

        fn expect_failure<S: Read + Write + 'static>(
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
        fn sync_connect_accepts_non_send_stream() {
            trait LocalIo: Read + Write {}
            impl<T: Read + Write> LocalIo for T {}

            let io: Box<dyn LocalIo> = Box::new(ScriptedIo::default());
            let mid = expect_would_block(test_connector().connect("example.com", io));
            expect_would_block(mid.handshake());
        }

        #[test]
        fn invalid_domain_keeps_typed_error() {
            let err = expect_failure(
                test_connector().connect("not a valid host!", ScriptedIo::default()),
            );
            assert_eq!(err.kind(), io::ErrorKind::InvalidData);
            let inner = err.get_ref().unwrap();
            assert!(inner.is::<rustls::pki_types::InvalidDnsNameError>());
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

        /// A connector whose configuration rustls rejects when creating a connection.
        fn invalid_connector() -> RustlsConnector {
            let mut config = ClientConfig::clone(&test_connector().0);
            config.max_fragment_size = Some(10);
            config.into()
        }

        #[test]
        fn invalid_connection_config_fails() {
            let err =
                expect_failure(invalid_connector().connect("example.com", ScriptedIo::default()));
            assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        }

        #[cfg(feature = "futures")]
        mod futures {
            use super::*;

            impl_async_io!(ScriptedIo);

            fn expect_async_failure<T>(future: impl Future<Output = io::Result<T>>) -> io::Error {
                match poll_once(future) {
                    Poll::Ready(Err(err)) => err,
                    Poll::Ready(Ok(_)) => panic!("expected a failure, got a TLS stream"),
                    Poll::Pending => panic!("expected a failure, got Pending"),
                }
            }

            #[test]
            fn async_connect_starts_handshake() {
                let mut io = ScriptedIo::default();
                let poll = poll_once(test_connector().connect_async("example.com", &mut io));
                assert!(poll.is_pending());
                // The ClientHello went out.
                assert!(io.calls.writes > 0);
            }

            #[test]
            fn async_connect_accepts_borrowed_non_send_stream() {
                trait LocalIo: AsyncRead + AsyncWrite + Unpin {}
                impl<T: AsyncRead + AsyncWrite + Unpin> LocalIo for T {}

                let mut io: Box<dyn LocalIo> = Box::new(ScriptedIo::default());
                let poll = poll_once(test_connector().connect_async("example.com", &mut io));
                assert!(poll.is_pending());
            }

            #[test]
            fn async_connect_future_is_static() {
                fn spawnable<F: Future + Send + 'static>(future: F) -> F {
                    future
                }

                let connector = test_connector();
                let domain = String::from("example.com");
                let future = spawnable(connector.connect_async(&domain, ScriptedIo::default()));
                drop((connector, domain));
                assert!(poll_once(future).is_pending());
            }

            #[test]
            fn async_connect_reports_errors_like_connect() {
                let connector = invalid_connector();
                let err = expect_async_failure(
                    connector.connect_async("example.com", ScriptedIo::default()),
                );
                assert_eq!(err.kind(), io::ErrorKind::InvalidData);
            }

            #[test]
            fn async_invalid_domain_keeps_typed_error() {
                let connect =
                    test_connector().connect_async("not a valid host!", ScriptedIo::default());
                let err = expect_async_failure(connect);
                assert_eq!(err.kind(), io::ErrorKind::InvalidData);
                let inner = err.get_ref().unwrap();
                assert!(inner.is::<rustls::pki_types::InvalidDnsNameError>());
            }

            #[test]
            fn async_peer_closing_fails() {
                let io = ScriptedIo::default().reads([Step::Zero]);
                let err = expect_async_failure(test_connector().connect_async("example.com", io));
                // Not a TLS error, so it keeps its kind.
                assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
            }
        }

        #[test]
        #[cfg(feature = "webpki-root-certs")]
        fn webpki_root_certs_connector_builds() {
            RustlsConnector::new_with_webpki_root_certs().unwrap();
        }

        /// Whether the OS certificate store is empty, as in some package build environments,
        /// where the tests that need it skip.
        #[cfg(feature = "native-certs")]
        fn os_store_is_empty() -> bool {
            rustls_native_certs::load_native_certs().certs.is_empty()
        }

        #[test]
        #[cfg(feature = "native-certs")]
        fn native_certs_connector_builds() {
            if os_store_is_empty() {
                return;
            }
            RustlsConnector::new_with_native_certs().unwrap();
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
        #[cfg(all(feature = "platform-verifier", feature = "native-certs"))]
        fn platform_verifier_tolerates_invalid_native_certs() {
            // Pre-filtered where it needs them, as it would parse them strictly. The test CA lets
            // the verifier build without an OS certificate store.
            let mut config = RustlsConnectorConfig::new_with_platform_verifier()
                .with_parsable_certificates(vec![test_ca()]);
            config.native_certs = vec![CertificateDer::from(vec![0x00, 0x01, 0x02])];
            config.native_certs_needed = true;
            config.connector_with_no_client_auth().unwrap();
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
            // Callers may downcast to the rustls error.
            assert!(err.get_ref().unwrap().is::<rustls::Error>(), "{err:?}");
        }

        #[test]
        fn unusable_client_certificates_are_rejected() {
            let connector = |chain, key| test_config().connector_with_single_cert(chain, key);
            connector(vec![test_cert()], test_key()).unwrap();
            let invalid_key = PrivateKeyDer::Pkcs8(vec![0x00, 0x01, 0x02].into());
            for (case, chain, key) in [
                ("empty chain", vec![], test_key()),
                (
                    "unparsable certificate",
                    vec![CertificateDer::from(vec![0x00, 0x01, 0x02])],
                    test_key(),
                ),
                ("mismatched key", vec![test_ca()], test_key()),
                ("invalid key", vec![test_cert()], invalid_key),
            ] {
                let err = connector(chain, key).expect_err(case);
                assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{case}: {err}");
            }
        }

        mod end_to_end {
            use super::*;

            use std::sync::{Mutex, PoisonError};

            type Pipe = Arc<Mutex<VecDeque<u8>>>;

            /// One end of an in-memory connection. Reads block while there is nothing to read.
            /// When `buffered`, writes are held back until flushed, and the first flush of each
            /// batch blocks. `writes_blocked` makes writes block, and `closed` makes reads report
            /// that the peer closed the connection.
            #[derive(Debug, Default)]
            struct PipeEnd {
                rx: Pipe,
                tx: Pipe,
                buffered: bool,
                pending: Vec<u8>,
                flush_blocked: bool,
                writes_blocked: bool,
                closed: bool,
            }

            /// The client end of an in-memory connection, with a server for `example.com` on the
            /// other end.
            fn pipe(buffered: bool) -> (PipeEnd, Server) {
                let (a, b) = (Pipe::default(), Pipe::default());
                let client = PipeEnd {
                    rx: a.clone(),
                    tx: b.clone(),
                    buffered,
                    ..PipeEnd::default()
                };
                let server = PipeEnd {
                    rx: b,
                    tx: a,
                    ..PipeEnd::default()
                };
                (client, Server::new(server))
            }

            impl Read for PipeEnd {
                fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                    if self.closed {
                        return Ok(0);
                    }
                    let mut rx = self.rx.lock().unwrap_or_else(PoisonError::into_inner);
                    if rx.is_empty() {
                        return Err(io::ErrorKind::WouldBlock.into());
                    }
                    rx.read(buf)
                }
            }

            impl Write for PipeEnd {
                fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                    if self.writes_blocked {
                        return Err(io::ErrorKind::WouldBlock.into());
                    }
                    if self.buffered {
                        self.pending.extend_from_slice(buf);
                    } else {
                        self.tx
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .extend(buf);
                    }
                    Ok(buf.len())
                }

                fn flush(&mut self) -> io::Result<()> {
                    if self.pending.is_empty() {
                        return Ok(());
                    }
                    if !self.flush_blocked {
                        self.flush_blocked = true;
                        return Err(io::ErrorKind::WouldBlock.into());
                    }
                    self.flush_blocked = false;
                    self.tx
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .extend(self.pending.drain(..));
                    Ok(())
                }
            }

            #[cfg(feature = "futures")]
            impl_async_io!(PipeEnd);

            struct Server {
                conn: rustls::ServerConnection,
                io: PipeEnd,
            }

            impl Server {
                fn new(io: PipeEnd) -> Self {
                    let certs = vec![test_cert(), test_ca()];
                    let key = test_key();
                    let config =
                        rustls::ServerConfig::builder_with_provider(crypto_provider().unwrap())
                            .with_safe_default_protocol_versions()
                            .unwrap()
                            .with_no_client_auth()
                            .with_single_cert(certs, key)
                            .unwrap();
                    let conn = rustls::ServerConnection::new(Arc::new(config)).unwrap();
                    Self { conn, io }
                }

                fn pump(&mut self) {
                    match self.conn.complete_io(&mut self.io) {
                        Ok(_) => {}
                        Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
                        Err(err) => panic!("server failed: {err}"),
                    }
                }
            }

            /// A connector trusting the test CA, connected to a server for `example.com`.
            fn connect(client_io: PipeEnd, server: &mut Server) -> TlsStream<PipeEnd> {
                try_connect(&test_connector(), client_io, server).unwrap()
            }

            fn try_connect(
                connector: &RustlsConnector,
                client_io: PipeEnd,
                server: &mut Server,
            ) -> io::Result<TlsStream<PipeEnd>> {
                let mut result = connector.connect("example.com", client_io);
                for _ in 0..100 {
                    match result {
                        Ok(tls) => {
                            // Bounded, so that a client leaving data unsent fails the test
                            // instead of hanging it.
                            for _ in 0..10 {
                                if !server.conn.is_handshaking() {
                                    return Ok(tls);
                                }
                                server.pump();
                            }
                            return Err(io::Error::other(
                                "the client left part of the handshake unsent",
                            ));
                        }
                        Err(HandshakeError::WouldBlock(mid)) => {
                            server.pump();
                            result = mid.handshake();
                        }
                        Err(HandshakeError::Failure(err)) => return Err(err),
                    }
                }
                Err(io::Error::other("the handshake made no progress"))
            }

            /// Bounded, so that a flush that never completes fails the test instead of hanging it.
            fn retry(mut op: impl FnMut() -> io::Result<()>) {
                for _ in 0..10 {
                    match op() {
                        Ok(()) => return,
                        Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
                        Err(err) => panic!("flush failed: {err}"),
                    }
                }
                panic!("the flush never completed");
            }

            fn send_ping(buffered: bool) {
                let (client_io, mut server) = pipe(buffered);
                let mut tls = connect(client_io, &mut server);
                tls.write_all(b"ping").unwrap();
                retry(|| tls.flush());
                expect_ping(&mut server);
            }

            fn expect_ping(server: &mut Server) {
                server.pump();
                let mut ping = [0; 4];
                server.conn.reader().read_exact(&mut ping).unwrap();
                assert_eq!(&ping, b"ping");
            }

            /// `connect`'s async counterpart.
            #[cfg(feature = "futures")]
            fn async_connect(client_io: PipeEnd, server: &mut Server) -> AsyncTlsStream<PipeEnd> {
                let mut connect = pin!(test_connector().connect_async("example.com", client_io));
                // Bounded, so that a stalled handshake fails the test instead of hanging it.
                let tls = (0..10)
                    .find_map(|_| {
                        let poll = poll_once(connect.as_mut());
                        server.pump();
                        match poll {
                            Poll::Ready(tls) => Some(tls.unwrap()),
                            Poll::Pending => None,
                        }
                    })
                    .expect("the handshake made no progress");
                assert!(!tls.get_ref().1.is_handshaking());
                tls
            }

            #[cfg(feature = "futures")]
            fn async_send_ping() {
                let (client_io, mut server) = pipe(false);
                let mut tls = async_connect(client_io, &mut server);
                let mut cx = Context::from_waker(Waker::noop());
                let mut tls = Pin::new(&mut tls);
                let written = tls.as_mut().poll_write(&mut cx, b"ping");
                assert!(matches!(written, Poll::Ready(Ok(4))), "{written:?}");
                retry(|| match tls.as_mut().poll_flush(&mut cx) {
                    Poll::Ready(result) => result,
                    Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
                });
                expect_ping(&mut server);
            }

            #[test]
            fn peer_closing_before_the_last_flight_fails() {
                let (client_io, mut server) = pipe(false);
                let mut mid =
                    expect_would_block(test_connector().connect("example.com", client_io));
                server.pump();
                mid.get_mut().writes_blocked = true;
                // The client is done with the handshake, except for sending its last flight.
                let mut mid = expect_would_block(mid.handshake());
                assert!(!mid.session.is_handshaking() && mid.wants_write());
                mid.get_mut().closed = true;
                let err = expect_failure(mid.handshake());
                assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
            }

            #[test]
            fn handshake_completes() {
                send_ping(false);
            }

            #[test]
            fn handshake_completes_over_a_buffering_stream() {
                send_ping(true);
            }

            #[test]
            #[cfg(feature = "futures")]
            fn async_handshake_completes() {
                async_send_ping();
            }

            #[test]
            #[cfg(all(
                feature = "platform-verifier",
                feature = "native-certs",
                any(target_os = "linux", target_os = "freebsd")
            ))]
            fn platform_verifier_trusts_native_certs_it_needs() {
                // There, it parses extra roots like webpki does, which accepts the long-lived test
                // certificates.
                let mut config = RustlsConnectorConfig::new_with_platform_verifier();
                config.native_certs = vec![CertificateDer::from(vec![0x00, 0x01, 0x02]), test_ca()];
                config.native_certs_needed = true;
                let connector = config.connector_with_no_client_auth().unwrap();
                let (client_io, mut server) = pipe(false);
                try_connect(&connector, client_io, &mut server).unwrap();
            }

            // Not on Apple platforms, which reject the long-lived test certificates whatever the
            // roots.
            #[test]
            #[cfg(all(
                feature = "platform-verifier",
                feature = "native-certs",
                not(target_vendor = "apple")
            ))]
            fn platform_verifier_ignores_native_certs_it_does_not_need() {
                if os_store_is_empty() {
                    return;
                }
                let mut config = RustlsConnectorConfig::new_with_platform_verifier();
                config.native_certs = vec![test_ca()];
                config.native_certs_needed = false;
                let connector = config.connector_with_no_client_auth().unwrap();
                let (client_io, mut server) = pipe(false);
                let err = try_connect(&connector, client_io, &mut server)
                    .expect_err("the platform verifier trusted the native certificates");
                let inner = err.get_ref().and_then(|err| err.downcast_ref());
                assert!(
                    matches!(inner, Some(rustls::Error::InvalidCertificate(_))),
                    "{err:?}"
                );
            }
        }
    }
}
