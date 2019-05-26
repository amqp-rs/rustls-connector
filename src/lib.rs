#![deny(missing_docs)]
#![warn(rust_2018_idioms)]
#![doc(html_root_url = "https://docs.rs/rustls-connector/0.3.0/")]

//! # Connector similar to openssl or native-tls for rustls
//!
//! tcp-stream is a library aiming at simplifying using rustls as
//! an alternative to openssl and native-tls

pub use rustls;
pub use webpki;
pub use webpki_roots;

use failure::{Backtrace, Context, Fail};
use rustls::{ClientConfig, ClientSession, Session, StreamOwned};

use std::{
    fmt,
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
        Self {
            config: Arc::new(config),
        }
    }
}

macro_rules! perform_handshake (
    ($session: expr, $stream: expr) => (
        if let Err(e) = $session.complete_io(&mut $stream) {
            return Err(if e.kind() == io::ErrorKind::WouldBlock {
                ErrorKind::HandshakeWouldBlock(MidHandshakeTlsStream{ session: $session, stream: $stream })
            } else {
                ErrorKind::IOError(e)
            }.into());
        }
        return Ok(TlsStream::new($session, $stream));
    );
);

impl RustlsConnector {
    /// Connect to the given host
    pub fn connect<S: fmt::Debug + Read + Write + Send + Sync>(&self, mut stream: S, domain: &str) -> Result<TlsStream<S>, Error<S>> {
        let mut session = ClientSession::new(&self.config, webpki::DNSNameRef::try_from_ascii_str(domain).map_err(|()| ErrorKind::InvalidDomainName(domain.to_owned()))?);
        perform_handshake!(session, stream);
    }
}

/// A TLS stream which has been interrupted during the handshake
#[derive(Debug)]
pub struct MidHandshakeTlsStream<S: Read + Write> {
    session: ClientSession,
    stream:  S,
}

impl<S: fmt::Debug + Read + Write + Send + Sync + 'static> MidHandshakeTlsStream<S> {
    /// Get a reference to the inner stream
    pub fn get_ref(&self) -> &S {
        &self.stream
    }

    /// Get a mutable reference to the inner stream
    pub fn get_mut(&mut self) -> &S {
        &mut self.stream
    }

    /// Retry the handshake
    pub fn handshake(mut self) -> Result<TlsStream<S>, Error<S>> {
        perform_handshake!(self.session, self.stream);
    }
}

impl<S: Read + Write> fmt::Display for MidHandshakeTlsStream<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MidHandshakeTlsStream")
    }
}

/// The type of error that can be returned in this crate.
#[derive(Debug)]
pub struct Error<S: fmt::Debug + Read + Write + Send + Sync + 'static> {
    inner: Context<ErrorKind<S>>,
}

/// The different kinds of errors that can be reported.
#[derive(Debug, Fail)]
pub enum ErrorKind<S: fmt::Debug + Read + Write + Send + Sync + 'static> {
    /// We hit a WouldBlock during handshake
    #[fail(display = "WouldBlock during handshake")]
    HandshakeWouldBlock(MidHandshakeTlsStream<S>),
    /// An invalid domain name
    #[fail(display = "Invalid domain name: {}", _0)]
    InvalidDomainName(String),
    /// An std::io::Error
    #[fail(display = "IO error: {:?}", _0)]
    IOError(#[fail(cause)] io::Error),
    #[doc(hidden)]
    #[fail(display = "rustls_connector::ErrorKind::__Nonexhaustive: this should not be printed")]
    __Nonexhaustive,
}

impl<S: fmt::Debug + Read + Write + Send + Sync> Error<S> {
    /// Return the underlying ErrorKind
    pub fn kind(&self) -> &ErrorKind<S> {
        self.inner.get_context()
    }
}

impl<S: fmt::Debug + Read + Write + Send + Sync + 'static> fmt::Display for Error<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner.fmt(f)
    }
}

impl<S: fmt::Debug + Read + Write + Send + Sync + 'static> Fail for Error<S> {
    fn cause(&self) -> Option<&dyn Fail> {
        self.inner.cause()
    }

    fn backtrace(&self) -> Option<&Backtrace> {
        self.inner.backtrace()
    }
}

impl<S: fmt::Debug + Read + Write + Send + Sync> From<ErrorKind<S>> for Error<S> {
    fn from(kind: ErrorKind<S>) -> Self {
        Context::new(kind).into()
    }
}

impl<S: fmt::Debug + Read + Write + Send + Sync> From<Context<ErrorKind<S>>> for Error<S> {
    fn from(inner: Context<ErrorKind<S>>) -> Self {
        Error { inner }
    }
}

impl<S: fmt::Debug + Read + Write + Send + Sync + 'static> From<io::Error> for Error<S> {
    fn from(io: io::Error) -> Self {
        ErrorKind::IOError(io).into()
    }
}
