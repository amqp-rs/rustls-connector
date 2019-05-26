#![deny(missing_docs)]
#![warn(rust_2018_idioms)]
#![doc(html_root_url = "https://docs.rs/rustls-connector/0.2.0/")]

//! # Connector similar to openssl or native-tls for rustls
//!
//! tcp-stream is a library aiming at simplifying using rustls as
//! an alternative to openssl and native-tls

pub use rustls;
pub use webpki;
pub use webpki_roots;

use failure::{Backtrace, Context, Fail};
use rustls::{ClientConfig, ClientSession, Session, StreamOwned as TlsStream, TLSError};

use std::{
    fmt,
    io::{self, Read, Write},
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
    pub fn connect<S: Read + Write>(&self, mut stream: S, domain: &str) -> Result<TlsStream<ClientSession, S>, Error> {
        let mut session = ClientSession::new(&self.config, webpki::DNSNameRef::try_from_ascii_str(domain).map_err(|()| ErrorKind::InvalidDomainName(domain.to_owned()))?);
        // FIXME: handle MidHandshake/WouldBlock
        while session.is_handshaking() {
            while session.is_handshaking() && session.wants_write() {
                session.write_tls(&mut stream)?;
            }
            while session.is_handshaking() && session.wants_read() {
                if session.read_tls(&mut stream)? == 0 {
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "connection closed during handshake").into());
                }
                session.process_new_packets()?;
            }
        }
        Ok(TlsStream::new(session, stream))
    }
}

/// The type of error that can be returned in this crate.
#[derive(Debug)]
pub struct Error {
    inner: Context<ErrorKind>,
}

/// The different kinds of errors that can be reported.
#[derive(Debug, Fail)]
pub enum ErrorKind {
    /// An invalid domain name
    #[fail(display = "Invalid domain name: {}", _0)]
    InvalidDomainName(String),
    /// An std::io::Error
    #[fail(display = "IO error: {:?}", _0)]
    IOError(#[fail(cause)] io::Error),
    /// An invalid domain name
    #[fail(display = "TLS error: {:?}", _0)]
    TLSError(#[fail(cause)] TLSError),
    #[doc(hidden)]
    #[fail(display = "rustls_connector::ErrorKind::__Nonexhaustive: this should not be printed")]
    __Nonexhaustive,
}

impl Error {
    /// Return the underlying ErrorKind
    pub fn kind(&self) -> &ErrorKind{
        self.inner.get_context()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner.fmt(f)
    }
}

impl Fail for Error {
    fn cause(&self) -> Option<&dyn Fail> {
        self.inner.cause()
    }

    fn backtrace(&self) -> Option<&Backtrace> {
        self.inner.backtrace()
    }
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Self {
        Context::new(kind).into()
    }
}

impl From<Context<ErrorKind>> for Error {
    fn from(inner: Context<ErrorKind>) -> Self {
        Error { inner }
    }
}

impl From<io::Error> for Error {
    fn from(io: io::Error) -> Self {
        ErrorKind::IOError(io).into()
    }
}

impl From<TLSError> for Error {
    fn from(tls: TLSError) -> Self {
        ErrorKind::TLSError(tls).into()
    }
}
