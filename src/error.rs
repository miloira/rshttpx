//! Error types for `rshttpx`.
//!
//! Mirrors the exception hierarchy of Python's `httpx` where it makes sense in
//! Rust: a single [`Error`] enum with variants that correspond to httpx's
//! `InvalidURL`, `ConnectError`/`TransportError`, `TimeoutException`,
//! `TooManyRedirects`, `DecodingError`, and `HTTPStatusError`.

use std::fmt;

/// Convenience alias used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;

/// The kind of error that occurred.
#[derive(Debug)]
#[non_exhaustive]
pub enum ErrorKind {
    /// A URL was malformed or could not be parsed.
    InvalidUrl,
    /// A request could not be built (bad header, bad body, etc.).
    InvalidRequest,
    /// A low-level transport/connection failure.
    Transport,
    /// The request exceeded its configured timeout.
    Timeout,
    /// The redirect limit was exceeded while following redirects.
    TooManyRedirects,
    /// A redirect response was missing a usable `Location` header.
    InvalidRedirect,
    /// Response content could not be decoded (text, JSON, ...).
    Decoding,
    /// A non-success HTTP status was raised via `raise_for_status`.
    Status,
}

/// The error type returned by all fallible operations in this crate.
pub struct Error {
    kind: ErrorKind,
    message: String,
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl Error {
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Error {
            kind,
            message: message.into(),
            source: None,
        }
    }

    pub fn with_source(
        kind: ErrorKind,
        message: impl Into<String>,
        source: impl Into<Box<dyn std::error::Error + Send + Sync>>,
    ) -> Self {
        Error {
            kind,
            message: message.into(),
            source: Some(source.into()),
        }
    }

    pub fn kind(&self) -> &ErrorKind {
        &self.kind
    }

    pub fn is_timeout(&self) -> bool {
        matches!(self.kind, ErrorKind::Timeout)
    }

    pub fn is_status(&self) -> bool {
        matches!(self.kind, ErrorKind::Status)
    }

    pub(crate) fn invalid_request(msg: impl Into<String>) -> Self {
        Error::new(ErrorKind::InvalidRequest, msg)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut d = f.debug_struct("Error");
        d.field("kind", &self.kind).field("message", &self.message);
        if let Some(src) = &self.source {
            d.field("source", src);
        }
        d.finish()
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_ref()
            .map(|s| s.as_ref() as &(dyn std::error::Error + 'static))
    }
}

impl From<url::ParseError> for Error {
    fn from(e: url::ParseError) -> Self {
        Error::with_source(ErrorKind::InvalidUrl, format!("invalid URL: {e}"), e)
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::with_source(ErrorKind::Decoding, format!("JSON error: {e}"), e)
    }
}

impl From<http::Error> for Error {
    fn from(e: http::Error) -> Self {
        Error::with_source(ErrorKind::InvalidRequest, format!("http error: {e}"), e)
    }
}
