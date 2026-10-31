//! Pluggable transports, mirroring httpx's `transport=` parameter.
//!
//! A [`Transport`] performs the actual request/response round trip. The default
//! transport uses the hyper connection pool, but a custom transport can be
//! supplied to intercept requests — most usefully a mock for tests, or an
//! adapter to a different backend. Custom transports handle the buffered path;
//! response streaming and streaming uploads require the default transport.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use bytes::Bytes;
use http::StatusCode;

use crate::error::Result;
use crate::headers::Headers;
use crate::request::Request;

/// The raw result of a transport round trip: the status, headers and the
/// (still possibly compressed) response body. The client applies decompression.
#[derive(Clone, Debug)]
pub struct TransportResponse {
    pub status: StatusCode,
    pub headers: Headers,
    pub body: Bytes,
}

impl TransportResponse {
    pub fn new(status: StatusCode, headers: Headers, body: Bytes) -> Self {
        TransportResponse {
            status,
            headers,
            body,
        }
    }
}

/// A boxed future returned by [`Transport::roundtrip`].
pub type TransportFuture<'a> = Pin<Box<dyn Future<Output = Result<TransportResponse>> + Send + 'a>>;

/// Something that can perform an HTTP request/response round trip.
pub trait Transport: Send + Sync {
    /// Perform the round trip for `request`, honouring `timeout` if set.
    fn roundtrip<'a>(&'a self, request: &'a Request, timeout: Option<Duration>)
        -> TransportFuture<'a>;
}
