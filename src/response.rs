//! The [`Response`] model, mirroring `httpx.Response`.

use bytes::Bytes;
use http::StatusCode;
use serde::de::DeserializeOwned;

use crate::error::{Error, ErrorKind, Result};
use crate::headers::Headers;
use crate::url::Url;

/// A received HTTP response with a fully-buffered body.
///
/// Like `httpx.Response`: exposes the status, headers, final URL (after
/// redirects), and decoding helpers [`Response::text`], [`Response::json`] and
/// [`Response::bytes`]. v1 buffers the whole body on receipt.
#[derive(Clone, Debug)]
pub struct Response {
    status: StatusCode,
    headers: Headers,
    url: Url,
    body: Bytes,
    /// The URLs visited before this one, oldest first (redirect chain).
    history: Vec<Url>,
}

impl Response {
    pub(crate) fn new(status: StatusCode, headers: Headers, url: Url, body: Bytes) -> Self {
        Response {
            status,
            headers,
            url,
            body,
            history: Vec::new(),
        }
    }

    pub(crate) fn set_history(&mut self, history: Vec<Url>) {
        self.history = history;
    }

    /// The HTTP status code.
    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// The numeric status code, matching httpx's `response.status_code`.
    pub fn status_code(&self) -> u16 {
        self.status.as_u16()
    }

    pub fn headers(&self) -> &Headers {
        &self.headers
    }

    /// The final URL this response was received from.
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// The redirect chain that led here (empty when no redirects occurred).
    pub fn history(&self) -> &[Url] {
        &self.history
    }

    /// `true` for 2xx status codes.
    pub fn is_success(&self) -> bool {
        self.status.is_success()
    }

    pub fn is_redirect(&self) -> bool {
        self.status.is_redirection()
    }

    pub fn is_client_error(&self) -> bool {
        self.status.is_client_error()
    }

    pub fn is_server_error(&self) -> bool {
        self.status.is_server_error()
    }

    /// The raw response body.
    pub fn bytes(&self) -> &Bytes {
        &self.body
    }

    /// Consume the response, returning the owned body bytes.
    pub fn into_bytes(self) -> Bytes {
        self.body
    }

    /// Decode the body as UTF-8 text.
    ///
    /// Uses the `charset` from `Content-Type` only when it is `utf-8` (the
    /// common case); other charsets fall back to lossy UTF-8 decoding, matching
    /// httpx's best-effort behaviour closely enough for v1.
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    /// Deserialize the body as JSON into `T`.
    pub fn json<T: DeserializeOwned>(&self) -> Result<T> {
        serde_json::from_slice(&self.body).map_err(Error::from)
    }

    /// The value of the `Content-Type` header, if present.
    pub fn content_type(&self) -> Option<&str> {
        self.headers.get("content-type")
    }

    /// Return an error if the status is 4xx or 5xx, mirroring
    /// `response.raise_for_status()`. On success returns `&self` for chaining.
    pub fn raise_for_status(&self) -> Result<&Self> {
        if self.status.is_client_error() || self.status.is_server_error() {
            let reason = self.status.canonical_reason().unwrap_or("Unknown");
            Err(Error::new(
                ErrorKind::Status,
                format!(
                    "{} {} for url {}",
                    self.status.as_u16(),
                    reason,
                    self.url
                ),
            ))
        } else {
            Ok(self)
        }
    }
}
