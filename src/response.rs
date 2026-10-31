//! The [`Response`] model, mirroring `httpx.Response`.

use std::time::Duration;

use bytes::Bytes;
use http::StatusCode;
use serde::de::DeserializeOwned;

use crate::decode;
use crate::error::{Error, ErrorKind, Result};
use crate::headers::Headers;
use crate::url::Url;

/// A received HTTP response with a fully-buffered, already-decompressed body.
///
/// Like `httpx.Response`: exposes the status, headers, final URL (after
/// redirects), elapsed time, and decoding helpers [`Response::text`],
/// [`Response::json`] and [`Response::bytes`].
#[derive(Clone, Debug)]
pub struct Response {
    status: StatusCode,
    headers: Headers,
    url: Url,
    body: Bytes,
    history: Vec<Url>,
    elapsed: Duration,
}

impl Response {
    pub(crate) fn new(status: StatusCode, headers: Headers, url: Url, body: Bytes) -> Self {
        Response {
            status,
            headers,
            url,
            body,
            history: Vec::new(),
            elapsed: Duration::ZERO,
        }
    }

    pub(crate) fn set_history(&mut self, history: Vec<Url>) {
        self.history = history;
    }

    pub(crate) fn set_elapsed(&mut self, elapsed: Duration) {
        self.elapsed = elapsed;
    }

    /// The HTTP status code.
    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// The numeric status code, matching httpx's `response.status_code`.
    pub fn status_code(&self) -> u16 {
        self.status.as_u16()
    }

    /// The reason phrase (e.g. `"Not Found"`), matching `response.reason_phrase`.
    pub fn reason_phrase(&self) -> &str {
        self.status.canonical_reason().unwrap_or("")
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

    /// Time taken for the request, matching `response.elapsed`.
    pub fn elapsed(&self) -> Duration {
        self.elapsed
    }

    /// `true` for 2xx status codes.
    pub fn is_success(&self) -> bool {
        self.status.is_success()
    }

    pub fn is_informational(&self) -> bool {
        self.status.is_informational()
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

    pub fn is_error(&self) -> bool {
        self.status.is_client_error() || self.status.is_server_error()
    }

    /// The raw (decompressed) response body.
    pub fn bytes(&self) -> &Bytes {
        &self.body
    }

    /// Consume the response, returning the owned body bytes.
    pub fn into_bytes(self) -> Bytes {
        self.body
    }

    /// Decode the body as text, honouring the `charset` in `Content-Type`
    /// (defaulting to UTF-8), matching `response.text`.
    pub fn text(&self) -> String {
        decode::decode_text(self.content_type(), &self.body)
    }

    /// The detected charset/encoding label, matching `response.encoding`.
    pub fn encoding(&self) -> String {
        self.content_type()
            .and_then(decode::parse_charset)
            .unwrap_or_else(|| "utf-8".to_string())
    }

    /// Deserialize the body as JSON into `T`.
    pub fn json<T: DeserializeOwned>(&self) -> Result<T> {
        serde_json::from_slice(&self.body).map_err(Error::from)
    }

    /// The value of the `Content-Type` header, if present.
    pub fn content_type(&self) -> Option<&str> {
        self.headers.get("content-type")
    }

    /// The cookies the server set on this response, as `(name, value)` pairs.
    pub fn cookies(&self) -> Vec<(String, String)> {
        let mut out = Vec::new();
        for value in self.headers.get_all("set-cookie") {
            if let Some(first) = value.split(';').next() {
                if let Some((name, val)) = first.split_once('=') {
                    out.push((name.trim().to_string(), val.trim().to_string()));
                }
            }
        }
        out
    }

    /// Return an error if the status is 4xx or 5xx, mirroring
    /// `response.raise_for_status()`. On success returns `&self` for chaining.
    pub fn raise_for_status(&self) -> Result<&Self> {
        if self.is_error() {
            let reason = self.status.canonical_reason().unwrap_or("Unknown");
            Err(Error::new(
                ErrorKind::Status,
                format!("{} {} for url {}", self.status.as_u16(), reason, self.url),
            ))
        } else {
            Ok(self)
        }
    }
}
