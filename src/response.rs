//! The [`Response`] model, mirroring `httpx.Response`.

use std::time::Duration;

use bytes::Bytes;
use http::StatusCode;
use serde::de::DeserializeOwned;

use crate::decode;
use crate::error::{Error, ErrorKind, Result};
use crate::headers::Headers;
use crate::request::Request;
use crate::url::Url;

/// A `Link` header entry, as returned by [`Response::links`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Link {
    /// The target URL.
    pub url: String,
    /// The `rel` relation type, if present.
    pub rel: Option<String>,
    /// Any other parameters on the link (e.g. `title`, `type`).
    pub params: Vec<(String, String)>,
}

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
    request: Option<Request>,
    default_encoding: Option<String>,
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
            request: None,
            default_encoding: None,
        }
    }

    pub(crate) fn set_history(&mut self, history: Vec<Url>) {
        self.history = history;
    }

    pub(crate) fn set_elapsed(&mut self, elapsed: Duration) {
        self.elapsed = elapsed;
    }

    pub(crate) fn set_request(&mut self, request: Request) {
        self.request = Some(request);
    }

    pub(crate) fn set_default_encoding(&mut self, encoding: Option<String>) {
        self.default_encoding = encoding;
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

    /// Decode the body as text. If a `default_encoding` was configured on the
    /// client it takes precedence; otherwise the `Content-Type` charset is used,
    /// then a BOM, then content-based detection. Matches `response.text`.
    pub fn text(&self) -> String {
        if let Some(label) = &self.default_encoding {
            let content_type = format!("x; charset={label}");
            return decode::decode_text(Some(&content_type), &self.body);
        }
        decode::decode_text(self.content_type(), &self.body)
    }

    /// The request that produced this response (the final one after redirects),
    /// matching `response.request`.
    pub fn request(&self) -> Option<&Request> {
        self.request.as_ref()
    }

    /// Number of bytes in the (decompressed) body, matching
    /// `response.num_bytes_downloaded`.
    pub fn num_bytes_downloaded(&self) -> usize {
        self.body.len()
    }

    /// Parsed `Link` header entries, matching `response.links`.
    pub fn links(&self) -> Vec<Link> {
        let mut links = Vec::new();
        for header in self.headers.get_all("link") {
            links.extend(parse_link_header(header));
        }
        links
    }

    /// The resolved charset/encoding label, matching `response.encoding`
    /// (header charset, then BOM, then content-based detection).
    pub fn encoding(&self) -> String {
        decode::resolve_encoding(self.content_type(), &self.body)
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

/// Parse a single `Link` header value (which may contain several links).
fn parse_link_header(header: &str) -> Vec<Link> {
    let mut links = Vec::new();
    // Split on commas that separate links (each link begins with `<`).
    for segment in split_links(header) {
        let segment = segment.trim();
        let Some(end) = segment.find('>') else {
            continue;
        };
        if !segment.starts_with('<') {
            continue;
        }
        let url = segment[1..end].trim().to_string();
        let mut rel = None;
        let mut params = Vec::new();
        for part in segment[end + 1..].split(';') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            if let Some((key, value)) = part.split_once('=') {
                let key = key.trim().to_string();
                let value = value.trim().trim_matches('"').to_string();
                if key.eq_ignore_ascii_case("rel") {
                    rel = Some(value);
                } else {
                    params.push((key, value));
                }
            }
        }
        links.push(Link { url, rel, params });
    }
    links
}

/// Split a `Link` header into individual links, respecting the `<...>` URL
/// brackets so commas inside a URL do not split it.
fn split_links(header: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut in_brackets = false;
    for ch in header.chars() {
        match ch {
            '<' => {
                in_brackets = true;
                current.push(ch);
            }
            '>' => {
                in_brackets = false;
                current.push(ch);
            }
            ',' if !in_brackets => {
                out.push(std::mem::take(&mut current));
            }
            _ => current.push(ch),
        }
    }
    if !current.trim().is_empty() {
        out.push(current);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resp_with_link(value: &str) -> Response {
        let mut headers = Headers::new();
        headers.insert("link", value);
        Response::new(
            StatusCode::OK,
            headers,
            Url::parse("https://example.com/").unwrap(),
            Bytes::new(),
        )
    }

    #[test]
    fn parses_link_header() {
        let resp = resp_with_link(
            "<https://api.test/next>; rel=\"next\", <https://api.test/last>; rel=\"last\"",
        );
        let links = resp.links();
        assert_eq!(links.len(), 2);
        assert_eq!(links[0].url, "https://api.test/next");
        assert_eq!(links[0].rel.as_deref(), Some("next"));
        assert_eq!(links[1].rel.as_deref(), Some("last"));
    }

    #[test]
    fn num_bytes_downloaded_counts_body() {
        let resp = Response::new(
            StatusCode::OK,
            Headers::new(),
            Url::parse("https://example.com/").unwrap(),
            Bytes::from_static(b"12345"),
        );
        assert_eq!(resp.num_bytes_downloaded(), 5);
    }
}
