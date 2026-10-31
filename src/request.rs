//! The [`Request`] model, mirroring `httpx.Request`.

use bytes::Bytes;
use http::Method;

use crate::content::Content;
use crate::headers::Headers;
use crate::url::Url;

/// A fully-formed HTTP request: method, URL, headers and a buffered body.
///
/// Like `httpx.Request`, this is a plain data object; the [`crate::Client`]
/// turns it into bytes on the wire. Bodies are buffered (v1 does not stream
/// request bodies).
#[derive(Clone, Debug)]
pub struct Request {
    method: Method,
    url: Url,
    headers: Headers,
    body: Bytes,
}

impl Request {
    /// Construct a request. The caller is responsible for the final URL
    /// (including merged query params) and for any content headers.
    pub fn new(method: Method, url: Url) -> Self {
        Request {
            method,
            url,
            headers: Headers::new(),
            body: Bytes::new(),
        }
    }

    pub fn method(&self) -> &Method {
        &self.method
    }

    pub fn set_method(&mut self, method: Method) {
        self.method = method;
    }

    pub fn url(&self) -> &Url {
        &self.url
    }

    pub fn set_url(&mut self, url: Url) {
        self.url = url;
    }

    pub fn headers(&self) -> &Headers {
        &self.headers
    }

    pub fn headers_mut(&mut self) -> &mut Headers {
        &mut self.headers
    }

    pub fn body(&self) -> &Bytes {
        &self.body
    }

    /// Apply an encoded [`Content`]: set the body and, unless already present,
    /// the implied `Content-Type`.
    pub fn set_content(&mut self, content: Content) {
        if let Some(ct) = content.content_type {
            self.headers.set_default("content-type", ct);
        }
        self.body = content.body;
    }

    pub fn set_body(&mut self, body: impl Into<Bytes>) {
        self.body = body.into();
    }
}
