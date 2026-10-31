//! A blocking (synchronous) client, mirroring `httpx.Client`.
//!
//! This wraps the async [`crate::Client`] with a dedicated Tokio runtime so
//! callers can issue requests without `async`/`await`. The request-building API
//! mirrors the async [`crate::client::RequestBuilder`].

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::Method;
use serde::Serialize;

use crate::auth::Auth;
use crate::client::{
    Client as AsyncClient, ClientBuilder as AsyncBuilder, Limits, RequestBuilder as AsyncRequestBuilder,
    Timeout,
};
use crate::content::{Content, Multipart};
use crate::error::{Error, Result};
use crate::headers::Headers;
use crate::response::Response;
use crate::url::QueryParams;

type Op = Box<dyn for<'a> FnOnce(AsyncRequestBuilder<'a>) -> AsyncRequestBuilder<'a>>;

/// A synchronous HTTP client. Cloning shares the runtime and connection pool.
#[derive(Clone)]
pub struct Client {
    inner: AsyncClient,
    rt: Arc<tokio::runtime::Runtime>,
}

impl Client {
    /// A blocking client with default settings.
    pub fn new() -> Result<Self> {
        ClientBuilder::new().build()
    }

    pub fn builder() -> ClientBuilder {
        ClientBuilder::new()
    }

    pub fn cookies(&self) -> &crate::cookies::Cookies {
        self.inner.cookies()
    }

    pub fn get(&self, url: &str) -> RequestBuilder {
        self.request(Method::GET, url)
    }

    pub fn post(&self, url: &str) -> RequestBuilder {
        self.request(Method::POST, url)
    }

    pub fn put(&self, url: &str) -> RequestBuilder {
        self.request(Method::PUT, url)
    }

    pub fn patch(&self, url: &str) -> RequestBuilder {
        self.request(Method::PATCH, url)
    }

    pub fn delete(&self, url: &str) -> RequestBuilder {
        self.request(Method::DELETE, url)
    }

    pub fn head(&self, url: &str) -> RequestBuilder {
        self.request(Method::HEAD, url)
    }

    pub fn options(&self, url: &str) -> RequestBuilder {
        self.request(Method::OPTIONS, url)
    }

    pub fn request(&self, method: Method, url: &str) -> RequestBuilder {
        RequestBuilder {
            inner: self.inner.clone(),
            rt: self.rt.clone(),
            method,
            url: url.to_string(),
            ops: Vec::new(),
            error: None,
        }
    }
}

/// Builder for a blocking [`Client`].
pub struct ClientBuilder {
    inner: AsyncBuilder,
}

impl ClientBuilder {
    pub fn new() -> Self {
        ClientBuilder {
            inner: AsyncBuilder::new(),
        }
    }

    pub fn base_url(mut self, url: impl Into<String>) -> Self {
        self.inner = self.inner.base_url(url);
        self
    }

    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.inner = self.inner.header(name, value);
        self
    }

    pub fn headers(mut self, headers: Headers) -> Self {
        self.inner = self.inner.headers(headers);
        self
    }

    pub fn basic_auth(mut self, username: impl AsRef<str>, password: impl AsRef<str>) -> Self {
        self.inner = self.inner.basic_auth(username, password);
        self
    }

    pub fn bearer_auth(mut self, token: impl AsRef<str>) -> Self {
        self.inner = self.inner.bearer_auth(token);
        self
    }

    pub fn digest_auth(mut self, username: impl Into<String>, password: impl Into<String>) -> Self {
        self.inner = self.inner.digest_auth(username, password);
        self
    }

    pub fn auth(mut self, auth: Arc<dyn Auth>) -> Self {
        self.inner = self.inner.auth(auth);
        self
    }

    pub fn timeout(mut self, timeout: Option<Duration>) -> Self {
        self.inner = self.inner.timeout(timeout);
        self
    }

    pub fn timeouts(mut self, timeout: Timeout) -> Self {
        self.inner = self.inner.timeouts(timeout);
        self
    }

    pub fn follow_redirects(mut self, follow: bool) -> Self {
        self.inner = self.inner.follow_redirects(follow);
        self
    }

    pub fn max_redirects(mut self, max: usize) -> Self {
        self.inner = self.inner.max_redirects(max);
        self
    }

    pub fn http2(mut self, enabled: bool) -> Self {
        self.inner = self.inner.http2(enabled);
        self
    }

    pub fn verify(mut self, verify: bool) -> Self {
        self.inner = self.inner.verify(verify);
        self
    }

    pub fn limits(mut self, limits: Limits) -> Self {
        self.inner = self.inner.limits(limits);
        self
    }

    pub fn decompress(mut self, enabled: bool) -> Self {
        self.inner = self.inner.decompress(enabled);
        self
    }

    pub fn proxy(mut self, url: impl Into<String>) -> Self {
        self.inner = self.inner.proxy(url);
        self
    }

    pub fn build(self) -> Result<Client> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| {
                Error::with_source(
                    crate::error::ErrorKind::Transport,
                    format!("could not start runtime: {e}"),
                    e,
                )
            })?;
        Ok(Client {
            inner: self.inner.build(),
            rt: Arc::new(rt),
        })
    }
}

impl Default for ClientBuilder {
    fn default() -> Self {
        ClientBuilder::new()
    }
}

/// Fluent builder for a single blocking request.
pub struct RequestBuilder {
    inner: AsyncClient,
    rt: Arc<tokio::runtime::Runtime>,
    method: Method,
    url: String,
    ops: Vec<Op>,
    error: Option<Error>,
}

impl RequestBuilder {
    fn push<F>(mut self, op: F) -> Self
    where
        F: for<'a> FnOnce(AsyncRequestBuilder<'a>) -> AsyncRequestBuilder<'a> + 'static,
    {
        self.ops.push(Box::new(op));
        self
    }

    pub fn header(self, name: impl Into<String>, value: impl Into<String>) -> Self {
        let name = name.into();
        let value = value.into();
        self.push(move |rb| rb.header(name, value))
    }

    pub fn headers(self, headers: Headers) -> Self {
        self.push(move |rb| rb.headers(headers))
    }

    pub fn query(self, key: impl Into<String>, value: impl Into<String>) -> Self {
        let key = key.into();
        let value = value.into();
        self.push(move |rb| rb.query(key, value))
    }

    pub fn params(self, params: QueryParams) -> Self {
        self.push(move |rb| rb.params(params))
    }

    pub fn body(self, body: impl Into<Bytes>) -> Self {
        let body = body.into();
        self.push(move |rb| rb.body(body))
    }

    pub fn text(self, body: impl Into<String>) -> Self {
        let body = body.into();
        self.push(move |rb| rb.text(body))
    }

    pub fn json<T: Serialize>(mut self, value: &T) -> Self {
        match Content::json(value) {
            Ok(content) => self.push(move |rb| rb.content(content)),
            Err(e) => {
                self.error = Some(e);
                self
            }
        }
    }

    pub fn form<T: Serialize>(mut self, value: &T) -> Self {
        match Content::form(value) {
            Ok(content) => self.push(move |rb| rb.content(content)),
            Err(e) => {
                self.error = Some(e);
                self
            }
        }
    }

    pub fn multipart(self, multipart: Multipart) -> Self {
        self.push(move |rb| rb.multipart(multipart))
    }

    pub fn content(self, content: Content) -> Self {
        self.push(move |rb| rb.content(content))
    }

    pub fn basic_auth(self, username: impl AsRef<str>, password: impl AsRef<str>) -> Self {
        let username = username.as_ref().to_string();
        let password = password.as_ref().to_string();
        self.push(move |rb| rb.basic_auth(username, password))
    }

    pub fn bearer_auth(self, token: impl AsRef<str>) -> Self {
        let token = token.as_ref().to_string();
        self.push(move |rb| rb.bearer_auth(token))
    }

    pub fn digest_auth(self, username: impl Into<String>, password: impl Into<String>) -> Self {
        let username = username.into();
        let password = password.into();
        self.push(move |rb| rb.digest_auth(username, password))
    }

    pub fn auth(self, auth: Arc<dyn Auth>) -> Self {
        self.push(move |rb| rb.auth(auth))
    }

    pub fn timeout(self, timeout: Option<Duration>) -> Self {
        self.push(move |rb| rb.timeout(timeout))
    }

    pub fn follow_redirects(self, follow: bool) -> Self {
        self.push(move |rb| rb.follow_redirects(follow))
    }

    /// Send the request and block until the response is available.
    pub fn send(self) -> Result<Response> {
        if let Some(error) = self.error {
            return Err(error);
        }
        let RequestBuilder {
            inner,
            rt,
            method,
            url,
            ops,
            ..
        } = self;
        rt.block_on(async move {
            let mut rb = inner.request(method, &url);
            for op in ops {
                rb = op(rb);
            }
            rb.send().await
        })
    }
}
