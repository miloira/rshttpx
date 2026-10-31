//! The async [`Client`] and its builder, mirroring `httpx.AsyncClient`.
//!
//! The client owns a connection pool (via `hyper-util`'s pooling client over a
//! rustls TLS connector), plus httpx-style configuration: a base URL, default
//! headers, default auth, a cookie jar, a timeout, and redirect policy. Request
//! construction uses the ergonomic [`RequestBuilder`] returned by the per-method
//! helpers (`get`, `post`, ...), which stands in for httpx's keyword arguments.

use std::sync::Arc;
use std::sync::Once;
use std::time::Duration;

use bytes::Bytes;
use http::{Method, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client as HyperClient;
use hyper_util::rt::TokioExecutor;
use serde::Serialize;

use crate::auth::{Auth, BasicAuth, BearerAuth};
use crate::content::{Content, Multipart};
use crate::cookies::Cookies;
use crate::error::{Error, ErrorKind, Result};
use crate::headers::Headers;
use crate::request::Request;
use crate::response::Response;
use crate::url::{QueryParams, Url};

type Connector = HttpsConnector<HttpConnector>;
type Inner = HyperClient<Connector, Full<Bytes>>;

static CRYPTO_INIT: Once = Once::new();

fn ensure_crypto_provider() {
    CRYPTO_INIT.call_once(|| {
        // Install the ring-based process-default crypto provider for rustls.
        // Ignore the error if another provider was already installed.
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// Configuration shared by a [`Client`] across requests.
struct Config {
    base_url: Option<Url>,
    headers: Headers,
    auth: Option<Arc<dyn Auth>>,
    cookies: Cookies,
    timeout: Option<Duration>,
    follow_redirects: bool,
    max_redirects: usize,
}

/// An async HTTP client with connection pooling, mirroring `httpx.AsyncClient`.
///
/// Cheap to clone: clones share the same connection pool, cookie jar and
/// configuration via an internal `Arc`.
#[derive(Clone)]
pub struct Client {
    inner: Inner,
    config: Arc<Config>,
}

impl Client {
    /// A client with default settings.
    pub fn new() -> Self {
        ClientBuilder::new().build()
    }

    /// Start building a configured client.
    pub fn builder() -> ClientBuilder {
        ClientBuilder::new()
    }

    /// The cookie jar shared by this client.
    pub fn cookies(&self) -> &Cookies {
        &self.config.cookies
    }

    /// Start a `GET` request.
    pub fn get(&self, url: &str) -> RequestBuilder<'_> {
        self.request(Method::GET, url)
    }

    /// Start a `POST` request.
    pub fn post(&self, url: &str) -> RequestBuilder<'_> {
        self.request(Method::POST, url)
    }

    /// Start a `PUT` request.
    pub fn put(&self, url: &str) -> RequestBuilder<'_> {
        self.request(Method::PUT, url)
    }

    /// Start a `PATCH` request.
    pub fn patch(&self, url: &str) -> RequestBuilder<'_> {
        self.request(Method::PATCH, url)
    }

    /// Start a `DELETE` request.
    pub fn delete(&self, url: &str) -> RequestBuilder<'_> {
        self.request(Method::DELETE, url)
    }

    /// Start a `HEAD` request.
    pub fn head(&self, url: &str) -> RequestBuilder<'_> {
        self.request(Method::HEAD, url)
    }

    /// Start an `OPTIONS` request.
    pub fn options(&self, url: &str) -> RequestBuilder<'_> {
        self.request(Method::OPTIONS, url)
    }

    /// Start a request with an arbitrary method.
    pub fn request(&self, method: Method, url: &str) -> RequestBuilder<'_> {
        RequestBuilder::new(self, method, url)
    }

    /// Resolve a (possibly relative) request URL against the client base URL.
    fn resolve_url(&self, raw: &str) -> Result<Url> {
        match &self.config.base_url {
            Some(base) => base.join(raw),
            None => Url::parse(raw),
        }
    }

    /// Execute a fully-built request, following redirects per policy.
    async fn execute(
        &self,
        mut request: Request,
        timeout: Option<Duration>,
        follow_redirects: bool,
    ) -> Result<Response> {
        let mut history: Vec<Url> = Vec::new();

        loop {
            // Attach cookies from the jar for the current URL.
            if let Some(cookie_header) = self.config.cookies.header_for(request.url()) {
                request
                    .headers_mut()
                    .set_default("cookie", cookie_header);
            }

            let (status, resp_headers, body) = self.send_once(&request, timeout).await?;

            // Record any cookies the server set.
            self.config.cookies.extract(request.url(), &resp_headers);

            let is_redirect = matches!(
                status.as_u16(),
                301 | 302 | 303 | 307 | 308
            );

            if !(follow_redirects && is_redirect) {
                let mut response = Response::new(
                    status,
                    resp_headers,
                    request.url().clone(),
                    body,
                );
                response.set_history(history);
                return Ok(response);
            }

            if history.len() >= self.config.max_redirects {
                return Err(Error::new(
                    ErrorKind::TooManyRedirects,
                    format!(
                        "exceeded maximum of {} redirects",
                        self.config.max_redirects
                    ),
                ));
            }

            let location = resp_headers.get("location").ok_or_else(|| {
                Error::new(
                    ErrorKind::InvalidRedirect,
                    "redirect response missing Location header",
                )
            })?;

            let next_url = request.url().join(location).map_err(|e| {
                Error::new(
                    ErrorKind::InvalidRedirect,
                    format!("invalid redirect Location {location:?}: {e}"),
                )
            })?;

            history.push(request.url().clone());
            request = self.build_redirect(request, status, next_url);
        }
    }

    /// Build the follow-up request for a redirect, adjusting method, body and
    /// sensitive headers as httpx does.
    fn build_redirect(&self, prev: Request, status: StatusCode, next_url: Url) -> Request {
        let cross_origin = {
            let a = prev.url();
            a.scheme() != next_url.scheme()
                || a.host() != next_url.host()
                || a.port_or_default() != next_url.port_or_default()
        };

        let method = prev.method().clone();
        let (new_method, drop_body) = redirect_method(status, &method);

        let mut request = Request::new(new_method, next_url);

        // Carry over headers, dropping body-specific and (cross-origin) sensitive ones.
        for (name, value) in prev.headers().iter() {
            let lower = name.to_ascii_lowercase();
            if drop_body && (lower == "content-length" || lower == "content-type") {
                continue;
            }
            // Cookie/Host are recomputed per-request; Authorization dropped cross-origin.
            if lower == "cookie" || lower == "host" {
                continue;
            }
            if cross_origin && lower == "authorization" {
                continue;
            }
            request.headers_mut().append(name, value);
        }

        if !drop_body {
            request.set_body(prev.body().clone());
        }

        request
    }

    /// Perform a single request/response round trip (no redirect handling).
    async fn send_once(
        &self,
        request: &Request,
        timeout: Option<Duration>,
    ) -> Result<(StatusCode, Headers, Bytes)> {
        let uri: http::Uri = request
            .url()
            .as_str()
            .parse()
            .map_err(|e| Error::invalid_request(format!("invalid request URI: {e}")))?;

        let mut builder = http::Request::builder()
            .method(request.method().clone())
            .uri(uri);
        if let Some(hmap) = builder.headers_mut() {
            *hmap = request.headers().to_header_map()?;
        }
        let http_request = builder
            .body(Full::new(request.body().clone()))
            .map_err(Error::from)?;

        let fut = self.inner.request(http_request);

        let response = match timeout {
            Some(dur) => tokio::time::timeout(dur, fut)
                .await
                .map_err(|_| {
                    Error::new(
                        ErrorKind::Timeout,
                        format!("request timed out after {dur:?}"),
                    )
                })?
                .map_err(|e| Error::with_source(ErrorKind::Transport, e.to_string(), e))?,
            None => fut
                .await
                .map_err(|e| Error::with_source(ErrorKind::Transport, e.to_string(), e))?,
        };

        let status = response.status();
        let headers = Headers::from_header_map(response.headers());

        let collected = response
            .into_body()
            .collect()
            .await
            .map_err(|e| Error::with_source(ErrorKind::Transport, e.to_string(), e))?;
        let body = collected.to_bytes();

        Ok((status, headers, body))
    }
}

impl Default for Client {
    fn default() -> Self {
        Client::new()
    }
}

/// Determine the method and whether to drop the body for a redirect.
fn redirect_method(status: StatusCode, method: &Method) -> (Method, bool) {
    match status.as_u16() {
        // See Other: always switch to GET (except HEAD), drop the body.
        303 if method != Method::HEAD => (Method::GET, true),
        // Moved Permanently / Found: browsers and httpx turn POST into GET.
        301 | 302 if method == Method::POST => (Method::GET, true),
        // Temporary / Permanent redirect: preserve method and body.
        _ => (method.clone(), false),
    }
}

/// Builder for a [`Client`], mirroring `httpx.AsyncClient(...)` keyword options.
pub struct ClientBuilder {
    base_url: Option<String>,
    headers: Headers,
    auth: Option<Arc<dyn Auth>>,
    timeout: Option<Duration>,
    follow_redirects: bool,
    max_redirects: usize,
    http2: bool,
    accept_encoding_identity: bool,
}

impl ClientBuilder {
    pub fn new() -> Self {
        ClientBuilder {
            base_url: None,
            headers: Headers::new(),
            auth: None,
            timeout: Some(Duration::from_secs(5)),
            follow_redirects: false,
            max_redirects: 20,
            http2: true,
            accept_encoding_identity: true,
        }
    }

    /// Set a base URL that relative request URLs are resolved against.
    pub fn base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = Some(url.into());
        self
    }

    /// Add a default header sent with every request.
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.append(name, value);
        self
    }

    /// Replace the default header set.
    pub fn headers(mut self, headers: Headers) -> Self {
        self.headers = headers;
        self
    }

    /// Set default HTTP Basic auth.
    pub fn basic_auth(mut self, username: impl AsRef<str>, password: impl AsRef<str>) -> Self {
        self.auth = Some(Arc::new(BasicAuth::new(username, password)));
        self
    }

    /// Set a default bearer token.
    pub fn bearer_auth(mut self, token: impl AsRef<str>) -> Self {
        self.auth = Some(Arc::new(BearerAuth::new(token)));
        self
    }

    /// Set a custom default auth scheme.
    pub fn auth(mut self, auth: Arc<dyn Auth>) -> Self {
        self.auth = Some(auth);
        self
    }

    /// The default per-request timeout. `None` disables the timeout.
    pub fn timeout(mut self, timeout: Option<Duration>) -> Self {
        self.timeout = timeout;
        self
    }

    /// Whether to follow redirects automatically (httpx default is `false`).
    pub fn follow_redirects(mut self, follow: bool) -> Self {
        self.follow_redirects = follow;
        self
    }

    /// Maximum number of redirects to follow before erroring.
    pub fn max_redirects(mut self, max: usize) -> Self {
        self.max_redirects = max;
        self
    }

    /// Enable or disable HTTP/2 negotiation via ALPN.
    pub fn http2(mut self, enabled: bool) -> Self {
        self.http2 = enabled;
        self
    }

    /// When `true` (default), advertise `Accept-Encoding: identity` so the
    /// server does not compress responses (v1 does not decompress bodies).
    pub fn accept_encoding_identity(mut self, enabled: bool) -> Self {
        self.accept_encoding_identity = enabled;
        self
    }

    /// Build the client. Panics only on an internally-inconsistent base URL at
    /// first use; URL errors surface per-request instead.
    pub fn build(self) -> Client {
        ensure_crypto_provider();

        let builder = hyper_rustls::HttpsConnectorBuilder::new()
            .with_webpki_roots()
            .https_or_http();
        let https = if self.http2 {
            builder.enable_all_versions().build()
        } else {
            builder.enable_http1().build()
        };

        let inner = HyperClient::builder(TokioExecutor::new()).build(https);

        // Assemble default headers with httpx-like defaults.
        let mut headers = Headers::new();
        headers.insert("user-agent", concat!("rshttpx/", env!("CARGO_PKG_VERSION")));
        headers.insert("accept", "*/*");
        if self.accept_encoding_identity {
            headers.insert("accept-encoding", "identity");
        }
        headers.extend(&self.headers);

        let base_url = self.base_url.as_deref().and_then(|u| Url::parse(u).ok());

        let config = Config {
            base_url,
            headers,
            auth: self.auth,
            cookies: Cookies::new(),
            timeout: self.timeout,
            follow_redirects: self.follow_redirects,
            max_redirects: self.max_redirects,
        };

        Client {
            inner,
            config: Arc::new(config),
        }
    }
}

impl Default for ClientBuilder {
    fn default() -> Self {
        ClientBuilder::new()
    }
}

/// Fluent builder for a single request, returned by the [`Client`] method
/// helpers. Stands in for httpx's keyword arguments (`params=`, `json=`, ...).
pub struct RequestBuilder<'a> {
    client: &'a Client,
    method: Method,
    raw_url: String,
    headers: Headers,
    query: QueryParams,
    content: Option<Result<Content>>,
    auth: Option<Arc<dyn Auth>>,
    timeout_override: Option<Option<Duration>>,
    follow_redirects_override: Option<bool>,
}

impl<'a> RequestBuilder<'a> {
    fn new(client: &'a Client, method: Method, url: &str) -> Self {
        RequestBuilder {
            client,
            method,
            raw_url: url.to_string(),
            headers: Headers::new(),
            query: QueryParams::new(),
            content: None,
            auth: None,
            timeout_override: None,
            follow_redirects_override: None,
        }
    }

    /// Add a single header.
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.append(name, value);
        self
    }

    /// Merge in a header collection.
    pub fn headers(mut self, headers: Headers) -> Self {
        self.headers.extend(&headers);
        self
    }

    /// Append a query parameter (httpx `params=`).
    pub fn query(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.query.append(key, value);
        self
    }

    /// Set the whole query parameter set.
    pub fn params(mut self, params: QueryParams) -> Self {
        self.query = params;
        self
    }

    /// Set a raw byte body (httpx `content=`).
    pub fn body(mut self, body: impl Into<Bytes>) -> Self {
        self.content = Some(Ok(Content::bytes(body)));
        self
    }

    /// Set a UTF-8 text body.
    pub fn text(mut self, body: impl Into<String>) -> Self {
        self.content = Some(Ok(Content::text(body)));
        self
    }

    /// Set a JSON body (httpx `json=`).
    pub fn json<T: Serialize>(mut self, value: &T) -> Self {
        self.content = Some(Content::json(value));
        self
    }

    /// Set a url-encoded form body (httpx `data=`).
    pub fn form<T: Serialize>(mut self, value: &T) -> Self {
        self.content = Some(Content::form(value));
        self
    }

    /// Set a multipart/form-data body (httpx `files=`).
    pub fn multipart(mut self, multipart: Multipart) -> Self {
        self.content = Some(Ok(multipart.encode()));
        self
    }

    /// Set a pre-encoded [`Content`].
    pub fn content(mut self, content: Content) -> Self {
        self.content = Some(Ok(content));
        self
    }

    /// Use HTTP Basic auth for this request only.
    pub fn basic_auth(mut self, username: impl AsRef<str>, password: impl AsRef<str>) -> Self {
        self.auth = Some(Arc::new(BasicAuth::new(username, password)));
        self
    }

    /// Use a bearer token for this request only.
    pub fn bearer_auth(mut self, token: impl AsRef<str>) -> Self {
        self.auth = Some(Arc::new(BearerAuth::new(token)));
        self
    }

    /// Use a custom auth scheme for this request only.
    pub fn auth(mut self, auth: Arc<dyn Auth>) -> Self {
        self.auth = Some(auth);
        self
    }

    /// Override the timeout for this request. `None` disables it.
    pub fn timeout(mut self, timeout: Option<Duration>) -> Self {
        self.timeout_override = Some(timeout);
        self
    }

    /// Override redirect-following for this request.
    pub fn follow_redirects(mut self, follow: bool) -> Self {
        self.follow_redirects_override = Some(follow);
        self
    }

    /// Build the [`Request`] without sending it.
    pub fn build(self) -> Result<Request> {
        let base = self.client.resolve_url(&self.raw_url)?;
        let url = if self.query.is_empty() {
            base
        } else {
            base.merge_params(&self.query)
        };

        let mut request = Request::new(self.method, url);

        // Default headers first, then per-request headers (which may override).
        request.headers_mut().extend(&self.client.config.headers);
        for (name, value) in self.headers.iter() {
            request.headers_mut().insert(name, value);
        }

        if let Some(content) = self.content {
            request.set_content(content?);
        }

        // Auth precedence: per-request overrides client default.
        if let Some(auth) = &self.auth {
            auth.apply(&mut request);
        } else if let Some(auth) = &self.client.config.auth {
            auth.apply(&mut request);
        }

        Ok(request)
    }

    /// Build and send the request, returning the response.
    pub async fn send(self) -> Result<Response> {
        let client = self.client;
        let timeout = self
            .timeout_override
            .unwrap_or(client.config.timeout);
        let follow = self
            .follow_redirects_override
            .unwrap_or(client.config.follow_redirects);
        let request = self.build()?;
        client.execute(request, timeout, follow).await
    }
}
