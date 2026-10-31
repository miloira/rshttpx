//! The async [`Client`] and its builder, mirroring `httpx.AsyncClient`.

use std::sync::Arc;
use std::sync::Once;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::{Method, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::connect::proxy::Tunnel;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::{Client as HyperClient, ResponseFuture};
use hyper_util::rt::TokioExecutor;
use serde::Serialize;

use crate::auth::{Auth, BasicAuth, BearerAuth, DigestAuth};
use crate::content::{Content, Multipart};
use crate::cookies::Cookies;
use crate::decode;
use crate::error::{Error, ErrorKind, Result};
use crate::headers::Headers;
use crate::request::Request;
use crate::response::Response;
use crate::tls;
use crate::url::{QueryParams, Url};

type DirectConnector = HttpsConnector<HttpConnector>;
type ProxyConnector = HttpsConnector<Tunnel<HttpConnector>>;

/// A connection pool that is either direct or routed through an HTTP(S) proxy.
#[derive(Clone)]
enum Pool {
    Direct(HyperClient<DirectConnector, Full<Bytes>>),
    Proxied(HyperClient<ProxyConnector, Full<Bytes>>),
}

impl Pool {
    fn request(&self, req: http::Request<Full<Bytes>>) -> ResponseFuture {
        match self {
            Pool::Direct(c) => c.request(req),
            Pool::Proxied(c) => c.request(req),
        }
    }
}

static CRYPTO_INIT: Once = Once::new();

pub(crate) fn ensure_crypto_provider() {
    CRYPTO_INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// Granular timeout settings, mirroring `httpx.Timeout`.
#[derive(Clone, Copy, Debug)]
pub struct Timeout {
    /// Time budget to establish a TCP connection.
    pub connect: Option<Duration>,
    /// Overall time budget for the request/response round trip.
    pub total: Option<Duration>,
}

impl Timeout {
    /// A single timeout applied to both connect and the overall round trip.
    pub fn all(duration: Duration) -> Self {
        Timeout {
            connect: Some(duration),
            total: Some(duration),
        }
    }

    /// Disable all timeouts.
    pub fn none() -> Self {
        Timeout {
            connect: None,
            total: None,
        }
    }
}

impl Default for Timeout {
    fn default() -> Self {
        Timeout::all(Duration::from_secs(5))
    }
}

/// Connection-pool limits, mirroring `httpx.Limits`.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_idle_per_host: usize,
    pub idle_timeout: Option<Duration>,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_idle_per_host: 10,
            idle_timeout: Some(Duration::from_secs(90)),
        }
    }
}

struct Config {
    base_url: Option<Url>,
    headers: Headers,
    auth: Option<Arc<dyn Auth>>,
    cookies: Cookies,
    timeout: Timeout,
    follow_redirects: bool,
    max_redirects: usize,
}

/// An async HTTP client with connection pooling, mirroring `httpx.AsyncClient`.
#[derive(Clone)]
pub struct Client {
    inner: Pool,
    config: Arc<Config>,
}

impl Client {
    pub fn new() -> Self {
        ClientBuilder::new().build()
    }

    pub fn builder() -> ClientBuilder {
        ClientBuilder::new()
    }

    pub fn cookies(&self) -> &Cookies {
        &self.config.cookies
    }

    pub fn get(&self, url: &str) -> RequestBuilder<'_> {
        self.request(Method::GET, url)
    }

    pub fn post(&self, url: &str) -> RequestBuilder<'_> {
        self.request(Method::POST, url)
    }

    pub fn put(&self, url: &str) -> RequestBuilder<'_> {
        self.request(Method::PUT, url)
    }

    pub fn patch(&self, url: &str) -> RequestBuilder<'_> {
        self.request(Method::PATCH, url)
    }

    pub fn delete(&self, url: &str) -> RequestBuilder<'_> {
        self.request(Method::DELETE, url)
    }

    pub fn head(&self, url: &str) -> RequestBuilder<'_> {
        self.request(Method::HEAD, url)
    }

    pub fn options(&self, url: &str) -> RequestBuilder<'_> {
        self.request(Method::OPTIONS, url)
    }

    pub fn request(&self, method: Method, url: &str) -> RequestBuilder<'_> {
        RequestBuilder::new(self, method, url)
    }

    fn resolve_url(&self, raw: &str) -> Result<Url> {
        match &self.config.base_url {
            Some(base) => base.join(raw),
            None => Url::parse(raw),
        }
    }

    async fn execute(
        &self,
        mut request: Request,
        timeout: Option<Duration>,
        follow_redirects: bool,
        auth: Option<Arc<dyn Auth>>,
    ) -> Result<Response> {
        let start = Instant::now();
        let mut history: Vec<Url> = Vec::new();
        let mut auth_attempted = false;

        loop {
            if let Some(cookie_header) = self.config.cookies.header_for(request.url()) {
                request.headers_mut().set_default("cookie", cookie_header);
            }

            let (status, resp_headers, body) = self.send_once(&request, timeout).await?;
            self.config.cookies.extract(request.url(), &resp_headers);

            let mut response =
                Response::new(status, resp_headers, request.url().clone(), body);

            // Digest / challenge-driven auth: retry once with credentials.
            if let Some(auth) = &auth {
                if auth.needs_response() && !auth_attempted {
                    let mut next = request.clone();
                    if auth.respond_to_challenge(&response, &mut next) {
                        auth_attempted = true;
                        request = next;
                        continue;
                    }
                }
            }

            let is_redirect = matches!(status.as_u16(), 301 | 302 | 303 | 307 | 308);

            if !(follow_redirects && is_redirect) {
                response.set_history(history);
                response.set_elapsed(start.elapsed());
                return Ok(response);
            }

            if history.len() >= self.config.max_redirects {
                return Err(Error::new(
                    ErrorKind::TooManyRedirects,
                    format!("exceeded maximum of {} redirects", self.config.max_redirects),
                ));
            }

            let location = response.headers().get("location").ok_or_else(|| {
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
            auth_attempted = false;
        }
    }

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

        for (name, value) in prev.headers().iter() {
            let lower = name.to_ascii_lowercase();
            if drop_body && (lower == "content-length" || lower == "content-type") {
                continue;
            }
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
                    Error::new(ErrorKind::Timeout, format!("request timed out after {dur:?}"))
                })?
                .map_err(|e| Error::with_source(ErrorKind::Transport, e.to_string(), e))?,
            None => fut
                .await
                .map_err(|e| Error::with_source(ErrorKind::Transport, e.to_string(), e))?,
        };

        let status = response.status();
        let mut headers = Headers::from_header_map(response.headers());

        let collected = response
            .into_body()
            .collect()
            .await
            .map_err(|e| Error::with_source(ErrorKind::Transport, e.to_string(), e))?;
        let raw = collected.to_bytes();

        // Transparently decompress per Content-Encoding.
        let body = if raw.is_empty() {
            raw
        } else {
            let decoded = decode::decode_body(headers.get("content-encoding"), raw)?;
            headers.remove("content-encoding");
            headers.remove("content-length");
            decoded
        };

        Ok((status, headers, body))
    }

    /// Send a single request and return a streaming response (no redirect
    /// following, no decompression).
    async fn send_stream_once(
        &self,
        request: &Request,
        timeout: Option<Duration>,
    ) -> Result<crate::stream::StreamingResponse> {
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
                    Error::new(ErrorKind::Timeout, format!("request timed out after {dur:?}"))
                })?
                .map_err(|e| Error::with_source(ErrorKind::Transport, e.to_string(), e))?,
            None => fut
                .await
                .map_err(|e| Error::with_source(ErrorKind::Transport, e.to_string(), e))?,
        };

        let status = response.status();
        let headers = Headers::from_header_map(response.headers());
        Ok(crate::stream::StreamingResponse {
            status,
            headers,
            url: request.url().clone(),
            body: response.into_body(),
        })
    }
}

impl Default for Client {
    fn default() -> Self {
        Client::new()
    }
}

fn redirect_method(status: StatusCode, method: &Method) -> (Method, bool) {
    match status.as_u16() {
        303 if method != Method::HEAD => (Method::GET, true),
        301 | 302 if method == Method::POST => (Method::GET, true),
        _ => (method.clone(), false),
    }
}

/// Builder for a [`Client`], mirroring `httpx.AsyncClient(...)` options.
pub struct ClientBuilder {
    base_url: Option<String>,
    headers: Headers,
    auth: Option<Arc<dyn Auth>>,
    timeout: Timeout,
    follow_redirects: bool,
    max_redirects: usize,
    http2: bool,
    verify: bool,
    limits: Limits,
    default_encoding: bool,
    proxy: Option<String>,
}

impl ClientBuilder {
    pub fn new() -> Self {
        ClientBuilder {
            base_url: None,
            headers: Headers::new(),
            auth: None,
            timeout: Timeout::default(),
            follow_redirects: false,
            max_redirects: 20,
            http2: true,
            verify: true,
            limits: Limits::default(),
            default_encoding: true,
            proxy: None,
        }
    }

    pub fn base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = Some(url.into());
        self
    }

    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.append(name, value);
        self
    }

    pub fn headers(mut self, headers: Headers) -> Self {
        self.headers = headers;
        self
    }

    pub fn basic_auth(mut self, username: impl AsRef<str>, password: impl AsRef<str>) -> Self {
        self.auth = Some(Arc::new(BasicAuth::new(username, password)));
        self
    }

    pub fn bearer_auth(mut self, token: impl AsRef<str>) -> Self {
        self.auth = Some(Arc::new(BearerAuth::new(token)));
        self
    }

    pub fn digest_auth(mut self, username: impl Into<String>, password: impl Into<String>) -> Self {
        self.auth = Some(Arc::new(DigestAuth::new(username, password)));
        self
    }

    pub fn auth(mut self, auth: Arc<dyn Auth>) -> Self {
        self.auth = Some(auth);
        self
    }

    /// Set a single overall timeout (connect + total). Use [`Self::timeouts`]
    /// for granular control.
    pub fn timeout(mut self, timeout: Option<Duration>) -> Self {
        self.timeout = match timeout {
            Some(d) => Timeout::all(d),
            None => Timeout::none(),
        };
        self
    }

    /// Set granular timeouts.
    pub fn timeouts(mut self, timeout: Timeout) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn follow_redirects(mut self, follow: bool) -> Self {
        self.follow_redirects = follow;
        self
    }

    pub fn max_redirects(mut self, max: usize) -> Self {
        self.max_redirects = max;
        self
    }

    pub fn http2(mut self, enabled: bool) -> Self {
        self.http2 = enabled;
        self
    }

    /// Whether to verify TLS server certificates (httpx `verify=`). Disabling
    /// this is insecure and intended only for local testing.
    pub fn verify(mut self, verify: bool) -> Self {
        self.verify = verify;
        self
    }

    /// Connection-pool limits.
    pub fn limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// When `true` (default), advertise `Accept-Encoding: gzip, deflate, br`
    /// and transparently decompress responses.
    pub fn decompress(mut self, enabled: bool) -> Self {
        self.default_encoding = enabled;
        self
    }

    /// Route requests through an HTTP(S) proxy, e.g. `http://localhost:8080`.
    ///
    /// Connections are established with an HTTP `CONNECT` tunnel, which works
    /// for `https://` targets (and `http://` targets via proxies that permit
    /// tunnelling). An unparseable proxy URL is ignored (direct connection).
    pub fn proxy(mut self, url: impl Into<String>) -> Self {
        self.proxy = Some(url.into());
        self
    }

    pub fn build(self) -> Client {
        ensure_crypto_provider();

        let make_http = || {
            let mut http = HttpConnector::new();
            http.enforce_http(false);
            if let Some(connect) = self.timeout.connect {
                http.set_connect_timeout(Some(connect));
            }
            http
        };

        let make_builder = || {
            let mut b = HyperClient::builder(TokioExecutor::new());
            b.pool_max_idle_per_host(self.limits.max_idle_per_host);
            b.pool_idle_timeout(self.limits.idle_timeout);
            b
        };

        let proxy_uri = self
            .proxy
            .as_deref()
            .and_then(|p| p.parse::<http::Uri>().ok());

        let inner = match proxy_uri {
            Some(uri) => {
                let tunnel = Tunnel::new(uri, make_http());
                let base = hyper_rustls::HttpsConnectorBuilder::new();
                let schemes = if self.verify {
                    base.with_webpki_roots()
                } else {
                    base.with_tls_config(tls::no_verify_config())
                };
                let protocols = schemes.https_or_http();
                let https = if self.http2 {
                    protocols.enable_all_versions().wrap_connector(tunnel)
                } else {
                    protocols.enable_http1().wrap_connector(tunnel)
                };
                Pool::Proxied(make_builder().build(https))
            }
            None => {
                let base = hyper_rustls::HttpsConnectorBuilder::new();
                let schemes = if self.verify {
                    base.with_webpki_roots()
                } else {
                    base.with_tls_config(tls::no_verify_config())
                };
                let protocols = schemes.https_or_http();
                let https = if self.http2 {
                    protocols.enable_all_versions().wrap_connector(make_http())
                } else {
                    protocols.enable_http1().wrap_connector(make_http())
                };
                Pool::Direct(make_builder().build(https))
            }
        };

        let mut headers = Headers::new();
        headers.insert("user-agent", concat!("rshttpx/", env!("CARGO_PKG_VERSION")));
        headers.insert("accept", "*/*");
        if self.default_encoding {
            headers.insert("accept-encoding", decode::DEFAULT_ACCEPT_ENCODING);
        } else {
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

/// Fluent builder for a single request, returned by the [`Client`] helpers.
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

    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.append(name, value);
        self
    }

    pub fn headers(mut self, headers: Headers) -> Self {
        self.headers.extend(&headers);
        self
    }

    pub fn query(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.query.append(key, value);
        self
    }

    pub fn params(mut self, params: QueryParams) -> Self {
        self.query = params;
        self
    }

    pub fn body(mut self, body: impl Into<Bytes>) -> Self {
        self.content = Some(Ok(Content::bytes(body)));
        self
    }

    pub fn text(mut self, body: impl Into<String>) -> Self {
        self.content = Some(Ok(Content::text(body)));
        self
    }

    pub fn json<T: Serialize>(mut self, value: &T) -> Self {
        self.content = Some(Content::json(value));
        self
    }

    pub fn form<T: Serialize>(mut self, value: &T) -> Self {
        self.content = Some(Content::form(value));
        self
    }

    pub fn multipart(mut self, multipart: Multipart) -> Self {
        self.content = Some(Ok(multipart.encode()));
        self
    }

    pub fn content(mut self, content: Content) -> Self {
        self.content = Some(Ok(content));
        self
    }

    pub fn basic_auth(mut self, username: impl AsRef<str>, password: impl AsRef<str>) -> Self {
        self.auth = Some(Arc::new(BasicAuth::new(username, password)));
        self
    }

    pub fn bearer_auth(mut self, token: impl AsRef<str>) -> Self {
        self.auth = Some(Arc::new(BearerAuth::new(token)));
        self
    }

    pub fn digest_auth(mut self, username: impl Into<String>, password: impl Into<String>) -> Self {
        self.auth = Some(Arc::new(DigestAuth::new(username, password)));
        self
    }

    pub fn auth(mut self, auth: Arc<dyn Auth>) -> Self {
        self.auth = Some(auth);
        self
    }

    pub fn timeout(mut self, timeout: Option<Duration>) -> Self {
        self.timeout_override = Some(timeout);
        self
    }

    pub fn follow_redirects(mut self, follow: bool) -> Self {
        self.follow_redirects_override = Some(follow);
        self
    }

    /// Build the [`Request`] without sending it.
    pub fn build(self) -> Result<Request> {
        let (request, _auth) = self.into_request()?;
        Ok(request)
    }

    fn into_request(self) -> Result<(Request, Option<Arc<dyn Auth>>)> {
        let base = self.client.resolve_url(&self.raw_url)?;
        let url = if self.query.is_empty() {
            base
        } else {
            base.merge_params(&self.query)
        };

        let mut request = Request::new(self.method, url);
        request.headers_mut().extend(&self.client.config.headers);
        for (name, value) in self.headers.iter() {
            request.headers_mut().insert(name, value);
        }

        if let Some(content) = self.content {
            request.set_content(content?);
        }

        let auth = self.auth.or_else(|| self.client.config.auth.clone());
        if let Some(auth) = &auth {
            auth.apply(&mut request);
        }

        Ok((request, auth))
    }

    /// Build and send the request, returning the response.
    pub async fn send(self) -> Result<Response> {
        let client = self.client;
        let timeout = self.timeout_override.unwrap_or(client.config.timeout.total);
        let follow = self
            .follow_redirects_override
            .unwrap_or(client.config.follow_redirects);
        let (request, auth) = self.into_request()?;
        client.execute(request, timeout, follow, auth).await
    }

    /// Build and send the request, returning a streaming response whose body is
    /// consumed on demand. Redirects and decompression are not applied.
    pub async fn send_stream(self) -> Result<crate::stream::StreamingResponse> {
        let client = self.client;
        let timeout = self.timeout_override.unwrap_or(client.config.timeout.total);
        let (request, _auth) = self.into_request()?;
        client.send_stream_once(&request, timeout).await
    }
}
