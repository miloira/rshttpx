//! The async [`Client`] and its builder, mirroring `httpx.AsyncClient`.

use std::sync::Arc;
use std::sync::Once;
use std::time::{Duration, Instant};

use bytes::Bytes;
use futures_core::Stream;
use futures_util::TryStreamExt;
use http::{Method, StatusCode};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::connect::proxy::{SocksV5, Tunnel};
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
use crate::netrc::Netrc;
use crate::request::Request;
use crate::response::Response;
use crate::tls::{self, TlsOptions};
use crate::transport::Transport;
use crate::url::{QueryParams, Url};

/// A URL pattern for per-host proxy mounts, mirroring httpx mount keys such as
/// `"all://"`, `"https://"`, `"https://example.com"` and `"all://*.example.com"`.
#[derive(Clone, Debug)]
struct Pattern {
    scheme: Option<String>,
    host: Option<String>,
    subdomains: bool,
}

impl Pattern {
    fn parse(raw: &str) -> Pattern {
        let (scheme, rest) = match raw.split_once("://") {
            Some((s, r)) => {
                let scheme = if s == "all" || s.is_empty() {
                    None
                } else {
                    Some(s.to_ascii_lowercase())
                };
                (scheme, r)
            }
            None => (None, raw),
        };
        let rest = rest.trim();
        if rest.is_empty() {
            return Pattern {
                scheme,
                host: None,
                subdomains: false,
            };
        }
        // Drop any port component for matching purposes.
        let host_part = rest.split(':').next().unwrap_or(rest);
        if let Some(suffix) = host_part.strip_prefix("*.") {
            Pattern {
                scheme,
                host: Some(suffix.to_ascii_lowercase()),
                subdomains: true,
            }
        } else {
            Pattern {
                scheme,
                host: Some(host_part.to_ascii_lowercase()),
                subdomains: false,
            }
        }
    }

    fn matches(&self, url: &Url) -> bool {
        if let Some(scheme) = &self.scheme {
            if !url.scheme().eq_ignore_ascii_case(scheme) {
                return false;
            }
        }
        match &self.host {
            None => true,
            Some(host) => {
                let url_host = url.host().unwrap_or("").to_ascii_lowercase();
                if self.subdomains {
                    url_host == *host
                        || (url_host.ends_with(host)
                            && url_host.len() > host.len()
                            && url_host.as_bytes()[url_host.len() - host.len() - 1] == b'.')
                } else {
                    url_host == *host
                }
            }
        }
    }
}

/// Build a connection pool for an optional proxy using the given TLS config.
fn build_pool(
    proxy: Option<&str>,
    tls_config: rustls::ClientConfig,
    http2: bool,
    limits: Limits,
    connect_timeout: Option<Duration>,
) -> Pool {
    let make_http = || {
        let mut http = HttpConnector::new();
        http.enforce_http(false);
        if let Some(c) = connect_timeout {
            http.set_connect_timeout(Some(c));
        }
        http
    };
    let make_builder = || {
        let mut b = HyperClient::builder(TokioExecutor::new());
        b.pool_max_idle_per_host(limits.max_idle_per_host);
        b.pool_idle_timeout(limits.idle_timeout);
        b
    };
    let make_https = |tls: rustls::ClientConfig| {
        hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(tls)
            .https_or_http()
    };

    let proxy_uri = proxy.and_then(|p| p.parse::<http::Uri>().ok());
    let is_socks = proxy.map(|p| p.starts_with("socks")).unwrap_or(false);

    match proxy_uri {
        Some(uri) if is_socks => {
            let socks = SocksV5::new(uri, make_http());
            let p = make_https(tls_config);
            let https = if http2 {
                p.enable_all_versions().wrap_connector(socks)
            } else {
                p.enable_http1().wrap_connector(socks)
            };
            Pool::Socks(make_builder().build(https))
        }
        Some(uri) => {
            let tunnel = Tunnel::new(uri, make_http());
            let p = make_https(tls_config);
            let https = if http2 {
                p.enable_all_versions().wrap_connector(tunnel)
            } else {
                p.enable_http1().wrap_connector(tunnel)
            };
            Pool::Tunnel(make_builder().build(https))
        }
        None => {
            let p = make_https(tls_config);
            let https = if http2 {
                p.enable_all_versions().wrap_connector(make_http())
            } else {
                p.enable_http1().wrap_connector(make_http())
            };
            Pool::Direct(make_builder().build(https))
        }
    }
}

/// A hook invoked on each outgoing request before it is sent (httpx
/// `event_hooks["request"]`). It may mutate the request.
pub type RequestHook = Arc<dyn Fn(&mut Request) + Send + Sync>;
/// A hook invoked on each received response (httpx `event_hooks["response"]`).
pub type ResponseHook = Arc<dyn Fn(&Response) + Send + Sync>;

type DirectConnector = HttpsConnector<HttpConnector>;
type TunnelConnector = HttpsConnector<Tunnel<HttpConnector>>;
type SocksConnector = HttpsConnector<SocksV5<HttpConnector>>;

/// The request body type: boxed so it can be either buffered bytes or a stream.
type ReqBody = BoxBody<Bytes, std::io::Error>;

/// Wrap buffered bytes as a [`ReqBody`].
fn buffered_body(bytes: Bytes) -> ReqBody {
    Full::new(bytes).map_err(|e: std::convert::Infallible| match e {}).boxed()
}

/// Apply transparent decompression to a raw response body per `Content-Encoding`.
fn finalize_body(
    status: StatusCode,
    mut headers: Headers,
    raw: Bytes,
) -> Result<(StatusCode, Headers, Bytes)> {
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

/// A connection pool: direct, through an HTTP `CONNECT` tunnel, or via SOCKS5.
#[derive(Clone)]
enum Pool {
    Direct(HyperClient<DirectConnector, ReqBody>),
    Tunnel(HyperClient<TunnelConnector, ReqBody>),
    Socks(HyperClient<SocksConnector, ReqBody>),
}

impl Pool {
    fn request(&self, req: http::Request<ReqBody>) -> ResponseFuture {
        match self {
            Pool::Direct(c) => c.request(req),
            Pool::Tunnel(c) => c.request(req),
            Pool::Socks(c) => c.request(req),
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
    retries: u32,
    netrc: Option<Arc<Netrc>>,
    on_request: Vec<RequestHook>,
    on_response: Vec<ResponseHook>,
    mounts: Vec<(Pattern, Pool)>,
    transport: Option<Arc<dyn Transport>>,
}

/// An async HTTP client with connection pooling, mirroring `httpx.AsyncClient`.
#[derive(Clone)]
pub struct Client {
    inner: Pool,
    config: Arc<Config>,
}

impl Client {
    pub fn new() -> Self {
        ClientBuilder::new()
            .build()
            .expect("default client configuration is always valid")
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

            // Request event hooks may observe or mutate the outgoing request.
            for hook in &self.config.on_request {
                hook(&mut request);
            }

            let (status, resp_headers, body) = self.send_with_retries(&request, timeout).await?;
            self.config.cookies.extract(request.url(), &resp_headers);

            let mut response =
                Response::new(status, resp_headers, request.url().clone(), body);

            // Response event hooks observe every response (including redirects).
            for hook in &self.config.on_response {
                hook(&response);
            }

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

    /// Send one request, retrying transient transport (connect) failures up to
    /// the configured retry budget with a short linear backoff.
    async fn send_with_retries(
        &self,
        request: &Request,
        timeout: Option<Duration>,
    ) -> Result<(StatusCode, Headers, Bytes)> {
        let mut attempt: u32 = 0;
        loop {
            match self.send_once(request, timeout).await {
                Ok(v) => return Ok(v),
                Err(e) => {
                    let retryable = matches!(e.kind(), ErrorKind::Transport);
                    if retryable && attempt < self.config.retries {
                        attempt += 1;
                        tokio::time::sleep(Duration::from_millis(100 * attempt as u64)).await;
                        continue;
                    }
                    return Err(e);
                }
            }
        }
    }

    /// Select the connection pool for a URL, honouring per-host proxy mounts.
    fn pool_for(&self, url: &Url) -> &Pool {
        for (pattern, pool) in &self.config.mounts {
            if pattern.matches(url) {
                return pool;
            }
        }
        &self.inner
    }

    /// One buffered round trip: via a custom transport if configured, otherwise
    /// the selected pool. Response decompression is applied uniformly.
    async fn send_once(
        &self,
        request: &Request,
        timeout: Option<Duration>,
    ) -> Result<(StatusCode, Headers, Bytes)> {
        let (status, headers, raw) = match &self.config.transport {
            Some(transport) => {
                let r = transport.roundtrip(request, timeout).await?;
                (r.status, r.headers, r.body)
            }
            None => {
                let body = buffered_body(request.body().clone());
                self.pool_roundtrip(self.pool_for(request.url()), request, body, timeout)
                    .await?
            }
        };
        finalize_body(status, headers, raw)
    }

    /// Send a request through a specific pool and return the raw (undecoded)
    /// status, headers and body.
    async fn pool_roundtrip(
        &self,
        pool: &Pool,
        request: &Request,
        body: ReqBody,
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
        let http_request = builder.body(body).map_err(Error::from)?;

        let fut = pool.request(http_request);
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
        let collected = response
            .into_body()
            .collect()
            .await
            .map_err(|e| Error::with_source(ErrorKind::Transport, e.to_string(), e))?;
        Ok((status, headers, collected.to_bytes()))
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
            .body(buffered_body(request.body().clone()))
            .map_err(Error::from)?;

        let fut = self.pool_for(request.url()).request(http_request);
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

impl Client {
    /// One-shot send of a request with a streaming body (no redirect following
    /// or challenge-auth retry, since a stream body cannot be replayed).
    async fn execute_stream_upload(
        &self,
        mut request: Request,
        body: ReqBody,
        timeout: Option<Duration>,
    ) -> Result<Response> {
        let start = Instant::now();
        if let Some(cookie_header) = self.config.cookies.header_for(request.url()) {
            request.headers_mut().set_default("cookie", cookie_header);
        }
        for hook in &self.config.on_request {
            hook(&mut request);
        }
        let pool = self.pool_for(request.url());
        let (status, headers, raw) = self.pool_roundtrip(pool, &request, body, timeout).await?;
        let (status, headers, bytes) = finalize_body(status, headers, raw)?;
        self.config.cookies.extract(request.url(), &headers);
        let mut response = Response::new(status, headers, request.url().clone(), bytes);
        for hook in &self.config.on_response {
            hook(&response);
        }
        response.set_elapsed(start.elapsed());
        Ok(response)
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
    extra_ca_pem: Vec<Vec<u8>>,
    identity_pem: Option<(Vec<u8>, Vec<u8>)>,
    limits: Limits,
    default_encoding: bool,
    proxy: Option<String>,
    retries: u32,
    trust_env: bool,
    use_netrc: bool,
    on_request: Vec<RequestHook>,
    on_response: Vec<ResponseHook>,
    mounts: Vec<(String, Option<String>)>,
    transport: Option<Arc<dyn Transport>>,
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
            extra_ca_pem: Vec::new(),
            identity_pem: None,
            limits: Limits::default(),
            default_encoding: true,
            proxy: None,
            retries: 0,
            trust_env: true,
            use_netrc: false,
            on_request: Vec::new(),
            on_response: Vec::new(),
            mounts: Vec::new(),
            transport: None,
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

    /// Route requests through a proxy. `http(s)://host:port` uses an HTTP
    /// `CONNECT` tunnel; `socks5://host:port` (or `socks5h://`) uses SOCKS5.
    /// An unparseable proxy URL is ignored (direct connection).
    pub fn proxy(mut self, url: impl Into<String>) -> Self {
        self.proxy = Some(url.into());
        self
    }

    /// Add a trust-anchor certificate (PEM) to the default root store, for
    /// servers signed by a private/custom CA (httpx `verify=<ca bundle>`).
    pub fn add_root_certificate_pem(mut self, pem: impl Into<Vec<u8>>) -> Self {
        self.extra_ca_pem.push(pem.into());
        self
    }

    /// Present a client certificate for mutual TLS (httpx `cert=`). Both the
    /// certificate chain and the private key are PEM-encoded.
    pub fn identity_pem(
        mut self,
        cert_pem: impl Into<Vec<u8>>,
        key_pem: impl Into<Vec<u8>>,
    ) -> Self {
        self.identity_pem = Some((cert_pem.into(), key_pem.into()));
        self
    }

    /// Number of times to retry a request on a transient connection failure.
    pub fn retries(mut self, retries: u32) -> Self {
        self.retries = retries;
        self
    }

    /// Whether to honour environment proxy settings (`HTTPS_PROXY`,
    /// `ALL_PROXY`, `HTTP_PROXY`) when no explicit proxy is configured. Matches
    /// httpx's `trust_env` (default `true`).
    pub fn trust_env(mut self, trust_env: bool) -> Self {
        self.trust_env = trust_env;
        self
    }

    /// Use credentials from the user's `.netrc` for requests that have no
    /// explicit auth (httpx reads netrc when `trust_env` is set).
    pub fn netrc(mut self, enabled: bool) -> Self {
        self.use_netrc = enabled;
        self
    }

    /// Register a hook invoked on every outgoing request (may mutate it).
    pub fn on_request<F>(mut self, hook: F) -> Self
    where
        F: Fn(&mut Request) + Send + Sync + 'static,
    {
        self.on_request.push(Arc::new(hook));
        self
    }

    /// Register a hook invoked on every received response.
    pub fn on_response<F>(mut self, hook: F) -> Self
    where
        F: Fn(&Response) + Send + Sync + 'static,
    {
        self.on_response.push(Arc::new(hook));
        self
    }

    /// Mount a proxy for URLs matching `pattern` (httpx `mounts=`). The pattern
    /// uses httpx mount syntax: `"all://"`, `"https://"`, `"https://example.com"`,
    /// or `"all://*.example.com"`. The most specific match wins; mounts are
    /// tried in the order added. Pass the proxy URL (`http(s)://` or `socks5://`).
    pub fn mount_proxy(mut self, pattern: impl Into<String>, proxy: impl Into<String>) -> Self {
        self.mounts.push((pattern.into(), Some(proxy.into())));
        self
    }

    /// Mount a direct (no-proxy) connection for URLs matching `pattern`, useful
    /// for carving out exceptions to a broader proxy mount.
    pub fn mount_direct(mut self, pattern: impl Into<String>) -> Self {
        self.mounts.push((pattern.into(), None));
        self
    }

    /// Use a custom [`Transport`] for the buffered request path (httpx
    /// `transport=`), e.g. a mock in tests. Response streaming and streaming
    /// uploads still use the built-in pool.
    pub fn transport(mut self, transport: Arc<dyn Transport>) -> Self {
        self.transport = Some(transport);
        self
    }

    /// Build the client. Returns an error if a custom CA bundle or client
    /// identity PEM is invalid.
    pub fn build(self) -> Result<Client> {
        ensure_crypto_provider();

        let tls_options = TlsOptions {
            verify: self.verify,
            extra_ca_pem: self.extra_ca_pem.clone(),
            identity_pem: self.identity_pem.clone(),
        };
        let tls_config = tls::build_config(&tls_options)?;

        let http2 = self.http2;
        let connect_timeout = self.timeout.connect;
        let limits = self.limits;

        // Resolve the effective default proxy: explicit, else environment.
        let proxy = self.proxy.clone().or_else(|| {
            if self.trust_env {
                std::env::var("HTTPS_PROXY")
                    .or_else(|_| std::env::var("https_proxy"))
                    .or_else(|_| std::env::var("ALL_PROXY"))
                    .or_else(|_| std::env::var("all_proxy"))
                    .or_else(|_| std::env::var("HTTP_PROXY"))
                    .or_else(|_| std::env::var("http_proxy"))
                    .ok()
            } else {
                None
            }
        });

        let inner = build_pool(
            proxy.as_deref(),
            tls_config.clone(),
            http2,
            limits,
            connect_timeout,
        );

        let mounts: Vec<(Pattern, Pool)> = self
            .mounts
            .iter()
            .map(|(pattern, proxy)| {
                let pool = build_pool(
                    proxy.as_deref(),
                    tls_config.clone(),
                    http2,
                    limits,
                    connect_timeout,
                );
                (Pattern::parse(pattern), pool)
            })
            .collect();

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

        let netrc = if self.use_netrc && self.trust_env {
            Netrc::from_env().map(Arc::new)
        } else {
            None
        };

        let config = Config {
            base_url,
            headers,
            auth: self.auth,
            cookies: Cookies::new(),
            timeout: self.timeout,
            follow_redirects: self.follow_redirects,
            max_redirects: self.max_redirects,
            retries: self.retries,
            netrc,
            on_request: self.on_request,
            on_response: self.on_response,
            mounts,
            transport: self.transport,
        };

        Ok(Client {
            inner,
            config: Arc::new(config),
        })
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
    stream_body: Option<ReqBody>,
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
            stream_body: None,
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

    /// Stream the request body from a byte stream instead of buffering it
    /// (httpx's streaming request content). A streamed request cannot be
    /// replayed, so redirects and challenge-auth retries are not applied to it.
    pub fn body_stream<S>(mut self, stream: S) -> Self
    where
        S: Stream<Item = std::result::Result<Bytes, std::io::Error>> + Send + Sync + 'static,
    {
        let body = StreamBody::new(stream.map_ok(hyper::body::Frame::data)).boxed();
        self.stream_body = Some(body);
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

        let mut auth = self.auth.or_else(|| self.client.config.auth.clone());
        if auth.is_none() {
            if let Some(netrc) = &self.client.config.netrc {
                if let Some(host) = request.url().host() {
                    if let Some((user, pass)) = netrc.lookup(host) {
                        auth = Some(Arc::new(BasicAuth::new(user, pass)));
                    }
                }
            }
        }
        if let Some(auth) = &auth {
            auth.apply(&mut request);
        }

        Ok((request, auth))
    }

    /// Build and send the request, returning the response.
    pub async fn send(mut self) -> Result<Response> {
        let client = self.client;
        let timeout = self.timeout_override.unwrap_or(client.config.timeout.total);
        let follow = self
            .follow_redirects_override
            .unwrap_or(client.config.follow_redirects);
        let stream_body = self.stream_body.take();
        let (request, auth) = self.into_request()?;
        match stream_body {
            Some(body) => client.execute_stream_upload(request, body, timeout).await,
            None => client.execute(request, timeout, follow, auth).await,
        }
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
