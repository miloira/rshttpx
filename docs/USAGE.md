# rshttpx — Usage Guide

A practical guide to using `rshttpx`, a Rust port of Python's
[httpx](https://www.python-httpx.org/). It assumes basic familiarity with
`async`/`await` and `tokio`.

- [Install](#install)
- [Quick start](#quick-start)
- [Building a client](#building-a-client)
- [Making requests](#making-requests)
- [Request bodies](#request-bodies)
- [Working with responses](#working-with-responses)
- [Authentication](#authentication)
- [Redirects](#redirects)
- [Timeouts and retries](#timeouts-and-retries)
- [Cookies](#cookies)
- [Proxies and mounts](#proxies-and-mounts)
- [TLS: verification, custom CA, mutual TLS](#tls)
- [Event hooks](#event-hooks)
- [Streaming](#streaming)
- [The blocking client](#the-blocking-client)
- [Custom transports](#custom-transports)
- [URLs, headers, query params](#urls-headers-query-params)
- [Error handling](#error-handling)
- [Top-level helpers](#top-level-helpers)
- [httpx ↔ rshttpx cheatsheet](#cheatsheet)

---

## Install

Add to `Cargo.toml`:

```toml
[dependencies]
rshttpx = { git = "https://github.com/miloira/rshttpx" }
tokio = { version = "1", features = ["full"] }
serde_json = "1"   # if you use JSON
```

`rshttpx` builds on `hyper` + `tokio` with `rustls` for TLS, so it needs a
Tokio runtime.

---

## Quick start

```rust
use rshttpx::Client;

#[tokio::main]
async fn main() -> rshttpx::Result<()> {
    let client = Client::new();

    let resp = client.get("https://httpbin.org/get").send().await?;
    println!("status: {}", resp.status_code());
    println!("body: {}", resp.text());
    Ok(())
}
```

Every per-method helper (`get`, `post`, ...) returns a `RequestBuilder`. You
configure the request with chained calls and finish with `.send().await`.

---

## Building a client

Reuse one `Client` across requests — it holds the connection pool and the
cookie jar. Cloning a `Client` is cheap and shares that state.

```rust
use std::time::Duration;
use rshttpx::{Client, Limits, Timeout};

let client = Client::builder()
    .base_url("https://api.example.com")       // relative request URLs resolve against this
    .header("user-agent", "my-app/1.0")        // default header on every request
    .timeout(Some(Duration::from_secs(10)))    // overall per-request timeout
    .follow_redirects(true)
    .max_redirects(10)
    .http2(true)                               // negotiate HTTP/2 via ALPN (default true)
    .decompress(true)                          // transparently handle gzip/deflate/br (default true)
    .limits(Limits { max_connections: 50, max_idle_per_host: 10, idle_timeout: Some(Duration::from_secs(90)) })
    .build()?;                                  // build() returns Result (invalid TLS PEM errors here)
```

`Client::new()` is shorthand for the default builder.

---

## Making requests

```rust
// Methods
client.get(url);
client.post(url);
client.put(url);
client.patch(url);
client.delete(url);
client.head(url);
client.options(url);
client.request(rshttpx::Method::from_bytes(b"REPORT").unwrap(), url);

// Query parameters (repeatable)
let resp = client
    .get("https://httpbin.org/get")
    .query("q", "rust")
    .query("page", "2")
    .send()
    .await?;

// Per-request headers (override client defaults)
let resp = client
    .get("https://httpbin.org/headers")
    .header("x-request-id", "abc123")
    .send()
    .await?;
```

With a `base_url` set, pass a relative path: `client.get("/users/42")`.

---

## Request bodies

```rust
use rshttpx::{Content, Multipart};

// JSON (sets Content-Type: application/json)
client.post("/items").json(&serde_json::json!({ "name": "ada" })).send().await?;

// Any Serialize type works
#[derive(serde::Serialize)]
struct NewItem { name: String, qty: u32 }
client.post("/items").json(&NewItem { name: "ada".into(), qty: 3 }).send().await?;

// URL-encoded form (application/x-www-form-urlencoded)
client.post("/login").form(&[("user", "ada"), ("pass", "secret")]).send().await?;

// Raw bytes / text
client.post("/raw").body(vec![0u8, 1, 2, 3]).send().await?;
client.post("/raw").text("plain text").send().await?;

// Multipart / file upload
let form = Multipart::new()
    .text("field", "value")
    .file("upload", "hello.txt", b"file bytes".to_vec());
client.post("/upload").multipart(form).send().await?;

// Pre-encoded content
client.post("/x").content(Content::json(&serde_json::json!({"a":1}))?).send().await?;
```

---

## Working with responses

```rust
let resp = client.get("https://httpbin.org/json").send().await?;

resp.status();                 // http::StatusCode
resp.status_code();            // u16, e.g. 200
resp.reason_phrase();          // "OK"
resp.is_success();             // 2xx
resp.is_redirect();            // 3xx
resp.is_error();               // 4xx or 5xx

resp.headers().get("content-type");
resp.content_type();           // Option<&str>
resp.url();                    // final URL after redirects
resp.history();                // &[Url] redirect chain
resp.elapsed();                // Duration
resp.cookies();                // Vec<(String, String)> from Set-Cookie
resp.links();                  // parsed Link header entries
resp.num_bytes_downloaded();   // body length
resp.request();                // the Request that produced this response

// Body decoding
resp.bytes();                  // &Bytes (decompressed)
resp.text();                   // String (charset-aware)
let v: serde_json::Value = resp.json()?;

// Error on 4xx/5xx
resp.raise_for_status()?;      // returns &Response on success, for chaining
```

`.text()` resolves the charset from the `Content-Type` header, then a BOM, then
content-based detection, defaulting to UTF-8. Override it with the client's
`default_encoding("iso-8859-1")`.

---

## Authentication

```rust
use std::sync::Arc;
use rshttpx::{BasicAuth, Client};

// Per request
client.get(url).basic_auth("user", "pass").send().await?;
client.get(url).bearer_auth("my-token").send().await?;
client.get(url).digest_auth("user", "pass").send().await?;

// As a client default (applies to every request)
let client = Client::builder().basic_auth("user", "pass").build()?;
let client = Client::builder().digest_auth("user", "pass").build()?;

// Custom scheme: implement the Auth trait
use rshttpx::{Auth, Request};
struct ApiKey(String);
impl Auth for ApiKey {
    fn apply(&self, request: &mut Request) {
        request.headers_mut().insert("x-api-key", self.0.clone());
    }
}
let client = Client::builder().auth(Arc::new(ApiKey("secret".into()))).build()?;
```

Digest auth performs the full challenge/response: the first request is sent
without credentials, and on a `401 WWW-Authenticate: Digest` it computes the
`Authorization` header and retries once (MD5 and SHA-256 supported).

---

## Redirects

Redirects are **not** followed by default (matching httpx). Enable per client or
per request:

```rust
let client = Client::builder().follow_redirects(true).max_redirects(5).build()?;
// or per-request:
client.get(url).follow_redirects(true).send().await?;
```

Method rewriting follows httpx's rules (303 → GET, 301/302 POST → GET, 307/308
preserve method and body) and the `Authorization` header is stripped on
cross-origin redirects. `response.history()` lists the URLs visited.

---

## Timeouts and retries

```rust
use std::time::Duration;
use rshttpx::{Client, Timeout};

// Single overall timeout
let client = Client::builder().timeout(Some(Duration::from_secs(5))).build()?;

// Disable timeouts
let client = Client::builder().timeout(None).build()?;

// Granular: separate connect vs total
let client = Client::builder()
    .timeouts(Timeout { connect: Some(Duration::from_secs(2)), total: Some(Duration::from_secs(30)) })
    .build()?;

// Per-request override
client.get(url).timeout(Some(Duration::from_secs(1))).send().await?;

// Retry transient connection failures (linear backoff)
let client = Client::builder().retries(3).build()?;
```

Retries apply only to transport/connection failures, not to HTTP error
statuses.

---

## Cookies

The client keeps a cookie jar. Server `Set-Cookie` headers are stored and
matching cookies are attached to later requests (domain/path/secure aware).

```rust
// Seed an initial cookie
let client = Client::builder()
    .cookie("session", "abc123", "example.com", "/")
    .build()?;

// Inspect the jar
println!("jar size: {}", client.cookies().len());

// Cookies set by a specific response
for (name, value) in resp.cookies() {
    println!("{name}={value}");
}
```

---

## Proxies and mounts

```rust
// HTTP(S) proxy (CONNECT tunnel)
let client = Client::builder().proxy("http://localhost:8080").build()?;

// SOCKS5 proxy
let client = Client::builder().proxy("socks5://localhost:1080").build()?;

// Environment proxies (HTTPS_PROXY / ALL_PROXY / HTTP_PROXY) — on by default
let client = Client::builder().trust_env(true).build()?;
let client = Client::builder().trust_env(false).build()?; // ignore env

// Per-host mounts: route specific patterns differently
let client = Client::builder()
    .proxy("http://corp-proxy:8080")                 // default for everything
    .mount_direct("all://localhost")                 // but localhost goes direct
    .mount_proxy("https://*.internal", "socks5://127.0.0.1:1080")
    .build()?;
```

Mount patterns use httpx syntax: `all://`, `https://`, `https://example.com`,
`all://*.example.com`. The first matching mount wins; otherwise the default
connection (and default proxy) is used.

---

## TLS

```rust
// Trust a private/custom CA (PEM)
let ca_pem = std::fs::read("corp-ca.pem")?;
let client = Client::builder().add_root_certificate_pem(ca_pem).build()?;

// Mutual TLS: present a client certificate (PEM chain + PEM key)
let cert = std::fs::read("client.crt")?;
let key = std::fs::read("client.key")?;
let client = Client::builder().identity_pem(cert, key).build()?;

// Disable verification (local testing only — insecure!)
let client = Client::builder().verify(false).build()?;
```

Invalid CA or identity PEM is reported as an error from `build()`.

---

## Event hooks

Observe or mutate every request, and observe every response (e.g. logging,
tracing, metrics):

```rust
let client = Client::builder()
    .on_request(|req| {
        println!("-> {} {}", req.method(), req.url());
    })
    .on_response(|resp| {
        println!("<- {} in {:?}", resp.status_code(), resp.elapsed());
    })
    .build()?;
```

Request hooks receive `&mut Request` and may modify headers/body before sending.

---

## Streaming

For large downloads, stream the body instead of buffering it. Streaming skips
automatic decompression and redirect following (you get the first response).

```rust
use futures_util::StreamExt;

let resp = client.get("https://httpbin.org/stream-bytes/1048576").send_stream().await?;
println!("status: {}", resp.status_code());

// Pull chunks one at a time
let mut resp = resp;
while let Some(chunk) = resp.chunk().await? {
    println!("got {} bytes", chunk.len());
}

// Or as a Stream
let resp = client.get(url).send_stream().await?;
let mut body = Box::pin(resp.bytes_stream());
while let Some(chunk) = body.next().await {
    let chunk = chunk?;
    // ...
}

// Convenience collectors
let text = client.get(url).send_stream().await?.text().await?;
let value: serde_json::Value = client.get(url).send_stream().await?.json().await?;

// Line-by-line (e.g. server-sent events, NDJSON)
let resp = client.get(url).send_stream().await?;
let mut lines = Box::pin(resp.lines());
while let Some(line) = lines.next().await {
    println!("line: {}", line?);
}
```

### Streaming a request body (upload)

```rust
use bytes::Bytes;
let chunks: Vec<std::result::Result<Bytes, std::io::Error>> =
    vec![Ok(Bytes::from("part 1 ")), Ok(Bytes::from("part 2"))];
let resp = client
    .post("https://httpbin.org/post")
    .header("content-type", "text/plain")
    .body_stream(futures_util::stream::iter(chunks))
    .send()
    .await?;
```

A streamed request body is sent once (chunked), so it is not replayed across
redirects or auth retries.

---

## The blocking client

For synchronous code, use `blocking::Client`. It owns its own runtime and must
**not** be called from inside an existing async runtime.

```rust
fn main() -> rshttpx::Result<()> {
    let client = rshttpx::blocking::Client::builder()
        .base_url("https://httpbin.org")
        .build()?;

    let resp = client.post("/post").json(&serde_json::json!({ "x": 1 })).send()?;
    println!("{}", resp.status_code());
    let body: serde_json::Value = resp.json()?;
    println!("{}", body["json"]);
    Ok(())
}
```

The request-building API mirrors the async one; only `.send()` is synchronous.

---

## Custom transports

Swap out the network layer — most useful for tests (a mock) or adapting to
another backend. A custom transport handles the buffered path.

```rust
use std::sync::Arc;
use std::time::Duration;
use rshttpx::{Client, Request, StatusCode, Headers};
use rshttpx::transport::{Transport, TransportFuture, TransportResponse};

struct Mock;
impl Transport for Mock {
    fn roundtrip<'a>(&'a self, request: &'a Request, _timeout: Option<Duration>) -> TransportFuture<'a> {
        let path = request.url().path().to_string();
        Box::pin(async move {
            let mut headers = Headers::new();
            headers.insert("content-type", "application/json");
            Ok(TransportResponse::new(
                StatusCode::OK,
                headers,
                bytes::Bytes::from(format!(r#"{{"path":"{path}"}}"#)),
            ))
        })
    }
}

let client = Client::builder().transport(Arc::new(Mock)).build()?;
let resp = client.get("https://anything.test/hello").send().await?; // answered by the mock
```

---

## URLs, headers, query params

```rust
use rshttpx::{Url, QueryParams, Headers};

// URL
let url = Url::parse("https://user:pw@example.com:8443/a/b?x=1#frag")?;
url.scheme();           // "https"
url.host();             // Some("example.com")
url.port();             // Some(8443)
url.path();             // "/a/b"
url.userinfo();         // "user:pw"
url.is_absolute_url();  // true
let joined = url.join("../c")?;              // resolve relative
let changed = url.with_path("/new").with_fragment(None);
let p = url.copy_set_param("x", "2");        // replace a query param

// QueryParams (ordered multi-dict)
let mut q = QueryParams::new();
q.append("tag", "a").append("tag", "b").set("page", "1");
q.get_all("tag");       // ["a", "b"]
q.to_query_string();    // "tag=a&tag=b&page=1"

// Headers (case-insensitive, multi-value)
let mut h = Headers::new();
h.insert("Content-Type", "application/json");
h.append("set-cookie", "a=1");
h.get("content-type");  // Some("application/json")
```

---

## Error handling

All fallible calls return `rshttpx::Result<T>` (`Result<T, rshttpx::Error>`).

```rust
use rshttpx::ErrorKind;

match client.get(url).send().await {
    Ok(resp) => { /* ... */ }
    Err(e) if e.is_timeout() => eprintln!("timed out"),
    Err(e) => match e.kind() {
        ErrorKind::Transport => eprintln!("connection failed: {e}"),
        ErrorKind::TooManyRedirects => eprintln!("redirect loop"),
        _ => eprintln!("error: {e}"),
    },
}

// raise_for_status turns a 4xx/5xx into an Err(ErrorKind::Status)
let resp = client.get(url).send().await?;
let resp = resp.raise_for_status()?;
```

---

## Top-level helpers

For one-off requests (each builds a throwaway client; prefer a reused `Client`
for repeated calls):

```rust
let resp = rshttpx::get("https://httpbin.org/get").await?;
let resp = rshttpx::post_json("https://httpbin.org/post", &serde_json::json!({"x":1})).await?;
let resp = rshttpx::delete("https://httpbin.org/delete").await?;
```

---

## Cheatsheet

| httpx (Python)                         | rshttpx (Rust)                                             |
|----------------------------------------|------------------------------------------------------------|
| `httpx.AsyncClient()`                  | `rshttpx::Client::new()` / `::builder()`                   |
| `httpx.Client()`                       | `rshttpx::blocking::Client::new()?`                        |
| `client.get(url, params=..., headers=...)` | `client.get(url).query(...).header(...).send().await?` |
| `client.post(url, json=...)`           | `client.post(url).json(&v).send().await?`                  |
| `client.post(url, data=...)`           | `client.post(url).form(&pairs).send().await?`              |
| `client.post(url, files=...)`          | `client.post(url).multipart(form).send().await?`           |
| `r.status_code`                        | `r.status_code()`                                          |
| `r.json()`                             | `r.json::<T>()?`                                            |
| `r.text`                               | `r.text()`                                                 |
| `r.raise_for_status()`                 | `r.raise_for_status()?`                                    |
| `auth=httpx.BasicAuth(u, p)`           | `.basic_auth(u, p)`                                        |
| `auth=httpx.DigestAuth(u, p)`          | `.digest_auth(u, p)`                                       |
| `follow_redirects=True`                | `.follow_redirects(true)`                                  |
| `timeout=httpx.Timeout(...)`           | `.timeouts(Timeout { .. })`                                |
| `verify=False` / `verify=ca`           | `.verify(false)` / `.add_root_certificate_pem(ca)`         |
| `cert=(crt, key)`                      | `.identity_pem(crt, key)`                                  |
| `proxy=...` / `mounts=...`             | `.proxy(...)` / `.mount_proxy(...)`, `.mount_direct(...)`  |
| `event_hooks={...}`                    | `.on_request(..)`, `.on_response(..)`                      |
| `transport=...`                        | `.transport(Arc::new(..))`                                 |
| `with client.stream(...) as r:`        | `client.get(url).send_stream().await?`                     |
