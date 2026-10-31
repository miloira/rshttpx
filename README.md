# rshttpx

A Rust port of Python's [httpx](https://www.python-httpx.org/): a
next-generation HTTP client. The API mirrors httpx's model as closely as Rust
idioms allow, built on [`hyper`](https://hyper.rs/) + `tokio` with
[`rustls`](https://github.com/rustls/rustls) for TLS.

## Features

- Async `Client` (`httpx.AsyncClient`) **and** blocking `blocking::Client` (`httpx.Client`)
- HTTP/1.1 and HTTP/2 (negotiated via ALPN)
- httpx-shaped `Url`, `QueryParams`, `Headers`, `Request`, `Response`, `Cookies`
- JSON, form, multipart, text, and raw byte bodies
- Redirect following (with httpx's method-rewrite rules and cross-origin header stripping)
- Basic, Bearer, and **Digest** auth (MD5 / SHA-256, with challenge/response)
- Transparent response decompression: `gzip`, `deflate`, `br` (Brotli)
- Streaming responses (`send_stream()` → chunked `bytes_stream()`)
- Streaming request bodies (`body_stream()`, chunked upload)
- Cookie jar with domain/path/secure matching
- Granular `Timeout` (connect + total), connection-pool `Limits`
- Proxies: HTTP(S) `CONNECT` tunnel and SOCKS5, plus environment proxies (`trust_env`)
- TLS: verification toggle (`verify`), custom CA bundle, client certificates (mTLS)
- Transient-failure retries, `.netrc` credentials, request/response event hooks
- Response helpers: `.json()`, `.text()` (charset-aware), `.bytes()`, `.elapsed()`,
  `.reason_phrase()`, `.encoding()`, `.cookies()`, `.raise_for_status()`

## API mapping

| httpx (Python)        | rshttpx (Rust)                        |
|-----------------------|---------------------------------------|
| `httpx.AsyncClient`   | `rshttpx::Client`                     |
| `httpx.Client`        | `rshttpx::blocking::Client`           |
| `httpx.URL`           | `rshttpx::Url`                        |
| `httpx.QueryParams`   | `rshttpx::QueryParams`                |
| `httpx.Headers`       | `rshttpx::Headers`                    |
| `httpx.Request`       | `rshttpx::Request`                    |
| `httpx.Response`      | `rshttpx::Response`                   |
| `httpx.Cookies`       | `rshttpx::Cookies`                    |
| `httpx.BasicAuth`     | `rshttpx::BasicAuth`                  |
| `httpx.DigestAuth`    | `rshttpx::DigestAuth`                 |
| `httpx.Timeout`       | `rshttpx::Timeout`                    |
| `httpx.Limits`        | `rshttpx::Limits`                     |
| `httpx.get(...)` etc. | `rshttpx::get`, `post_json`, ...      |

Since Rust has no keyword arguments, httpx's per-request options (`params=`,
`json=`, `headers=`, `auth=`, `timeout=`, ...) are expressed with a fluent
`RequestBuilder` returned by the client method helpers.

## Quick start (async)

```rust
use rshttpx::Client;

#[tokio::main]
async fn main() -> rshttpx::Result<()> {
    let client = Client::builder()
        .base_url("https://httpbin.org")
        .follow_redirects(true)
        .build();

    let resp = client
        .post("/post")
        .json(&serde_json::json!({ "framework": "rshttpx" }))
        .send()
        .await?;
    resp.raise_for_status()?;
    let body: serde_json::Value = resp.json()?;
    println!("{}", body["json"]);
    Ok(())
}
```

## Blocking client

```rust
let client = rshttpx::blocking::Client::new()?;
let resp = client.get("https://example.com").send()?;
println!("{}", resp.status_code());
```

The blocking client owns its own runtime; do not call it from inside an
existing async runtime (use the async `Client` there).

## Examples

- `cargo run --example quickstart` — basic GET/POST
- `cargo run --example verify_features` — gzip/brotli, Digest auth, streaming, elapsed
- `cargo run --example blocking` — the synchronous client

## Not yet covered

A close port. The remaining gaps vs upstream httpx are niche: per-host proxy
"mounts", pluggable custom transports (httpx's ASGI/WSGI transports have no Rust
analogue), and content-based charset auto-detection (we use the `Content-Type`
charset, defaulting to UTF-8). Streamed request bodies are sent once, so they do
not participate in redirect following or challenge-auth retries (same as httpx).

## License

BSD-3-Clause, matching upstream httpx. See [LICENSE](LICENSE).
