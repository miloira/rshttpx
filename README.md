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
- Per-host proxy mounts (`mount_proxy`/`mount_direct`) and a pluggable `Transport` trait (for mocks/custom backends)
- Charset auto-detection for `.text()` (header charset → BOM → content detection), with a `default_encoding` override
- Connection-pool `Limits` incl. `max_connections` (concurrency gate), initial client cookies
- Rich `Url`: `copy_with`-style `with_scheme/host/port/path/fragment`, `copy_set_param`, `userinfo`, `is_absolute_url`
- Response helpers: `.json()`, `.text()`, `.bytes()`, `.elapsed()`, `.reason_phrase()`,
  `.encoding()`, `.cookies()`, `.links()`, `.request()`, `.num_bytes_downloaded()`, `.raise_for_status()`
- Streaming response helpers: `.chunk()`, `.bytes_stream()`, `.text()`, `.json()`, `.lines()`

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

## Testing

```
cargo test        # unit + integration (spins up local HTTP/TLS/SOCKS5 servers)
cargo clippy --all-targets
```

Integration tests (`tests/integration.rs`, `tests/integration_secure.rs`) cover
redirects, retries against a flaky server, the mock `Transport`, per-host mount
routing, TLS with a generated custom CA, mutual TLS (both accept and reject), and
a SOCKS5 proxy — all against local servers, no network required.

## Parity notes

This aims for functional parity with httpx (which itself supports HTTP/1.1 and
HTTP/2 only — there is no HTTP/3 in httpx). The one Python-specific feature
without a direct port is httpx's in-process ASGI/WSGI transports; the generic
[`Transport`](src/transport.rs) trait is the Rust analogue for custom backends
and mocks. Streamed request bodies are sent once, so they do not participate in
redirect following or challenge-auth retries (same constraint as httpx).

## License

BSD-3-Clause, matching upstream httpx. See [LICENSE](LICENSE).
