# rshttpx

A Rust port of Python's [httpx](https://www.python-httpx.org/): a
next-generation async HTTP client. The API mirrors httpx's model as closely as
Rust idioms allow, built on [`hyper`](https://hyper.rs/) + `tokio` with
[`rustls`](https://github.com/rustls/rustls) for TLS.

- Async-first `Client` (equivalent to `httpx.AsyncClient`) with connection pooling
- HTTP/1.1 and HTTP/2 (negotiated via ALPN)
- httpx-shaped `Url`, `QueryParams`, `Headers`, `Request`, `Response`, `Cookies`
- JSON, form, multipart, and raw byte bodies
- Redirect following, per-request timeouts, Basic/Bearer auth, a cookie jar
- `raise_for_status()`, `.json()`, `.text()`, `.bytes()`

## API mapping

| httpx (Python)        | rshttpx (Rust)                      |
|-----------------------|-------------------------------------|
| `httpx.AsyncClient`   | `rshttpx::Client`                   |
| `httpx.URL`           | `rshttpx::Url`                      |
| `httpx.QueryParams`   | `rshttpx::QueryParams`              |
| `httpx.Headers`       | `rshttpx::Headers`                  |
| `httpx.Request`       | `rshttpx::Request`                  |
| `httpx.Response`      | `rshttpx::Response`                 |
| `httpx.Cookies`       | `rshttpx::Cookies`                  |
| `httpx.BasicAuth`     | `rshttpx::BasicAuth`                |
| `httpx.get(...)` etc. | `rshttpx::get`, `post_json`, ...    |

Since Rust has no keyword arguments, httpx's per-request options (`params=`,
`json=`, `headers=`, `auth=`, `timeout=`, ...) are expressed with a fluent
`RequestBuilder` returned by the client method helpers.

## Quick start

```rust
use rshttpx::Client;

#[tokio::main]
async fn main() -> rshttpx::Result<()> {
    let client = Client::builder()
        .base_url("https://httpbin.org")
        .follow_redirects(true)
        .build();

    // GET with query params
    let resp = client
        .get("/get")
        .query("hello", "world")
        .send()
        .await?;
    resp.raise_for_status()?;

    // POST JSON and read it back
    let resp = client
        .post("/post")
        .json(&serde_json::json!({ "framework": "rshttpx" }))
        .send()
        .await?;
    let body: serde_json::Value = resp.json()?;
    println!("{}", body["json"]);

    Ok(())
}
```

Run the bundled demo with `cargo run --example quickstart`.

## Status and scope

This is the v1 milestone: the core request/response path with an httpx-shaped
API. Bodies are buffered (no streaming yet). Planned follow-ups:

- Streaming request/response bodies
- Digest auth (challenge/response)
- Automatic response decompression (gzip/deflate/br)
- A blocking `Client` wrapper
- Proxy support

## License

BSD-3-Clause, matching upstream httpx. See [LICENSE](LICENSE).
