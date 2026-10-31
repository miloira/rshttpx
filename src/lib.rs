//! # rshttpx
//!
//! A Rust port of Python's [`httpx`](https://www.python-httpx.org/): a
//! next-generation async HTTP client. The API mirrors httpx's model as closely
//! as Rust idioms allow.
//!
//! | httpx (Python)        | rshttpx (Rust)                         |
//! |-----------------------|----------------------------------------|
//! | `httpx.AsyncClient`   | [`Client`]                             |
//! | `httpx.URL`           | [`Url`]                                |
//! | `httpx.QueryParams`   | [`QueryParams`]                        |
//! | `httpx.Headers`       | [`Headers`]                            |
//! | `httpx.Request`       | [`Request`]                            |
//! | `httpx.Response`      | [`Response`]                           |
//! | `httpx.Cookies`       | [`Cookies`]                            |
//! | `httpx.BasicAuth`     | [`BasicAuth`]                          |
//! | `httpx.get(...)` etc. | [`get`], [`post_json`], ...            |
//!
//! Since Rust has no keyword arguments, per-request options (`params=`,
//! `json=`, `headers=`, ...) are expressed with a fluent [`RequestBuilder`]
//! returned by the client method helpers.
//!
//! ## Quick start
//!
//! ```no_run
//! # async fn run() -> rshttpx::Result<()> {
//! let client = rshttpx::Client::builder()
//!     .base_url("https://httpbin.org")
//!     .follow_redirects(true)
//!     .build();
//!
//! let resp = client
//!     .post("/post")
//!     .json(&serde_json::json!({ "hello": "world" }))
//!     .send()
//!     .await?;
//!
//! resp.raise_for_status()?;
//! let body: serde_json::Value = resp.json()?;
//! println!("{body}");
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]

pub mod api;
pub mod auth;
pub mod blocking;
pub mod client;
pub mod content;
pub mod cookies;
mod decode;
pub mod error;
pub mod headers;
pub mod request;
pub mod response;
pub mod stream;
mod tls;
pub mod url;

pub use api::{delete, get, head, options, post_json, request};
pub use auth::{Auth, BasicAuth, BearerAuth, DigestAuth};
pub use client::{Client, ClientBuilder, Limits, RequestBuilder, Timeout};
pub use content::{Content, Multipart, Part};
pub use cookies::Cookies;
pub use stream::StreamingResponse;
pub use error::{Error, ErrorKind, Result};
pub use headers::Headers;
pub use request::Request;
pub use response::Response;
pub use url::{QueryParams, Url};

// Re-export commonly-used types from the `http` crate so users do not need to
// depend on it directly for `Method` and `StatusCode`.
pub use http::{Method, StatusCode};
