//! Top-level convenience functions, mirroring `httpx.get()`, `httpx.post()`, etc.
//!
//! Each call builds a throwaway [`Client`] with default settings and issues a
//! single request. As in httpx, redirects are **not** followed by default; use
//! a [`Client`] with `follow_redirects(true)` when you need that. For repeated
//! requests, construct a [`Client`] and reuse it to benefit from connection
//! pooling.

use http::Method;

use crate::client::Client;
use crate::error::Result;
use crate::response::Response;

fn ephemeral_client() -> Client {
    Client::new()
}

/// Issue a one-off `GET` request.
pub async fn get(url: &str) -> Result<Response> {
    ephemeral_client().get(url).send().await
}

/// Issue a one-off `HEAD` request.
pub async fn head(url: &str) -> Result<Response> {
    ephemeral_client().head(url).send().await
}

/// Issue a one-off `OPTIONS` request.
pub async fn options(url: &str) -> Result<Response> {
    ephemeral_client().options(url).send().await
}

/// Issue a one-off `DELETE` request.
pub async fn delete(url: &str) -> Result<Response> {
    ephemeral_client().delete(url).send().await
}

/// Issue a one-off `POST` request with a JSON body.
pub async fn post_json<T: serde::Serialize>(url: &str, json: &T) -> Result<Response> {
    ephemeral_client().post(url).json(json).send().await
}

/// Issue a one-off request with an arbitrary method and no body.
pub async fn request(method: Method, url: &str) -> Result<Response> {
    ephemeral_client().request(method, url).send().await
}
