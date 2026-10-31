//! Integration tests against local servers and a mock transport.
//!
//! Covers the paths that cannot be exercised offline: the custom [`Transport`]
//! trait, redirect following, transient-failure retries, and (in
//! `integration_tls.rs`) TLS with a custom CA, mTLS and a SOCKS5 proxy.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request as HyperRequest, Response as HyperResponse};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use rshttpx::transport::{Transport, TransportFuture, TransportResponse};
use rshttpx::{Client, Headers, Method, Request, StatusCode};

/// Spawn a minimal HTTP/1 server handling a few test routes. Returns its addr.
async fn spawn_http_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => break,
            };
            let io = TokioIo::new(stream);
            tokio::spawn(async move {
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, service_fn(handle))
                    .await;
            });
        }
    });
    addr
}

async fn handle(
    req: HyperRequest<Incoming>,
) -> Result<HyperResponse<Full<Bytes>>, Infallible> {
    let path = req.uri().path().to_string();
    let resp = match path.as_str() {
        "/hello" => HyperResponse::builder()
            .status(200)
            .header("content-type", "text/plain")
            .body(Full::new(Bytes::from("hello world")))
            .unwrap(),
        "/redirect" => HyperResponse::builder()
            .status(302)
            .header("location", "/hello")
            .body(Full::new(Bytes::new()))
            .unwrap(),
        "/echo-header" => {
            let value = req
                .headers()
                .get("x-test")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            HyperResponse::builder()
                .status(200)
                .body(Full::new(Bytes::from(value)))
                .unwrap()
        }
        _ => HyperResponse::builder()
            .status(404)
            .body(Full::new(Bytes::from("not found")))
            .unwrap(),
    };
    Ok(resp)
}

/// Spawn a server that drops the first `fail_count` connections (simulating a
/// transient connection failure) before serving `/hello` normally.
async fn spawn_flaky_server(fail_count: usize) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(AtomicUsize::new(0));
    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => break,
            };
            let n = seen.fetch_add(1, Ordering::SeqCst);
            if n < fail_count {
                // Drop the connection immediately without responding.
                drop(stream);
                continue;
            }
            let io = TokioIo::new(stream);
            tokio::spawn(async move {
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, service_fn(handle))
                    .await;
            });
        }
    });
    addr
}

#[tokio::test]
async fn basic_get_against_local_server() {
    let addr = spawn_http_server().await;
    let client = Client::new();
    let resp = client
        .get(&format!("http://{addr}/hello"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status_code(), 200);
    assert_eq!(resp.text(), "hello world");
}

#[tokio::test]
async fn follows_redirect() {
    let addr = spawn_http_server().await;
    let client = Client::builder().follow_redirects(true).build().unwrap();
    let resp = client
        .get(&format!("http://{addr}/redirect"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status_code(), 200);
    assert_eq!(resp.text(), "hello world");
    assert_eq!(resp.history().len(), 1);
}

#[tokio::test]
async fn does_not_follow_redirect_by_default() {
    let addr = spawn_http_server().await;
    let client = Client::new();
    let resp = client
        .get(&format!("http://{addr}/redirect"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status_code(), 302);
}

#[tokio::test]
async fn request_header_is_sent() {
    let addr = spawn_http_server().await;
    let client = Client::new();
    let resp = client
        .get(&format!("http://{addr}/echo-header"))
        .header("x-test", "present")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.text(), "present");
}

#[tokio::test]
async fn retries_recover_from_dropped_connections() {
    let addr = spawn_flaky_server(2).await;
    let client = Client::builder()
        .retries(5)
        .timeout(Some(Duration::from_secs(5)))
        .build()
        .unwrap();
    let resp = client
        .get(&format!("http://{addr}/hello"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status_code(), 200);
    assert_eq!(resp.text(), "hello world");
}

#[tokio::test]
async fn retries_exhausted_returns_error() {
    let addr = spawn_flaky_server(10).await;
    let client = Client::builder().retries(1).build().unwrap();
    let result = client.get(&format!("http://{addr}/hello")).send().await;
    assert!(result.is_err());
}

// --- Custom transport (mock) -------------------------------------------------

struct MockTransport {
    body: Bytes,
}

impl Transport for MockTransport {
    fn roundtrip<'a>(
        &'a self,
        request: &'a Request,
        _timeout: Option<Duration>,
    ) -> TransportFuture<'a> {
        let body = self.body.clone();
        let path = request.url().path().to_string();
        Box::pin(async move {
            let mut headers = Headers::new();
            headers.insert("content-type", "application/json");
            headers.insert("x-echo-path", path);
            Ok(TransportResponse::new(StatusCode::OK, headers, body))
        })
    }
}

#[tokio::test]
async fn broken_default_proxy_fails_without_mount() {
    let addr = spawn_http_server().await;
    let client = Client::builder()
        .proxy("socks5://127.0.0.1:1")
        .trust_env(false)
        .build()
        .unwrap();
    let result = client.get(&format!("http://{addr}/hello")).send().await;
    assert!(result.is_err());
}

#[tokio::test]
async fn mount_direct_overrides_broken_default_proxy() {
    let addr = spawn_http_server().await;
    let client = Client::builder()
        .proxy("socks5://127.0.0.1:1")
        .trust_env(false)
        .mount_direct(format!("http://{}", addr.ip()))
        .build()
        .unwrap();
    // The broken default proxy would fail, but the direct mount routes around it.
    let resp = client
        .get(&format!("http://{addr}/hello"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status_code(), 200);
    assert_eq!(resp.text(), "hello world");
}

#[tokio::test]
async fn custom_transport_intercepts_requests() {
    let transport = Arc::new(MockTransport {
        body: Bytes::from(r#"{"mocked":true}"#),
    });
    let client = Client::builder()
        .transport(transport)
        .build()
        .unwrap();

    // No server is running; the mock answers.
    let resp = client
        .get("https://example.invalid/some/path")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status_code(), 200);
    assert_eq!(resp.headers().get("x-echo-path"), Some("/some/path"));
    let json: serde_json::Value = resp.json().unwrap();
    assert_eq!(json["mocked"], serde_json::Value::Bool(true));
}

#[tokio::test]
async fn mock_transport_body_is_used_for_method_helpers() {
    let transport = Arc::new(MockTransport {
        body: Bytes::from("plain text body"),
    });
    let client = Client::builder().transport(transport).build().unwrap();
    let resp = client
        .request(Method::POST, "https://anything.test/")
        .text("ignored by mock")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.text(), "plain text body");
}
