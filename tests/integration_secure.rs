//! TLS (custom CA, insecure, mTLS) and SOCKS5-proxy integration tests.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request as HyperRequest, Response as HyperResponse};
use hyper_util::rt::TokioIo;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, SanType,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

use rshttpx::Client;

fn install_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

struct Certs {
    ca_pem: String,
    server_cert_pem: String,
    server_key_pem: String,
    client_cert_pem: String,
    client_key_pem: String,
}

fn generate_certs() -> Certs {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "rshttpx test CA");
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();

    let server_key = KeyPair::generate().unwrap();
    let mut server_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    server_params.subject_alt_names = vec![
        SanType::DnsName("localhost".try_into().unwrap()),
        SanType::IpAddress("127.0.0.1".parse().unwrap()),
    ];
    server_params
        .distinguished_name
        .push(DnType::CommonName, "localhost");
    let server_cert = server_params.signed_by(&server_key, &ca_cert, &ca_key).unwrap();

    let client_key = KeyPair::generate().unwrap();
    let mut client_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    client_params
        .distinguished_name
        .push(DnType::CommonName, "rshttpx test client");
    let client_cert = client_params.signed_by(&client_key, &ca_cert, &ca_key).unwrap();

    Certs {
        ca_pem: ca_cert.pem(),
        server_cert_pem: server_cert.pem(),
        server_key_pem: server_key.serialize_pem(),
        client_cert_pem: client_cert.pem(),
        client_key_pem: client_key.serialize_pem(),
    }
}

fn load_certs(pem: &str) -> Vec<CertificateDer<'static>> {
    rustls_pemfile::certs(&mut pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
}

fn load_key(pem: &str) -> PrivateKeyDer<'static> {
    rustls_pemfile::private_key(&mut pem.as_bytes())
        .unwrap()
        .unwrap()
}

async fn handle(
    _req: HyperRequest<Incoming>,
) -> Result<HyperResponse<Full<Bytes>>, Infallible> {
    Ok(HyperResponse::builder()
        .status(200)
        .body(Full::new(Bytes::from("secure hello")))
        .unwrap())
}

async fn spawn_tls_server(certs: &Certs, require_client_ca: Option<String>) -> SocketAddr {
    install_provider();
    let cert_chain = load_certs(&certs.server_cert_pem);
    let key = load_key(&certs.server_key_pem);

    let config = match require_client_ca {
        Some(ca_pem) => {
            let mut roots = RootCertStore::empty();
            for c in load_certs(&ca_pem) {
                roots.add(c).unwrap();
            }
            let verifier = WebPkiClientVerifier::builder(Arc::new(roots)).build().unwrap();
            ServerConfig::builder()
                .with_client_cert_verifier(verifier)
                .with_single_cert(cert_chain, key)
                .unwrap()
        }
        None => ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)
            .unwrap(),
    };

    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => break,
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(tls) = acceptor.accept(stream).await {
                    let io = TokioIo::new(tls);
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(io, service_fn(handle))
                        .await;
                }
            });
        }
    });
    addr
}

#[tokio::test]
async fn tls_with_custom_ca() {
    let certs = generate_certs();
    let addr = spawn_tls_server(&certs, None).await;
    let client = Client::builder()
        .http2(false)
        .add_root_certificate_pem(certs.ca_pem.clone().into_bytes())
        .build()
        .unwrap();
    let resp = client
        .get(&format!("https://localhost:{}/", addr.port()))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status_code(), 200);
    assert_eq!(resp.text(), "secure hello");
}

#[tokio::test]
async fn tls_verify_false_accepts_untrusted() {
    let certs = generate_certs();
    let addr = spawn_tls_server(&certs, None).await;
    // No custom CA, but verification disabled.
    let client = Client::builder().http2(false).verify(false).build().unwrap();
    let resp = client
        .get(&format!("https://127.0.0.1:{}/", addr.port()))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status_code(), 200);
}

#[tokio::test]
async fn tls_custom_ca_rejects_without_trust() {
    let certs = generate_certs();
    let addr = spawn_tls_server(&certs, None).await;
    // Default roots do not include our CA, so verification must fail.
    let client = Client::builder().http2(false).build().unwrap();
    let result = client
        .get(&format!("https://localhost:{}/", addr.port()))
        .send()
        .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn mutual_tls_with_client_certificate() {
    let certs = generate_certs();
    let addr = spawn_tls_server(&certs, Some(certs.ca_pem.clone())).await;
    let client = Client::builder()
        .http2(false)
        .add_root_certificate_pem(certs.ca_pem.clone().into_bytes())
        .identity_pem(
            certs.client_cert_pem.clone().into_bytes(),
            certs.client_key_pem.clone().into_bytes(),
        )
        .build()
        .unwrap();
    let resp = client
        .get(&format!("https://localhost:{}/", addr.port()))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status_code(), 200);
}

#[tokio::test]
async fn mutual_tls_rejects_missing_client_certificate() {
    let certs = generate_certs();
    let addr = spawn_tls_server(&certs, Some(certs.ca_pem.clone())).await;
    // Trusts the server CA but presents no client certificate.
    let client = Client::builder()
        .http2(false)
        .add_root_certificate_pem(certs.ca_pem.clone().into_bytes())
        .build()
        .unwrap();
    let result = client
        .get(&format!("https://localhost:{}/", addr.port()))
        .send()
        .await;
    assert!(result.is_err());
}

// --- SOCKS5 proxy ------------------------------------------------------------

async fn spawn_plain_http_server() -> SocketAddr {
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

async fn spawn_socks5_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut inbound, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => break,
            };
            tokio::spawn(async move {
                let _ = socks5_handle(&mut inbound).await;
            });
        }
    });
    addr
}

async fn socks5_handle(inbound: &mut TcpStream) -> std::io::Result<()> {
    // Greeting: VER, NMETHODS, METHODS...
    if inbound.read_u8().await? != 5 {
        return Ok(());
    }
    let nmethods = inbound.read_u8().await?;
    let mut methods = vec![0u8; nmethods as usize];
    inbound.read_exact(&mut methods).await?;
    inbound.write_all(&[5, 0]).await?; // choose "no authentication"

    // Request: VER, CMD, RSV, ATYP, ADDR, PORT
    let ver = inbound.read_u8().await?;
    let cmd = inbound.read_u8().await?;
    let _rsv = inbound.read_u8().await?;
    let atyp = inbound.read_u8().await?;
    let host = match atyp {
        1 => {
            let mut a = [0u8; 4];
            inbound.read_exact(&mut a).await?;
            format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3])
        }
        3 => {
            let len = inbound.read_u8().await? as usize;
            let mut d = vec![0u8; len];
            inbound.read_exact(&mut d).await?;
            String::from_utf8_lossy(&d).to_string()
        }
        4 => {
            let mut a = [0u8; 16];
            inbound.read_exact(&mut a).await?;
            std::net::Ipv6Addr::from(a).to_string()
        }
        _ => return Ok(()),
    };
    let port = inbound.read_u16().await?;
    if ver != 5 || cmd != 1 {
        return Ok(());
    }

    let mut outbound = TcpStream::connect((host.as_str(), port)).await?;
    // Reply: success, bound address 0.0.0.0:0
    inbound
        .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
        .await?;
    tokio::io::copy_bidirectional(inbound, &mut outbound).await?;
    Ok(())
}

#[tokio::test]
async fn socks5_proxy_reaches_target() {
    let target = spawn_plain_http_server().await;
    let socks = spawn_socks5_server().await;
    let client = Client::builder()
        .http2(false)
        .proxy(format!("socks5://{socks}"))
        .build()
        .unwrap();
    let resp = client
        .get(&format!("http://{target}/hello"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status_code(), 200);
    assert_eq!(resp.text(), "secure hello");
}
