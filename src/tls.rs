//! TLS configuration, mirroring httpx's `verify=`, custom CA bundles and
//! client-certificate (mTLS) options.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::ring::default_provider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};

use crate::error::{Error, ErrorKind, Result};

/// Options describing how TLS connections are authenticated.
#[derive(Clone, Default)]
pub(crate) struct TlsOptions {
    /// Verify the server certificate chain (httpx `verify=True`).
    pub verify: bool,
    /// Extra trust-anchor certificates in PEM form (custom CA bundle).
    pub extra_ca_pem: Vec<Vec<u8>>,
    /// Client identity for mutual TLS: `(certificate chain PEM, private key PEM)`.
    pub identity_pem: Option<(Vec<u8>, Vec<u8>)>,
}

/// Build a rustls [`ClientConfig`] from the given options.
pub(crate) fn build_config(opts: &TlsOptions) -> Result<ClientConfig> {
    crate::client::ensure_crypto_provider();

    let identity = match &opts.identity_pem {
        Some((cert_pem, key_pem)) => Some(parse_identity(cert_pem, key_pem)?),
        None => None,
    };

    if !opts.verify {
        let builder = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier));
        return finish(builder, identity);
    }

    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    for pem in &opts.extra_ca_pem {
        let mut reader = pem.as_slice();
        for cert in rustls_pemfile::certs(&mut reader) {
            let cert = cert.map_err(|e| {
                Error::new(ErrorKind::InvalidRequest, format!("invalid CA PEM: {e}"))
            })?;
            roots.add(cert).map_err(|e| {
                Error::new(ErrorKind::InvalidRequest, format!("invalid CA cert: {e}"))
            })?;
        }
    }

    let stage = ClientConfig::builder().with_root_certificates(roots);
    finish(stage, identity)
}

/// The "wants client auth" builder stage, shared by the verifying and
/// non-verifying paths (both produce the same next stage).
type AuthStage = rustls::ConfigBuilder<ClientConfig, rustls::client::WantsClientCert>;

fn finish(
    stage: AuthStage,
    identity: Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>,
) -> Result<ClientConfig> {
    match identity {
        Some((chain, key)) => stage.with_client_auth_cert(chain, key).map_err(|e| {
            Error::new(
                ErrorKind::InvalidRequest,
                format!("invalid client identity: {e}"),
            )
        }),
        None => Ok(stage.with_no_client_auth()),
    }
}

fn parse_identity(
    cert_pem: &[u8],
    key_pem: &[u8],
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let mut cert_reader = cert_pem;
    let chain: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| {
            Error::new(
                ErrorKind::InvalidRequest,
                format!("invalid client certificate PEM: {e}"),
            )
        })?;
    if chain.is_empty() {
        return Err(Error::new(
            ErrorKind::InvalidRequest,
            "client certificate PEM contained no certificates",
        ));
    }

    let mut key_reader = key_pem;
    let key = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|e| {
            Error::new(
                ErrorKind::InvalidRequest,
                format!("invalid client key PEM: {e}"),
            )
        })?
        .ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidRequest,
                "client key PEM contained no private key",
            )
        })?;

    Ok((chain, key))
}

#[derive(Debug)]
struct NoVerifier;

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
