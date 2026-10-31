//! Authentication schemes, mirroring `httpx.Auth` and `httpx.BasicAuth`.
//!
//! An [`Auth`] implementation mutates an outgoing [`Request`] to add the
//! credentials it needs. v1 ships HTTP Basic auth and a bearer-token helper;
//! Digest auth (which requires a challenge/response round trip) is a planned
//! follow-up and would hook into the client's send loop rather than this
//! one-shot interface.

use base64::Engine;

use crate::request::Request;

/// Something that can authenticate a request by mutating its headers.
pub trait Auth: Send + Sync {
    /// Apply credentials to the outgoing request.
    fn apply(&self, request: &mut Request);
}

/// HTTP Basic authentication (`Authorization: Basic base64(user:pass)`).
#[derive(Clone, Debug)]
pub struct BasicAuth {
    header_value: String,
}

impl BasicAuth {
    pub fn new(username: impl AsRef<str>, password: impl AsRef<str>) -> Self {
        let raw = format!("{}:{}", username.as_ref(), password.as_ref());
        let encoded = base64::engine::general_purpose::STANDARD.encode(raw.as_bytes());
        BasicAuth {
            header_value: format!("Basic {encoded}"),
        }
    }
}

impl Auth for BasicAuth {
    fn apply(&self, request: &mut Request) {
        request
            .headers_mut()
            .insert("authorization", self.header_value.clone());
    }
}

/// Bearer-token authentication (`Authorization: Bearer <token>`).
#[derive(Clone, Debug)]
pub struct BearerAuth {
    header_value: String,
}

impl BearerAuth {
    pub fn new(token: impl AsRef<str>) -> Self {
        BearerAuth {
            header_value: format!("Bearer {}", token.as_ref()),
        }
    }
}

impl Auth for BearerAuth {
    fn apply(&self, request: &mut Request) {
        request
            .headers_mut()
            .insert("authorization", self.header_value.clone());
    }
}
