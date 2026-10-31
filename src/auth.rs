//! Authentication schemes, mirroring `httpx.Auth`, `httpx.BasicAuth` and
//! `httpx.DigestAuth`.
//!
//! An [`Auth`] implementation applies credentials to an outgoing request, and
//! may optionally inspect the response to perform a challenge/response retry
//! (as HTTP Digest requires). This corresponds to httpx's `auth_flow`
//! generator: `apply` is the first yield, and [`Auth::respond_to_challenge`]
//! handles a subsequent 401 to produce one retried request.

use std::sync::atomic::{AtomicU32, Ordering};

use base64::Engine;
use rand::Rng;

use crate::request::Request;
use crate::response::Response;

/// Something that can authenticate a request.
pub trait Auth: Send + Sync {
    /// Apply credentials to the outgoing request before it is first sent.
    fn apply(&self, request: &mut Request);

    /// Whether this scheme may need to see the response to retry (e.g. Digest).
    fn needs_response(&self) -> bool {
        false
    }

    /// Given the response to the initial attempt, optionally mutate `next`
    /// (a fresh copy of the request) with challenge credentials and return
    /// `true` to have it re-sent. The default never retries.
    fn respond_to_challenge(&self, _response: &Response, _next: &mut Request) -> bool {
        false
    }
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

/// HTTP Digest authentication (RFC 7616 / 2617), mirroring `httpx.DigestAuth`.
///
/// The first request is sent without credentials; on a `401` carrying a
/// `WWW-Authenticate: Digest ...` challenge, the `Authorization` header is
/// computed and the request retried once. Supports the `MD5`, `MD5-sess`,
/// `SHA-256` and `SHA-256-sess` algorithms with the `auth` qop.
pub struct DigestAuth {
    username: String,
    password: String,
    nonce_count: AtomicU32,
}

impl DigestAuth {
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        DigestAuth {
            username: username.into(),
            password: password.into(),
            nonce_count: AtomicU32::new(0),
        }
    }

    fn build_header(&self, challenge: &DigestChallenge, method: &str, uri: &str) -> String {
        let nc = self.nonce_count.fetch_add(1, Ordering::SeqCst) + 1;
        let nc_str = format!("{nc:08x}");
        let cnonce = random_cnonce();

        let algorithm = challenge
            .algorithm
            .as_deref()
            .unwrap_or("MD5")
            .to_string();
        let sess = algorithm.to_ascii_uppercase().ends_with("-SESS");
        let hash = Hasher::from_algorithm(&algorithm);

        let ha1_base = hash.hex(&format!(
            "{}:{}:{}",
            self.username, challenge.realm, self.password
        ));
        let ha1 = if sess {
            hash.hex(&format!("{}:{}:{}", ha1_base, challenge.nonce, cnonce))
        } else {
            ha1_base
        };
        let ha2 = hash.hex(&format!("{method}:{uri}"));

        let qop = challenge.qop.as_deref();
        let response = if let Some(qop) = qop {
            hash.hex(&format!(
                "{ha1}:{}:{nc_str}:{cnonce}:{qop}:{ha2}",
                challenge.nonce
            ))
        } else {
            hash.hex(&format!("{ha1}:{}:{ha2}", challenge.nonce))
        };

        let mut parts = vec![
            format!("username=\"{}\"", self.username),
            format!("realm=\"{}\"", challenge.realm),
            format!("nonce=\"{}\"", challenge.nonce),
            format!("uri=\"{uri}\""),
            format!("response=\"{response}\""),
        ];
        if let Some(opaque) = &challenge.opaque {
            parts.push(format!("opaque=\"{opaque}\""));
        }
        if challenge.algorithm.is_some() {
            parts.push(format!("algorithm={algorithm}"));
        }
        if let Some(qop) = qop {
            parts.push(format!("qop={qop}"));
            parts.push(format!("nc={nc_str}"));
            parts.push(format!("cnonce=\"{cnonce}\""));
        }
        format!("Digest {}", parts.join(", "))
    }
}

impl Auth for DigestAuth {
    fn apply(&self, _request: &mut Request) {
        // Digest sends nothing until it receives a challenge.
    }

    fn needs_response(&self) -> bool {
        true
    }

    fn respond_to_challenge(&self, response: &Response, next: &mut Request) -> bool {
        if response.status_code() != 401 {
            return false;
        }
        let header = match response
            .headers()
            .get_all("www-authenticate")
            .into_iter()
            .find(|h| h.trim_start().to_ascii_lowercase().starts_with("digest"))
        {
            Some(h) => h,
            None => return false,
        };
        let challenge = match DigestChallenge::parse(header) {
            Some(c) => c,
            None => return false,
        };
        let method = next.method().as_str().to_string();
        let uri = next.url().request_target();
        let auth_header = self.build_header(&challenge, &method, &uri);
        next.headers_mut().insert("authorization", auth_header);
        true
    }
}

struct DigestChallenge {
    realm: String,
    nonce: String,
    qop: Option<String>,
    opaque: Option<String>,
    algorithm: Option<String>,
}

impl DigestChallenge {
    fn parse(header: &str) -> Option<Self> {
        let body = header.trim().strip_prefix("Digest").or_else(|| {
            // Case-insensitive scheme prefix.
            if header.trim().to_ascii_lowercase().starts_with("digest") {
                Some(&header.trim()[6..])
            } else {
                None
            }
        })?;

        let mut realm = None;
        let mut nonce = None;
        let mut qop = None;
        let mut opaque = None;
        let mut algorithm = None;

        for (key, value) in parse_auth_params(body) {
            match key.as_str() {
                "realm" => realm = Some(value),
                "nonce" => nonce = Some(value),
                "qop" => {
                    // May be a comma-separated list; prefer "auth".
                    let chosen = value
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .find(|s| s == "auth")
                        .or_else(|| value.split(',').next().map(|s| s.trim().to_string()));
                    qop = chosen;
                }
                "opaque" => opaque = Some(value),
                "algorithm" => algorithm = Some(value),
                _ => {}
            }
        }

        Some(DigestChallenge {
            realm: realm.unwrap_or_default(),
            nonce: nonce?,
            qop,
            opaque,
            algorithm,
        })
    }
}

/// Parse `key=value` / `key="value"` auth parameters separated by commas.
fn parse_auth_params(input: &str) -> Vec<(String, String)> {
    let mut params = Vec::new();
    let bytes = input.as_bytes();
    let mut i = 0;
    let n = bytes.len();
    while i < n {
        while i < n && (bytes[i] == b' ' || bytes[i] == b',') {
            i += 1;
        }
        let key_start = i;
        while i < n && bytes[i] != b'=' && bytes[i] != b',' {
            i += 1;
        }
        if i >= n || bytes[i] != b'=' {
            break;
        }
        let key = input[key_start..i].trim().to_ascii_lowercase();
        i += 1; // skip '='
        let value;
        if i < n && bytes[i] == b'"' {
            i += 1;
            let val_start = i;
            while i < n && bytes[i] != b'"' {
                i += 1;
            }
            value = input[val_start..i].to_string();
            if i < n {
                i += 1; // skip closing quote
            }
        } else {
            let val_start = i;
            while i < n && bytes[i] != b',' {
                i += 1;
            }
            value = input[val_start..i].trim().to_string();
        }
        params.push((key, value));
    }
    params
}

enum Hasher {
    Md5,
    Sha256,
}

impl Hasher {
    fn from_algorithm(algorithm: &str) -> Self {
        if algorithm.to_ascii_uppercase().starts_with("SHA-256") {
            Hasher::Sha256
        } else {
            Hasher::Md5
        }
    }

    fn hex(&self, input: &str) -> String {
        match self {
            Hasher::Md5 => format!("{:x}", md5::compute(input.as_bytes())),
            Hasher::Sha256 => sha256_hex(input.as_bytes()),
        }
    }
}

fn random_cnonce() -> String {
    let mut rng = rand::thread_rng();
    (0..16)
        .map(|_| {
            let n: u8 = rng.gen_range(0..16);
            char::from_digit(n as u32, 16).unwrap()
        })
        .collect()
}

/// A tiny self-contained SHA-256 (avoids pulling in a crypto dependency just
/// for Digest's optional SHA-256 variant).
fn sha256_hex(data: &[u8]) -> String {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    let mut msg = data.to_vec();
    let bit_len = (data.len() as u64) * 8;
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (i, word) in w.iter_mut().enumerate().take(16) {
            let j = i * 4;
            *word = u32::from_be_bytes([chunk[j], chunk[j + 1], chunk[j + 2], chunk[j + 3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut f = h[5];
        let mut g = h[6];
        let mut hh = h[7];
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut out = String::with_capacity(64);
    for word in h {
        out.push_str(&format!("{word:08x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_known_vectors() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn parse_params_quoted_and_bare() {
        let p = parse_auth_params("realm=\"r\", nonce=\"n\", qop=auth, algorithm=MD5");
        let find = |k: &str| p.iter().find(|(key, _)| key == k).map(|(_, v)| v.clone());
        assert_eq!(find("realm").as_deref(), Some("r"));
        assert_eq!(find("nonce").as_deref(), Some("n"));
        assert_eq!(find("qop").as_deref(), Some("auth"));
        assert_eq!(find("algorithm").as_deref(), Some("MD5"));
    }

    #[test]
    fn digest_no_qop_matches_rfc2069() {
        let challenge = DigestChallenge::parse(
            "Digest realm=\"testrealm@host.com\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\"",
        )
        .unwrap();
        let auth = DigestAuth::new("Mufasa", "CircleOfLife");
        let header = auth.build_header(&challenge, "GET", "/dir/index.html");

        let ha1 = format!("{:x}", md5::compute(b"Mufasa:testrealm@host.com:CircleOfLife"));
        let ha2 = format!("{:x}", md5::compute(b"GET:/dir/index.html"));
        let expected = format!(
            "{:x}",
            md5::compute(
                format!("{ha1}:dcd98b7102dd2f0e8b11d0f600bfb0c093:{ha2}").as_bytes()
            )
        );
        assert!(header.contains(&format!("response=\"{expected}\"")));
        assert!(!header.contains("qop="));
    }

    #[test]
    fn digest_with_qop_includes_nc_and_cnonce() {
        let challenge = DigestChallenge::parse(
            "Digest realm=\"r\", nonce=\"abc\", qop=\"auth\", opaque=\"xyz\"",
        )
        .unwrap();
        let auth = DigestAuth::new("u", "p");
        let header = auth.build_header(&challenge, "GET", "/");
        assert!(header.contains("qop=auth"));
        assert!(header.contains("nc=00000001"));
        assert!(header.contains("cnonce=\""));
        assert!(header.contains("opaque=\"xyz\""));
    }
}
