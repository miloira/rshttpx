//! A simplified cookie store, mirroring `httpx.Cookies`.
//!
//! This is a pragmatic subset of RFC 6265: it stores cookies keyed by
//! (domain, path, name), applies host-and-path matching when building the
//! `Cookie` request header, and honours the `Secure` attribute and a basic
//! `Max-Age`/`Expires`-insensitive lifetime (session cookies only). Full
//! expiry handling is a planned refinement.

use std::sync::Mutex;

use crate::headers::Headers;
use crate::url::Url;

#[derive(Clone, Debug)]
struct StoredCookie {
    name: String,
    value: String,
    domain: String,
    path: String,
    secure: bool,
    host_only: bool,
}

/// A thread-safe cookie jar shared by a [`crate::Client`].
#[derive(Default)]
pub struct Cookies {
    jar: Mutex<Vec<StoredCookie>>,
}

impl Cookies {
    pub fn new() -> Self {
        Cookies {
            jar: Mutex::new(Vec::new()),
        }
    }

    /// Manually set a cookie for a domain.
    pub fn set(
        &self,
        name: impl Into<String>,
        value: impl Into<String>,
        domain: impl Into<String>,
        path: impl Into<String>,
    ) {
        let cookie = StoredCookie {
            name: name.into(),
            value: value.into(),
            domain: domain.into().trim_start_matches('.').to_ascii_lowercase(),
            path: path.into(),
            secure: false,
            host_only: false,
        };
        self.store(cookie);
    }

    fn store(&self, cookie: StoredCookie) {
        let mut jar = self.jar.lock().unwrap();
        jar.retain(|c| {
            !(c.name == cookie.name && c.domain == cookie.domain && c.path == cookie.path)
        });
        jar.push(cookie);
    }

    /// Record all `Set-Cookie` headers from a response received for `url`.
    pub fn extract(&self, url: &Url, headers: &Headers) {
        let request_host = url.host().unwrap_or("").to_ascii_lowercase();
        for value in headers.get_all("set-cookie") {
            if let Some(cookie) = parse_set_cookie(value, &request_host, url.path()) {
                self.store(cookie);
            }
        }
    }

    /// Build the `Cookie` header value for a request to `url`, if any cookies
    /// match the host, path and scheme.
    pub fn header_for(&self, url: &Url) -> Option<String> {
        let host = url.host().unwrap_or("").to_ascii_lowercase();
        let path = url.path();
        let secure = url.is_https();
        let jar = self.jar.lock().unwrap();
        let mut matched: Vec<String> = Vec::new();
        for c in jar.iter() {
            if c.secure && !secure {
                continue;
            }
            if !domain_matches(&host, &c.domain, c.host_only) {
                continue;
            }
            if !path_matches(path, &c.path) {
                continue;
            }
            matched.push(format!("{}={}", c.name, c.value));
        }
        if matched.is_empty() {
            None
        } else {
            Some(matched.join("; "))
        }
    }

    pub fn is_empty(&self) -> bool {
        self.jar.lock().unwrap().is_empty()
    }

    pub fn len(&self) -> usize {
        self.jar.lock().unwrap().len()
    }
}

fn domain_matches(host: &str, cookie_domain: &str, host_only: bool) -> bool {
    if host == cookie_domain {
        return true;
    }
    if host_only {
        return false;
    }
    // host must be a subdomain of cookie_domain.
    host.ends_with(cookie_domain)
        && host.len() > cookie_domain.len()
        && host.as_bytes()[host.len() - cookie_domain.len() - 1] == b'.'
}

fn path_matches(request_path: &str, cookie_path: &str) -> bool {
    if request_path == cookie_path {
        return true;
    }
    if !request_path.starts_with(cookie_path) {
        return false;
    }
    cookie_path.ends_with('/') || request_path.as_bytes().get(cookie_path.len()) == Some(&b'/')
}

fn default_path(request_path: &str) -> String {
    match request_path.rfind('/') {
        Some(0) | None => "/".to_string(),
        Some(idx) => request_path[..idx].to_string(),
    }
}

fn parse_set_cookie(raw: &str, request_host: &str, request_path: &str) -> Option<StoredCookie> {
    let mut parts = raw.split(';');
    let name_value = parts.next()?.trim();
    let (name, value) = name_value.split_once('=')?;
    let name = name.trim().to_string();
    let value = value.trim().to_string();
    if name.is_empty() {
        return None;
    }

    let mut domain: Option<String> = None;
    let mut path: Option<String> = None;
    let mut secure = false;

    for attr in parts {
        let attr = attr.trim();
        let (key, val) = match attr.split_once('=') {
            Some((k, v)) => (k.trim().to_ascii_lowercase(), Some(v.trim().to_string())),
            None => (attr.to_ascii_lowercase(), None),
        };
        match key.as_str() {
            "domain" => {
                if let Some(v) = val {
                    domain = Some(v.trim_start_matches('.').to_ascii_lowercase());
                }
            }
            "path" => path = val,
            "secure" => secure = true,
            _ => {}
        }
    }

    let host_only = domain.is_none();
    let domain = domain.unwrap_or_else(|| request_host.to_string());
    let path = path
        .filter(|p| p.starts_with('/'))
        .unwrap_or_else(|| default_path(request_path));

    Some(StoredCookie {
        name,
        value,
        domain,
        path,
        secure,
        host_only,
    })
}
