//! Case-insensitive, multi-value HTTP headers, mirroring `httpx.Headers`.

use std::fmt;

use http::header::{HeaderName, HeaderValue};
use http::HeaderMap;

/// An ordered, case-insensitive, multi-value header collection.
///
/// Like `httpx.Headers`: lookups are case-insensitive, a key may appear more
/// than once, and insertion order is preserved. Values are stored as strings;
/// non-UTF-8 header values are not supported (httpx has the same practical
/// limitation for its string API).
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Headers {
    /// (original-cased name, lowercased name, value)
    entries: Vec<(String, String, String)>,
}

impl Headers {
    pub fn new() -> Self {
        Headers {
            entries: Vec::new(),
        }
    }

    /// The first value for `name` (case-insensitive).
    pub fn get(&self, name: &str) -> Option<&str> {
        let lower = name.to_ascii_lowercase();
        self.entries
            .iter()
            .find(|(_, k, _)| k == &lower)
            .map(|(_, _, v)| v.as_str())
    }

    /// All values for `name`, in order.
    pub fn get_all(&self, name: &str) -> Vec<&str> {
        let lower = name.to_ascii_lowercase();
        self.entries
            .iter()
            .filter(|(_, k, _)| k == &lower)
            .map(|(_, _, v)| v.as_str())
            .collect()
    }

    pub fn contains_key(&self, name: &str) -> bool {
        let lower = name.to_ascii_lowercase();
        self.entries.iter().any(|(_, k, _)| k == &lower)
    }

    /// Set `name` to `value`, removing any existing values for that name.
    pub fn insert(&mut self, name: impl Into<String>, value: impl Into<String>) -> &mut Self {
        let name = name.into();
        let lower = name.to_ascii_lowercase();
        self.entries.retain(|(_, k, _)| k != &lower);
        self.entries.push((name, lower, value.into()));
        self
    }

    /// Append `value` for `name`, keeping existing values.
    pub fn append(&mut self, name: impl Into<String>, value: impl Into<String>) -> &mut Self {
        let name = name.into();
        let lower = name.to_ascii_lowercase();
        self.entries.push((name, lower, value.into()));
        self
    }

    /// Set `name` only if it is not already present.
    pub fn set_default(&mut self, name: impl Into<String>, value: impl Into<String>) -> &mut Self {
        let name = name.into();
        if !self.contains_key(&name) {
            self.insert(name, value);
        }
        self
    }

    /// Remove all values for `name`.
    pub fn remove(&mut self, name: &str) -> &mut Self {
        let lower = name.to_ascii_lowercase();
        self.entries.retain(|(_, k, _)| k != &lower);
        self
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Iterate over `(name, value)` pairs in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.entries.iter().map(|(n, _, v)| (n.as_str(), v.as_str()))
    }

    /// Merge all entries from `other` into `self` (appending).
    pub fn extend(&mut self, other: &Headers) {
        for (n, v) in other.iter() {
            self.append(n, v);
        }
    }

    /// Convert to an `http::HeaderMap` for use with hyper.
    pub(crate) fn to_header_map(&self) -> crate::error::Result<HeaderMap> {
        let mut map = HeaderMap::with_capacity(self.entries.len());
        for (name, _, value) in &self.entries {
            let hn = HeaderName::from_bytes(name.as_bytes()).map_err(|e| {
                crate::error::Error::invalid_request(format!("invalid header name {name:?}: {e}"))
            })?;
            let hv = HeaderValue::from_str(value).map_err(|e| {
                crate::error::Error::invalid_request(format!(
                    "invalid header value for {name:?}: {e}"
                ))
            })?;
            map.append(hn, hv);
        }
        Ok(map)
    }

    /// Build from an `http::HeaderMap` (as produced by a hyper response).
    pub(crate) fn from_header_map(map: &HeaderMap) -> Self {
        let mut headers = Headers::new();
        for (name, value) in map.iter() {
            let v = value.to_str().unwrap_or("").to_string();
            headers.append(name.as_str(), v);
        }
        headers
    }
}

impl<K, V> FromIterator<(K, V)> for Headers
where
    K: Into<String>,
    V: Into<String>,
{
    fn from_iter<T: IntoIterator<Item = (K, V)>>(iter: T) -> Self {
        let mut headers = Headers::new();
        for (k, v) in iter {
            headers.append(k, v);
        }
        headers
    }
}

impl fmt::Debug for Headers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map()
            .entries(self.entries.iter().map(|(n, _, v)| {
                // Redact sensitive values, like httpx's repr.
                let lower = n.to_ascii_lowercase();
                if lower == "authorization" || lower == "proxy-authorization" || lower == "cookie" {
                    (n.as_str(), "[secure]")
                } else {
                    (n.as_str(), v.as_str())
                }
            }))
            .finish()
    }
}
