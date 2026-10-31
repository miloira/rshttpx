//! URL handling, mirroring `httpx.URL` and `httpx.QueryParams`.
//!
//! [`Url`] wraps the well-tested `url` crate but exposes an httpx-shaped API:
//! `scheme`, `host`, `port`, `path`, `query`, `fragment`, `userinfo`, and a
//! mutable [`QueryParams`] view. [`QueryParams`] is an ordered multi-dict, like
//! httpx's immutable-ish `QueryParams` but with convenient builders.

use std::fmt;
use std::str::FromStr;

use crate::error::{Error, Result};

/// An ordered, multi-value collection of query parameters.
///
/// Comparable to `httpx.QueryParams`. Keys may repeat; insertion order is
/// preserved. Encoding/decoding uses `application/x-www-form-urlencoded`.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct QueryParams {
    pairs: Vec<(String, String)>,
}

impl QueryParams {
    pub fn new() -> Self {
        QueryParams { pairs: Vec::new() }
    }

    /// Parse from a raw `key=value&...` query string (without the leading `?`).
    pub fn parse(raw: &str) -> Self {
        let mut pairs = Vec::new();
        for (k, v) in url::form_urlencoded::parse(raw.as_bytes()) {
            pairs.push((k.into_owned(), v.into_owned()));
        }
        QueryParams { pairs }
    }

    /// The first value associated with `key`, if any.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.pairs
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// All values associated with `key`, in order.
    pub fn get_all(&self, key: &str) -> Vec<&str> {
        self.pairs
            .iter()
            .filter(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
            .collect()
    }

    pub fn contains_key(&self, key: &str) -> bool {
        self.pairs.iter().any(|(k, _)| k == key)
    }

    /// Replace all existing values for `key` with a single value.
    pub fn set(&mut self, key: impl Into<String>, value: impl Into<String>) -> &mut Self {
        let key = key.into();
        self.pairs.retain(|(k, _)| k != &key);
        self.pairs.push((key, value.into()));
        self
    }

    /// Append a value for `key`, keeping any existing values.
    pub fn append(&mut self, key: impl Into<String>, value: impl Into<String>) -> &mut Self {
        self.pairs.push((key.into(), value.into()));
        self
    }

    /// Remove all values for `key`.
    pub fn remove(&mut self, key: &str) -> &mut Self {
        self.pairs.retain(|(k, _)| k != key);
        self
    }

    pub fn is_empty(&self) -> bool {
        self.pairs.is_empty()
    }

    pub fn len(&self) -> usize {
        self.pairs.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.pairs.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// Encode to a `key=value&...` string.
    pub fn to_query_string(&self) -> String {
        url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(self.pairs.iter().map(|(k, v)| (k.as_str(), v.as_str())))
            .finish()
    }
}

impl<K, V> FromIterator<(K, V)> for QueryParams
where
    K: Into<String>,
    V: Into<String>,
{
    fn from_iter<T: IntoIterator<Item = (K, V)>>(iter: T) -> Self {
        QueryParams {
            pairs: iter
                .into_iter()
                .map(|(k, v)| (k.into(), v.into()))
                .collect(),
        }
    }
}

impl fmt::Display for QueryParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_query_string())
    }
}

impl fmt::Debug for QueryParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "QueryParams({:?})", self.to_query_string())
    }
}

/// A parsed, absolute-or-relative URL with an httpx-shaped accessor API.
#[derive(Clone, PartialEq, Eq)]
pub struct Url {
    inner: url::Url,
}

impl Url {
    /// Parse an absolute URL.
    pub fn parse(s: &str) -> Result<Self> {
        let inner = url::Url::parse(s)?;
        Ok(Url { inner })
    }

    /// Resolve a possibly-relative reference against this URL as a base.
    pub fn join(&self, reference: &str) -> Result<Self> {
        let inner = self.inner.join(reference)?;
        Ok(Url { inner })
    }

    pub fn scheme(&self) -> &str {
        self.inner.scheme()
    }

    pub fn host(&self) -> Option<&str> {
        self.inner.host_str()
    }

    pub fn port(&self) -> Option<u16> {
        self.inner.port()
    }

    /// The port, falling back to the default for the scheme (80/443).
    pub fn port_or_default(&self) -> Option<u16> {
        self.inner.port_or_known_default()
    }

    pub fn path(&self) -> &str {
        self.inner.path()
    }

    pub fn query(&self) -> Option<&str> {
        self.inner.query()
    }

    pub fn fragment(&self) -> Option<&str> {
        self.inner.fragment()
    }

    pub fn username(&self) -> &str {
        self.inner.username()
    }

    pub fn password(&self) -> Option<&str> {
        self.inner.password()
    }

    /// `host[:port]` authority used for the `Host` header.
    pub fn authority(&self) -> String {
        match (self.host(), self.inner.port()) {
            (Some(h), Some(p)) => format!("{h}:{p}"),
            (Some(h), None) => h.to_string(),
            (None, _) => String::new(),
        }
    }

    pub fn is_https(&self) -> bool {
        self.inner.scheme() == "https"
    }

    /// The query parameters as a mutable-friendly [`QueryParams`].
    pub fn params(&self) -> QueryParams {
        match self.query() {
            Some(q) => QueryParams::parse(q),
            None => QueryParams::new(),
        }
    }

    /// Return a copy with the query string replaced by `params`.
    pub fn with_params(&self, params: &QueryParams) -> Url {
        let mut inner = self.inner.clone();
        if params.is_empty() {
            inner.set_query(None);
        } else {
            inner.set_query(Some(&params.to_query_string()));
        }
        Url { inner }
    }

    /// Merge additional params into this URL's existing query, returning a copy.
    pub fn merge_params(&self, extra: &QueryParams) -> Url {
        let mut params = self.params();
        for (k, v) in extra.iter() {
            params.append(k, v);
        }
        self.with_params(&params)
    }

    /// The path plus query, as used in an HTTP request target line.
    pub fn request_target(&self) -> String {
        match self.inner.query() {
            Some(q) => format!("{}?{}", self.inner.path(), q),
            None => self.inner.path().to_string(),
        }
    }

    pub fn as_str(&self) -> &str {
        self.inner.as_str()
    }
}

impl FromStr for Url {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        Url::parse(s)
    }
}

impl TryFrom<&str> for Url {
    type Error = Error;
    fn try_from(s: &str) -> Result<Self> {
        Url::parse(s)
    }
}

impl fmt::Display for Url {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.inner.as_str())
    }
}

impl fmt::Debug for Url {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Url({:?})", self.inner.as_str())
    }
}
