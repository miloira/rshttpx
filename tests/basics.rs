//! Offline unit tests for the httpx-shaped data types (no network required).

use rshttpx::{BasicAuth, Content, Headers, Multipart, QueryParams, Url};
use rshttpx::auth::Auth;
use rshttpx::{Method, Request};

#[test]
fn url_components() {
    let url = Url::parse("https://user:pw@example.com:8443/a/b?x=1&y=2#frag").unwrap();
    assert_eq!(url.scheme(), "https");
    assert_eq!(url.host(), Some("example.com"));
    assert_eq!(url.port(), Some(8443));
    assert_eq!(url.path(), "/a/b");
    assert_eq!(url.username(), "user");
    assert_eq!(url.password(), Some("pw"));
    assert_eq!(url.fragment(), Some("frag"));
    assert!(url.is_https());
    assert_eq!(url.request_target(), "/a/b?x=1&y=2");
}

#[test]
fn url_default_port_and_authority() {
    let url = Url::parse("http://example.com/").unwrap();
    assert_eq!(url.port(), None);
    assert_eq!(url.port_or_default(), Some(80));
    assert_eq!(url.authority(), "example.com");
}

#[test]
fn url_join_relative() {
    let base = Url::parse("https://example.com/api/v1/").unwrap();
    let joined = base.join("users?page=2").unwrap();
    assert_eq!(joined.as_str(), "https://example.com/api/v1/users?page=2");
}

#[test]
fn query_params_multi_value() {
    let mut q = QueryParams::new();
    q.append("tag", "a").append("tag", "b").set("page", "1");
    assert_eq!(q.get("tag"), Some("a"));
    assert_eq!(q.get_all("tag"), vec!["a", "b"]);
    assert_eq!(q.get("page"), Some("1"));
    // set() replaces:
    q.set("tag", "c");
    assert_eq!(q.get_all("tag"), vec!["c"]);
}

#[test]
fn url_merge_params() {
    let url = Url::parse("https://example.com/?a=1").unwrap();
    let extra = QueryParams::from_iter([("b", "2"), ("c", "3")]);
    let merged = url.merge_params(&extra);
    let params = merged.params();
    assert_eq!(params.get("a"), Some("1"));
    assert_eq!(params.get("b"), Some("2"));
    assert_eq!(params.get("c"), Some("3"));
}

#[test]
fn headers_case_insensitive_multi() {
    let mut h = Headers::new();
    h.insert("Content-Type", "text/plain");
    h.append("Set-Cookie", "a=1");
    h.append("set-cookie", "b=2");
    assert_eq!(h.get("content-type"), Some("text/plain"));
    assert_eq!(h.get("CONTENT-TYPE"), Some("text/plain"));
    assert_eq!(h.get_all("Set-Cookie"), vec!["a=1", "b=2"]);
    assert!(h.contains_key("content-TYPE"));
    h.remove("content-type");
    assert!(!h.contains_key("content-type"));
}

#[test]
fn headers_debug_redacts_secrets() {
    let mut h = Headers::new();
    h.insert("Authorization", "Basic c2VjcmV0");
    let dbg = format!("{h:?}");
    assert!(dbg.contains("[secure]"));
    assert!(!dbg.contains("c2VjcmV0"));
}

#[test]
fn basic_auth_header() {
    let auth = BasicAuth::new("user", "pass");
    let mut req = Request::new(Method::GET, Url::parse("https://example.com/").unwrap());
    auth.apply(&mut req);
    // base64("user:pass") == "dXNlcjpwYXNz"
    assert_eq!(
        req.headers().get("authorization"),
        Some("Basic dXNlcjpwYXNz")
    );
}

#[test]
fn json_content() {
    let value = serde_json::json!({ "a": 1, "b": [true, false] });
    let content = Content::json(&value).unwrap();
    assert_eq!(content.content_type.as_deref(), Some("application/json"));
    let parsed: serde_json::Value = serde_json::from_slice(&content.body).unwrap();
    assert_eq!(parsed, value);
}

#[test]
fn form_content() {
    let content = Content::form(&[("name", "ada"), ("lang", "rust")]).unwrap();
    assert_eq!(
        content.content_type.as_deref(),
        Some("application/x-www-form-urlencoded")
    );
    let body = String::from_utf8(content.body.to_vec()).unwrap();
    assert_eq!(body, "name=ada&lang=rust");
}

#[test]
fn multipart_content() {
    let mp = Multipart::new()
        .text("field", "value")
        .file("upload", "hello.txt", b"file-bytes".to_vec());
    let content = mp.encode();
    let ct = content.content_type.unwrap();
    assert!(ct.starts_with("multipart/form-data; boundary="));
    let body = String::from_utf8(content.body.to_vec()).unwrap();
    assert!(body.contains("name=\"field\""));
    assert!(body.contains("value"));
    assert!(body.contains("filename=\"hello.txt\""));
    assert!(body.contains("Content-Type: text/plain"));
    assert!(body.contains("file-bytes"));
}
