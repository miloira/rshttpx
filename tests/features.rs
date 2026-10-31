//! Offline tests for the expanded feature set, via the public API.

use std::io::{Read, Write};

use rshttpx::auth::Auth;
use rshttpx::{DigestAuth, Method, Request, Url};

#[test]
fn gzip_decoder_is_wired() {
    let original = b"hello rshttpx decompression";
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(original).unwrap();
    let compressed = encoder.finish().unwrap();

    let mut decoder = flate2::read::GzDecoder::new(&compressed[..]);
    let mut out = Vec::new();
    decoder.read_to_end(&mut out).unwrap();
    assert_eq!(out, original);
}

#[test]
fn digest_sends_nothing_before_challenge() {
    let auth = DigestAuth::new("user", "pass");
    let mut req = Request::new(Method::GET, Url::parse("https://example.com/").unwrap());
    auth.apply(&mut req);
    assert_eq!(req.headers().get("authorization"), None);
    assert!(auth.needs_response());
}
