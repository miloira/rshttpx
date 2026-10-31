//! Response body decompression, mirroring httpx's transparent handling of
//! `Content-Encoding`. Supports `gzip`, `deflate`, `br` (Brotli), and `identity`.

use std::io::Read;

use bytes::Bytes;

use crate::error::{Error, ErrorKind, Result};

/// The set of content codings advertised in the default `Accept-Encoding`.
pub const DEFAULT_ACCEPT_ENCODING: &str = "gzip, deflate, br";

/// Decode `body` according to a `Content-Encoding` header value.
///
/// The header may list multiple codings (applied in order); this undoes them
/// in reverse, matching HTTP semantics. Unknown or `identity` codings pass the
/// bytes through unchanged.
pub fn decode_body(content_encoding: Option<&str>, body: Bytes) -> Result<Bytes> {
    let encoding = match content_encoding {
        Some(e) => e.trim(),
        None => return Ok(body),
    };
    if encoding.is_empty() {
        return Ok(body);
    }

    // Codings are listed in the order applied; undo them last-first.
    let codings: Vec<String> = encoding
        .split(',')
        .map(|c| c.trim().to_ascii_lowercase())
        .filter(|c| !c.is_empty())
        .collect();

    let mut data = body;
    for coding in codings.into_iter().rev() {
        data = decode_one(&coding, data)?;
    }
    Ok(data)
}

fn decode_one(coding: &str, data: Bytes) -> Result<Bytes> {
    match coding {
        "identity" => Ok(data),
        "gzip" | "x-gzip" => inflate_gzip(&data),
        "deflate" => inflate_deflate(&data),
        "br" => inflate_brotli(&data),
        other => Err(Error::new(
            ErrorKind::Decoding,
            format!("unsupported Content-Encoding: {other}"),
        )),
    }
}

fn inflate_gzip(data: &[u8]) -> Result<Bytes> {
    let mut decoder = flate2::read::GzDecoder::new(data);
    let mut out = Vec::new();
    decoder
        .read_to_end(&mut out)
        .map_err(|e| Error::with_source(ErrorKind::Decoding, format!("gzip decode: {e}"), e))?;
    Ok(Bytes::from(out))
}

fn inflate_deflate(data: &[u8]) -> Result<Bytes> {
    // Per RFC 7230 "deflate" means zlib-wrapped; some servers send raw deflate.
    let mut out = Vec::new();
    if flate2::read::ZlibDecoder::new(data)
        .read_to_end(&mut out)
        .is_ok()
    {
        return Ok(Bytes::from(out));
    }
    out.clear();
    flate2::read::DeflateDecoder::new(data)
        .read_to_end(&mut out)
        .map_err(|e| Error::with_source(ErrorKind::Decoding, format!("deflate decode: {e}"), e))?;
    Ok(Bytes::from(out))
}

fn inflate_brotli(data: &[u8]) -> Result<Bytes> {
    let mut decoder = brotli::Decompressor::new(data, 4096);
    let mut out = Vec::new();
    decoder
        .read_to_end(&mut out)
        .map_err(|e| Error::with_source(ErrorKind::Decoding, format!("brotli decode: {e}"), e))?;
    Ok(Bytes::from(out))
}

/// Decode response bytes to text using the charset from a `Content-Type` value,
/// mirroring httpx's `Response.text`. Defaults to UTF-8 when unspecified.
pub fn decode_text(content_type: Option<&str>, body: &[u8]) -> String {
    let charset = content_type
        .and_then(parse_charset)
        .unwrap_or_else(|| "utf-8".to_string());
    let encoding = encoding_rs::Encoding::for_label(charset.as_bytes())
        .unwrap_or(encoding_rs::UTF_8);
    let (text, _, _) = encoding.decode(body);
    text.into_owned()
}

/// Extract the `charset` parameter from a `Content-Type` header value.
pub fn parse_charset(content_type: &str) -> Option<String> {
    for part in content_type.split(';').skip(1) {
        let part = part.trim();
        if let Some(rest) = part.strip_prefix("charset=") {
            return Some(rest.trim().trim_matches('"').to_ascii_lowercase());
        }
    }
    None
}
