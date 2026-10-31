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

/// Decode response bytes to text, mirroring httpx's `Response.text`.
///
/// Resolution order, matching httpx's charset handling:
/// 1. the `charset` from `Content-Type`, if present and recognised;
/// 2. a Unicode byte-order mark, if present;
/// 3. content-based detection (via `chardetng`), defaulting to UTF-8.
pub fn decode_text(content_type: Option<&str>, body: &[u8]) -> String {
    if let Some(label) = content_type.and_then(parse_charset) {
        if let Some(encoding) = encoding_rs::Encoding::for_label(label.as_bytes()) {
            return encoding.decode(body).0.into_owned();
        }
    }
    if let Some((encoding, _)) = encoding_rs::Encoding::for_bom(body) {
        return encoding.decode(body).0.into_owned();
    }
    detect_encoding(body).decode(body).0.into_owned()
}

/// The resolved encoding label for a response, used by `Response::encoding`.
pub fn resolve_encoding(content_type: Option<&str>, body: &[u8]) -> String {
    if let Some(label) = content_type.and_then(parse_charset) {
        if let Some(encoding) = encoding_rs::Encoding::for_label(label.as_bytes()) {
            return encoding.name().to_ascii_lowercase();
        }
    }
    if let Some((encoding, _)) = encoding_rs::Encoding::for_bom(body) {
        return encoding.name().to_ascii_lowercase();
    }
    detect_encoding(body).name().to_ascii_lowercase()
}

fn detect_encoding(body: &[u8]) -> &'static encoding_rs::Encoding {
    let mut detector = chardetng::EncodingDetector::new();
    detector.feed(body, true);
    detector.guess(None, true)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uses_header_charset() {
        // 0xE9 is 'é' in ISO-8859-1 / Windows-1252.
        let text = decode_text(Some("text/plain; charset=iso-8859-1"), &[0xE9]);
        assert_eq!(text, "é");
    }

    #[test]
    fn strips_utf8_bom() {
        let mut bytes = vec![0xEF, 0xBB, 0xBF];
        bytes.extend_from_slice(b"hi");
        let text = decode_text(None, &bytes);
        assert_eq!(text, "hi");
    }

    #[test]
    fn decodes_utf16le_bom() {
        // UTF-16LE BOM + "AB".
        let bytes = [0xFF, 0xFE, b'A', 0x00, b'B', 0x00];
        let text = decode_text(None, &bytes);
        assert_eq!(text, "AB");
    }

    #[test]
    fn detection_defaults_to_ascii_utf8() {
        let text = decode_text(None, b"plain ascii");
        assert_eq!(text, "plain ascii");
    }

    #[test]
    fn resolve_encoding_reports_header_charset() {
        assert_eq!(
            resolve_encoding(Some("text/html; charset=shift_jis"), b"x"),
            "shift_jis"
        );
    }

    #[test]
    fn gzip_decode_body() {
        use std::io::Write;
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(b"payload").unwrap();
        let compressed = enc.finish().unwrap();
        let out = decode_body(Some("gzip"), bytes::Bytes::from(compressed)).unwrap();
        assert_eq!(&out[..], b"payload");
    }
}
