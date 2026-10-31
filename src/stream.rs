//! Streaming responses, mirroring httpx's `client.stream(...)` /
//! `response.aiter_bytes()`.
//!
//! A [`StreamingResponse`] exposes the status and headers immediately and lets
//! the body be consumed chunk-by-chunk without buffering it all in memory.
//! Streaming bypasses automatic decompression and redirect following (as httpx
//! streaming also hands you the raw first response).

use bytes::Bytes;
use futures_core::Stream;
use futures_util::StreamExt;
use http::StatusCode;
use http_body_util::BodyExt;
use serde::de::DeserializeOwned;

use crate::error::{Error, ErrorKind, Result};
use crate::headers::Headers;
use crate::url::Url;

/// A response whose body is streamed on demand.
pub struct StreamingResponse {
    pub(crate) status: StatusCode,
    pub(crate) headers: Headers,
    pub(crate) url: Url,
    pub(crate) body: hyper::body::Incoming,
}

impl StreamingResponse {
    pub fn status(&self) -> StatusCode {
        self.status
    }

    pub fn status_code(&self) -> u16 {
        self.status.as_u16()
    }

    pub fn headers(&self) -> &Headers {
        &self.headers
    }

    pub fn url(&self) -> &Url {
        &self.url
    }

    pub fn is_success(&self) -> bool {
        self.status.is_success()
    }

    /// Await the next body chunk, or `None` at end of stream.
    pub async fn chunk(&mut self) -> Result<Option<Bytes>> {
        loop {
            match self.body.frame().await {
                Some(Ok(frame)) => {
                    if let Ok(data) = frame.into_data() {
                        return Ok(Some(data));
                    }
                    // Trailers frame: skip and continue.
                    continue;
                }
                Some(Err(e)) => {
                    return Err(Error::with_source(ErrorKind::Transport, e.to_string(), e))
                }
                None => return Ok(None),
            }
        }
    }

    /// Consume the stream as a [`Stream`] of byte chunks.
    pub fn bytes_stream(self) -> impl Stream<Item = Result<Bytes>> {
        let body = self.body;
        futures_util::stream::unfold(Some(body), |state| async move {
            let mut body = state?;
            loop {
                match body.frame().await {
                    Some(Ok(frame)) => {
                        if let Ok(data) = frame.into_data() {
                            return Some((Ok(data), Some(body)));
                        }
                        continue;
                    }
                    Some(Err(e)) => {
                        return Some((
                            Err(Error::with_source(ErrorKind::Transport, e.to_string(), e)),
                            None,
                        ))
                    }
                    None => return None,
                }
            }
        })
    }

    /// Collect the entire remaining body into memory.
    pub async fn bytes(self) -> Result<Bytes> {
        let collected = self
            .body
            .collect()
            .await
            .map_err(|e| Error::with_source(ErrorKind::Transport, e.to_string(), e))?;
        Ok(collected.to_bytes())
    }

    /// Collect the remaining body and decode it as text (charset-aware),
    /// matching httpx's `response.aread()` + `.text`.
    pub async fn text(self) -> Result<String> {
        let content_type = self.headers.get("content-type").map(str::to_string);
        let bytes = self.bytes().await?;
        Ok(crate::decode::decode_text(content_type.as_deref(), &bytes))
    }

    /// Collect the remaining body and deserialize it as JSON.
    pub async fn json<T: DeserializeOwned>(self) -> Result<T> {
        let bytes = self.bytes().await?;
        serde_json::from_slice(&bytes).map_err(Error::from)
    }

    /// Stream the body as decoded text lines (newline-delimited), matching
    /// httpx's `response.aiter_lines()`. Trailing `\r\n`/`\n` are stripped.
    pub fn lines(self) -> impl Stream<Item = Result<String>> {
        let stream = Box::pin(self.bytes_stream());
        futures_util::stream::unfold(
            (stream, Vec::<u8>::new(), false),
            |(mut stream, mut buffer, mut finished)| async move {
                loop {
                    if let Some(pos) = buffer.iter().position(|&b| b == b'\n') {
                        let mut line: Vec<u8> = buffer.drain(..=pos).collect();
                        line.pop(); // trailing '\n'
                        if line.last() == Some(&b'\r') {
                            line.pop();
                        }
                        let text = String::from_utf8_lossy(&line).into_owned();
                        return Some((Ok(text), (stream, buffer, finished)));
                    }
                    if finished {
                        if buffer.is_empty() {
                            return None;
                        }
                        let text = String::from_utf8_lossy(&buffer).into_owned();
                        return Some((Ok(text), (stream, Vec::new(), true)));
                    }
                    match stream.next().await {
                        Some(Ok(chunk)) => buffer.extend_from_slice(&chunk),
                        Some(Err(e)) => return Some((Err(e), (stream, buffer, true))),
                        None => finished = true,
                    }
                }
            },
        )
    }
}
