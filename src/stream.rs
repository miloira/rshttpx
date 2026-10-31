//! Streaming responses, mirroring httpx's `client.stream(...)` /
//! `response.aiter_bytes()`.
//!
//! A [`StreamingResponse`] exposes the status and headers immediately and lets
//! the body be consumed chunk-by-chunk without buffering it all in memory.
//! Streaming bypasses automatic decompression and redirect following (as httpx
//! streaming also hands you the raw first response).

use bytes::Bytes;
use futures_core::Stream;
use http::StatusCode;
use http_body_util::BodyExt;

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
}
