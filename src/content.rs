//! Request body content encodings, mirroring httpx's `content=`, `data=`,
//! `json=`, and `files=` request options.

use bytes::Bytes;
use rand::Rng;
use serde::Serialize;

use crate::error::{Error, Result};

/// An encoded request body plus the `Content-Type` it implies (if any).
#[derive(Clone, Debug, Default)]
pub struct Content {
    pub body: Bytes,
    pub content_type: Option<String>,
}

impl Content {
    pub fn empty() -> Self {
        Content {
            body: Bytes::new(),
            content_type: None,
        }
    }

    /// Raw bytes with no implied content type (httpx `content=`).
    pub fn bytes(data: impl Into<Bytes>) -> Self {
        Content {
            body: data.into(),
            content_type: None,
        }
    }

    /// UTF-8 text body (`text/plain; charset=utf-8`).
    pub fn text(data: impl Into<String>) -> Self {
        Content {
            body: Bytes::from(data.into().into_bytes()),
            content_type: Some("text/plain; charset=utf-8".to_string()),
        }
    }

    /// JSON body, serialized from any `serde::Serialize` value (httpx `json=`).
    pub fn json<T: Serialize>(value: &T) -> Result<Self> {
        let body = serde_json::to_vec(value)?;
        Ok(Content {
            body: Bytes::from(body),
            content_type: Some("application/json".to_string()),
        })
    }

    /// `application/x-www-form-urlencoded` body (httpx `data=`).
    pub fn form<T: Serialize>(value: &T) -> Result<Self> {
        let encoded = serde_urlencoded::to_string(value)
            .map_err(|e| Error::invalid_request(format!("could not url-encode form: {e}")))?;
        Ok(Content {
            body: Bytes::from(encoded.into_bytes()),
            content_type: Some("application/x-www-form-urlencoded".to_string()),
        })
    }
}

/// A single part of a multipart/form-data body.
#[derive(Clone, Debug)]
pub struct Part {
    name: String,
    value: Bytes,
    filename: Option<String>,
    content_type: Option<String>,
}

impl Part {
    /// A plain text field.
    pub fn text(name: impl Into<String>, value: impl Into<String>) -> Self {
        Part {
            name: name.into(),
            value: Bytes::from(value.into().into_bytes()),
            filename: None,
            content_type: None,
        }
    }

    /// A file field. The content type is guessed from `filename` when not set.
    pub fn file(
        name: impl Into<String>,
        filename: impl Into<String>,
        value: impl Into<Bytes>,
    ) -> Self {
        let filename = filename.into();
        let content_type = mime_guess::from_path(&filename)
            .first()
            .map(|m| m.essence_str().to_string());
        Part {
            name: name.into(),
            value: value.into(),
            filename: Some(filename),
            content_type,
        }
    }

    pub fn with_content_type(mut self, content_type: impl Into<String>) -> Self {
        self.content_type = Some(content_type.into());
        self
    }
}

/// A `multipart/form-data` body builder (httpx `files=`/`data=` combined).
#[derive(Clone, Debug, Default)]
pub struct Multipart {
    parts: Vec<Part>,
}

impl Multipart {
    pub fn new() -> Self {
        Multipart { parts: Vec::new() }
    }

    pub fn part(mut self, part: Part) -> Self {
        self.parts.push(part);
        self
    }

    pub fn text(self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.part(Part::text(name, value))
    }

    pub fn file(
        self,
        name: impl Into<String>,
        filename: impl Into<String>,
        value: impl Into<Bytes>,
    ) -> Self {
        self.part(Part::file(name, filename, value))
    }

    fn generate_boundary() -> String {
        let mut rng = rand::thread_rng();
        let suffix: String = (0..32)
            .map(|_| {
                let n: u8 = rng.gen_range(0..16);
                char::from_digit(n as u32, 16).unwrap()
            })
            .collect();
        format!("----------rshttpx{suffix}")
    }

    /// Encode to a [`Content`] with a generated boundary.
    pub fn encode(&self) -> Content {
        let boundary = Self::generate_boundary();
        let mut body: Vec<u8> = Vec::new();
        for part in &self.parts {
            body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
            let mut disposition = format!("Content-Disposition: form-data; name=\"{}\"", part.name);
            if let Some(filename) = &part.filename {
                disposition.push_str(&format!("; filename=\"{filename}\""));
            }
            disposition.push_str("\r\n");
            body.extend_from_slice(disposition.as_bytes());
            if let Some(ct) = &part.content_type {
                body.extend_from_slice(format!("Content-Type: {ct}\r\n").as_bytes());
            }
            body.extend_from_slice(b"\r\n");
            body.extend_from_slice(&part.value);
            body.extend_from_slice(b"\r\n");
        }
        body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());

        Content {
            body: Bytes::from(body),
            content_type: Some(format!("multipart/form-data; boundary={boundary}")),
        }
    }
}
