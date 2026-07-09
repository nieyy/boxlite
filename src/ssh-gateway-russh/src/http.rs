//! Minimal HTTP/1.1 client plumbing shared by the Hosted API client and the
//! Runner client.
//!
//! Deliberately hand-rolled over `hyper::client::conn::http1` (one TCP
//! connection per request, no pool): the Runner leg needs the raw upgraded
//! byte stream after `101 Switching Protocols`, and both legs are
//! low-frequency control-plane calls where pooling buys nothing.

use std::fmt;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::body::Incoming;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use serde::de::DeserializeOwned;
use tokio::net::TcpStream;

/// Parsed `http://host[:port]` base of an internal service.
#[derive(Debug, Clone)]
pub(crate) struct HttpBase {
    pub host: String,
    pub port: u16,
    /// `host[:port]` as sent in the `Host` header.
    pub authority: String,
}

/// Parses and validates an internal service base URL. Only plain `http` is
/// supported in Stage 1; TLS termination is expected inside the cluster.
pub(crate) fn parse_http_base(url: &str) -> Result<HttpBase, String> {
    let uri: hyper::Uri = url
        .parse()
        .map_err(|e| format!("cannot parse {url:?}: {e}"))?;
    match uri.scheme_str() {
        Some("http") => {}
        Some(other) => {
            return Err(format!(
                "unsupported scheme {other:?} (Stage 1 supports only \"http\")"
            ));
        }
        None => return Err("URL must include a scheme".into()),
    }
    let host = uri
        .host()
        .ok_or_else(|| "URL must include a host".to_string())?
        .to_string();
    let port = uri.port_u16().unwrap_or(80);
    let authority = uri
        .authority()
        .expect("host presence checked above")
        .to_string();
    Ok(HttpBase {
        host,
        port,
        authority,
    })
}

/// Transport-level failure of an internal HTTP call. Never contains request
/// URLs or credentials, so it is safe to log.
#[derive(Debug)]
pub(crate) enum HttpCallError {
    Connect(std::io::Error),
    Timeout,
    Protocol(String),
}

impl fmt::Display for HttpCallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connect(e) => write!(f, "connect failed: {e}"),
            Self::Timeout => write!(f, "request timed out"),
            Self::Protocol(e) => write!(f, "http error: {e}"),
        }
    }
}

impl std::error::Error for HttpCallError {}

/// Opens a fresh TCP connection to `base`, performs the HTTP/1.1 exchange,
/// and returns the raw response (body unread). Upgrades are enabled so the
/// caller may follow a `101` with [`hyper::upgrade::on`].
pub(crate) async fn send_request(
    base: &HttpBase,
    request: Request<Empty<Bytes>>,
    timeout: Duration,
) -> Result<Response<Incoming>, HttpCallError> {
    let exchange = async {
        let tcp = TcpStream::connect((base.host.as_str(), base.port))
            .await
            .map_err(HttpCallError::Connect)?;
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tcp))
            .await
            .map_err(|e| HttpCallError::Protocol(e.to_string()))?;
        tokio::spawn(async move {
            // Drives the connection; ends when the request completes or the
            // upgraded stream is dropped.
            let _ = connection.with_upgrades().await;
        });
        sender
            .send_request(request)
            .await
            .map_err(|e| HttpCallError::Protocol(e.to_string()))
    };
    tokio::time::timeout(timeout, exchange)
        .await
        .map_err(|_| HttpCallError::Timeout)?
}

/// Collects the response body and deserializes it as JSON.
pub(crate) async fn read_json_body<T: DeserializeOwned>(
    response: Response<Incoming>,
    timeout: Duration,
) -> Result<T, HttpCallError> {
    let bytes = read_body_bytes(response, timeout).await?;
    serde_json::from_slice(&bytes)
        .map_err(|e| HttpCallError::Protocol(format!("invalid JSON body: {e}")))
}

/// Collects the (small) response body; used for typed error bodies.
pub(crate) async fn read_body_bytes(
    response: Response<Incoming>,
    timeout: Duration,
) -> Result<Bytes, HttpCallError> {
    let collected = tokio::time::timeout(timeout, response.into_body().collect())
        .await
        .map_err(|_| HttpCallError::Timeout)?
        .map_err(|e| HttpCallError::Protocol(e.to_string()))?;
    Ok(collected.to_bytes())
}

/// Percent-encodes a value for use in a query string or path segment
/// (RFC 3986 unreserved characters pass through).
pub(crate) fn percent_encode(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(byte as char)
            }
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_http_base_accepts_host_with_and_without_port() {
        let base = parse_http_base("http://runner.internal:3003").expect("valid");
        assert_eq!((base.host.as_str(), base.port), ("runner.internal", 3003));
        assert_eq!(base.authority, "runner.internal:3003");

        let base = parse_http_base("http://runner.internal").expect("valid");
        assert_eq!(base.port, 80);
    }

    #[test]
    fn parse_http_base_rejects_non_http() {
        assert!(parse_http_base("https://runner.internal").is_err());
        assert!(parse_http_base("runner.internal").is_err());
        assert!(parse_http_base("vsock://3").is_err());
    }

    #[test]
    fn percent_encode_escapes_reserved_bytes() {
        assert_eq!(percent_encode("abc-DEF_0.9~"), "abc-DEF_0.9~");
        assert_eq!(percent_encode("a b&c=d/%"), "a%20b%26c%3Dd%2F%25");
        assert_eq!(percent_encode("密"), "%E5%AF%86");
    }
}
