//! The HTTP half of the data plane and the whole of the control plane: enough
//! of HTTP/1.1 to read a request line, a bearer header and a JSON body.
//!
//! Same reasoning as [`crate::dns`]: the oracle answers a fixed set of shapes
//! and needs the PEER ADDRESS more than it needs a router. A framework here
//! would be more code to trust in the one process whose whole value is that a
//! reader believes what it recorded.

use std::collections::HashMap;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// The most a single request may be. The data plane's beacons are a URL and no
/// body; the control plane's largest body is a phase declaration. Anything
/// larger is a scan or a mistake and is refused rather than buffered.
pub const MAX_REQUEST: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub method: String,
    /// Path with the query string removed.
    pub path: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

impl Request {
    /// The `Authorization: Bearer <t>` token, if one was sent.
    pub fn bearer(&self) -> Option<&str> {
        self.headers
            .get("authorization")?
            .strip_prefix("Bearer ")
            .map(str::trim)
    }

    /// `/a/b/c` -> `["a", "b", "c"]`.
    pub fn segments(&self) -> Vec<&str> {
        self.path.split('/').filter(|s| !s.is_empty()).collect()
    }
}

/// Read one request off `sock`.
///
/// Returns `None` on anything malformed, oversized, or closed early — all of
/// which are the internet, not a defect.
pub async fn read_request<S>(sock: &mut S) -> Option<Request>
where
    S: AsyncReadExt + Unpin,
{
    let mut buf = Vec::with_capacity(1024);
    let mut head_end = None;
    while head_end.is_none() {
        let mut chunk = [0u8; 4096];
        let n = sock.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > MAX_REQUEST {
            return None;
        }
        head_end = find_head_end(&buf);
    }
    let head_end = head_end?;
    let head = std::str::from_utf8(&buf[..head_end]).ok()?;
    let mut lines = head.split("\r\n");
    let mut start = lines.next()?.split_whitespace();
    let method = start.next()?.to_string();
    let target = start.next()?;
    let path = target.split('?').next()?.to_string();

    let mut headers = HashMap::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }

    let want: usize = headers
        .get("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    if want > MAX_REQUEST {
        return None;
    }
    let mut body = buf[head_end + 4..].to_vec();
    while body.len() < want {
        let mut chunk = [0u8; 4096];
        let n = sock.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        body.extend_from_slice(&chunk[..n]);
        if body.len() > MAX_REQUEST {
            return None;
        }
    }
    body.truncate(want);
    Some(Request {
        method,
        path,
        headers,
        body,
    })
}

fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// Write a response. `Connection: close` on every one: the beacons are
/// one-shot and a kept-alive connection is state the oracle has no reason to
/// hold.
pub async fn respond<S>(sock: &mut S, status: u16, content_type: &str, body: &[u8])
where
    S: AsyncWriteExt + Unpin,
{
    let reason = match status {
        200 => "OK",
        201 => "Created",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        409 => "Conflict",
        _ => "Error",
    };
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\
         Cache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = sock.write_all(head.as_bytes()).await;
    let _ = sock.write_all(body).await;
    let _ = sock.flush().await;
    let _ = sock.shutdown().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_request_with_a_body_and_a_bearer_parses() {
        let raw = b"POST /v1/sessions?x=1 HTTP/1.1\r\nHost: o\r\nAuthorization: Bearer abc\r\n\
                    Content-Length: 7\r\n\r\n{\"a\":1}";
        let mut cur = std::io::Cursor::new(raw.to_vec());
        let req = read_request(&mut cur).await.expect("must parse");
        assert_eq!(req.method, "POST");
        // The query string is dropped, so routing cannot be confused by one.
        assert_eq!(req.path, "/v1/sessions");
        assert_eq!(req.bearer(), Some("abc"));
        assert_eq!(req.body, b"{\"a\":1}");
        assert_eq!(req.segments(), vec!["v1", "sessions"]);
    }

    /// The data-plane socket faces the internet. Garbage must be dropped.
    #[tokio::test]
    async fn garbage_and_early_close_are_dropped() {
        let mut cur = std::io::Cursor::new(b"not http at all".to_vec());
        assert!(read_request(&mut cur).await.is_none());
        let mut empty = std::io::Cursor::new(Vec::new());
        assert!(read_request(&mut empty).await.is_none());
    }
}
