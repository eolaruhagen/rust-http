use std::{collections::HashMap, net::TcpStream};

use crate::{error::{HttpError, SerializationError}, server::response::HttpResponse};

/// Represents a parsed HTTP/1.1 request per RFC 9112 (HTTP/1.1) and RFC 9110 (HTTP Semantics).
///
/// # HTTP/1.1 Request Format (RFC 9112, Section 2.1)
///
/// An HTTP request message has the following structure:
///
/// ```text
/// request-line\r\n
/// *(header-field\r\n)
/// \r\n
/// [message-body]
/// ```
///
/// ## Request Line (RFC 9112, Section 3)
///
/// The first line of the request. Format: `method SP request-target SP HTTP-version CRLF`
///
/// ```text
/// GET /api/users?page=2 HTTP/1.1\r\n
/// ^   ^                 ^
/// |   |                 +-- HTTP version: must be "HTTP/1.1" (or "HTTP/1.0")
/// |   +-- Request target: the path + optional query string
/// +-- Method: one of GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS, TRACE, CONNECT
/// ```
///
/// - The method is case-sensitive (RFC 9110, Section 9.1). "GET" is valid, "get" is not.
/// - The request-target includes the path and query string but NOT the fragment (#).
/// - If this line is malformed or missing any of the three parts, respond with 400 Bad Request.
///
/// ## Headers (RFC 9110, Section 6.3)
///
/// Zero or more `field-name: field-value\r\n` lines following the request line.
/// Headers are terminated by an empty line (`\r\n\r\n`), which separates headers from the body.
///
/// ```text
/// Host: localhost:8080\r\n
/// Content-Type: application/json\r\n
/// Content-Length: 27\r\n
/// \r\n  <-- empty line = end of headers, start of body
/// ```
///
/// - Split on the FIRST `:` only — values may contain colons (e.g., `Host: localhost:8080`).
/// - Trim leading/trailing whitespace from the value (RFC 9110, Section 5.5).
/// - Field names are case-insensitive (RFC 9110, Section 5.1): "Content-Type" == "content-type".
/// - The `Host` header is REQUIRED in HTTP/1.1 (RFC 9112, Section 3.2). Missing = 400.
///
/// ### Headers that matter for parsing:
/// - `Content-Length`: Number of bytes in the body. Required to know when to stop reading.
/// - `Content-Type`: Format of the body (e.g., `application/json`, `text/html`).
/// - `Connection`: `keep-alive` or `close`. Determines if the TCP connection stays open.
/// - `Transfer-Encoding: chunked`: Alternative to Content-Length; body sent in chunks.
///   (Can be deferred — treat as unsupported initially and return 501.)
///
/// ## Body (RFC 9112, Section 6)
///
/// Optional. Present on POST, PUT, PATCH. Determined by `Content-Length` header.
/// GET, HEAD, DELETE, OPTIONS typically have no body.
/// Everything after the `\r\n\r\n` header terminator, up to `Content-Length` bytes.
///
/// # Lifetime `'a`
///
/// All string fields borrow from the raw request buffer that was read from the `TcpStream`.
/// This avoids allocating new `String`s per request (zero-copy parsing).
/// The buffer must outlive this struct — both must live within the same `handle()` scope.
struct HttpRequest<'a> {
    /// HTTP method: GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS.
    /// Case-sensitive per RFC 9110 Section 9.1.
    method: &'a HttpMethod,

    /// The request target path, e.g., "/api/users".
    /// Does not include the query string — split on '?' to separate.
    path: &'a str,

    /// Optional query string, e.g., "page=2&sort=asc".
    /// Everything after '?' in the request target. `None` if no '?' present.
    query: Option<&'a str>,

    /// HTTP version string, e.g., "HTTP/1.1".
    /// For compliance, accept "HTTP/1.0" and "HTTP/1.1".
    /// Return 505 HTTP Version Not Supported for anything else.
    http_version: &'a str,

    /// Request headers as key-value pairs.
    /// Keys are stored as-is from the request (spec says case-insensitive,
    /// so lookups should be case-insensitive or normalize to lowercase on parse).
    headers: HashMap<&'a str, &'a str>,

    /// Optional request body. Present when `Content-Length` header exists and is > 0.
    /// The body is the raw bytes after the `\r\n\r\n` header terminator,
    /// read up to exactly `Content-Length` bytes.
    body: Option<&'a str>,
}

enum HttpMethod {
    GET,
    POST,
    PUT,
    DELETE,
    PATCH,
    HEAD,
    OPTIONS,
}

impl HttpMethod {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "GET" => Some(HttpMethod::GET),
            "POST" => Some(HttpMethod::POST),
            "PUT" => Some(HttpMethod::PUT),
            "DELETE" => Some(HttpMethod::DELETE),
            "PATCH" => Some(HttpMethod::PATCH),
            "HEAD" => Some(HttpMethod::HEAD),
            "OPTIONS" => Some(HttpMethod::OPTIONS),
            _ => None,
        }
    }
}

impl<'a> HttpRequest<'a> {
    pub fn from_bytes(bytes: &[u8], max_header_size: u32, max_body_size: u32) -> Result<Self, SerializationError>{
        return Ok(HttpRequest {
            http_version: "HTTP/1.1",
            method: &HttpMethod::GET,
            path: "/",
            query: None,
            headers: HashMap::new(),
            body: None,
        })
    }
}
