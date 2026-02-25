use std::{collections::HashMap};

use crate::{error::{SerializationError}};


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
pub(crate) struct HttpRequest<'a> {
    /// HTTP method: GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS.
    /// Case-sensitive per RFC 9110 Section 9.1.
    method: HttpMethod,

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

/// RFC 9110 Compliant Statics for Parsing
static HTTP_VERSION_1_0: &str = "HTTP/1.0";
static HTTP_VERSION_1_1: &str = "HTTP/1.1";

static CRLF: &[u8] = b"\r\n";
static HEADER_TERMINATOR: &[u8] = b"\r\n\r\n";

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
    pub fn from_bytes(bytes: &'a [u8], max_header_size: u32, max_body_size: u32) -> Result<Self, SerializationError>{
        let header_end_position = find_header_boundary_position(bytes)?;

        if header_end_position > max_header_size as usize {
            return Err(SerializationError::HeaderTooLarge);
        }

        let request_line = extract_request_line(bytes)?;
        let (method, path, query, http_version) = parse_request_line(request_line)?;
        validate_http_version(http_version)?;

        // given the request line at this point we can only assume valid method gives based by the enum, and a valid HTTP version
        // now we have to create the headers given the header


        return Ok(HttpRequest {
            http_version,
            method,
            path,
            query,
            headers: HashMap::new(),
            body: None,
        })
    }
}

/// An Internal Helper for Parsing the HTTP Request Based on RFC 9112 and RFC 9110. These are not exposed outside the server module.


/// * Attempts to find the double CRLF that separates headers from the body
/// * Agnositcally sends a usize representing the position if the boundary is found, without checking if its position or the buffer is valid.
///     - Returns a SerializationError only if the boundary is *NOT* found
/// 
fn find_header_boundary_position(buffer: &[u8]) -> Result<usize, SerializationError> {
    let header_end_position = buffer
        .windows(HEADER_TERMINATOR.len())
        .position(|w| w == HEADER_TERMINATOR)
        .ok_or(SerializationError::InvalidBuffer)?;
    Ok(header_end_position)
}

/// Extracts the first line from the raw buffer as a UTF-8 string slice.
/// Finds the first `\r\n` and returns everything before it.
/// Returns `InvalidRequestLine` if no CRLF is found or the bytes aren't valid UTF-8.
fn extract_request_line(buffer: &[u8]) -> Result<&str, SerializationError> {
    let request_line_end = buffer
        .windows(CRLF.len())
        .position(|w| w == CRLF)
        .ok_or(SerializationError::InvalidRequestLine)?;
    let request_line_bytes = &buffer[..request_line_end];
    std::str::from_utf8(request_line_bytes).map_err(|_| SerializationError::InvalidRequestLine)
}

/// Splits a request line string into its three components per RFC 9112 Section 3:
/// `method SP request-target SP HTTP-version`
///
/// The request-target is further split on `?` into path and optional query string.
/// Returns `InvalidRequestLine` if any of the three parts are missing,
/// or `InvalidMethod` if the method string isn't a recognized HTTP method.
fn parse_request_line(request_line: &str) -> Result<(HttpMethod, &str, Option<&str>, &str), SerializationError> {
    let mut parts = request_line.split_whitespace();
    let method_str = parts
        .next()
        .ok_or(SerializationError::InvalidRequestLine)?;
    let parsed_method = HttpMethod::from_str(method_str).ok_or(SerializationError::InvalidMethod)?;
    let request_target = parts
        .next()
        .ok_or(SerializationError::InvalidRequestLine)?;
    let (path, query) = if let Some(q) = request_target.find('?') {
        (&request_target[..q], Some(&request_target[q + 1..]))
    } else {
        (request_target, None)
    };
    let http_version = parts
        .next()
        .ok_or(SerializationError::InvalidRequestLine)?;

    Ok((parsed_method, path, query, http_version))
}

/// Validates that the HTTP version string is one we support.
/// Accepts "HTTP/1.0" and "HTTP/1.1" per RFC 9112.
/// Returns `VersionNotSupported` for anything else (maps to 505).
fn validate_http_version(version: &str) -> Result<(), SerializationError> {
    if version == HTTP_VERSION_1_0 || version == HTTP_VERSION_1_1 {
        Ok(())
    } else {
        Err(SerializationError::VersionNotSupported)
    }
}