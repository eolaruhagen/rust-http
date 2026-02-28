use std::collections::HashMap;

use crate::error::SerializationError;

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
pub(crate) struct ParsedHttpRequest<'a> {
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

    // ── Well-known headers (RFC 9110) ──
    // Extracted during parsing for direct access. These are used by the server
    // internally for framing (Content-Length), routing, and connection management.
    // Stored as parsed types where possible to avoid repeated string parsing.
    /// The `Host` header — REQUIRED in HTTP/1.1 (RFC 9112, Section 3.2).
    /// Contains the host and optional port, e.g., "localhost:8080".
    /// Missing Host in an HTTP/1.1 request is a 400 Bad Request.
    host: &'a str,

    /// Parsed value of the `Content-Length` header.
    /// Already converted to `usize` during parsing so consumers don't need to
    /// re-parse the string. `None` if the header is absent (no body expected).
    content_length: Option<usize>,

    /// The `Content-Type` header, e.g., "application/json", "text/html".
    /// Determines how the body should be interpreted. `None` if absent.
    content_type: Option<&'a str>,

    /// The `Connection` header — "keep-alive" or "close".
    /// Determines whether the TCP connection should persist after this request.
    /// `None` if absent (HTTP/1.1 defaults to keep-alive).
    connection: Option<&'a str>,

    // ── Remaining headers ──
    /// All other headers not extracted above, stored as key-value pairs in a HashMap
    /// for O(1) lookups. Exposed to library users for middleware and handler access
    /// (e.g., `Authorization`, `X-Request-Id`, custom headers).
    headers: HashMap<&'a str, &'a str>,

    /// Optional request body. Present when `Content-Length` header exists and is > 0.
    /// The body is the raw bytes after the `\r\n\r\n` header terminator,
    /// read up to exactly `Content-Length` bytes.
    body: Option<&'a [u8]>,
}

/// RFC 9110 Compliant Statics for Parsing
static HTTP_VERSION_1_0: &str = "HTTP/1.0";
static HTTP_VERSION_1_1: &str = "HTTP/1.1";

static CRLF: &[u8] = b"\r\n";
static CRLFS: &'static str = "\r\n";
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

impl<'a> ParsedHttpRequest<'a> {
    pub fn from_bytes(
        bytes: &'a [u8],
        max_header_size: usize,
        max_body_size: usize,
    ) -> Result<Self, SerializationError> {
        let header_end_position = find_header_boundary_position(bytes)?;

        if header_end_position > max_header_size as usize {
            return Err(SerializationError::HeaderTooLarge);
        }

        let (request_line, request_line_end) = extract_request_line(bytes)?;
        let (method, path, query, http_version) = parse_request_line(request_line)?;
        validate_http_version(http_version)?;

        // given the request line at this point we can only assume valid method gives based by the enum, and a valid HTTP version
        // now we have to create the headers given the header
        let header_buffer = &bytes[request_line_end + CRLF.len()..header_end_position];
        let header_map = extract_http_headers(header_buffer)?;
        let contains_body = bytes.len() > header_end_position + HEADER_TERMINATOR.len();
        validate_http_headers(
            &header_map,
            contains_body,
            max_body_size,
            bytes,
            header_end_position,
        )?;

        // once headers are validated and extracted, parse out the well-known headers for direct access, and store the rest in the headers map
        let host = header_map
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("host"))
            .map(|(_, v)| *v)
            .ok_or(SerializationError::InvalidBuffer)?; // Host is required in HTTP/1.1 -> Note that we shouldnt error out at this point, should already be caught
        let content_length = header_map
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
            .map(|(_, v)| *v)
            .map(|s| s.parse::<usize>())
            .transpose()
            .map_err(|_| SerializationError::InvalidBuffer)?; // non-integer Content-Length is malformed
        let content_type = header_map
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
            .map(|(_, v)| *v);
        let connection = header_map
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("connection"))
            .map(|(_, v)| *v);

        // remove well-known headers so they only live in the typed struct fields, not duplicated in the map
        let mut headers = header_map;
        headers.retain(|k, _| {
            !k.eq_ignore_ascii_case("host")
                && !k.eq_ignore_ascii_case("content-length")
                && !k.eq_ignore_ascii_case("content-type")
                && !k.eq_ignore_ascii_case("connection")
        });

        return Ok(ParsedHttpRequest {
            http_version,
            method,
            path,
            query,
            host,
            content_length,
            content_type,
            connection,
            headers,
            body: None,
        });
    }

    /// Case-insensitive header lookup. Checks well-known fields first, then falls back
    /// to an O(n) scan of the remaining headers HashMap.
    /// For `Content-Length`, use `get_content_length()` instead (returns `Option<usize>`).
    pub fn get_header(&self, name: &str) -> Option<&str> {
        if name.eq_ignore_ascii_case("host") {
            return Some(self.host);
        }
        if name.eq_ignore_ascii_case("content-type") {
            return self.content_type;
        }
        if name.eq_ignore_ascii_case("connection") {
            return self.connection;
        }
        if name.eq_ignore_ascii_case("content-length") {
            return None; // use get_content_length() for the parsed usize value
        }
        // O(n) scan — case-insensitive key match over remaining headers
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| *v)
    }

    /// Returns the parsed `Content-Length` value as `usize`.
    /// Already converted from string during parsing.
    pub fn get_content_length(&self) -> Option<usize> {
        self.content_length
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
/// Finds the first `\r\n` and returns everything before it along with the first index of the first CRLF.
/// - Returns `InvalidRequestLine` if no CRLF is found or the bytes aren't valid UTF-8.
fn extract_request_line(buffer: &[u8]) -> Result<(&str, usize), SerializationError> {
    let request_line_end = buffer
        .windows(CRLF.len())
        .position(|w| w == CRLF)
        .ok_or(SerializationError::InvalidRequestLine)?;
    let request_line_bytes = &buffer[..request_line_end];
    std::str::from_utf8(request_line_bytes)
        .map_err(|_| SerializationError::InvalidRequestLine)
        .map(|s| (s, request_line_end))
}

/// Splits a request line string into its three components per RFC 9112 Section 3:
/// `method SP request-target SP HTTP-version`
///
/// The request-target is further split on `?` into path and optional query string.
/// Returns `InvalidRequestLine` if any of the three parts are missing,
/// or `InvalidMethod` if the method string isn't a recognized HTTP method.
fn parse_request_line(
    request_line: &str,
) -> Result<(HttpMethod, &str, Option<&str>, &str), SerializationError> {
    let mut parts = request_line.split_whitespace();
    let method_str = parts.next().ok_or(SerializationError::InvalidRequestLine)?;
    let parsed_method =
        HttpMethod::from_str(method_str).ok_or(SerializationError::InvalidMethod)?;
    let request_target = parts.next().ok_or(SerializationError::InvalidRequestLine)?;
    let (path, query) = if let Some(q) = request_target.find('?') {
        (&request_target[..q], Some(&request_target[q + 1..]))
    } else {
        (request_target, None)
    };
    let http_version = parts.next().ok_or(SerializationError::InvalidRequestLine)?;

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

/// Parses out the raw headers into a hashmap from the header buffer.
/// - Assumes that the header buffer is the first byte of the headers, to the last CRLF of the headers (exclusive of the `\r\n\r\n` separator).
/// - Returns `InvalidBuffer` if the header buffer isn't valid UTF-8 or a non-conformant header line is found (e.g., missing `:`).
fn extract_http_headers(header_buffer: &[u8]) -> Result<HashMap<&str, &str>, SerializationError> {
    // we guarantee header buffer is the first byte of the header, to the last CRLF of the header
    let mut headers: HashMap<&str, &str> = HashMap::new();
    let header_str =
        std::str::from_utf8(header_buffer).map_err(|_| SerializationError::InvalidBuffer)?;
    let header_lines = header_str.split(CRLFS);
    for line in header_lines {
        if line.is_empty() {
            continue; // skip empty lines, still valid
        }

        let parts: Vec<&str> = line.splitn(2, ':').collect(); // contains the ":'" in the value field
        let field_name = match parts.first() {
            Some(name) => name.trim(), // header field names are case-insensitive, must be handled during lookups
            None => return Err(SerializationError::InvalidBuffer), // malformed header line
        };
        let field_value = match parts.get(1) {
            Some(value) => value.trim(), // trim whitespace from the value
            None => return Err(SerializationError::InvalidBuffer), // header with no value (e.g., "X-Flag:") is valid, treat as empty string
        };
        headers.insert(field_name, field_value);
    }

    Ok(headers)
}

/// Requires validation after the existence of the body is determined, and the content length is parsed. Validates that if a body exists, the content length header is present and matches the size of the body.
fn validate_http_headers(
    header_map: &HashMap<&str, &str>,
    contains_body: bool,
    max_body_size: usize,
    buffer: &[u8],
    header_end_position: usize,
) -> Result<(), SerializationError> {
    // we need to validate the presence of the Host header, and the content length header if there is a body
    // if host is not available we return a 400,
    // no matter of the request type is , if there is a body, we need to have a content length and type header,
    // along with the content len matching that of the body.

    // Return malformed request on missing Host header (required in HTTP/1.1)
    if header_map
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("host"))
        .is_none()
    {
        return Err(SerializationError::InvalidBuffer);
    }

    // If a body exists, content-length must be present, and match the size of the body in the buffer.
    if contains_body {
        let content_length_str = header_map
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
            .map(|(_, v)| *v)
            .ok_or(SerializationError::InvalidBuffer)?; // missing Content-Length is a malformed request if body exists

        let content_length = content_length_str
            .parse::<usize>()
            .map_err(|_| SerializationError::InvalidBuffer)?; // non-integer Content-Length is malformed
        // we can't validate the content length against the body size here because we don't have access to the body bytes in this function, but we can at least validate that it's a valid integer and present if a body exists.
        if content_length > max_body_size {
            return Err(SerializationError::HeaderTooLarge);
        }

        let true_body_size = buffer.len() - (header_end_position + HEADER_TERMINATOR.len());
        if content_length != true_body_size {
            return Err(SerializationError::InvalidBuffer); // Content-Length doesn't match actual body size
        }
    }
    Ok(())
}
