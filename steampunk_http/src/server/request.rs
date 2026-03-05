use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

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
#[derive(Debug)]
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
    /// with **lowercase owned `String` keys** for true O(1) lookups.
    /// Values remain zero-copy borrows from the raw buffer.
    /// Exposed to library users for middleware and handler access
    /// (e.g., `Authorization`, `X-Request-Id`, custom headers).
    headers: HashMap<String, &'a str>,

    /// Optional request body. Present when `Content-Length` header exists and is > 0.
    /// The body is the raw bytes after the `\r\n\r\n` header terminator,
    /// read up to exactly `Content-Length` bytes.
    body: Option<&'a [u8]>,
}

/// RFC 9110 Compliant Statics for Parsing
static HTTP_VERSION_1_0: &str = "HTTP/1.0";
static HTTP_VERSION_1_1: &str = "HTTP/1.1";

static CRLF: &[u8] = b"\r\n";
static CRLFS: &str = "\r\n";
static HEADER_TERMINATOR: &[u8] = b"\r\n\r\n";

#[derive(Debug)]
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

        if header_end_position > max_header_size {
            return Err(SerializationError::HeaderTooLarge);
        }

        let (request_line, request_line_end) = extract_request_line(bytes)?;
        let (method, path, query, http_version) = parse_request_line(request_line)?;
        let is_version_1_0 = http_version == HTTP_VERSION_1_0;
        validate_http_version(http_version)?;

        // given the request line at this point we can only assume valid method gives based by the enum, and a valid HTTP version
        // now we have to create the headers given the header
        let header_start = request_line_end + CRLF.len();
        let header_buffer = if header_start <= header_end_position {
            &bytes[header_start..header_end_position]
        } else {
            // No headers at all — the request line's \r\n overlaps with the
            // \r\n\r\n terminator (e.g., "GET / HTTP/1.0\r\n\r\n").
            b""
        };
        let header_map = extract_http_headers(header_buffer)?;
        let contains_body = bytes.len() > header_end_position + HEADER_TERMINATOR.len();
        validate_http_headers(
            &header_map,
            contains_body,
            max_body_size,
            bytes,
            header_end_position,
            is_version_1_0
        )?;

        // once headers are validated and extracted, parse out the well-known headers for direct access, and store the rest in the headers map
        // Keys are already lowercase — direct .get() is O(1), no case-insensitive scan needed.
        let host = match header_map.get("host").copied() {
            Some(h) => h,
            None if is_version_1_0 => "", // Host is optional in HTTP/1.0
            None => return Err(SerializationError::InvalidBuffer), // required in HTTP/1.1
        };
        let content_length = header_map
            .get("content-length")
            .copied()
            .map(|s| s.parse::<usize>())
            .transpose()
            .map_err(|_| SerializationError::InvalidBuffer)?; // non-integer Content-Length is malformed
        let content_type = header_map.get("content-type").copied();
        let connection = header_map.get("connection").copied();

        // remove well-known headers so they only live in the typed struct fields, not duplicated in the map
        let mut headers = header_map;
        headers.remove("host");
        headers.remove("content-length");
        headers.remove("content-type");
        headers.remove("connection");

        // finally extract the body if it exists, everything after the header terminator
        let body = if contains_body {
            let body_start = header_end_position + HEADER_TERMINATOR.len();
            // unwrap safe — validate_http_headers guarantees content_length exists when contains_body is true
            Some(&bytes[body_start..body_start + content_length.unwrap()])
        } else {
            None
        };

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
            body,
        });
    }

    /// Case-insensitive header lookup. Checks well-known fields first, then falls back
    /// to an O(1) lookup in the remaining headers HashMap (keys are stored lowercase).
    /// For `Content-Length`, use `get_content_length()` instead (returns `Option<usize>`).
    pub fn get_header(&self, name: &str) -> Option<&str> {
        let lower = name.to_ascii_lowercase();
        match lower.as_str() {
            "host" => Some(self.host),
            "content-type" => self.content_type,
            "connection" => self.connection,
            "content-length" => None, // use get_content_length() for the parsed usize value
            _ => self.headers.get(&lower).copied(),
        }
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

/// Headers whose ABNF definition uses the `#` (list) rule, meaning their values
/// are comma-separated lists and multiple instances of the header are allowed
/// (RFC 7230 §3.2.2). Duplicates of these are combined: `"v1" + "v2"` → `"v1, v2"`.
///
/// Any header NOT in this list that appears more than once is a malformed request
/// and must be rejected with 400 Bad Request.
///
/// Derived from RFC 7231 Section 5, RFC 7230, RFC 7232, RFC 7233, RFC 7234, RFC 7235.
/// Lazily initialized `HashSet` for O(1) membership checks.
/// All entries are lowercase — callers must lowercase the name before checking.
static LIST_BASED_HEADERS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    HashSet::from([
        // Content negotiation (RFC 7231 §5.3)
        "accept",
        "accept-charset",
        "accept-encoding",
        "accept-language",
        // Representation metadata (RFC 7231 §3.1)
        "content-encoding",
        "content-language",
        "allow",
        // Connection management / hop-by-hop (RFC 7230)
        "connection",
        "te",
        "via",
        "trailer",
        "transfer-encoding",
        // Caching (RFC 7234)
        "cache-control",
        "pragma",
        // Conditionals — list forms (RFC 7232)
        "if-match",
        "if-none-match",
        // Misc
        "upgrade",
        "vary",
        "warning",
    ])
});

/// Parses out the raw headers into a hashmap from the header buffer.
/// - Assumes that the header buffer is the first byte of the headers, to the last CRLF of the headers (exclusive of the `\r\n\r\n` separator).
/// - Returns `InvalidBuffer` if the header buffer isn't valid UTF-8 or a non-conformant header line is found (e.g., missing `:`).
///
/// ## Duplicate header handling (RFC 7230 §3.2.2)
///
/// - **List-based headers** (ABNF uses `#` rule, e.g., `Accept`, `Cache-Control`):
///   multiple instances are combined into a single comma-separated value.
/// - **Singleton headers** (everything else, e.g., `Host`, `Content-Type`):
///   a second occurrence is a malformed request → `InvalidBuffer` (400).
fn extract_http_headers<'a>(
    header_buffer: &'a [u8],
) -> Result<HashMap<String, &'a str>, SerializationError> {
    let mut headers: HashMap<String, &'a str> = HashMap::new();
    // Owned buffer for combined list-based header values.
    // We leak these at the end so they can be stored as &'a str in the map.
    let mut combined: HashMap<String, String> = HashMap::new();
    let header_str =
        std::str::from_utf8(header_buffer).map_err(|_| SerializationError::InvalidBuffer)?;
    let header_lines = header_str.split(CRLFS);
    for line in header_lines {
        if line.is_empty() {
            continue; // skip empty lines, still valid
        }

        let parts: Vec<&str> = line.splitn(2, ':').collect();
        let field_name = match parts.first() {
            Some(name) => name.trim(),
            None => return Err(SerializationError::InvalidBuffer),
        };
        let field_value = match parts.get(1) {
            Some(value) => value.trim(),
            None => return Err(SerializationError::InvalidBuffer),
        };

        let key = field_name.to_ascii_lowercase();

        if headers.contains_key(&key) {
            // Duplicate header — only allowed for list-based headers
            if !LIST_BASED_HEADERS.contains(key.as_str()) {
                return Err(SerializationError::InvalidBuffer);
            }

            // Combine with the previous value using ", "
            combined
                .entry(key)
                .and_modify(|v| {
                    v.push_str(", ");
                    v.push_str(field_value);
                })
                .or_insert_with(|| {
                    // Seed with the original value already in headers
                    match headers.get(field_name.to_ascii_lowercase().as_str()) {
                        Some(original) => format!("{}, {}", original, field_value),
                        None => field_value.to_string(),
                    }
                });
        } else {
            headers.insert(key, field_value);
        }
    }

    // Patch combined list-based headers into the map.
    // Leak the owned Strings so they live for 'a — acceptable because the
    // ParsedHttpRequest (and its borrows) lives only within the handler scope.
    for (key, combined_value) in combined {
        let leaked: &'a str = Box::leak(combined_value.into_boxed_str());
        headers.insert(key, leaked);
    }

    Ok(headers)
}

/// Requires validation after the existence of the body is determined, and the content length is parsed. Validates that if a body exists, the content length header is present and matches the size of the body.
fn validate_http_headers(
    header_map: &HashMap<String, &str>,
    contains_body: bool,
    max_body_size: usize,
    buffer: &[u8],
    header_end_position: usize,
    is_version_1_0: bool,
) -> Result<(), SerializationError> {
    if !header_map.contains_key("host") && !is_version_1_0 {
        return Err(SerializationError::InvalidBuffer);
    }

    if contains_body {
        let content_length_str = header_map
            .get("content-length")
            .ok_or(SerializationError::InvalidBuffer)?;

        let content_length = content_length_str
            .parse::<usize>()
            .map_err(|_| SerializationError::InvalidBuffer)?;
        if content_length > max_body_size {
            return Err(SerializationError::BodyTooLarge);
        }

        let true_body_size = buffer.len() - (header_end_position + HEADER_TERMINATOR.len());
        if content_length != true_body_size {
            return Err(SerializationError::InvalidBuffer);
        }
    }
    Ok(())
}


/// ALL Request Parsing Test Cases
#[cfg(test)]
mod tests {
    use super::*;
    const MAX_HEADER_SIZE: usize = 8192; // 8 KB
    const MAX_BODY_SIZE: usize = 1_048_576; // 1 MB


    // Tests for from_bytes asssuming a properly formed HTTP request
    #[test]
    fn from_bytes_simple_get() {
        let raw = b"GET /hello HTTP/1.1\r\nHost: localhost:8080\r\n\r\n";

        let req = ParsedHttpRequest::from_bytes(raw, MAX_HEADER_SIZE, MAX_BODY_SIZE)
            .expect("valid GET request should parse successfully");

        // request-line fields
        assert!(matches!(req.method, HttpMethod::GET));
        assert_eq!(req.path, "/hello");
        assert_eq!(req.query, None);
        assert_eq!(req.http_version, "HTTP/1.1");

        // well-known headers
        assert_eq!(req.host, "localhost:8080");
        assert_eq!(req.content_length, None); // no body → no Content-Length
        assert_eq!(req.content_type, None);
        assert_eq!(req.connection, None);

        // no extra headers beyond Host (which was extracted)
        assert!(req.headers.is_empty());

        // no body
        assert!(req.body.is_none());
    }

    #[test]
    fn from_bytes_post_with_json_body() {
        let body_str = r#"{"name":"lord_voldemort","admin":true}"#;
        assert_eq!(body_str.len(), 38); // sanity check so the test stays in sync

        // Build the raw request by concatenating header + body.
        // Using a Vec<u8> avoids format!() brace-escaping issues.
        let mut raw = Vec::new();
        raw.extend_from_slice(b"POST /api/users?verbose=true HTTP/1.1\r\n");
        raw.extend_from_slice(b"Host: example.com\r\n");
        raw.extend_from_slice(b"Content-Type: application/json\r\n");
        raw.extend_from_slice(format!("Content-Length: {}\r\n", body_str.len()).as_bytes());
        raw.extend_from_slice(b"Connection: keep-alive\r\n");
        raw.extend_from_slice(b"\r\n"); // header terminator
        raw.extend_from_slice(body_str.as_bytes());

        let req = ParsedHttpRequest::from_bytes(&raw, MAX_HEADER_SIZE, MAX_BODY_SIZE)
            .expect("valid POST with body should parse successfully");

        // request-line
        assert!(matches!(req.method, HttpMethod::POST));
        assert_eq!(req.path, "/api/users");
        assert_eq!(req.query, Some("verbose=true"));
        assert_eq!(req.http_version, "HTTP/1.1");

        // well-known headers
        assert_eq!(req.host, "example.com");
        assert_eq!(req.content_length, Some(body_str.len()));
        assert_eq!(req.content_type, Some("application/json"));
        assert_eq!(req.connection, Some("keep-alive"));

        // remaining headers map should be empty — all headers were well-known
        assert!(req.headers.is_empty());

        // body
        assert_eq!(req.body, Some(body_str.as_bytes()));
    }

    #[test]
    fn from_bytes_post_with_xml_body() {
        let body_str = r#"<?xml version="1.0"?><user><name>Erico</name></user>"#;

        let mut raw = Vec::new();
        raw.extend_from_slice(b"POST /api/users HTTP/1.1\r\n");
        raw.extend_from_slice(b"Host: example.com\r\n");
        raw.extend_from_slice(b"Content-Type: application/xml\r\n");
        raw.extend_from_slice(format!("Content-Length: {}\r\n", body_str.len()).as_bytes());
        raw.extend_from_slice(b"\r\n");
        raw.extend_from_slice(body_str.as_bytes());

        let req = ParsedHttpRequest::from_bytes(&raw, MAX_HEADER_SIZE, MAX_BODY_SIZE)
            .expect("valid POST with XML body should parse successfully");

        assert!(matches!(req.method, HttpMethod::POST));
        assert_eq!(req.content_type, Some("application/xml"));
        assert_eq!(req.content_length, Some(body_str.len()));
        assert_eq!(req.body, Some(body_str.as_bytes()));
    }

    #[test]
    fn from_bytes_post_with_binary_body() {
        let body_bytes: &[u8] = &[
            0x89, 0x50, 0x4E, 0x47, // .PNG
            0x0D, 0x0A, 0x1A, 0x0A, // \r\n . \n
            0x00, 0x00, 0x00, 0x0D, // null bytes + length
            0xFF, 0xFE, 0xFD, 0xFC, // high bytes, not valid UTF-8
        ];

        let mut raw = Vec::new();
        raw.extend_from_slice(b"POST /upload HTTP/1.1\r\n");
        raw.extend_from_slice(b"Host: example.com\r\n");
        raw.extend_from_slice(b"Content-Type: image/png\r\n");
        raw.extend_from_slice(format!("Content-Length: {}\r\n", body_bytes.len()).as_bytes());
        raw.extend_from_slice(b"\r\n");
        raw.extend_from_slice(body_bytes);

        let req = ParsedHttpRequest::from_bytes(&raw, MAX_HEADER_SIZE, MAX_BODY_SIZE)
            .expect("valid POST with binary body should parse successfully");

        assert!(matches!(req.method, HttpMethod::POST));
        assert_eq!(req.content_type, Some("image/png"));
        assert_eq!(req.content_length, Some(body_bytes.len()));
        assert_eq!(req.body, Some(body_bytes));
    }

    #[test]
    // Test with a properly formed request, with large body and many headers on a GET request. 
    // Still technicaly valid as GET requests can have bodies. Thus body should be present in the struct
    // also contains a query in the request target as well.
    fn from_bytes_large_get_with_body_and_query() {
        let body_str = "x".repeat(1024); // 1 KB body

        let mut raw = Vec::new();
        raw.extend_from_slice(b"GET /search?q=rust&page=3&limit=50 HTTP/1.1\r\n");
        raw.extend_from_slice(b"Host: example.com\r\n");
        raw.extend_from_slice(b"Content-Type: text/plain\r\n");
        raw.extend_from_slice(format!("Content-Length: {}\r\n", body_str.len()).as_bytes());
        raw.extend_from_slice(b"Authorization: Bearer tok_abc123\r\n");
        raw.extend_from_slice(b"Accept: text/html\r\n");
        raw.extend_from_slice(b"X-Request-Id: 550e8400-e29b-41d4-a716-446655440000\r\n");
        raw.extend_from_slice(b"\r\n");
        raw.extend_from_slice(body_str.as_bytes());

        let req = ParsedHttpRequest::from_bytes(&raw, MAX_HEADER_SIZE, MAX_BODY_SIZE)
            .expect("valid GET with body and query should parse successfully");

        assert!(matches!(req.method, HttpMethod::GET));
        assert_eq!(req.path, "/search");
        assert_eq!(req.query, Some("q=rust&page=3&limit=50"));

        assert_eq!(req.host, "example.com");
        assert_eq!(req.content_length, Some(1024));
        assert_eq!(req.content_type, Some("text/plain"));

        // non-well-known headers land in the HashMap
        assert_eq!(req.headers.len(), 3);
        assert_eq!(req.get_header("Authorization"), Some("Bearer tok_abc123"));
        assert_eq!(req.get_header("Accept"), Some("text/html"));
        assert_eq!(
            req.get_header("X-Request-Id"),
            Some("550e8400-e29b-41d4-a716-446655440000")
        );

        assert_eq!(req.body, Some(body_str.as_bytes()));
    }

    #[test]
    fn from_bytes_options_no_body() {
        // OPTIONS is commonly used for CORS preflight — no body, just headers.
        let raw = b"OPTIONS /api/data HTTP/1.1\r\nHost: example.com\r\n\r\n";

        let req = ParsedHttpRequest::from_bytes(raw, MAX_HEADER_SIZE, MAX_BODY_SIZE)
            .expect("valid OPTIONS request should parse successfully");

        assert!(matches!(req.method, HttpMethod::OPTIONS));
        assert_eq!(req.path, "/api/data");
        assert_eq!(req.query, None);
        assert_eq!(req.host, "example.com");
        assert!(req.body.is_none());
        assert_eq!(req.content_length, None);
    }

    #[test]
    // Test with a properly formed request, no body and at least one header with "key" : "" (empty value) Which should still be valid
    // Tests PATCH method parsing too
    fn from_bytes_empty_but_valid_headers() {
        // RFC 9110 Section 5.5: field values MAY be empty after trimming.
        // A header like "X-Empty: \r\n" has an empty string as its value, which is legal.
        let body_str = r#"{"status":"active"}"#;

        let mut raw = Vec::new();
        raw.extend_from_slice(b"PATCH /api/users/42 HTTP/1.1\r\n");
        raw.extend_from_slice(b"Host: example.com\r\n");
        raw.extend_from_slice(b"Content-Type: application/json\r\n");
        raw.extend_from_slice(format!("Content-Length: {}\r\n", body_str.len()).as_bytes());
        raw.extend_from_slice(b"X-Empty: \r\n"); // empty value after trim
        raw.extend_from_slice(b"X-Also-Empty:\r\n");
        raw.extend_from_slice(b"\r\n");
        raw.extend_from_slice(body_str.as_bytes());

        let req = ParsedHttpRequest::from_bytes(&raw, MAX_HEADER_SIZE, MAX_BODY_SIZE)
            .expect("headers with empty values are valid per RFC 9110");

        assert!(matches!(req.method, HttpMethod::PATCH));
        assert_eq!(req.path, "/api/users/42");

        // empty header values should be stored as empty strings, not None
        assert_eq!(req.get_header("X-Empty"), Some(""));
        assert_eq!(req.get_header("X-Also-Empty"), Some(""));

        assert_eq!(req.body, Some(body_str.as_bytes()));
    }

    #[test]
    fn from_bytes_update_with_keep_alive() {
        let body_str = r#"{"email":"new@example.com"}"#;

        let mut raw = Vec::new();
        raw.extend_from_slice(b"PUT /api/users/7 HTTP/1.1\r\n");
        raw.extend_from_slice(b"Host: api.example.com\r\n");
        raw.extend_from_slice(b"Content-Type: application/json\r\n");
        raw.extend_from_slice(format!("Content-Length: {}\r\n", body_str.len()).as_bytes());
        raw.extend_from_slice(b"Connection: keep-alive\r\n");
        raw.extend_from_slice(b"\r\n");
        raw.extend_from_slice(body_str.as_bytes());

        let req = ParsedHttpRequest::from_bytes(&raw, MAX_HEADER_SIZE, MAX_BODY_SIZE)
            .expect("valid PUT with keep-alive should parse successfully");

        assert!(matches!(req.method, HttpMethod::PUT));
        assert_eq!(req.path, "/api/users/7");
        assert_eq!(req.connection, Some("keep-alive"));
        assert_eq!(req.body, Some(body_str.as_bytes()));
    }

    #[test]
    fn from_bytes_delete_with_query() {
        let raw = b"DELETE /api/cache?region=us-east HTTP/1.1\r\nHost: example.com\r\n\r\n";

        let req = ParsedHttpRequest::from_bytes(raw, MAX_HEADER_SIZE, MAX_BODY_SIZE)
            .expect("valid DELETE with query should parse successfully");

        assert!(matches!(req.method, HttpMethod::DELETE));
        assert_eq!(req.path, "/api/cache");
        assert_eq!(req.query, Some("region=us-east"));
        assert!(req.body.is_none());
    }

    #[test]
    fn from_bytes_options_with_custom_headers() {
        // Custom headers should land in the HashMap, not be silently dropped.
        // Also tests a header value containing a colon — splitn(2, ':') must only
        // split on the FIRST colon, keeping "10.0.0.1:443" intact in the value.
        let mut raw = Vec::new();
        raw.extend_from_slice(b"OPTIONS /api HTTP/1.1\r\n");
        raw.extend_from_slice(b"Host: example.com\r\n");
        raw.extend_from_slice(b"X-Forwarded-For: 10.0.0.1:443\r\n");
        raw.extend_from_slice(b"X-Correlation-Id: abc-123\r\n");
        raw.extend_from_slice(b"Accept: */*\r\n");
        raw.extend_from_slice(b"\r\n");

        let req = ParsedHttpRequest::from_bytes(&raw, MAX_HEADER_SIZE, MAX_BODY_SIZE)
            .expect("OPTIONS with custom headers should parse successfully");

        assert!(matches!(req.method, HttpMethod::OPTIONS));
        assert_eq!(req.headers.len(), 3);

        // colon in value must be preserved — split on first colon only
        assert_eq!(req.get_header("X-Forwarded-For"), Some("10.0.0.1:443"));
        assert_eq!(req.get_header("X-Correlation-Id"), Some("abc-123"));
        assert_eq!(req.get_header("Accept"), Some("*/*"));
    }

    #[test]
    /// As per the HTTP 1.1 RFC 7230 §3.2.2, headers whose ABNF uses the `#` (list)
    /// rule may appear multiple times. Their values must be combined into a single
    /// comma-separated value. Accept is a list-based header.
    fn from_bytes_with_duplicate_list_headers() {
        let mut raw = Vec::new();
        raw.extend_from_slice(b"GET /resource HTTP/1.1\r\n");
        raw.extend_from_slice(b"Host: example.com\r\n");
        raw.extend_from_slice(b"Accept: text/html\r\n");
        raw.extend_from_slice(b"Accept: application/json\r\n");
        raw.extend_from_slice(b"\r\n");

        let req = ParsedHttpRequest::from_bytes(&raw, MAX_HEADER_SIZE, MAX_BODY_SIZE)
            .expect("duplicate list-based headers should be combined");

        // RFC 7230 §3.2.2: duplicate list-based header values must be combined with ", "
        assert_eq!(req.get_header("Accept"), Some("text/html, application/json"));
    }

    #[test]
    /// Singleton headers (those NOT defined with the `#` list rule) MUST NOT appear
    /// more than once. A duplicate Content-Type is malformed → 400 Bad Request.
    fn from_bytes_rejects_duplicate_singleton_headers() {
        let mut raw = Vec::new();
        raw.extend_from_slice(b"POST /data HTTP/1.1\r\n");
        raw.extend_from_slice(b"Host: example.com\r\n");
        raw.extend_from_slice(b"Content-Type: text/plain\r\n");
        raw.extend_from_slice(b"Content-Type: application/json\r\n");
        raw.extend_from_slice(b"Content-Length: 5\r\n");
        raw.extend_from_slice(b"\r\n");
        raw.extend_from_slice(b"hello");

        let err = ParsedHttpRequest::from_bytes(&raw, MAX_HEADER_SIZE, MAX_BODY_SIZE)
            .expect_err("duplicate singleton header should be rejected");
        assert!(matches!(err, SerializationError::InvalidBuffer));
    }

    #[test]
    /// Duplicate Host header MUST be rejected — Host is a singleton.
    fn from_bytes_rejects_duplicate_host() {
        let raw = b"GET / HTTP/1.1\r\nHost: a.com\r\nHost: b.com\r\n\r\n";

        let err = ParsedHttpRequest::from_bytes(raw, MAX_HEADER_SIZE, MAX_BODY_SIZE)
            .expect_err("duplicate Host header should be rejected");
        assert!(matches!(err, SerializationError::InvalidBuffer));
    }

    #[test]
    /// Multiple list-based headers (Accept-Encoding, Cache-Control) should all
    /// be combined correctly in the same request.
    fn from_bytes_combines_multiple_list_based_headers() {
        let mut raw = Vec::new();
        raw.extend_from_slice(b"GET / HTTP/1.1\r\n");
        raw.extend_from_slice(b"Host: example.com\r\n");
        raw.extend_from_slice(b"Accept-Encoding: gzip\r\n");
        raw.extend_from_slice(b"Accept-Encoding: deflate\r\n");
        raw.extend_from_slice(b"Cache-Control: no-cache\r\n");
        raw.extend_from_slice(b"Cache-Control: no-store\r\n");
        raw.extend_from_slice(b"\r\n");

        let req = ParsedHttpRequest::from_bytes(&raw, MAX_HEADER_SIZE, MAX_BODY_SIZE)
            .expect("multiple list-based duplicate headers should combine");

        assert_eq!(
            req.get_header("Accept-Encoding"),
            Some("gzip, deflate")
        );
        assert_eq!(
            req.get_header("Cache-Control"),
            Some("no-cache, no-store")
        );
    }

    #[test]
    fn from_bytes_enforce_header_names_are_case_insensitive() {
        // RFC 9110 Section 5.1: field names are case-insensitive.
        // get_header() must find headers regardless of the casing used in the request
        // vs. the casing used in the lookup.
        let body_str = "hello";

        let mut raw = Vec::new();
        raw.extend_from_slice(b"POST /test HTTP/1.1\r\n");
        raw.extend_from_slice(b"hOsT: example.com\r\n"); // weird casing for Host
        raw.extend_from_slice(b"content-type: text/plain\r\n"); // all lowercase
        raw.extend_from_slice(format!("CONTENT-LENGTH: {}\r\n", body_str.len()).as_bytes()); // ALL CAPS
        raw.extend_from_slice(b"connection: close\r\n"); // lowercase
        raw.extend_from_slice(b"x-CUSTOM-Header: some-value\r\n"); // mixed case custom header
        raw.extend_from_slice(b"\r\n");
        raw.extend_from_slice(body_str.as_bytes());

        let req = ParsedHttpRequest::from_bytes(&raw, MAX_HEADER_SIZE, MAX_BODY_SIZE)
            .expect("case-insensitive headers should parse successfully");

        // well-known headers extracted despite non-standard casing
        assert_eq!(req.host, "example.com");
        assert_eq!(req.content_type, Some("text/plain"));
        assert_eq!(req.content_length, Some(5));
        assert_eq!(req.connection, Some("close"));

        // get_header lookups with different casing than what was in the request
        assert_eq!(req.get_header("HOST"), Some("example.com"));
        assert_eq!(req.get_header("Content-Type"), Some("text/plain"));
        assert_eq!(req.get_header("connection"), Some("close"));

        // custom header: stored with original casing, but lookup is case-insensitive
        assert_eq!(req.get_header("X-Custom-Header"), Some("some-value"));
        assert_eq!(req.get_header("x-custom-header"), Some("some-value"));
    }

    // ── Additional RFC-driven edge cases ────────────────────────────────

    #[test]
    fn from_bytes_http_1_0_with_host() {
        // HTTP/1.0 (RFC 1945) didn't mandate Host, but our parser requires it
        // unconditionally. This test documents that design decision:
        // HTTP/1.0 requests WITH Host are accepted.
        let raw = b"GET /legacy HTTP/1.0\r\nHost: oldserver.com\r\n\r\n";

        let req = ParsedHttpRequest::from_bytes(raw, MAX_HEADER_SIZE, MAX_BODY_SIZE)
            .expect("HTTP/1.0 with Host should parse successfully");

        assert!(matches!(req.method, HttpMethod::GET));
        assert_eq!(req.http_version, "HTTP/1.0");
        assert_eq!(req.host, "oldserver.com");
        assert!(req.body.is_none());
    }

    #[test]
    fn from_bytes_connection_close() {
        // Connection: close tells the server to tear down the TCP socket after
        // responding. Semantically distinct from keep-alive — make sure it parses.
        let raw = b"GET /bye HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n";

        let req = ParsedHttpRequest::from_bytes(raw, MAX_HEADER_SIZE, MAX_BODY_SIZE)
            .expect("Connection: close should parse successfully");

        assert_eq!(req.connection, Some("close"));
        assert!(req.body.is_none());
    }

    #[test]
    fn from_bytes_empty_query_after_question_mark() {
        // "GET /path? HTTP/1.1" — the '?' is present but nothing follows it.
        // Parser should produce query = Some(""), NOT None.
        // Consumers may care about the distinction (e.g., /path vs /path?).
        let raw = b"GET /path? HTTP/1.1\r\nHost: example.com\r\n\r\n";

        let req = ParsedHttpRequest::from_bytes(raw, MAX_HEADER_SIZE, MAX_BODY_SIZE)
            .expect("empty query string after ? should parse successfully");

        assert_eq!(req.path, "/path");
        assert_eq!(req.query, Some(""));
    }

    #[test]
    fn from_bytes_head_minimal() {
        // HEAD is identical to GET but the server must not return a body in the
        // response. From the *request* parser's perspective, it's just another
        // method with no body.
        let raw = b"HEAD / HTTP/1.1\r\nHost: example.com\r\n\r\n";

        let req = ParsedHttpRequest::from_bytes(raw, MAX_HEADER_SIZE, MAX_BODY_SIZE)
            .expect("minimal HEAD request should parse successfully");

        assert!(matches!(req.method, HttpMethod::HEAD));
        assert_eq!(req.path, "/");
        assert!(req.body.is_none());
    }

    #[test]
    /// HTTP/1.0 (RFC 1945) didn't mandate Host, but our parser follow that unconditionally
    /// HTTP/1.0 requests WITHOUT Host are not rejected.
    fn from_bytes_http_1_0_no_host() {
        let raw = b"GET /legacy HTTP/1.0\r\n\r\n";

        let req = ParsedHttpRequest::from_bytes(raw, MAX_HEADER_SIZE, MAX_BODY_SIZE)
            .expect("HTTP/1.0 without Host should parse successfully");
        assert_eq!(req.host, "");
    }


    /// Non Happy path test cases for from_bytes, ensuring malformed requests are rejected with the correct error type

    #[test]
    fn from_bytes_missing_host_on_1_1() {
        let raw = b"GET /hello HTTP/1.1\r\nAccept: text/html\r\n\r\n";

        let err = ParsedHttpRequest::from_bytes(raw, MAX_HEADER_SIZE, MAX_BODY_SIZE)
            .expect_err("missing Host header should be rejected");
        assert!(matches!(err, SerializationError::InvalidBuffer));
    }

    #[test]
    fn from_bytes_invalid_http_version() {
        let raw = b"GET /hello HTTP/2.0\r\nHost: example.com\r\n\r\n";

        let err = ParsedHttpRequest::from_bytes(raw, MAX_HEADER_SIZE, MAX_BODY_SIZE)
            .expect_err("unsupported HTTP version should be rejected");
        assert!(matches!(err, SerializationError::VersionNotSupported));
    }

    #[test]
    fn from_bytes_malformed_request_line() {
        let raw = b"GET /hello\r\nHost: example.com\r\n\r\n";

        let err = ParsedHttpRequest::from_bytes(raw, MAX_HEADER_SIZE, MAX_BODY_SIZE)
            .expect_err("request line with only two parts should be rejected");
        assert!(matches!(err, SerializationError::InvalidRequestLine));

        // Only one part (just method) → InvalidRequestLine (400).
        let raw = b"GET\r\nHost: example.com\r\n\r\n";

        let err = ParsedHttpRequest::from_bytes(raw, MAX_HEADER_SIZE, MAX_BODY_SIZE)
            .expect_err("request line with only method should be rejected");
        assert!(matches!(err, SerializationError::InvalidRequestLine));
    }

    #[test]
    fn from_bytes_non_integer_content_length() {
        let mut raw = Vec::new();
        raw.extend_from_slice(b"POST /data HTTP/1.1\r\n");
        raw.extend_from_slice(b"Host: example.com\r\n");
        raw.extend_from_slice(b"Content-Length: abc\r\n");
        raw.extend_from_slice(b"\r\n");
        raw.extend_from_slice(b"hello");

        let err = ParsedHttpRequest::from_bytes(&raw, MAX_HEADER_SIZE, MAX_BODY_SIZE)
            .expect_err("non-integer Content-Length should be rejected");
        assert!(matches!(err, SerializationError::InvalidBuffer));
    }

    #[test]
    fn from_bytes_body_without_content_length() {
        let mut raw = Vec::new();
        raw.extend_from_slice(b"POST /data HTTP/1.1\r\n");
        raw.extend_from_slice(b"Host: example.com\r\n");
        raw.extend_from_slice(b"Content-Type: text/plain\r\n");
        raw.extend_from_slice(b"\r\n");
        raw.extend_from_slice(b"some body bytes");

        let err = ParsedHttpRequest::from_bytes(&raw, MAX_HEADER_SIZE, MAX_BODY_SIZE)
            .expect_err("body without Content-Length should be rejected");
        assert!(matches!(err, SerializationError::InvalidBuffer));
    }

    #[test]
    fn from_bytes_content_length_mismatch() {
        let mut raw = Vec::new();
        raw.extend_from_slice(b"POST /data HTTP/1.1\r\n");
        raw.extend_from_slice(b"Host: example.com\r\n");
        raw.extend_from_slice(b"Content-Length: 5\r\n");
        raw.extend_from_slice(b"\r\n");
        raw.extend_from_slice(b"hello world");

        let err = ParsedHttpRequest::from_bytes(&raw, MAX_HEADER_SIZE, MAX_BODY_SIZE)
            .expect_err("Content-Length mismatch should be rejected");
        assert!(matches!(err, SerializationError::InvalidBuffer));
    }

    #[test]
    fn from_bytes_exceed_max_header_size() {
        // Construct a request where the header section genuinely exceeds MAX_HEADER_SIZE.
        // A single header with a massive value pushes past the 8 KB limit.
        let huge_value = "x".repeat(MAX_HEADER_SIZE); // 8 KB value alone

        let mut raw = Vec::new();
        raw.extend_from_slice(b"GET /hello HTTP/1.1\r\n");
        raw.extend_from_slice(b"Host: example.com\r\n");
        raw.extend_from_slice(format!("X-Huge: {}\r\n", huge_value).as_bytes());
        raw.extend_from_slice(b"\r\n");

        let err = ParsedHttpRequest::from_bytes(&raw, MAX_HEADER_SIZE, MAX_BODY_SIZE)
            .expect_err("oversized headers should be rejected");
        assert!(matches!(err, SerializationError::HeaderTooLarge));
    }

    #[test]
    fn from_bytes_exceed_max_body_size() {
        let body = b"0123456789";

        let mut raw = Vec::new();
        raw.extend_from_slice(b"POST /data HTTP/1.1\r\n");
        raw.extend_from_slice(b"Host: example.com\r\n");
        raw.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
        raw.extend_from_slice(b"\r\n");
        raw.extend_from_slice(body);

        let err = ParsedHttpRequest::from_bytes(&raw, MAX_HEADER_SIZE, 4)
            .expect_err("oversized body should be rejected");
        assert!(matches!(err, SerializationError::BodyTooLarge));
    }

    #[test]
    fn non_empty_header_without_colon() {
        let mut raw = Vec::new();
        raw.extend_from_slice(b"GET /hello HTTP/1.1\r\n");
        raw.extend_from_slice(b"Host: example.com\r\n");
        raw.extend_from_slice(b"BadHeaderNoColon\r\n");
        raw.extend_from_slice(b"\r\n");

        let err = ParsedHttpRequest::from_bytes(&raw, MAX_HEADER_SIZE, MAX_BODY_SIZE)
            .expect_err("header line without colon should be rejected");
        assert!(matches!(err, SerializationError::InvalidBuffer));
    }

    #[test]
    fn from_bytes_invalid_http_method() {
        let raw = b"FOG /hello HTTP/1.1\r\nHost: example.com\r\n\r\n";

        let err = ParsedHttpRequest::from_bytes(raw, MAX_HEADER_SIZE, MAX_BODY_SIZE)
            .expect_err("unrecognized HTTP method should be rejected");
        assert!(matches!(err, SerializationError::InvalidMethod));
    }

    #[test]
    fn from_bytes_no_crlf_in_request_line() {
        // No \r\n anywhere — extract_request_line can't find the end of the
        // request line. But first find_header_boundary_position will fail
        // because there's no \r\n\r\n either → InvalidBuffer.
        let raw = b"GET /hello HTTP/1.1 Host: example.com";

        let err = ParsedHttpRequest::from_bytes(raw, MAX_HEADER_SIZE, MAX_BODY_SIZE)
            .expect_err("request with no CRLF should be rejected");
        assert!(matches!(err, SerializationError::InvalidBuffer));
    }

    #[test]
    fn from_bytes_no_header_terminator() {
        // Has CRLFs between lines but never the double \r\n\r\n that ends
        // the header section → InvalidBuffer.
        let raw = b"GET /hello HTTP/1.1\r\nHost: example.com\r\n";

        let err = ParsedHttpRequest::from_bytes(raw, MAX_HEADER_SIZE, MAX_BODY_SIZE)
            .expect_err("missing header terminator should be rejected");
        assert!(matches!(err, SerializationError::InvalidBuffer));
    }

    #[test]
    fn from_bytes_non_utf8_headers() {
        let mut raw = Vec::new();
        raw.extend_from_slice(b"GET /hello HTTP/1.1\r\n");
        raw.extend_from_slice(b"Host: example.com\r\n");
        raw.extend_from_slice(&[0xFF, 0xFE]); // invalid UTF-8 in header area
        raw.extend_from_slice(b"\r\n");
        raw.extend_from_slice(b"\r\n");

        let err = ParsedHttpRequest::from_bytes(&raw, MAX_HEADER_SIZE, MAX_BODY_SIZE)
            .expect_err("non-UTF-8 headers should be rejected");
        assert!(matches!(err, SerializationError::InvalidBuffer));
    }

    #[test]
    fn from_bytes_non_utf8_request_line() {
        let mut raw = Vec::new();
        raw.extend_from_slice(b"GET /hello\xFF\xFE HTTP/1.1\r\n");
        raw.extend_from_slice(b"Host: example.com\r\n");
        raw.extend_from_slice(b"\r\n");

        let err = ParsedHttpRequest::from_bytes(&raw, MAX_HEADER_SIZE, MAX_BODY_SIZE)
            .expect_err("non-UTF-8 request line should be rejected");
        assert!(matches!(err, SerializationError::InvalidRequestLine));
    }

    #[test]
    fn from_bytes_empty_buffer() {
        let raw = b"";

        let err = ParsedHttpRequest::from_bytes(raw, MAX_HEADER_SIZE, MAX_BODY_SIZE)
            .expect_err("empty buffer should be rejected");
        assert!(matches!(err, SerializationError::InvalidBuffer));
    }
}