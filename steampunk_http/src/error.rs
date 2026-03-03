use std::{io, net::AddrParseError};

#[derive(Debug)]
pub enum SteamPunkError {
    ServerError(String),
}

impl From<ServerError> for SteamPunkError {
    fn from(e: ServerError) -> Self {
        SteamPunkError::ServerError(e.msg)
    }
}

pub struct HttpError;

impl From<SerializationError> for HttpError {
    fn from(_: SerializationError) -> Self {
        HttpError
    }
}

/// Errors encountered while parsing a raw HTTP request from bytes.
/// Each variant maps to a specific HTTP response status code that should be
/// returned to the client when the error occurs.
pub enum SerializationError {
    /// The raw byte buffer is malformed — missing CRLF terminators, not valid UTF-8,
    /// or otherwise unparseable as an HTTP message. Maps to **400 Bad Request**.
    InvalidBuffer,

    /// The header section (request line + headers) exceeds the server's configured
    /// `max_header_size`. Maps to **431 Request Header Fields Too Large**.
    HeaderTooLarge,

    /// The HTTP version in the request line is syntactically valid (e.g., `HTTP/2.0`)
    /// but not supported by this server. Only HTTP/1.0 and HTTP/1.1 are accepted.
    /// Maps to **505 HTTP Version Not Supported**.
    VersionNotSupported,

    /// The request method is not one of the recognized HTTP methods
    /// (GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS). Maps to **501 Not Implemented**.
    InvalidMethod,

    /// The request line does not contain the required three parts:
    /// `method SP request-target SP HTTP-version`. Maps to **400 Bad Request**.
    InvalidRequestLine,

    /// The request body exceeds the server's configured `max_body_size`.
    /// Maps to **413 Content Too Large** (RFC 9110, Section 15.5.14).
    BodyTooLarge,
}

#[derive(Debug)]
#[allow(unused)]
pub(crate) struct ServerError {
    msg: String,
}

/// Implementation for Server Error when building with a specified IP that is Invalid
/// Invalid IpAddr are `not` supported
impl From<AddrParseError> for ServerError {
    fn from(e: AddrParseError) -> ServerError {
        ServerError {
            msg: format!("IP Address for type {e}"),
        }
    }
}

/// Implementation for ServerError when failing to bind to the TcpListener
/// also accurs when reading events from the TCP listener that are invalid
impl From<io::Error> for ServerError {
    fn from(e: io::Error) -> ServerError {
        ServerError {
            msg: format!("Unexpected IO Error {e}"),
        }
    }
}
