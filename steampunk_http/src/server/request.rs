use std::collections::HashMap;

use crate::error::HttpError;

pub struct HttpResponse {
    status_line: String,
    /// One shot build, likely doesnt need HashMap for fast access
    headers: Vec<(String, String)>,
    body: String,
}

pub struct HttpRequest<'a> {
    http_version: &'a str,
    method: &'a str,
    path: &'a str,
    headers: HashMap<&'a str, &'a str>,
}

pub type HttpBody = String;

/// The **required response** type by all routed methods in the server.
pub type SteamPunkResponse = Result<HttpResponse, HttpError>;
