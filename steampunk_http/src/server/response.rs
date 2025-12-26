use crate::error::HttpError;

pub struct HttpResponse {
    status_line: String,
    headers: Vec<(String, String)>,
    body: String,
}

/// The **required response** type by all routed methods in the server.
pub type SteamPunkResponse = Result<HttpResponse, HttpError>;
