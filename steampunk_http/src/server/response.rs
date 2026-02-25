use crate::error::HttpError;

pub(crate) struct HttpResponse {
    status_line: String,
    /// One shot build, likely doesnt need HashMap for fast access
    headers: Vec<(String, String)>,
    body: String,
}
