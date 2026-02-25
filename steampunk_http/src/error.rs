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

pub struct SerializationError;

#[derive(Debug)]
#[allow(unused)]
pub(crate) struct ServerError {
    msg: String
}



/// Implementation for Server Error when building with a specified IP that is Invalid
/// Invalid IpAddr are `not` supported
impl From<AddrParseError> for ServerError  {
    fn from (e: AddrParseError) -> ServerError {
        ServerError {
            msg: format!("IP Address for type {e}")
        }
    }
}

/// Implementation for ServerError when failing to bind to the TcpListener
/// also accurs when reading events from the TCP listener that are invalid
impl From<io::Error> for ServerError {
    fn from(e: io::Error) -> ServerError {
        ServerError {
            msg: format!("Unexpected IO Error {e}")
        }
    }
}