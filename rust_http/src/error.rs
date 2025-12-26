use std::{io, net::AddrParseError};

pub enum SteamPunkError {

}

pub struct HttpError;

#[derive(Debug)]
#[allow(unused)]
pub(crate) struct ServerError {
    msg: String
}

impl From<AddrParseError> for ServerError  {
    fn from (e: AddrParseError) -> ServerError {
        ServerError {
            msg: format!("IP Address for type {e}")
        }
    }
}

impl From<io::Error> for ServerError {
    fn from(e: io::Error) -> ServerError {
        ServerError {
            msg: format!("Unexpected IO Error {e}")
        }
    }
}