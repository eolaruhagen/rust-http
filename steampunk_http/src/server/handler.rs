use std::{collections::VecDeque, io::Read, net::TcpStream};

use crate::server::request::{HttpResponse, SteamPunkResponse};

pub(crate) fn test_handler() {
    println!("pong!");
}

pub(crate) fn handler(request: &mut TcpStream) {
    // first pre parse headers such as method, path, and body
    // and content length
    let mut buffer = [0; 1024];
    request.read(&mut buffer);
    //
}
