use std::net::TcpStream;

pub(super) fn handle(stream: &mut TcpStream, buffsize: usize) {
    // the Tcp stream is large here, thus we want to pass it in by reference, and we cant necessarily return it bc of hte lifetimes.
    let mut stream_buffer = vec![0u8; buffsize];

    match std::io::Read::read(stream, &mut stream_buffer) {
        Ok(_) => {
            // parse request, and then somehow route to the write handler
        }
        Err(_) => {}
    };
}
