pub mod server;
pub mod error;

fn main() {
    println!("Hello, world!");

    server::server_builder::Server::default()
        .port(8080)
        .with_max_header_size(2048)
        .with_max_body_size(2048)
        .run()
        .expect("Failed to start server");
}