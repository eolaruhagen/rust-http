use std::net::{IpAddr, Ipv4Addr, TcpListener};
use crate::error::ServerError;
use std::thread;

const LOCALHOST: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);

pub struct Server {
    max_buffer: u32,
    port: u16,
    ip: IpAddr,
}

impl Default for Server {
    fn default() -> Self {
        Server {
            max_buffer: u32::default(),
            port: 8080,
            ip: IpAddr::V4(LOCALHOST)
        }
    }
}

impl Server {
    pub fn port(&mut self, port: u16) -> &mut Self {
        self.port = port;
        self
    }
    pub fn ip(&mut self, address: &str) -> Result<&mut Self, ServerError> {
        let ip_addr: IpAddr = address.parse()?;
        self.ip = ip_addr;
        Ok(self)
    }
    fn bind(&self) -> Result<TcpListener, ServerError> {
        let full_addr = format!("{}:{}", self.ip, self.port);
        Ok(TcpListener::bind(full_addr)?)
    }
    pub fn with_max_size(&mut self, buffsize: u32) -> &mut Self {
        self.max_buffer = buffsize;
        self
    }

    pub fn run(&mut self) -> Result<(), ServerError> {
        let listener = self.bind()?;

        for byte_stream in listener.incoming() {
            let raw_tcp_stream = byte_stream?;
            thread::spawn(|| {
                super::handler::test_handler();
            });
        }

        Ok(())
    }
}