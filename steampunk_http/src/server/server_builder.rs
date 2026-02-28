use crate::error::{ServerError, SteamPunkError};
use std::{
    collections::VecDeque,
    net::{IpAddr, Ipv4Addr, TcpListener, TcpStream},
};

const LOCALHOST: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);

pub struct Server {
    max_header_size: u32,
    max_body_size: u32,
    port: u16,
    ip: IpAddr,
    workers: usize,
}

impl Default for Server {
    fn default() -> Self {
        Server {
            max_header_size: u32::default(),
            max_body_size: u32::default(),
            port: 8080,
            ip: IpAddr::V4(LOCALHOST),
            workers: 1,
        }
    }
}

impl Server {
    pub fn port(&mut self, port: u16) -> &mut Self {
        self.port = port;
        self
    }
    pub fn ip(&mut self, address: &str) -> Result<&mut Self, SteamPunkError> {
        let ip_addr: IpAddr = address.parse().map_err(ServerError::from)?;
        self.ip = ip_addr;
        Ok(self)
    }
    fn bind(&self) -> Result<TcpListener, ServerError> {
        let full_addr = format!("{}:{}", self.ip, self.port);
        Ok(TcpListener::bind(full_addr)?)
    }
    pub fn with_max_header_size(&mut self, max_header_size: u32) -> &mut Self {
        self.max_header_size = max_header_size;
        self
    }
    pub fn with_max_body_size(&mut self, max_body_size: u32) -> &mut Self {
        self.max_body_size = max_body_size;
        self
    }

    pub fn workers(&mut self, num_workers: usize) {
        self.workers = num_workers;
    }

    pub fn run(&mut self) -> Result<(), SteamPunkError> {
        let listener = self.bind()?;

        let pool: ThreadPool = ThreadPool::new().spawn(self.workers);

        for stream in listener.incoming() {
            match stream {
                Ok(s) => pool.queue_task(s),
                Err(e) => {
                    eprintln!("Failed to accept connection: {e}");
                }
            };
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct ThreadPool {
    workers_queue: WorkerDequeue,
}

#[derive(Clone)]
struct WorkerDequeue(std::sync::Arc<std::sync::Mutex<VecDeque<TcpStream>>>);

impl WorkerDequeue {
    fn new() -> Self {
        WorkerDequeue(std::sync::Arc::new(std::sync::Mutex::new(VecDeque::new())))
    }
    /// Uses a blocking lock, which means until it can aqquire the Mutex, *nothing hapens*.
    fn pop_task(&self) -> Option<TcpStream> {
        self.0.lock().unwrap().pop_front()
    }

    /// Uses a blocking lock, which means until it can aqquire the Mutex, *nothing hapens*.
    fn add_task(&self, task: TcpStream) {
        self.0.lock().unwrap().push_back(task);
    }
}

impl ThreadPool {
    fn new() -> Self {
        ThreadPool {
            workers_queue: WorkerDequeue::new(),
        }
    }

    fn queue_task(&self, task: TcpStream) {
        self.workers_queue.add_task(task);
    }

    fn spawn(self, workers: usize) -> Self {
        for i in 0..workers {
            let pool_clone = self.workers_queue.clone();
            std::thread::spawn(move || {
                println!("Spawning worker {i}");
                loop {
                    if let Some(mut task) = pool_clone.pop_task() {}
                }
            });
        }

        self
    }
}
