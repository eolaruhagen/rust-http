use super::handler::handler;
use crate::error::ServerError;
use crate::server::handler::test_handler;
use std::thread;
use std::{
    collections::VecDeque,
    net::{IpAddr, Ipv4Addr, TcpListener, TcpStream},
    sync::Mutex,
    thread::Thread,
};

const LOCALHOST: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);

pub struct Server {
    max_buffer: u32,
    port: u16,
    ip: IpAddr,
    workers: usize,
}

impl Default for Server {
    fn default() -> Self {
        Server {
            max_buffer: u32::default(),
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

    pub fn workers(&mut self, num_workers: usize) {
        self.workers = num_workers;
    }

    pub fn run(&mut self) -> Result<(), ServerError> {
        let listener = self.bind()?;

        let pool: ThreadPool = ThreadPool::new(self.workers).spawn(self.workers);

        for stream in listener.incoming() {
            let stream = stream?;
            pool.queue_task(stream);
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
    fn new(workers: usize) -> Self {
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
                    if let Some(mut task) = pool_clone.pop_task() {
                        test_handler();
                    }
                }
            });
        }

        self
    }
}
