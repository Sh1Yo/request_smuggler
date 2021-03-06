use std::{
    io::{Write, Read},
    collections::HashMap,
    str::FromStr,
    fmt::{self, Debug}
};


#[derive(Debug, Clone)]
pub struct Response {
    pub time: u128,
    pub code: u16,
    pub http_version: String,
    pub headers: HashMap<String, String>,
    pub body: String
}

impl Response {
    //print the whole response
    pub fn print(&self) -> String {
        let mut text: String = String::new();
        for (k, v) in self.headers.iter() {
            text.push_str(&k);
            text.push(':');
            text.push_str(&v);
            text.push('\n');
        }
        text.push('\n');
        text.push_str(&self.body);
        text
    }

    /*pub fn fix_connection(self, config: &Config) -> Response {
        if self.is_closed() {
            self.reconnect(config)
        } else {
            self
        }
    }*/

    pub fn is_closed(&self) -> bool {
        if self.http_version != "HTTP/1.1" {
            true
        } else {
            match self.headers.get("connection") {
                Some(val) => match val.trim().to_lowercase().as_str() {
                    "close" => true,
                    _ => false
                },
                None => false
            }
        }
    }

    /*fn reconnect(self, config: &Config) -> Response {
        self.stream = make_connection(config).unwrap();
        self
    }*/
}

#[derive(Debug)]
pub enum Connection {
    Http {stream: std::net::TcpStream},
    Https {stream: native_tls::TlsStream<std::net::TcpStream>}
}

impl Connection {
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error> {
        match self {
            Connection::Http {stream} => stream.read(buf),
            Connection::Https {stream} => stream.read(buf)
        }
    }
    pub fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), std::io::Error> {
        match self {
            Connection::Http {stream} => stream.read_exact(buf),
            Connection::Https {stream} => stream.read_exact(buf)
        }
    }
    pub fn write(&mut self, buf: &[u8]) -> Result<usize, std::io::Error>{
        match self {
            Connection::Http {stream} => stream.write(buf),
            Connection::Https {stream} => stream.write(buf)
        }
    }
    pub fn write_all(&mut self, buf: &[u8]) -> Result<(), std::io::Error> {
        match self {
            Connection::Http {stream} => stream.write_all(buf),
            Connection::Https {stream} => stream.write_all(buf)
        }
    }
    pub fn shutdown(&mut self) -> Result<(), std::io::Error> {
        match self {
            Connection::Http {stream} => stream.shutdown(std::net::Shutdown::Both),
            Connection::Https {stream} => stream.shutdown()
        }
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub url: String,
    pub host: String,
    pub path: String,
    pub method: String,
    pub https: bool,
    pub port: usize,
    pub headers: HashMap<String, String>,
    pub attack_types: Vec<AttackType>,
    pub verify: usize,
    pub verbose: usize,
    pub amount_of_payloads: String,
    pub file: String
}

impl Config {
    pub fn print(&self) -> String {
        let mut req = format!("{} {} HTTP/1.1\r\n", self.method, self.path);
        for (k, v) in self.headers.iter() {
            req.push_str(&k);
            req.push_str(": ");
            req.push_str(&v);
            req.push_str("\r\n");
        }
        req
    }
    pub fn custom_print(&self, method: &str, path: &str) -> String {
        let mut req = format!("{} {} HTTP/1.1\r\n", method, path);
        for (k, v) in self.headers.iter() {
            req.push_str(&k);
            req.push_str(": ");
            req.push_str(&v);
            req.push_str("\r\n");
        }
        req
    }
}

#[derive(PartialEq)]
pub enum AttackKind {
    Time,
    Method,
    Path,
    Undefined
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum AttackType {
    ClTeMethod,
    ClTePath,
    ClTeTime,
    ClTe,
    TeClMethod,
    TeClPath,
    TeClTime,
}

impl FromStr for AttackType {

    type Err = ();

    fn from_str(input: &str) -> Result<AttackType, Self::Err> {

        match input.to_lowercase().as_str() {
            "cltemethod"  => Ok(AttackType::ClTeMethod),
            "cltepath"  => Ok(AttackType::ClTePath),
            "cltetime"  => Ok(AttackType::ClTeTime),
            "clte" => Ok(AttackType::ClTe),
            "teclmethod"  => Ok(AttackType::TeClMethod),
            "teclpath"  => Ok(AttackType::TeClPath),
            "tecltime"  => Ok(AttackType::TeClTime),
            _      => Err(()),
        }
    }
}

impl fmt::Display for AttackType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
        // or, alternatively:
        // fmt::Debug::fmt(self, f)
    }
}

impl AttackType {
    pub fn kind(&self) -> AttackKind {
        match self {
            AttackType::ClTeMethod => AttackKind::Method,
            AttackType::TeClMethod => AttackKind::Method,
            AttackType::ClTePath => AttackKind::Path,
            AttackType::TeClPath => AttackKind::Path,
            AttackType::ClTeTime => AttackKind::Time,
            AttackType::TeClTime => AttackKind::Time,
            _ => AttackKind::Undefined
        }
    }
}