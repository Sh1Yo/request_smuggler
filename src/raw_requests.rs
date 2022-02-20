use crate::{
    structs::{Config, Response, Connection}
};
use native_tls::TlsConnector;
use std::{
    usize,
    time::{Instant, Duration},
    collections::HashMap,
    net::{ToSocketAddrs, TcpStream},
    error::Error,
    io::{self, Write, Read, ErrorKind},
};
use flate2::read::{GzDecoder};

pub fn make_connection(config: &Config) -> Result<Connection, Box<dyn Error>> {
    if config.https {
        connect_to_https(&config.host, config.port)
    } else {
        connect_to_http(&config.host, config.port)
    }
}

pub fn raw_request(config: &Config, mut stream: Connection, request: &str) -> Result<(Option<Connection>, Response), Box<dyn Error>> {

    if config.verbose > 1 {
        writeln!(io::stdout(), "{}", request).ok();
    }

    //send the actual request and reconnect in case of Broken Pipe error
    stream = match stream.write_all(request.as_bytes()) {
        Ok(()) => stream,
        Err(err) =>  match err.kind() {
            ErrorKind::BrokenPipe => {
                stream = make_connection(&config)?;
                stream.write_all(request.as_bytes())?;
                stream
            }
            _ => return Err(Box::new(err))
        }
    };

    let start = Instant::now();

    //read the first line and try to reconnect in case of closed connection
    let (stream, firstline) = match read_firstline(stream) {
        Ok(val) => match val.1.len() {
            1 => {
                stream = make_connection(&config)?;
                stream.write_all(request.as_bytes())?;
                match read_firstline(stream) {
                    Ok(val) => val,
                    Err(err) => {
                        writeln!(io::stderr(), "{}", err).ok();
                        return Ok((None,
                            Response {
                                time: start.elapsed().as_millis(),
                                code: 0,
                                body: String::new(),
                                http_version: String::from("HTTP/0.0"),
                                headers: HashMap::new()
                            }))
                    }
                }
            },
            _ => val

        },
        Err(err) => {
            writeln!(io::stderr(), "{}", err).ok();
            return Ok((None,
                Response {
                    time: start.elapsed().as_millis(),
                    code: 0,
                    body: String::new(),
                    http_version: String::from("HTTP/0.0"),
                    headers: HashMap::new()
                }))
        }
    };

    let firstline = String::from_utf8_lossy(&firstline[..]);

    let (stream, headers) = match read_headers(stream) {
        Ok(val) => val,
        Err(err) => {
            writeln!(io::stderr(), "{}", err).ok();
            return Ok((None,
                Response {
                    time: start.elapsed().as_millis(),
                    code: 0,
                    body: String::new(),
                    http_version: String::from("HTTP/0.0"),
                    headers: HashMap::new()
                }))
        }
    };

    let (body, stream, duration) = match headers.get("content-length") {
        Some(val) => {
            //get the value of content-length header
            let mut val = val.to_string();
            val.retain(|c| !c.is_whitespace());
            let content_length: usize = val.parse::<usize>()?;

            match read_body(stream, start, content_length) {
                Ok(val) => val,
                Err(err) => {
                    writeln!(io::stderr(), "{}", err).ok();
                    return Ok((None,
                        Response {
                            time: start.elapsed().as_millis(),
                            code: 0,
                            body: String::new(),
                            http_version: String::from("HTTP/0.0"),
                            headers: headers
                        }))
                }
            }
        }
        None => match headers.get("transfer-encoding") {
            Some(val) => {
                if val.contains("chunked") {
                   match read_chunked_body(stream, start) {
                       Ok(val) => val,
                       Err(err) => {
                            writeln!(io::stderr(), "{}", err).ok();
                            return Ok((None,
                                Response {
                                    time: start.elapsed().as_millis(),
                                    code: 0,
                                    body: String::new(),
                                    http_version: String::from("HTTP/0.0"),
                                    headers: headers
                            }))
                       }
                   }
                } else {
                    (Vec::new(), stream, start.elapsed())
                }
            },
            None => (Vec::new(), stream, start.elapsed()),
        }
    };

    if config.verbose > 0 {
        writeln!(io::stdout(), "{:?}, {}ms", firstline.trim(), duration.as_millis()).ok();
        if config.verbose > 1 {
            writeln!(io::stdout(), "------------").ok();
        }
    }

    let mut firstline = firstline.split(' ');
    let http_version = firstline.next().unwrap_or("HTTP/0.0").trim().to_string();
    let code = match firstline.next() {
        Some(val) => val.trim(),
        None => "0",
    };

    let body = match headers.get("content-encoding") {
        Some(val) => decode_body(val, body),
        None => String::from_utf8_lossy(&body).to_string()
    };

    Ok((Some(stream), Response {
        time: duration.as_millis(),
        code: match code.parse::<u16>() {
            Ok(val) => val,
            Err(_) => 0,
        },
        http_version,
        headers,
        body
    }))
}

fn read_firstline(
    mut stream: Connection
) -> Result<(Connection, Vec<u8>), Box<dyn Error>> {
    let mut buffer = [0;1];
    let mut firstline: Vec<u8> = Vec::with_capacity(64);
    let mut crlf: usize = 0;

    loop {

        stream.read(&mut buffer)?;

        if (buffer[0] == 13 || buffer[0] == 10) && firstline.len() > 4  {
            crlf += 1
        } else if crlf != 0 {
            crlf = 0
        }

        firstline.push(buffer[0]);

        if buffer[0] == 0 || crlf == 2 || firstline.len() > 512 {
            break
        }

    }
    Ok((stream, firstline))
}

fn read_headers(
    mut stream: Connection,
) -> Result<(Connection, HashMap<String,String>), Box<dyn Error>> {
    let mut buffer = [0;1];
    let mut headers: Vec<u8> = Vec::new();
    let mut crlf: usize = 0;

    //read headers char by char
    loop {
        stream.read(&mut buffer)?;

        if buffer[0] == 13 || buffer[0] == 10 {
            crlf += 1
        } else if crlf != 0 {
            crlf = 0
        }

        headers.push(buffer[0]);

        if buffer[0] == 0 || crlf == 4 || headers.len() > 32768 {
            break
        }
    }

    let headers = std::str::from_utf8(&headers[..])?.split("\r\n");

    let mut headers_map: HashMap<String, String> = HashMap::new();

    for header in headers {
        //TODO fix Header: https(:)//something
        let header: Vec<&str> = header.split(':').collect();
        if header.len() > 1 {
            headers_map.insert(
                header[0].to_string().to_lowercase(),
                header[1].to_string()
            );
        }
    }
    Ok((stream, headers_map))
}

fn read_body(
    mut stream: Connection,
    start: Instant,
    content_length: usize
) -> Result<(Vec<u8>, Connection, Duration), Box<dyn Error>> {
    let duration: Duration;
    Ok((
        if content_length > 3 {
            //we need to read firstly one byte only in order to get the exact answer time
            let mut first_byte = vec![0;1];
            stream.read_exact(&mut first_byte)?;
            duration = start.elapsed();

            //read the rest of the body
            let mut buffer = vec![0;content_length-1];
            stream.read_exact(&mut buffer)?;
            first_byte.append(&mut buffer);

            first_byte
        } else {
            //content-length is small, read the whole body instead
            let mut buffer = vec![0;content_length];
            stream.read_exact(&mut buffer)?;
            duration = start.elapsed();

            buffer
        }, stream, duration))
}

fn read_chunked_body(
    mut stream: Connection,
    start: Instant,
) -> Result<(Vec<u8>, Connection, Duration), Box<dyn Error>> {
    let mut duration: Option<Duration> = None;
    let mut body: Vec<u8> = Vec::new();

    loop {
        let mut chunk: String = String::new();
        //read crlf chars and the first byte at the start of a body
        loop {
            let mut one_byte = vec![0;1];
            stream.read_exact(&mut one_byte)?;
            if one_byte[0] != 10 && one_byte[0] != 13 {
                chunk.push(one_byte[0] as char);
                break
            }
        }

        match duration {
            Some(_) => (),
            None => duration = Some(start.elapsed()),
        }

        loop { //read the rest of the chunk length
            let mut one_byte = vec![0;1];
            stream.read_exact(&mut one_byte)?;
            if one_byte[0] == 10 || one_byte[0] == 13 { //read the first \r
                stream.read_exact(&mut one_byte)?; //read the next \n
                break
            } else {
                chunk.push(one_byte[0] as char)
            }
        }

        if chunk == "0" || chunk.is_empty() {
            break;
        }

        let chunk = usize::from_str_radix(&chunk, 16)?;
        let mut chunk_of_bytes = vec![0;chunk];
        stream.read_exact(&mut chunk_of_bytes)?;
        body.append(&mut chunk_of_bytes);
    }

    Ok((body, stream, duration.unwrap_or(start.elapsed())))
}

fn decode_body(encoding: &str, body: Vec<u8>) -> String {
    match encoding.trim() {
        "gzip" => {
            let mut d = GzDecoder::new(&body[..]);
            let mut decompressed_body = String::new();
            match d.read_to_string(&mut decompressed_body) {
                Ok(_) => decompressed_body,
                Err(err) => {
                    writeln!(io::stderr(), "{} ({:?}...)", err, &body[0..10]).ok();
                    String::from_utf8_lossy(&body).to_string()
                }
            }
        }
        /*"deflate" => {
            let mut d = DeflateDecoder::new(&body[..]);
            let mut decompressed_body = String::new();
            d.read_to_string(&mut decompressed_body).unwrap();
            decompressed_body
        }*/
        _ => String::from_utf8_lossy(&body).to_string()
    }
}

//for now for testing purposes only
fn _connect_via_proxy(proxy: &str, host: &str, port: usize) -> Result<std::net::TcpStream, Box<dyn Error>> {
    //make CONNECT request to the proxy
    let connect = format!(
        "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\nProxy-Connection: Keep-Alive\r\n\r\n",
        host,
        port,
        host,
        port
    );

    //connect to the proxy
    let mut stream = TcpStream::connect(
        str::replace(
            proxy,
            "http://",
            "",
        )
    )?;

    stream.set_write_timeout(Some(Duration::from_secs(60)))?;
    stream.set_read_timeout(Some(Duration::from_secs(60)))?;

    //send request
    stream.write_all(connect.as_bytes())?;

    //read the answer from the proxy
    let mut buffer = [0;64];
    stream.read(&mut buffer)?;

    // check the answer from the proxy
    let answer = &String::from_utf8_lossy(&buffer);
    if !answer.contains("200") {
        writeln!(io::stderr(), "Got bad answer from the proxy").ok();
        std::process::exit(1)
    }

    Ok(stream)
}

fn connect_to_server(host: &str, port: usize) -> Result<std::net::TcpStream, Box<dyn Error>> {

    let stream = match TcpStream::connect_timeout(
        match &format!(
            "{}:{}",
            host,
            port
        )
        .to_socket_addrs()?
        .next() {
            Some(val) => val,
            None => {
                writeln!(io::stderr(), "Unable to connect to the server").ok();
                std::process::exit(1)
            }
        },
        Duration::from_secs(60)
    )  {
        Ok(val) => val,
        Err(_) => {
            writeln!(io::stderr(), "Unable to connect to the server").ok();
            std::process::exit(1)
        }
    };

    stream.set_read_timeout(Some(Duration::from_secs(60)))?;
    stream.set_write_timeout(Some(Duration::from_secs(60)))?;

    Ok(stream)
}

fn connect_to_http(
    host: &str,
    port: usize
) -> Result<Connection, Box<dyn Error>> {
    let stream = connect_to_server(host, port)?;

    Ok(Connection::Http{stream})
}

fn connect_to_https(
    host: &str,
    port: usize
) -> Result<Connection, Box<dyn Error>> {

    //connector to https
    let connector = TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .build()?;

    let stream = connect_to_server(host, port)?;

    let stream = connector.connect(host, stream)?;

    Ok(Connection::Https{stream})
}
