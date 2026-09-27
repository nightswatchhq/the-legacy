//! One JSON-RPC request per TCP connection. There is no keep-alive and no worker pool.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

use serde_json::Value;

use crate::config::Config;
use crate::rpc::{self, Snapshot};

const HEADER_LIMIT: usize = 64 * 1024;
const BODY_LIMIT: usize = 1024 * 1024;

pub fn serve(config: &Config) -> Result<(), Box<dyn std::error::Error>> {
    let snapshot = Snapshot::open(config)?;
    let listener = TcpListener::bind(&config.bind)?;
    let address = listener.local_addr()?;
    println!("listening {address}");
    println!("mode        sealed-only");
    match snapshot.head() {
        Some(head) => {
            println!("sealed head {head}");
            println!("chain       {}", snapshot.chain_id().unwrap_or(0));
        }
        None => println!("sealed head none"),
    }
    println!("{}", snapshot.checked_line());
    println!("{}", snapshot.not_checked_line());
    println!(
        "note        log bitmaps and hash indexes are rebuilt in memory and are not in the manifest; a hash hit still reads that relic and checks the stored hash"
    );
    let _ = std::io::stdout().flush();

    for connection in listener.incoming() {
        match connection {
            Ok(stream) => {
                if let Err(error) = handle(stream, &snapshot) {
                    eprintln!("solo: {error}");
                }
            }
            Err(error) => eprintln!("solo: {error}"),
        }
    }
    Ok(())
}

fn handle(mut stream: TcpStream, snapshot: &Snapshot) -> Result<(), Box<dyn std::error::Error>> {
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    let (method, body) = read_request(&mut stream)?;
    if method != "POST" {
        write_raw(&mut stream, 405, snapshot.head(), &[])?;
        return Ok(());
    }
    let response = match serde_json::from_slice::<Value>(&body) {
        Ok(value) => rpc::dispatch(snapshot, value),
        Err(_) => rpc::parse_error(),
    };
    write_raw(
        &mut stream,
        200,
        snapshot.head(),
        &serde_json::to_vec(&response)?,
    )?;
    Ok(())
}

fn read_request(stream: &mut TcpStream) -> Result<(String, Vec<u8>), Box<dyn std::error::Error>> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let header_end = loop {
        if buf.len() > HEADER_LIMIT {
            return Err("HTTP headers exceed 64KiB".into());
        }
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            return Err("connection closed before an HTTP request".into());
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(position) = buf.windows(4).position(|window| window == b"\r\n\r\n") {
            break position;
        }
    };
    let header = String::from_utf8_lossy(&buf[..header_end]);
    let method = header
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().next())
        .unwrap_or("")
        .to_string();
    let length = content_length(&header)?;
    if length > BODY_LIMIT {
        return Err("JSON-RPC body exceeds 1MiB".into());
    }
    let mut body = buf[header_end + 4..].to_vec();
    while body.len() < length {
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
    }
    if body.len() < length {
        return Err("truncated JSON-RPC body".into());
    }
    body.truncate(length);
    Ok((method, body))
}

fn content_length(header: &str) -> Result<usize, Box<dyn std::error::Error>> {
    for line in header.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("content-length") {
            return value
                .trim()
                .parse::<usize>()
                .map_err(|_| "Content-Length is not a number".to_string().into());
        }
    }
    Err("POST needs Content-Length".into())
}

fn write_raw(
    stream: &mut TcpStream,
    status: u16,
    head: Option<u64>,
    body: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let reason = if status == 200 {
        "OK"
    } else {
        "Method Not Allowed"
    };
    let mut response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    if let Some(head) = head {
        response.push_str(&format!("X-Legacy-Sealed-Head: {head}\r\n"));
    }
    response.push_str("\r\n");
    stream.write_all(response.as_bytes())?;
    stream.write_all(body)?;
    Ok(())
}
