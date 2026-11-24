//! Minimal network clients shared by back-ends.

pub(crate) mod http;
pub(crate) mod memcached;
pub(crate) mod resp;

use std::io;

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::TcpStream;

async fn line(stream: &mut BufReader<TcpStream>, buffer: &mut Vec<u8>) -> io::Result<()> {
    buffer.clear();
    stream.read_until(b'\n', buffer).await?;
    if !buffer.ends_with(b"\r\n") {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "missing protocol line ending",
        ));
    }
    buffer.truncate(buffer.len() - 2);
    Ok(())
}

fn protocol_error() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid server response")
}
