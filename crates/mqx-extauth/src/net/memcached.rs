use std::io;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

use super::{line, protocol_error};

const TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) struct Connection {
    socket: BufReader<TcpStream>,
    buffer: Vec<u8>,
}

impl Connection {
    pub(crate) async fn connect(host: &str, port: u16, probe: bool) -> io::Result<Self> {
        tokio::time::timeout(TIMEOUT, async {
            let socket = TcpStream::connect((host, port)).await?;
            let mut connection = Self {
                socket: BufReader::new(socket),
                buffer: Vec::new(),
            };
            if !probe {
                return Ok(connection);
            }
            // be-memcached.c: be_memcached_reconnect probes using memcached_stat.
            connection.socket.write_all(b"stats\r\n").await?;
            loop {
                line(&mut connection.socket, &mut connection.buffer).await?;
                if connection.buffer == b"END" {
                    return Ok(connection);
                }
                if !connection.buffer.starts_with(b"STAT ") {
                    return Err(protocol_error());
                }
            }
        })
        .await?
    }

    pub(crate) async fn get(&mut self, key: &[u8]) -> io::Result<Option<Vec<u8>>> {
        if key.is_empty() || key.len() > 250 || key.iter().any(|&b| b <= b' ' || b == 0x7f) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid memcached key",
            ));
        }
        tokio::time::timeout(TIMEOUT, self.get_value(key)).await?
    }

    async fn get_value(&mut self, key: &[u8]) -> io::Result<Option<Vec<u8>>> {
        self.buffer.clear();
        self.buffer.extend_from_slice(b"get ");
        self.buffer.extend_from_slice(key);
        self.buffer.extend_from_slice(b"\r\n");
        self.socket.write_all(&self.buffer).await?;
        line(&mut self.socket, &mut self.buffer).await?;
        if self.buffer == b"END" {
            return Ok(None);
        }
        let mut fields = self.buffer.split(|&b| b == b' ');
        if fields.next() != Some(b"VALUE") || fields.next() != Some(key) {
            return Err(protocol_error());
        }
        let _flags = fields.next().ok_or_else(protocol_error)?;
        let length: usize = fields
            .next()
            .and_then(|bytes| std::str::from_utf8(bytes).ok())
            .and_then(|n| n.parse().ok())
            .ok_or_else(protocol_error)?;
        let mut value = Vec::new();
        if (&mut self.socket)
            .take(length as u64)
            .read_to_end(&mut value)
            .await?
            != length
        {
            return Err(protocol_error());
        }
        let mut ending = [0; 7];
        self.socket.read_exact(&mut ending).await?;
        if ending != *b"\r\nEND\r\n" {
            return Err(protocol_error());
        }
        Ok(Some(value))
    }
}
