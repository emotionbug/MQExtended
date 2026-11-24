use std::io::{self, Write as _};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

use super::{line, protocol_error};

pub(crate) struct Connection {
    socket: BufReader<TcpStream>,
    buffer: Vec<u8>,
}

impl Connection {
    pub(crate) async fn connect(host: &str, port: u16) -> io::Result<Self> {
        // be-redis.c: be_redis_reconnect uses a connect timeout, not a
        // read/write timeout for AUTH, SELECT, or subsequent commands.
        let socket = tokio::time::timeout(
            Duration::from_millis(2500),
            TcpStream::connect((host, port)),
        )
        .await??;
        Ok(Self {
            socket: BufReader::new(socket),
            buffer: Vec::new(),
        })
    }

    pub(crate) async fn command(
        &mut self,
        arguments: &[impl AsRef<[u8]>],
    ) -> io::Result<Option<Vec<u8>>> {
        self.buffer.clear();
        write!(self.buffer, "*{}\r\n", arguments.len())?;
        for arg in arguments {
            let arg = arg.as_ref();
            write!(self.buffer, "${}\r\n", arg.len())?;
            self.buffer.extend_from_slice(arg);
            self.buffer.extend_from_slice(b"\r\n");
        }
        self.socket.write_all(&self.buffer).await?;
        self.reply().await
    }

    async fn reply(&mut self) -> io::Result<Option<Vec<u8>>> {
        let mut unread = 1usize;
        let mut top = true;
        // hiredis returns an ordinary reply object on Redis command errors,
        // arrays, integers, and status replies. None of these is a STRING.
        while unread > 0 {
            unread -= 1;
            line(&mut self.socket, &mut self.buffer).await?;
            let (kind, data) = self.buffer.split_first().ok_or_else(protocol_error)?;
            match kind {
                b'$' => {
                    if let Some(count) = count(data)? {
                        if top {
                            let mut value = Vec::new();
                            // Do not allocate a server-declared length before it arrives.
                            if (&mut self.socket)
                                .take(count as u64)
                                .read_to_end(&mut value)
                                .await?
                                != count
                            {
                                return Err(protocol_error());
                            }
                            self.end_of_bulk().await?;
                            return Ok(Some(value));
                        }
                        if tokio::io::copy(
                            &mut (&mut self.socket).take(count as u64),
                            &mut tokio::io::sink(),
                        )
                        .await?
                            != count as u64
                        {
                            return Err(protocol_error());
                        }
                        self.end_of_bulk().await?;
                    }
                }
                b'*' => {
                    unread = unread
                        .checked_add(count(data)?.unwrap_or_default())
                        .ok_or_else(protocol_error)?;
                }
                b':' => {
                    std::str::from_utf8(data)
                        .ok()
                        .and_then(|num| num.parse::<i64>().ok())
                        .ok_or_else(protocol_error)?;
                }
                b'+' | b'-' => (),
                _ => return Err(protocol_error()),
            }
            top = false;
        }
        Ok(None)
    }

    async fn end_of_bulk(&mut self) -> io::Result<()> {
        let mut ending = [0; 2];
        self.socket.read_exact(&mut ending).await?;
        if ending != *b"\r\n" {
            return Err(protocol_error());
        }
        Ok(())
    }
}

fn count(bytes: &[u8]) -> io::Result<Option<usize>> {
    if bytes == b"-1" {
        Ok(None)
    } else {
        std::str::from_utf8(bytes)
            .ok()
            .and_then(|num| num.parse().ok())
            .map(Some)
            .ok_or_else(protocol_error)
    }
}
