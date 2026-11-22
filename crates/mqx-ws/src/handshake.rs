use std::io;
use std::io::Write as _;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use sha1::{Digest, Sha1};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::WsStream;

/// Listener settings for the built-in Mosquitto WebSocket transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WsOptions {
    /// Global Mosquitto `packet_buffer_size` (`websockets_headers_size` is an alias).
    /// One byte is reserved for the NUL terminator.
    pub packet_buffer_size: u16,
    /// Allowed values of the repeatable listener setting `websockets_origin`.
    pub origins: Vec<String>,
}

impl Default for WsOptions {
    fn default() -> Self {
        // src/conf.c: config__init_reload.
        Self {
            packet_buffer_size: 4096,
            origins: Vec::new(),
        }
    }
}

/// Failure to establish the WebSocket transport. No HTTP error is sent.
#[derive(Debug, thiserror::Error)]
pub enum WsError {
    #[error("WebSocket upgrade I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("connection closed before the WebSocket upgrade")]
    Incomplete,
    #[error("WebSocket upgrade exceeds the HTTP header limit")]
    HeaderLimit,
    #[error("invalid HTTP request for WebSocket upgrade")]
    InvalidRequest,
    #[error("missing WebSocket upgrade headers")]
    MissingUpgrade,
    #[error("unsupported WebSocket version")]
    Version,
    #[error("no supported MQTT WebSocket subprotocol")]
    Subprotocol,
    #[error("disallowed WebSocket origin")]
    Origin,
}

/// Accept a WebSocket upgrade. All request paths are eligible; plain HTTP is
/// not served even when a Mosquitto listener is configured with `http_dir`.
pub async fn accept<S>(mut stream: S, options: &WsOptions) -> Result<WsStream<S>, WsError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // src/http_serv.c: http__read. A full packet buffer stays an incomplete
    // request until EOF; there is no response, nor can later input complete it.
    let capacity = usize::from(options.packet_buffer_size);
    if capacity == 0 {
        return Err(WsError::HeaderLimit);
    }
    let mut packet = vec![0; capacity];
    let mut used = 0;
    let mut parsed = 0;
    let mut parser = Request::default();
    let mut upgrade = Upgrade::default();
    let (key, protocol) = 'request: loop {
        let received = stream.read(&mut packet[used..]).await?;
        if received == 0 {
            return Err(WsError::Incomplete);
        }
        packet[capacity - 1] = 0;
        used += packet[used..].iter().position(|&byte| byte == 0).unwrap();
        while parsed < used {
            let i = parsed;
            parsed += 1;
            match parser.read_byte(packet[i], i)? {
                Some(Line::Header(start, end)) => {
                    upgrade.header(&packet[start..end], start, options);
                }
                Some(Line::End) => {
                    // The C check compares against the most recent socket read,
                    // not the total number of request bytes read so far.
                    if parsed < received {
                        return Err(WsError::InvalidRequest);
                    }
                    break 'request upgrade.finish(&packet)?;
                }
                None => {}
            }
        }
        if used == capacity - 1 {
            while stream.read(&mut packet).await? != 0 {}
            return Err(WsError::HeaderLimit);
        }
    };

    // lib/net_ws.c: ws__create_accept_key. The key is hashed as supplied;
    // Mosquitto does not validate the base64 or require a fixed length.
    let mut hash = Sha1::new();
    hash.update(key);
    hash.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    let mut encoded = [0; 28];
    STANDARD
        .encode_slice(hash.finalize(), &mut encoded)
        .unwrap();
    // Only prefixes of ASCII MQTT protocol names are eligible.
    let protocol = std::str::from_utf8(protocol).unwrap();
    let encoded = std::str::from_utf8(&encoded).unwrap();
    let mut response = [0; 192];
    let mut writer = io::Cursor::new(response.as_mut_slice());
    write!(
        writer,
        "HTTP/1.1 101 Switching Protocols\r\n\
         Upgrade: WebSocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Accept: {encoded}\r\n\
         Sec-WebSocket-Protocol: {protocol}\r\n\r\n"
    )
    .unwrap();
    let response_len = writer.position() as usize;
    drop(packet);
    stream.write_all(&response[..response_len]).await?;
    stream.flush().await?;
    Ok(WsStream::new(stream))
}

#[derive(Clone, Copy, Default)]
enum Syntax {
    #[default]
    First,
    Method,
    PathStart,
    Path,
    VersionStart,
    Version(usize),
    HeaderStart,
    Name,
    Value,
}

#[derive(Default)]
struct Request {
    syntax: Syntax,
    cr: bool,
    skipped_empty_line: bool,
    line_start: usize,
    headers: usize,
    get: bool,
    head: bool,
    method_ok: bool,
}

enum Line {
    Header(usize, usize),
    End,
}

impl Request {
    // deps/picohttpparser/picohttpparser.c: parse_request, parse_headers.
    // Keep offsets into the packet buffer as reads arrive, including within a line.
    fn read_byte(&mut self, byte: u8, i: usize) -> Result<Option<Line>, WsError> {
        use Syntax::*;

        const VERSION: &[u8] = b"HTTP/1.";
        if self.cr && byte != b'\n' {
            return Err(WsError::InvalidRequest);
        }
        if matches!(byte, b'\r' | b'\n') {
            let line = match self.syntax {
                First if !self.skipped_empty_line => None,
                Version(8) => None,
                HeaderStart if self.method_ok => Some(Line::End),
                Value => Some(Line::Header(self.line_start, i - usize::from(self.cr))),
                _ => return Err(WsError::InvalidRequest),
            };
            if byte == b'\r' {
                self.cr = true;
                return Ok(None);
            }
            self.cr = false;
            self.line_start = i + 1;
            match self.syntax {
                First => self.skipped_empty_line = true,
                Version(8) | Value => self.syntax = HeaderStart,
                _ => {}
            }
            return Ok(line);
        }

        self.syntax = match self.syntax {
            First if is_token(byte) => {
                self.get = byte == b'G';
                self.head = byte == b'H';
                Method
            }
            Method if is_token(byte) => {
                let j = i - self.line_start;
                self.get &= b"GET".get(j) == Some(&byte);
                self.head &= b"HEAD".get(j) == Some(&byte);
                Method
            }
            // src/http_serv.c: http__read uses a length-limited comparison.
            Method if byte == b' ' => {
                self.method_ok = self.get || self.head;
                PathStart
            }
            PathStart if byte == b' ' => PathStart,
            PathStart | Path if byte > b' ' && byte != 0x7f => Path,
            Path if byte == b' ' => VersionStart,
            VersionStart if byte == b' ' => VersionStart,
            VersionStart if byte == VERSION[0] => Version(1),
            Version(j) if VERSION.get(j) == Some(&byte) => Version(j + 1),
            Version(7) if byte.is_ascii_digit() => Version(8),
            HeaderStart if self.headers == 100 => return Err(WsError::HeaderLimit),
            HeaderStart if is_token(byte) => {
                self.headers += 1;
                Name
            }
            HeaderStart if self.headers != 0 && matches!(byte, b' ' | b'\t') => {
                self.headers += 1;
                Value
            }
            Name if is_token(byte) => Name,
            Name if byte == b':' => Value,
            Value if byte == b'\t' || (byte >= b' ' && byte != 0x7f) => Value,
            _ => return Err(WsError::InvalidRequest),
        };
        Ok(None)
    }
}

fn is_token(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

#[derive(Default)]
struct Upgrade {
    websocket: bool,
    connection: bool,
    key: Option<(usize, usize)>,
    protocol: Option<(usize, usize)>,
    rejection: Option<WsError>,
}

impl Upgrade {
    // src/http_serv.c: http__read. The comparisons use the incoming length,
    // permitting prefixes in header names and select values, and no token list
    // is parsed for Sec-WebSocket-Protocol.
    fn header(&mut self, line: &[u8], offset: usize, options: &WsOptions) {
        if self.rejection.is_some() {
            return;
        }
        let mut start = if matches!(line[0], b' ' | b'\t') {
            0 // picohttpparser represents folded lines with an empty name.
        } else {
            line.iter().position(|&byte| byte == b':').unwrap() + 1
        };
        let name = &line[..start.saturating_sub(1)];
        if start != 0 {
            while matches!(line.get(start), Some(b' ' | b'\t')) {
                start += 1;
            }
        }
        let mut end = line.len();
        while end > start && matches!(line[end - 1], b' ' | b'\t') {
            end -= 1;
        }
        let value = &line[start..end];
        if prefix_ignore_case(name, b"Upgrade") {
            self.websocket |= prefix_ignore_case(value, b"websocket");
        } else if prefix_ignore_case(name, b"Connection") {
            // The final C comparison uses length zero after scanning to end.
            self.connection = true;
        } else if prefix_ignore_case(name, b"Sec-WebSocket-Key") {
            self.key = Some((offset + start, offset + end));
        } else if prefix_ignore_case(name, b"Sec-WebSocket-Version") {
            if value != b"13" {
                self.rejection = Some(WsError::Version);
            }
        } else if prefix_ignore_case(name, b"Sec-WebSocket-Protocol") {
            if b"mqttv3.1".starts_with(value) {
                self.protocol = Some((offset + start, offset + end));
            }
        } else if prefix_ignore_case(name, b"Origin")
            && !options.origins.is_empty()
            && !options
                .origins
                .iter()
                .any(|origin| origin.as_bytes().starts_with(value))
        {
            self.rejection = Some(WsError::Origin);
        }
    }

    fn finish(self, packet: &[u8]) -> Result<(&[u8], &[u8]), WsError> {
        if let Some(error) = self.rejection {
            return Err(error);
        }
        let (p, q) = self.protocol.ok_or(WsError::Subprotocol)?;
        let (i, j) = self.key.ok_or(WsError::MissingUpgrade)?;
        if !self.websocket || !self.connection || i == j {
            return Err(WsError::MissingUpgrade);
        }
        Ok((&packet[i..j], &packet[p..q]))
    }
}

fn prefix_ignore_case(prefix: &[u8], word: &[u8]) -> bool {
    word.get(..prefix.len())
        .is_some_and(|part| part.eq_ignore_ascii_case(prefix))
}
