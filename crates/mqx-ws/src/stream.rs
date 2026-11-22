use std::io::{self, IoSlice};
use std::pin::Pin;
use std::task::{Context, Poll, Waker, ready};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

// lib/net_ws.c: net__read_ws limits frames to MQTT_MAX_PAYLOAD, not messages.
const MAX_FRAME: usize = 268_435_455;
const MAX_CONTROL: usize = 125;
const POLL_STEPS: usize = 64;
const CONTINUATION: u8 = 0;
const BINARY: u8 = 2;
const CLOSE: u8 = 8;
const PING: u8 = 9;
const PONG: u8 = 10;

/// An upgraded connection carrying MQTT bytes. Binary and continuation frames
/// contribute bytes to the stream; WebSocket control frames are handled here.
/// Flush after writing if delivery is needed before the next write.
#[derive(Debug)]
pub struct WsStream<S> {
    io: S,
    input: Input,
    output: Output,
    read_error: Option<&'static str>,
    closing: bool,
    closed: bool,
}

impl<S> WsStream<S> {
    pub(crate) fn new(io: S) -> Self {
        Self {
            io,
            input: Input::default(),
            output: Output::default(),
            read_error: None,
            closing: false,
            closed: false,
        }
    }
}

#[derive(Debug, Default)]
struct Input {
    header: [u8; 14],
    used: usize,
    mask: [u8; 4],
    frame: Option<Frame>,
}

#[derive(Debug, Clone, Copy)]
struct Frame {
    opcode: u8,
    len: usize,
    pos: usize,
}

impl Frame {
    fn remaining(self) -> usize {
        self.len - self.pos
    }

    fn unmask(self, data: &mut [u8], mask: [u8; 4]) {
        if mask != [0; 4] {
            for (i, byte) in data.iter_mut().enumerate() {
                *byte ^= mask[(i + self.pos) & 3];
            }
        }
    }
}

#[derive(Debug)]
struct FrameError {
    code: u8,
    message: &'static str,
}

impl FrameError {
    fn protocol(message: &'static str) -> Self {
        Self {
            code: 0xea,
            message,
        }
    }
}

impl Input {
    // lib/net_ws.c: read_ws_opcode, read_ws_payloadlen_{short,extended},
    // read_ws_mask, net__read_ws. FIN is only checked for control frames.
    fn parse(&mut self) -> Result<usize, FrameError> {
        if self.used == 0 {
            return Ok(1);
        }
        let first = self.header[0];
        let opcode = first & 0x0f;
        if first & 0x70 != 0 {
            return Err(FrameError::protocol("reserved WebSocket bits are set"));
        }
        match opcode {
            CONTINUATION | BINARY | CLOSE | PING | PONG => {}
            1 => {
                return Err(FrameError {
                    code: 0xeb,
                    message: "text WebSocket frames cannot carry MQTT",
                });
            }
            _ => return Err(FrameError::protocol("invalid WebSocket opcode")),
        }
        if opcode & 8 != 0 && first & 0x80 == 0 {
            return Err(FrameError::protocol("fragmented WebSocket control frame"));
        }
        if self.used == 1 {
            return Ok(2);
        }
        let second = self.header[1];
        let masked = second & 0x80 != 0;
        let short = second & 0x7f;
        let ext = match short {
            126 => 2,
            127 => 8,
            _ => 0,
        };
        let mask_pos = 2 + ext;
        let needed = mask_pos + if masked { 4 } else { 0 };
        if self.used < needed {
            return Ok(needed);
        }
        let len = match ext {
            2 => u64::from(u16::from_be_bytes(self.header[2..4].try_into().unwrap())),
            8 => u64::from_be_bytes(self.header[2..10].try_into().unwrap()),
            _ => u64::from(short),
        };
        if masked {
            self.mask.copy_from_slice(&self.header[mask_pos..needed]);
        }
        // An unmasked frame still uses the previous masking key (initially zero).
        if opcode == CLOSE && len == 1 {
            return Err(FrameError::protocol("one-byte WebSocket close payload"));
        }
        if opcode >= CLOSE && len > MAX_CONTROL as u64 {
            return Err(FrameError::protocol("oversized WebSocket control frame"));
        }
        if len > MAX_FRAME as u64 {
            return Err(FrameError {
                code: 0xe8,
                message: "WebSocket frame exceeds the MQTT payload limit",
            });
        }
        self.frame = Some(Frame {
            opcode,
            len: len as usize,
            pos: 0,
        });
        Ok(needed)
    }

    fn finish(&mut self) {
        self.used = 0;
        self.frame = None;
    }
}

#[derive(Debug)]
struct Output {
    tail: Vec<u8>,
    tail_pos: usize,
    control: [u8; MAX_CONTROL + 2],
    control_len: usize,
    control_pos: usize,
    reader: Option<Waker>,
    writer: Option<Waker>,
}

impl Default for Output {
    fn default() -> Self {
        Self {
            tail: Vec::new(),
            tail_pos: 0,
            control: [0; MAX_CONTROL + 2],
            control_len: 0,
            control_pos: 0,
            reader: None,
            writer: None,
        }
    }
}

impl Output {
    fn queue_control(&mut self, opcode: u8, len: usize) {
        self.control[..2].copy_from_slice(&[0x80 | opcode, len as u8]);
        self.control_len = len + 2;
        self.control_pos = 0;
    }

    // src/context.c: context__disconnect sends the server's reason, not the
    // peer's close payload. The high byte of its close codes is always 0x03.
    fn queue_close(&mut self, code: u8) {
        self.control[2..4].copy_from_slice(&[0x03, code]);
        self.queue_control(CLOSE, 2);
    }

    // The reader can write protocol replies. When split, the reader and writer
    // may replace each other's write waker on the underlying stream.
    fn observe<T>(&mut self, cx: &Context<'_>, read: bool, status: Poll<T>) -> Poll<T> {
        let (own, other) = if read {
            (&mut self.reader, &mut self.writer)
        } else {
            (&mut self.writer, &mut self.reader)
        };
        if status.is_pending() {
            if !own
                .as_ref()
                .is_some_and(|waker| waker.will_wake(cx.waker()))
            {
                *own = Some(cx.waker().clone());
            }
        } else {
            own.take();
            if let Some(waker) = other.take() {
                waker.wake();
            }
        }
        status
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for WsStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        for _ in 0..POLL_STEPS {
            if let Some(error) = this.read_error {
                // Mosquitto makes a best-effort attempt to send a close frame
                // before dropping the connection. Keep the framing error if
                // this peer is already gone and the close cannot be sent.
                let _ = ready!(this.poll_output(cx, true, false));
                return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, error)));
            }
            if this.output.control_len != 0 || (this.closing && !this.closed) {
                ready!(this.poll_output(cx, true, false))?;
            }
            if this.input.frame.is_none() {
                match this.input.parse() {
                    Ok(needed) if this.input.used < needed => {
                        let n = ready!(poll_read_slice(
                            &mut this.io,
                            cx,
                            &mut this.input.header[this.input.used..needed],
                        ))?;
                        if n == 0 {
                            return Poll::Ready(if this.input.used == 0 {
                                Ok(())
                            } else {
                                Err(truncated())
                            });
                        }
                        this.input.used += n;
                        continue;
                    }
                    Ok(_) => {}
                    Err(error) => {
                        this.read_error = Some(error.message);
                        if !this.closing {
                            this.closing = true;
                            this.output.queue_close(error.code);
                        }
                        continue;
                    }
                }
            }
            let frame = this.input.frame.as_mut().unwrap();
            if frame.opcode < CLOSE {
                if frame.remaining() == 0 {
                    this.input.finish();
                    continue;
                }
                let before = buf.filled().len();
                let n = if frame.remaining() >= buf.remaining() {
                    ready!(Pin::new(&mut this.io).poll_read(cx, buf))?;
                    buf.filled().len() - before
                } else {
                    let n = ready!(poll_read_slice(
                        &mut this.io,
                        cx,
                        buf.initialize_unfilled_to(frame.remaining()),
                    ))?;
                    buf.advance(n);
                    n
                };
                if n == 0 {
                    return Poll::Ready(Err(truncated()));
                }
                frame.unmask(&mut buf.filled_mut()[before..], this.input.mask);
                frame.pos += n;
                if frame.remaining() == 0 {
                    this.input.finish();
                }
                return Poll::Ready(Ok(()));
            }

            // lib/net_ws.c: net__read_ws ignores pong and close (even peer
            // close does not end the MQTT stream) and echoes ping as pong.
            if frame.remaining() != 0 {
                let body = &mut this.output.control[2 + frame.pos..2 + frame.len];
                let n = ready!(poll_read_slice(&mut this.io, cx, body))?;
                if n == 0 {
                    return Poll::Ready(Err(truncated()));
                }
                if frame.opcode == PING {
                    frame.unmask(&mut body[..n], this.input.mask);
                }
                frame.pos += n;
                if frame.remaining() != 0 {
                    continue;
                }
            }
            if frame.opcode == PING && !this.closing {
                this.output.queue_control(PONG, frame.len);
            }
            this.input.finish();
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

impl<S: AsyncWrite + Unpin> WsStream<S> {
    fn poll_output(
        &mut self,
        cx: &mut Context<'_>,
        read: bool,
        flush: bool,
    ) -> Poll<io::Result<()>> {
        let status = self.poll_drain(cx, flush);
        self.output.observe(cx, read, status)
    }

    fn poll_drain(&mut self, cx: &mut Context<'_>, flush: bool) -> Poll<io::Result<()>> {
        let output = &mut self.output;
        for _ in 0..POLL_STEPS {
            if output.tail_pos < output.tail.len() {
                output.tail_pos += ready!(poll_nonzero_write(
                    &mut self.io,
                    cx,
                    &output.tail[output.tail_pos..],
                ))?;
            } else if output.control_len != 0 {
                if output.control_pos < output.control_len {
                    output.control_pos += ready!(poll_nonzero_write(
                        &mut self.io,
                        cx,
                        &output.control[output.control_pos..output.control_len],
                    ))?;
                } else {
                    ready!(Pin::new(&mut self.io).poll_flush(cx))?;
                    output.control_len = 0;
                }
            } else {
                output.tail.clear();
                output.tail_pos = 0;
                if self.closing && !self.closed {
                    ready!(Pin::new(&mut self.io).poll_shutdown(cx))?;
                    self.closed = true;
                } else if flush && !self.closed {
                    ready!(Pin::new(&mut self.io).poll_flush(cx))?;
                }
                return Poll::Ready(Ok(()));
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for WsStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if this.closing {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        ready!(this.poll_output(cx, false, false))?;
        let data = &buf[..buf.len().min(MAX_FRAME)];
        let mut header_buf = [0; 10];
        let header = binary_header(&mut header_buf, data.len());
        let vectored = this.io.is_write_vectored();
        let start = if vectored {
            Pin::new(&mut this.io)
                .poll_write_vectored(cx, &[IoSlice::new(header), IoSlice::new(data)])
        } else {
            Pin::new(&mut this.io).poll_write(cx, header)
        };
        let start = ready!(this.output.observe(cx, false, start))?;
        if start == 0 {
            return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
        }
        let mut sent_data = start.saturating_sub(header.len());
        if !vectored && start == header.len() {
            match poll_nonzero_write(&mut this.io, cx, data) {
                Poll::Ready(result) => sent_data = result?,
                Poll::Pending => {}
            }
        }
        // A partially written frame commits these bytes even if the caller
        // cancels its write. Only retain the unsent part of the frame.
        let unsent_header = &header[start.min(header.len())..];
        let unsent_data = &data[sent_data..];
        this.output
            .tail
            .reserve(unsent_header.len() + unsent_data.len());
        this.output.tail.extend_from_slice(unsent_header);
        this.output.tail.extend_from_slice(unsent_data);
        Poll::Ready(Ok(data.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().poll_output(cx, false, true)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.closing {
            ready!(this.poll_output(cx, false, false))?;
            this.closing = true;
            this.output.queue_close(0xe8);
        }
        this.poll_output(cx, false, false)
    }
}

// lib/net_ws.c: ws__prepare_packet. The server sends unmasked FIN binary frames.
fn binary_header(out: &mut [u8; 10], len: usize) -> &[u8] {
    out[0] = 0x80 | BINARY;
    match len {
        0..=125 => {
            out[1] = len as u8;
            &out[..2]
        }
        126..=65_535 => {
            out[1] = 126;
            out[2..4].copy_from_slice(&(len as u16).to_be_bytes());
            &out[..4]
        }
        _ => {
            out[1] = 127;
            out[2..].copy_from_slice(&(len as u64).to_be_bytes());
            out
        }
    }
}

fn poll_read_slice<S: AsyncRead + Unpin>(
    io: &mut S,
    cx: &mut Context<'_>,
    buf: &mut [u8],
) -> Poll<io::Result<usize>> {
    let mut buf = ReadBuf::new(buf);
    ready!(Pin::new(io).poll_read(cx, &mut buf))?;
    Poll::Ready(Ok(buf.filled().len()))
}

fn poll_nonzero_write<S: AsyncWrite + Unpin>(
    io: &mut S,
    cx: &mut Context<'_>,
    data: &[u8],
) -> Poll<io::Result<usize>> {
    match ready!(Pin::new(io).poll_write(cx, data))? {
        0 => Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
        n => Poll::Ready(Ok(n)),
    }
}

fn truncated() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "truncated WebSocket frame")
}
