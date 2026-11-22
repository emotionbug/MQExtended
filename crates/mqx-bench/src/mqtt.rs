use std::{io, net::SocketAddr, time::Duration};

use bytes::BytesMut;
use mqx_codec::{
    Connect, ConnectReturnCode, DecodeContext, Packet, PacketId, ProtocolVersion, QoS, SubAck,
    Subscribe, SubscribeReturnCode, decode, encode,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::{Instant, timeout},
};

use crate::Error;

pub(crate) const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const CONTEXT: DecodeContext = DecodeContext::for_client(0, Some(ProtocolVersion::V311));

pub(crate) struct Client {
    stream: TcpStream,
    read: BytesMut,
    write: BytesMut,
}

impl Client {
    pub(crate) async fn connect(
        address: SocketAddr,
        client_id: String,
        clean_session: bool,
    ) -> Result<(Self, Duration, bool), Error> {
        let start = Instant::now();
        timeout(HANDSHAKE_TIMEOUT, async {
            let stream = TcpStream::connect(address).await?;
            stream.set_nodelay(true)?;
            let mut client = Self {
                stream,
                read: BytesMut::with_capacity(4096),
                write: BytesMut::with_capacity(4096),
            };
            client
                .send(&Packet::Connect(Connect {
                    protocol: ProtocolVersion::V311,
                    is_bridge: false,
                    clean_session,
                    keep_alive: 0,
                    client_id,
                    will: None,
                    username: None,
                    password: None,
                }))
                .await?;
            match client.recv().await? {
                Packet::ConnAck(ack) if ack.code == ConnectReturnCode::Accepted => {
                    Ok((client, start.elapsed(), ack.session_present))
                }
                _ => Err(Error::Protocol(
                    "CONNECT did not receive a successful CONNACK",
                )),
            }
        })
        .await
        .map_err(|_| Error::Timeout("connecting an MQTT client"))?
    }

    pub(crate) async fn subscribe(&mut self, filter: String, qos: QoS) -> Result<(), Error> {
        let packet_id = PacketId::MIN;
        timeout(HANDSHAKE_TIMEOUT, async {
            self.send(&Packet::Subscribe(Subscribe {
                packet_id,
                filters: vec![(filter, qos)],
            }))
            .await?;
            match self.recv().await? {
                Packet::SubAck(SubAck {
                    packet_id: id,
                    return_codes,
                }) if id == packet_id && return_codes == [SubscribeReturnCode::Success(qos)] => {
                    Ok(())
                }
                _ => Err(Error::Protocol(
                    "SUBSCRIBE did not receive the requested QoS",
                )),
            }
        })
        .await
        .map_err(|_| Error::Timeout("registering a subscription"))?
    }

    pub(crate) fn queue(&mut self, packet: &Packet) -> Result<(), Error> {
        encode(packet, &mut self.write)?;
        Ok(())
    }

    pub(crate) async fn flush(&mut self) -> Result<(), Error> {
        self.stream.write_all(&self.write).await?;
        self.write.clear();
        Ok(())
    }

    pub(crate) async fn send(&mut self, packet: &Packet) -> Result<(), Error> {
        self.queue(packet)?;
        self.flush().await
    }

    // read_buf is cancellation-safe, so publishers can race reads against pacing timers.
    pub(crate) async fn recv(&mut self) -> Result<Packet, Error> {
        loop {
            if let Some(packet) = decode(&mut self.read, CONTEXT)? {
                return Ok(packet);
            }
            if self.stream.read_buf(&mut self.read).await? == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "broker closed MQTT connection",
                )
                .into());
            }
        }
    }

    pub(crate) async fn disconnect(&mut self) -> Result<(), Error> {
        timeout(HANDSHAKE_TIMEOUT, self.send(&Packet::Disconnect))
            .await
            .map_err(|_| Error::Timeout("disconnecting an MQTT client"))?
    }
}
