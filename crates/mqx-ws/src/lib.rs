//! MQTT transport for Mosquitto's built-in WebSocket listener.

mod handshake;
mod stream;

pub use handshake::{WsError, WsOptions, accept};
pub use stream::WsStream;

#[cfg(test)]
mod tests;
