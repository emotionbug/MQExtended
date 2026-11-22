use std::io;

use bytes::Bytes;
use serde::Serialize;

use crate::{ClusterError, StateMachine};

// 0xc1 is reserved by MessagePack, so untagged schema 1 has no ambiguity.
const TAG: u8 = 0xc1;
pub(crate) fn split<'a>(
    body: &'a [u8],
    kind: &'static str,
) -> Result<(u16, &'a [u8]), ClusterError> {
    match body {
        [TAG, high, low, payload @ ..] => Ok((u16::from_be_bytes([*high, *low]), payload)),
        [TAG, ..] => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("truncated {kind} version"),
        )
        .into()),
        _ => Ok((1, body)),
    }
}

pub(crate) fn encode(value: &impl Serialize, version: u16, tagged: bool) -> io::Result<Bytes> {
    if !tagged {
        return crate::transport::encode(value).map(Bytes::from);
    }
    let [high, low] = version.to_be_bytes();
    let mut body = vec![TAG, high, low];
    rmp_serde::encode::write_named(&mut body, value).map_err(crate::transport::invalid_data)?;
    Ok(body.into())
}

pub(crate) fn check_app<S: StateMachine>(
    kind: &'static str,
    version: u16,
) -> Result<(), ClusterError> {
    if version != 0 && S::supports_version(version) {
        Ok(())
    } else {
        Err(ClusterError::UnsupportedVersion { kind, version })
    }
}

pub(crate) fn command_version<S: StateMachine>(body: &[u8]) -> Result<(u16, &[u8]), ClusterError> {
    let (version, payload) = split(body, "application command")?;
    check_app::<S>("application command", version)?;
    Ok((version, payload))
}

pub(crate) fn command<S: StateMachine>(body: &[u8]) -> Result<S::Command, ClusterError> {
    let (version, payload) = command_version::<S>(body)?;
    S::decode_command(version, payload)
}
