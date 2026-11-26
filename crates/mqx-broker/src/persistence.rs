//! Standalone snapshots and read-only migration from Mosquitto.

mod mosquitto;

use std::{
    fs::File,
    io::{self, BufReader, BufWriter, Read, Write},
    path::Path,
    sync::Arc,
    time::Duration,
};

use bytes::{Buf, Bytes};
use mqx_codec::{PacketId, QoS};
use serde::{Deserialize, Serialize};

use crate::{
    inbox::{Message, Publisher},
    state::BridgeState,
};

const HEADER: &[u8] = b"MQXPERSIST\0\x01";

/// MQTT data that survives a broker process restart, without process or Raft ownership.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PersistentState {
    pub(crate) messages: Vec<Arc<Message>>,
    pub(crate) retained: Vec<usize>,
    pub(crate) sessions: Vec<PersistentSession>,
    // Import provenance is local; the Raft import command identifies it on replay.
    #[serde(skip)]
    pub(crate) from_mosquitto: bool,
    // Sparse entries keyed by position in `retained`, in position order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) retained_store_times: Vec<(usize, Duration)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PersistentSession {
    pub(crate) publisher: Publisher,
    pub(crate) last_mid: u16,
    pub(crate) expiry_interval: Option<u32>,
    pub(crate) expires: Option<Duration>,
    pub(crate) bridge: Option<BridgeState>,
    pub(crate) subscriptions: Vec<PersistentSubscription>,
    pub(crate) outgoing: Vec<PersistentOutgoing>,
    pub(crate) incoming: Vec<(PacketId, usize)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PersistentSubscription {
    pub(crate) filter: Arc<str>,
    pub(crate) order: u64,
    pub(crate) qos: QoS,
    pub(crate) no_local: bool,
    pub(crate) retain_as_published: bool,
    pub(crate) identifier: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PersistentOutgoing {
    pub(crate) message: usize,
    pub(crate) id: Option<PacketId>,
    pub(crate) qos: QoS,
    pub(crate) retain: bool,
    pub(crate) dup: bool,
    pub(crate) release: bool,
    pub(crate) queued: bool,
    pub(crate) identifier: u32,
}

/// Counts in a restored persistence image, before applying current expiry policy.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistenceCounts {
    pub messages: usize,
    pub retained: usize,
    pub sessions: usize,
    pub subscriptions: usize,
    pub client_messages: usize,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub(crate) struct PendingImport {
    pub(crate) length: usize,
    pub(crate) parts: Vec<Bytes>,
}

impl PendingImport {
    pub(crate) fn decode(self) -> io::Result<PersistentState> {
        let mut reader = ImportReader {
            parts: self.parts.into_iter(),
            current: Bytes::new(),
        };
        let image: PersistentState = rmp_serde::from_read(&mut reader).map_err(invalid)?;
        if reader.read(&mut [0])? != 0 {
            return Err(invalid("trailing data in replicated persistence import"));
        }
        image.validate()?;
        Ok(image)
    }
}

struct ImportReader {
    parts: std::vec::IntoIter<Bytes>,
    current: Bytes,
}

impl Read for ImportReader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        while self.current.is_empty() {
            let Some(next) = self.parts.next() else {
                return Ok(0);
            };
            self.current = next;
        }
        let count = self.current.len().min(output.len());
        self.current.copy_to_slice(&mut output[..count]);
        Ok(count)
    }
}

impl PersistentState {
    pub fn counts(&self) -> PersistenceCounts {
        PersistenceCounts {
            messages: self.messages.len(),
            retained: self.retained.len(),
            sessions: self.sessions.len(),
            subscriptions: self.sessions.iter().map(|s| s.subscriptions.len()).sum(),
            client_messages: self
                .sessions
                .iter()
                .map(|s| s.incoming.len() + s.outgoing.len())
                .sum(),
        }
    }

    pub fn read_snapshot(path: &Path) -> io::Result<Option<Self>> {
        let Some(file) = open_database(path)? else {
            return Ok(None);
        };
        let mut reader = BufReader::new(file);
        let mut header = [0; HEADER.len()];
        reader.read_exact(&mut header)?;
        if header != HEADER {
            return Err(invalid(
                "unrecognised MQExtended persistence header or version",
            ));
        }
        let state: Self = rmp_serde::from_read(&mut reader).map_err(invalid)?;
        if reader.read(&mut [0])? != 0 {
            return Err(invalid("trailing data in MQExtended persistence file"));
        }
        state.validate()?;
        Ok(Some(state))
    }

    /// Does not change the source DB. Listener ports resolve to stable security IDs.
    pub fn read_mosquitto(
        path: &Path,
        security_id: impl Fn(u16) -> u64,
    ) -> io::Result<Option<Self>> {
        let Some(file) = open_database(path)? else {
            return Ok(None);
        };
        let mut state = mosquitto::read(BufReader::new(file), security_id)?;
        state.from_mosquitto = true;
        Ok(Some(state))
    }

    /// libcommon/file_common.c: mosquitto_write_file preserves the previous
    /// database until the replacement has been written and synced.
    pub fn write_snapshot(&self, path: &Path) -> io::Result<()> {
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        // libcommon/file_common.c: mosquitto_write_file unlinks a fixed
        // staging name before opening it, since it may alias the live image.
        // Exclusive creation prevents following a newly appeared symlink.
        let mut name = path
            .file_name()
            .ok_or(io::ErrorKind::InvalidInput)?
            .to_os_string();
        name.push(".new");
        match std::fs::remove_file(parent.join(&name)) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let mut temporary = tempfile::Builder::new()
            .prefix(&name)
            .rand_bytes(0)
            .tempfile_in(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // libcommon/file_common.c: mosquitto_fopen opens the DB with
            // umask 0077, independent of the process's ordinary umask.
            temporary
                .as_file()
                .set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        let mut writer = BufWriter::new(temporary.as_file_mut());
        writer.write_all(HEADER)?;
        self.serialize(&mut rmp_serde::Serializer::new(&mut writer))
            .map_err(io::Error::other)?;
        writer.flush()?;
        drop(writer);
        temporary.as_file().sync_all()?;
        // Open the directory before replacement so a failed open leaves the
        // old image intact, and a later rename of the directory cannot redirect sync.
        #[cfg(unix)]
        let directory = File::open(parent)?;
        temporary.persist(path)?;
        #[cfg(unix)]
        directory.sync_all()?;
        Ok(())
    }

    fn validate(&self) -> io::Result<()> {
        let exists = |index: usize| index < self.messages.len();
        if !self.retained.iter().copied().all(exists)
            || self.sessions.iter().any(|session| {
                session
                    .incoming
                    .iter()
                    .any(|&(_, message)| !exists(message))
                    || session.outgoing.iter().any(|entry| {
                        !exists(entry.message)
                            || (entry.qos != QoS::AtMostOnce && entry.id.is_none())
                            || (entry.release
                                && (entry.qos != QoS::ExactlyOnce || entry.id.is_none()))
                    })
            })
        {
            return Err(invalid("invalid persisted message reference"));
        }
        if self
            .retained_store_times
            .last()
            .is_some_and(|&(position, _)| position >= self.retained.len())
            || self
                .retained_store_times
                .windows(2)
                .any(|pair| pair[0].0 >= pair[1].0)
        {
            return Err(invalid("invalid persisted retained store time position"));
        }
        Ok(())
    }
}

fn open_database(path: &Path) -> io::Result<Option<File>> {
    let mut options = File::options();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut flags = nix::libc::O_NONBLOCK;
        if std::env::var_os("MOSQUITTO_UNSAFE_ALLOW_SYMLINKS").is_none() {
            flags |= nix::libc::O_NOFOLLOW;
        }
        options.custom_flags(flags);
    }
    match options.open(path) {
        Ok(file) if file.metadata()?.is_file() => Ok(Some(file)),
        Ok(_) => Err(invalid("persistence database is not a regular file")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn invalid(error: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn snapshot_save_recovers_only_its_fixed_staging_path() {
        let dir = tempfile::tempdir().unwrap();
        let dir = dir.path();
        let native = dir.join("mosquitto.db.mqx");
        let staged = dir.join("mosquitto.db.mqx.new");
        fs::write(&staged, b"incomplete image").unwrap();
        let unrelated = [
            dir.join("mosquitto.db.new"),
            dir.join("other.db.mqx.new"),
            dir.join(".tmpAb12Xy"),
        ];
        for path in &unrelated {
            fs::write(path, b"unrelated file").unwrap();
        }

        let state = PersistentState::default();
        state.write_snapshot(&native).unwrap();
        assert!(PersistentState::read_snapshot(&native).unwrap().is_some());
        assert!(!staged.exists());
        for path in &unrelated {
            assert_eq!(fs::read(path).unwrap(), b"unrelated file");
        }

        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&unrelated[0], &staged).unwrap();
            state.write_snapshot(&native).unwrap();
            assert!(!staged.is_symlink());
            assert_eq!(fs::read(&unrelated[0]).unwrap(), b"unrelated file");
        }
    }
}
