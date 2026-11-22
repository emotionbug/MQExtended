// The Raft storage integration follows OpenRaft's examples/log-wal (MIT OR Apache-2.0).
use std::cmp::Ordering;
use std::fmt::Debug;
use std::io;
use std::ops::{Bound, RangeBounds};
use std::path::Path;
use std::sync::Arc;

use bytes::Bytes;
use openraft::alias::{EntryOf, VoteOf};
use openraft::entry::RaftEntry;
use openraft::storage::{IOFlushed, RaftLogStorage};
use openraft::vote::RaftVote;
use openraft::{LogIdOptionExt, LogState, RaftLogReader};
use raft_log::api::raft_log_writer::RaftLogWriter;
use raft_log::codeq::{Decode, Encode, OffsetWriter};
use serde::{Serialize, de::DeserializeOwned};
use tokio::sync::{RwLock, RwLockMappedWriteGuard, RwLockReadGuard, RwLockWriteGuard, oneshot};

use crate::node::{LogId, Types};
use crate::snapshot::create_durable_dir;
use crate::transport::{decode, encode, invalid_data};

type Entry = EntryOf<Types>;
type Vote = VoteOf<Types>;
type Inner = raft_log::RaftLog<WalTypes>;

#[derive(Clone)]
pub(crate) struct Wal(Arc<RwLock<Option<Inner>>>);

impl Wal {
    pub(crate) fn open(path: &Path) -> io::Result<Self> {
        create_durable_dir(path)?;
        let dir = path
            .to_str()
            .ok_or_else(|| invalid_data("WAL path is not UTF-8"))?;
        let mut config = raft_log::Config {
            log_cache_capacity: Some(32 * 1024 * 1024),
            ..raft_log::Config::new(dir)
        };
        config.wal.chunk_max_size = Some(16 * 1024 * 1024);
        config.wal.chunk_max_records = Some(8192);
        config.wal.read_buffer_size = Some(64 * 1024);
        let log = raft_log::RaftLog::open(Arc::new(config))?;
        Ok(Self(Arc::new(RwLock::new(Some(log)))))
    }

    pub(crate) async fn close(self) -> io::Result<()> {
        let log = self.0.write().await.take();
        // Dropping the WAL joins its flush worker and releases the directory lock.
        tokio::task::spawn_blocking(move || drop(log))
            .await
            .map_err(io::Error::other)
    }

    async fn read(&self) -> io::Result<RwLockReadGuard<'_, Inner>> {
        RwLockReadGuard::try_map(self.0.read().await, Option::as_ref)
            .map_err(|_| io::ErrorKind::BrokenPipe.into())
    }

    async fn write(&self) -> io::Result<RwLockMappedWriteGuard<'_, Inner>> {
        RwLockWriteGuard::try_map(self.0.write().await, Option::as_mut)
            .map_err(|_| io::ErrorKind::BrokenPipe.into())
    }
}

impl RaftLogReader<Types> for Wal {
    async fn try_get_log_entries<R>(&mut self, range: R) -> io::Result<Vec<Entry>>
    where
        R: RangeBounds<u64> + Clone + Debug + Send,
    {
        let start = match range.start_bound() {
            Bound::Included(&n) => n,
            Bound::Excluded(&n) => n.saturating_add(1),
            Bound::Unbounded => 0,
        };
        let end = match range.end_bound() {
            Bound::Included(&n) => n.saturating_add(1),
            Bound::Excluded(&n) => n,
            Bound::Unbounded => u64::MAX,
        };
        self.read()
            .await?
            .read(start, end)
            .map(|item| decode(&item?.1.0))
            .collect()
    }

    async fn read_vote(&mut self) -> io::Result<Option<Vote>> {
        Ok(self.read().await?.log_state().vote().map(|vote| vote.0))
    }
}

impl RaftLogStorage<Types> for Wal {
    type LogReader = Self;

    async fn get_log_state(&mut self) -> io::Result<LogState<Types>> {
        let log = self.read().await?;
        let state = log.log_state();
        Ok(LogState {
            last_purged_log_id: state.purged().map(|id| id.0),
            last_log_id: state.last().map(|id| id.0),
        })
    }

    async fn get_log_reader(&mut self) -> Self {
        self.clone()
    }

    async fn save_vote(&mut self, vote: &Vote) -> io::Result<()> {
        let (tx, rx) = oneshot::channel();
        {
            let mut log = self.write().await?;
            log.save_vote(StoredVote(*vote))?;
            log.flush(true, Some(Flushed::Await(tx)))?;
        }
        rx.await.map_err(io::Error::other)?
    }

    async fn save_committed(&mut self, committed: Option<LogId>) -> io::Result<()> {
        if let Some(id) = committed {
            let (tx, rx) = oneshot::channel();
            {
                let mut log = self.write().await?;
                log.commit(Packed(id))?;
                log.flush(true, Some(Flushed::Await(tx)))?;
            }
            // OpenRaft applies after this returns. Persist the frontier now so restart
            // can replay locally acknowledged writes without waiting for a new election.
            rx.await.map_err(io::Error::other)??;
        }
        Ok(())
    }

    async fn read_committed(&mut self) -> io::Result<Option<LogId>> {
        Ok(self.read().await?.log_state().committed().map(|id| id.0))
    }

    async fn append<I>(&mut self, entries: I, callback: IOFlushed<Types>) -> io::Result<()>
    where
        I: IntoIterator<Item = Entry> + Send,
    {
        let encoded = entries
            .into_iter()
            .map(|entry| Ok((Packed(entry.log_id()), EntryBytes(encode(&entry)?.into()))))
            .collect::<io::Result<Vec<_>>>()?;
        let mut log = self.write().await?;
        log.append(encoded)?;
        log.flush(true, Some(Flushed::Raft(callback)))?;
        Ok(())
    }

    async fn truncate_after(&mut self, last: Option<LogId>) -> io::Result<()> {
        let mut log = self.write().await?;
        let first_removed = last.next_index();
        if first_removed < log.log_state().last().map(|id| id.0).next_index() {
            log.truncate(first_removed)?;
        }
        // If the truncation is lost to a crash before the next append, Raft can repeat it.
        Ok(())
    }

    async fn purge(&mut self, id: LogId) -> io::Result<()> {
        let mut log = self.write().await?;
        if id.index >= log.log_state().purged().map(|id| id.0).next_index() {
            log.purge(Packed(id))?;
            // raft-log only deletes obsolete chunk files after the covering purge is durable.
            log.flush(true, None)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct WalTypes;

impl raft_log::Types for WalTypes {
    type LogId = Packed<LogId>;
    type LogPayload = EntryBytes;
    type Vote = StoredVote;
    type Callback = Flushed;
    type UserData = Packed<()>;

    fn log_index(id: &Self::LogId) -> u64 {
        id.0.index
    }

    fn payload_size(payload: &Self::LogPayload) -> u64 {
        payload.0.len() as u64
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct EntryBytes(Bytes);

impl Encode for EntryBytes {
    fn encode<W: io::Write>(&self, mut writer: W) -> io::Result<usize> {
        let len = u32::try_from(self.0.len()).map_err(invalid_data)?;
        writer.write_all(&len.to_be_bytes())?;
        writer.write_all(&self.0)?;
        Ok(4 + self.0.len())
    }
}

impl Decode for EntryBytes {
    fn decode<R: io::Read>(reader: R) -> io::Result<Self> {
        Ok(Self(Vec::<u8>::decode(reader)?.into()))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Packed<T>(T);

impl<T: Serialize> Encode for Packed<T> {
    fn encode<W: io::Write>(&self, writer: W) -> io::Result<usize> {
        let mut writer = OffsetWriter::new(writer);
        rmp_serde::encode::write_named(&mut writer, &self.0).map_err(invalid_data)?;
        Ok(writer.offset())
    }
}

impl<T: DeserializeOwned> Decode for Packed<T> {
    fn decode<R: io::Read>(reader: R) -> io::Result<Self> {
        rmp_serde::from_read(reader)
            .map(Self)
            .map_err(|error| match error {
                // The WAL distinguishes an interrupted final write from invalid data.
                rmp_serde::decode::Error::InvalidMarkerRead(io)
                | rmp_serde::decode::Error::InvalidDataRead(io) => io,
                other => invalid_data(other),
            })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct StoredVote(Vote);

impl PartialOrd for StoredVote {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        RaftVote::partial_cmp(&self.0, &other.0)
    }
}

impl Encode for StoredVote {
    fn encode<W: io::Write>(&self, writer: W) -> io::Result<usize> {
        Packed(self.0).encode(writer)
    }
}

impl Decode for StoredVote {
    fn decode<R: io::Read>(reader: R) -> io::Result<Self> {
        Ok(Self(Packed::<Vote>::decode(reader)?.0))
    }
}

enum Flushed {
    Raft(IOFlushed<Types>),
    Await(oneshot::Sender<io::Result<()>>),
}

impl raft_log::Callback for Flushed {
    fn send(self, result: io::Result<()>) {
        match self {
            Self::Raft(callback) => callback.io_completed(result),
            Self::Await(tx) => {
                let _ = tx.send(result);
            }
        }
    }
}
