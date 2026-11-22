// The Raft storage integration follows OpenRaft's examples/log-wal (MIT OR Apache-2.0).
use std::cmp::Ordering;
use std::fmt::Debug;
use std::io;
use std::ops::{Bound, RangeBounds};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

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
use crate::snapshot::prepare_dir;
use crate::transport::{decode, encode, invalid_data};

type Entry = EntryOf<Types>;
type Vote = VoteOf<Types>;
struct Inner {
    log: raft_log::RaftLog<WalTypes>,
    pending_commit: Option<LogId>,
}

impl Inner {
    fn record_commit(&mut self) -> io::Result<()> {
        if let Some(id) = self.pending_commit.take() {
            self.log.commit(Packed(id))?;
        }
        Ok(())
    }
}

#[derive(Clone)]
pub(crate) struct Wal {
    inner: Arc<RwLock<Option<Inner>>>,
    append_budget: usize,
}

impl Wal {
    pub(crate) fn open(path: &Path, max_append_size: usize) -> io::Result<Self> {
        prepare_dir(path, true)?;
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
        // The WAL worker synchronizes a bounded FIFO group and invokes each
        // IOFlushed callback only once the group is durable.
        config.wal.flush_batch_wait = Some(Duration::from_micros(200));
        config.wal.flush_batch_max_items = Some(64);
        let log = raft_log::RaftLog::open(Arc::new(config))?;
        Ok(Self {
            inner: Arc::new(RwLock::new(Some(Inner {
                log,
                pending_commit: None,
            }))),
            append_budget: max_append_size - crate::transport::MAX_CONTROL_FRAME,
        })
    }

    pub(crate) async fn close(self) -> io::Result<()> {
        let inner = self.inner.write().await.take();
        tokio::task::spawn_blocking(move || {
            if let Some(mut inner) = inner {
                // A clean restart can replay up to the last observed commit
                // without waiting for the next leader to reaffirm it.
                inner.record_commit()?;
                let (tx, rx) = oneshot::channel();
                inner.log.flush(true, Some(Flushed::Await(tx)))?;
                rx.blocking_recv().map_err(io::Error::other)??;
            }
            Ok(())
        })
        .await
        .map_err(io::Error::other)?
    }

    async fn read(&self) -> io::Result<RwLockReadGuard<'_, Inner>> {
        RwLockReadGuard::try_map(self.inner.read().await, Option::as_ref)
            .map_err(|_| io::ErrorKind::BrokenPipe.into())
    }

    async fn write(&self) -> io::Result<RwLockMappedWriteGuard<'_, Inner>> {
        RwLockWriteGuard::try_map(self.inner.write().await, Option::as_mut)
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
            .log
            .read(start, end)
            .map(|item| decode(&item?.1.0))
            .collect()
    }

    async fn limited_get_log_entries(&mut self, start: u64, end: u64) -> io::Result<Vec<Entry>> {
        let log = self.read().await?;
        let mut remaining = self.append_budget;
        let mut entries = Vec::new();
        for item in log.log.read(start, end) {
            let (_, body) = item?;
            let len = body.0.len();
            if !entries.is_empty() && len > remaining {
                break;
            }
            entries.push(decode(&body.0)?);
            remaining = remaining.saturating_sub(len);
        }
        Ok(entries)
    }

    async fn read_vote(&mut self) -> io::Result<Option<Vote>> {
        Ok(self.read().await?.log.log_state().vote().map(|vote| vote.0))
    }
}

impl RaftLogStorage<Types> for Wal {
    type LogReader = Self;

    async fn get_log_state(&mut self) -> io::Result<LogState<Types>> {
        let log = self.read().await?;
        let state = log.log.log_state();
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
            log.record_commit()?;
            log.log.save_vote(StoredVote(*vote))?;
            log.log.flush(true, Some(Flushed::Await(tx)))?;
        }
        rx.await.map_err(io::Error::other)?
    }

    async fn save_committed(&mut self, committed: Option<LogId>) -> io::Result<()> {
        if let Some(id) = committed {
            let mut inner = self.write().await?;
            let persisted = inner.log.log_state().committed().map(|id| id.0);
            if Some(id) > inner.pending_commit.max(persisted) {
                // Commit progress is recoverable from Raft after a power loss.
                // Coalesce monotonic markers until the next required sync.
                inner.pending_commit = Some(id);
            }
        }
        Ok(())
    }

    async fn read_committed(&mut self) -> io::Result<Option<LogId>> {
        let inner = self.read().await?;
        Ok(inner
            .pending_commit
            .max(inner.log.log_state().committed().map(|id| id.0)))
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
        log.record_commit()?;
        log.log.append(encoded)?;
        log.log.flush(true, Some(Flushed::Raft(callback)))?;
        Ok(())
    }

    async fn truncate_after(&mut self, last: Option<LogId>) -> io::Result<()> {
        let mut log = self.write().await?;
        let first_removed = last.next_index();
        if first_removed < log.log.log_state().last().map(|id| id.0).next_index() {
            log.log.truncate(first_removed)?;
        }
        // If the truncation is lost to a crash before the next append, Raft can repeat it.
        Ok(())
    }

    async fn purge(&mut self, id: LogId) -> io::Result<()> {
        let mut log = self.write().await?;
        if id.index >= log.log.log_state().purged().map(|id| id.0).next_index() {
            log.record_commit()?;
            log.log.purge(Packed(id))?;
            // raft-log only deletes obsolete chunk files after the covering purge is durable.
            log.log.flush(true, None)?;
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
