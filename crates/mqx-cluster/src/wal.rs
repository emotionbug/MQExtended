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
use crate::transport::{decode, invalid_data};
use crate::version;

type Entry = EntryOf<Types>;
type Vote = VoteOf<Types>;

/// Metrics for the open WAL, reset when the node restarts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WalMetrics {
    /// Entries accepted for append, including Raft control and lease entries.
    pub appended_entries: u64,
    /// Filesystem-sync batches attempted by the WAL worker. A batch spanning
    /// multiple WAL files can sync more than one file.
    pub sync_batches: u64,
    /// Total time spent syncing WAL files.
    pub sync_time: Duration,
    /// Longest filesystem-sync phase of a completed batch.
    pub sync_max: Duration,
    /// Longest file-write phase of a completed batch.
    pub write_max: Duration,
    /// Longest wait from enqueue to the start of writing, including group wait.
    pub queue_wait_max: Duration,
}

struct Inner {
    log: raft_log::RaftLog<WalTypes>,
    pending_commit: Option<LogId>,
    appended_entries: u64,
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
    format: u16,
    term_floor: Option<u64>,
}

impl Wal {
    pub(crate) fn open(path: &Path, max_append_size: usize, format: u16) -> io::Result<Self> {
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
                appended_entries: 0,
            }))),
            append_budget: max_append_size - crate::transport::MAX_CONTROL_FRAME,
            format,
            term_floor: None,
        })
    }

    /// Check for preexisting Raft state on the blocking startup thread.
    pub(crate) fn has_raft_state(&self) -> bool {
        self.inner.blocking_read().as_ref().is_some_and(|inner| {
            let state = inner.log.log_state();
            state.vote().is_some() || state.last().is_some() || state.committed().is_some()
        })
    }

    pub(crate) fn with_term_floor(mut self, term: Option<u64>) -> Self {
        self.term_floor = term;
        self
    }

    pub(crate) async fn metrics(&self) -> io::Result<WalMetrics> {
        let inner = self.read().await?;
        let flush = inner.log.stat().flush_metrics;
        Ok(WalMetrics {
            appended_entries: inner.appended_entries,
            sync_batches: flush.sync_batch_count,
            sync_time: Duration::from_micros(flush.sync_us),
            sync_max: Duration::from_micros(flush.sync_max_us),
            write_max: Duration::from_micros(flush.write_max_us),
            queue_wait_max: Duration::from_micros(flush.queued_wait_max_us),
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
            .map(|item| item?.1.entry())
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
            entries.push(body.entry()?);
            remaining = remaining.saturating_sub(len);
        }
        Ok(entries)
    }

    async fn read_vote(&mut self) -> io::Result<Option<Vote>> {
        let vote = self.read().await?.log.log_state().vote().map(|vote| vote.0);
        // A fork has no saved vote. Seed the first election above its snapshot
        // term without granting a vote to any real member (node IDs are positive).
        Ok(vote.or_else(|| self.term_floor.map(|term| Vote::new(term, 0))))
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
            .map(|entry| {
                let body = version::encode(&entry, self.format, self.format != 1)?;
                Ok((Packed(entry.log_id()), EntryBytes(body)))
            })
            .collect::<io::Result<Vec<_>>>()?;
        let mut log = self.write().await?;
        log.record_commit()?;
        let count = encoded.len() as u64;
        log.log.append(encoded)?;
        log.log.flush(true, Some(Flushed::Raft(callback)))?;
        log.appended_entries += count;
        Ok(())
    }

    async fn truncate_after(&mut self, last: Option<LogId>) -> io::Result<()> {
        let rx = {
            let mut log = self.write().await?;
            let first_removed = last.next_index();
            if first_removed >= log.log.log_state().last().map(|id| id.0).next_index() {
                return Ok(());
            }
            log.record_commit()?;
            log.log.truncate(first_removed)?;
            // OpenRaft can publish a snapshot after truncating a conflicting
            // suffix, without an intervening append. Persist the truncation
            // before that snapshot can become the recovery point.
            let (tx, rx) = oneshot::channel();
            log.log.flush(true, Some(Flushed::Await(tx)))?;
            rx
        };
        rx.await.map_err(io::Error::other)?
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

impl EntryBytes {
    fn payload(&self) -> io::Result<&[u8]> {
        let (version, payload) = version::split(&self.0, "WAL entry").map_err(invalid_data)?;
        match version {
            1 | 2 => Ok(payload),
            _ => Err(invalid_data(crate::ClusterError::UnsupportedVersion {
                kind: "WAL entry",
                version,
            })),
        }
    }

    fn entry(&self) -> io::Result<Entry> {
        decode(self.payload()?)
    }
}

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
        let entry = Self(Vec::<u8>::decode(reader)?.into());
        entry.payload()?;
        Ok(entry)
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

#[cfg(test)]
mod tests {
    use openraft::type_config::TypeConfigExt;

    use super::*;
    use crate::node::Leadership;

    #[tokio::test]
    async fn vote_and_append_acknowledge_only_after_sync() {
        let dir = tempfile::tempdir().unwrap();
        let mut wal = Wal::open(dir.path(), crate::DEFAULT_MAX_APPEND_SIZE, 1).unwrap();
        let initial = wal.metrics().await.unwrap();
        let vote = Vote::new_committed(1, 1);
        wal.save_vote(&vote).await.unwrap();
        let voted = wal.metrics().await.unwrap();
        assert!(voted.sync_batches > initial.sync_batches);
        assert!(voted.sync_time >= initial.sync_time);
        assert!(voted.sync_max <= voted.sync_time);

        let log_id = LogId::new(
            Leadership {
                term: 1,
                node_id: 1,
            },
            0,
        );
        let (tx, rx) = Types::oneshot();
        wal.append(
            [Entry {
                log_id,
                payload: openraft::alias::EntryPayloadOf::<Types>::Blank,
            }],
            IOFlushed::signal(tx),
        )
        .await
        .unwrap();
        rx.await.unwrap().unwrap();
        let appended = wal.metrics().await.unwrap();
        assert_eq!(appended.appended_entries, 1);
        assert!(appended.sync_batches > voted.sync_batches);
        assert!(appended.sync_time >= voted.sync_time);
        assert!(appended.sync_max >= voted.sync_max);
        assert!(appended.sync_max <= appended.sync_time);
        assert!(appended.write_max >= voted.write_max);
        assert!(appended.queue_wait_max >= voted.queue_wait_max);
        wal.close().await.unwrap();
    }

    #[tokio::test]
    async fn commit_updates_write_only_the_highest_marker_with_the_next_vote() {
        let dir = tempfile::tempdir().unwrap();
        let mut wal = Wal::open(dir.path(), crate::DEFAULT_MAX_APPEND_SIZE, 2).unwrap();
        let leader = Leadership {
            term: 1,
            node_id: 1,
        };
        let ids = [LogId::new(leader, 0), LogId::new(leader, 1)];
        let (tx, rx) = Types::oneshot();
        wal.append(
            ids.map(|log_id| Entry {
                log_id,
                payload: openraft::alias::EntryPayloadOf::<Types>::Blank,
            }),
            IOFlushed::signal(tx),
        )
        .await
        .unwrap();
        rx.await.unwrap().unwrap();
        let before = wal.read().await.unwrap().log.stat();
        for id in [ids[0], ids[1], ids[0], ids[1]] {
            wal.save_committed(Some(id)).await.unwrap();
        }
        assert_eq!(wal.read_committed().await.unwrap(), Some(ids[1]));
        let pending = wal.read().await.unwrap().log.stat();
        assert_eq!(
            pending.open_chunk.records_count,
            before.open_chunk.records_count
        );
        assert_eq!(
            pending.flush_metrics.sync_batch_count,
            before.flush_metrics.sync_batch_count
        );

        wal.save_vote(&Vote::new(2, 1)).await.unwrap();
        let stored = wal.read().await.unwrap().log.stat();
        assert_eq!(
            stored.open_chunk.records_count,
            before.open_chunk.records_count + 2
        );
        assert_eq!(
            stored.open_chunk.log_state.committed().map(|id| id.0),
            Some(ids[1])
        );
        assert_eq!(
            stored.flush_metrics.sync_batch_count,
            before.flush_metrics.sync_batch_count + 1
        );
        wal.close().await.unwrap();
    }

    #[tokio::test]
    async fn conflicting_suffix_is_truncated_before_a_snapshot_can_be_published() {
        let dir = tempfile::tempdir().unwrap();
        let mut wal = Wal::open(dir.path(), crate::DEFAULT_MAX_APPEND_SIZE, 2).unwrap();
        let id = |term, index| LogId::new(Leadership { term, node_id: 1 }, index);
        let kept = id(1, 0);
        let (tx, rx) = Types::oneshot();
        wal.append(
            [kept, id(2, 1), id(2, 2)].map(|log_id| Entry {
                log_id,
                payload: openraft::alias::EntryPayloadOf::<Types>::Blank,
            }),
            IOFlushed::signal(tx),
        )
        .await
        .unwrap();
        rx.await.unwrap().unwrap();
        wal.save_committed(Some(kept)).await.unwrap();
        let initial = wal.metrics().await.unwrap();
        wal.truncate_after(Some(kept)).await.unwrap();
        assert!(wal.metrics().await.unwrap().sync_batches > initial.sync_batches);

        // Capture the disk image immediately, without letting shutdown or a
        // later purge flush the removed suffix out of the WAL.
        let copied = tempfile::tempdir().unwrap();
        for entry in dir.path().read_dir().unwrap() {
            let entry = entry.unwrap();
            std::fs::copy(entry.path(), copied.path().join(entry.file_name())).unwrap();
        }
        let mut reopened = Wal::open(copied.path(), crate::DEFAULT_MAX_APPEND_SIZE, 2).unwrap();
        assert_eq!(
            reopened.get_log_state().await.unwrap().last_log_id,
            Some(kept)
        );
        assert_eq!(reopened.read_committed().await.unwrap(), Some(kept));
        assert!(reopened.try_get_log_entries(1..).await.unwrap().is_empty());
        reopened.close().await.unwrap();
        wal.close().await.unwrap();
    }

    #[test]
    fn refuses_future_wal_envelope_before_deserializing_entry() {
        let bytes = version::encode(&0, 3, true).unwrap();
        let mut record = Vec::new();
        EntryBytes(bytes).encode(&mut record).unwrap();
        let error = EntryBytes::decode(record.as_slice()).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("unsupported WAL entry version 3")
        );
    }
}
