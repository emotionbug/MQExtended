// The Raft storage integration follows OpenRaft's examples/log-wal (MIT OR Apache-2.0).
use std::cmp::Ordering;
use std::fmt::Debug;
use std::fs::File;
use std::io::{self, Read};
use std::ops::{Bound, RangeBounds};
use std::path::{Path, PathBuf};
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

#[cfg(target_os = "linux")]
mod direct;

#[cfg(all(test, target_os = "linux"))]
mod direct_tests;

type Entry = EntryOf<Types>;
type Vote = VoteOf<Types>;

/// Metrics for the open WAL, reset when the node restarts.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
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
    /// Longest file-write phase; includes the sync when write and sync are fused.
    pub write_max: Duration,
    /// Longest wait from enqueue to the start of writing, including group wait.
    pub queue_wait_max: Duration,
}

struct Inner {
    log: Backend,
    pending_commit: Option<LogId>,
    appended_entries: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[cfg_attr(target_os = "linux", derive(Serialize, serde::Deserialize))]
struct State {
    vote: Option<Vote>,
    committed: Option<LogId>,
    purged: Option<LogId>,
    last: Option<LogId>,
}

enum Backend {
    Legacy(raft_log::RaftLog<WalTypes>),
    #[cfg(target_os = "linux")]
    Direct(direct::DirectLog),
}

impl Backend {
    fn state(&self) -> State {
        match self {
            Self::Legacy(log) => {
                let state = log.log_state();
                State {
                    vote: state.vote().map(|vote| vote.0),
                    committed: state.committed().map(|id| id.0),
                    purged: state.purged().map(|id| id.0),
                    last: state.last().map(|id| id.0),
                }
            }
            #[cfg(target_os = "linux")]
            Self::Direct(log) => log.state(),
        }
    }

    fn entries(&self, start: u64, end: u64, budget: Option<usize>) -> io::Result<Vec<Entry>> {
        if start >= end {
            return Ok(Vec::new());
        }
        match self {
            Self::Legacy(log) => collect_entries(
                log.read(start, end).map(|item| item.map(|(_, body)| body)),
                budget,
            ),
            #[cfg(target_os = "linux")]
            Self::Direct(log) => collect_entries(log.read(start, end), budget),
        }
    }

    #[cfg(test)]
    fn stat(&self) -> raft_log::Stat<WalTypes> {
        match self {
            Self::Legacy(log) => log.stat(),
            #[cfg(target_os = "linux")]
            Self::Direct(_) => unreachable!("legacy WAL test"),
        }
    }
}

fn collect_entries(
    bodies: impl Iterator<Item = io::Result<EntryBytes>>,
    budget: Option<usize>,
) -> io::Result<Vec<Entry>> {
    let Some(mut bytes) = budget else {
        return bodies.map(|body| body?.entry()).collect();
    };
    let mut entries = Vec::new();
    for body in bodies {
        let body = body?;
        let len = body.0.len();
        if !entries.is_empty() && len > bytes {
            break;
        }
        entries.push(body.entry()?);
        bytes = bytes.saturating_sub(len);
    }
    Ok(entries)
}

fn record_commit(log: &mut raft_log::RaftLog<WalTypes>, pending: Option<LogId>) -> io::Result<()> {
    if let Some(id) = pending {
        log.commit(Packed(id))?;
    }
    Ok(())
}

const DIRECT_SEGMENT_PREFIX: &[u8; 7] = b"MQX-DIR";

#[cfg(target_os = "linux")]
fn direct_guard_name() -> String {
    raft_log::chunked_wal::Config::chunk_file_name(raft_log::ChunkId(u64::MAX))
}

fn wal_chunk_files(path: &Path) -> io::Result<Vec<(u64, PathBuf)>> {
    let mut files = Vec::new();
    for entry in path.read_dir()? {
        let entry = entry?;
        if let Some(id) = entry
            .file_name()
            .to_str()
            .and_then(|name| raft_log::chunked_wal::Config::parse_chunk_file_name(name).ok())
        {
            files.push((id, entry.path()));
        }
    }
    files.sort_unstable_by_key(|(id, _)| *id);
    Ok(files)
}

fn select_direct(path: &Path, requested: bool) -> io::Result<bool> {
    let files = wal_chunk_files(path)?;
    if files.last().is_some_and(|(id, _)| *id == u64::MAX) {
        return Ok(true);
    }
    if let Some((_, first)) = files.first() {
        // The first segment may have been synced and published just before
        // the crash that interrupted publication of the format guard.
        let mut prefix = [0; DIRECT_SEGMENT_PREFIX.len()];
        match File::open(first)?.read_exact(&mut prefix) {
            Ok(()) if &prefix == DIRECT_SEGMENT_PREFIX => return Ok(true),
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {}
            Err(error) => return Err(error),
        }
        if requested {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "direct WAL requires an empty WAL directory; existing legacy WAL is unchanged",
            ));
        }
    }
    Ok(requested)
}

#[derive(Clone)]
pub(crate) struct Wal {
    inner: Arc<RwLock<Option<Inner>>>,
    append_budget: usize,
    format: u16,
    term_floor: Option<u64>,
}

impl Wal {
    #[cfg(test)]
    pub(crate) fn open(path: &Path, max_append_size: usize, format: u16) -> io::Result<Self> {
        Self::open_with_direct(path, max_append_size, format, false)
    }

    pub(crate) fn open_with_direct(
        path: &Path,
        max_append_size: usize,
        format: u16,
        direct: bool,
    ) -> io::Result<Self> {
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
        let log = if select_direct(path, direct)? {
            #[cfg(target_os = "linux")]
            {
                Backend::Direct(direct::DirectLog::open(path, &config.wal)?)
            }
            #[cfg(not(target_os = "linux"))]
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "direct WAL requires Linux",
            ));
        } else {
            match raft_log::RaftLog::open(Arc::new(config)) {
                Ok(log) => Backend::Legacy(log),
                Err(error) if select_direct(path, false)? => {
                    // A concurrent direct initializer won the directory lock.
                    // The legacy decoder rejected its guard; this is not
                    // grounds for destructive corruption recovery.
                    return Err(io::Error::new(io::ErrorKind::InvalidInput, error));
                }
                Err(error) => return Err(error),
            }
        };
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
            let state = inner.log.state();
            state.vote.is_some() || state.last.is_some() || state.committed.is_some()
        })
    }

    pub(crate) fn with_term_floor(mut self, term: Option<u64>) -> Self {
        self.term_floor = term;
        self
    }

    pub(crate) async fn metrics(&self) -> io::Result<WalMetrics> {
        let inner = self.read().await?;
        let mut metrics = match &inner.log {
            Backend::Legacy(log) => {
                let flush = log.stat().flush_metrics;
                WalMetrics {
                    sync_batches: flush.sync_batch_count,
                    sync_time: Duration::from_micros(flush.sync_us),
                    sync_max: Duration::from_micros(flush.sync_max_us),
                    write_max: Duration::from_micros(flush.write_max_us),
                    queue_wait_max: Duration::from_micros(flush.queued_wait_max_us),
                    ..WalMetrics::default()
                }
            }
            #[cfg(target_os = "linux")]
            Backend::Direct(log) => log.metrics(),
        };
        metrics.appended_entries = inner.appended_entries;
        Ok(metrics)
    }

    pub(crate) async fn close(self) -> io::Result<()> {
        let Some(Inner {
            log,
            pending_commit,
            ..
        }) = self.inner.write().await.take()
        else {
            return Ok(());
        };
        // A clean restart can replay up to the last observed commit without
        // waiting for the next leader to reaffirm it.
        let (tx, rx) = oneshot::channel();
        match log {
            Backend::Legacy(mut log) => tokio::task::spawn_blocking(move || {
                record_commit(&mut log, pending_commit)?;
                log.flush(true, Some(Flushed::Await(tx)))?;
                rx.blocking_recv().map_err(io::Error::other)?
            })
            .await
            .map_err(io::Error::other)?,
            #[cfg(target_os = "linux")]
            Backend::Direct(mut log) => {
                let result = match log
                    .control(pending_commit, None, Some(Flushed::Await(tx)))
                    .await
                {
                    Ok(()) => rx.await.map_err(io::Error::other).and_then(|result| result),
                    Err(error) => Err(error),
                };
                let shutdown = tokio::task::spawn_blocking(move || log.shutdown())
                    .await
                    .map_err(io::Error::other)?;
                result.and(shutdown)
            }
        }
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
        self.read().await?.log.entries(start, end, None)
    }

    async fn limited_get_log_entries(&mut self, start: u64, end: u64) -> io::Result<Vec<Entry>> {
        self.read()
            .await?
            .log
            .entries(start, end, Some(self.append_budget))
    }

    async fn read_vote(&mut self) -> io::Result<Option<Vote>> {
        let vote = self.read().await?.log.state().vote;
        // A fork has no saved vote. Seed the first election above its snapshot
        // term without granting a vote to any real member (node IDs are positive).
        Ok(vote.or_else(|| self.term_floor.map(|term| Vote::new(term, 0))))
    }
}

impl RaftLogStorage<Types> for Wal {
    type LogReader = Self;

    async fn get_log_state(&mut self) -> io::Result<LogState<Types>> {
        let log = self.read().await?;
        let state = log.log.state();
        Ok(LogState {
            last_purged_log_id: state.purged,
            last_log_id: state.last,
        })
    }

    async fn get_log_reader(&mut self) -> Self {
        self.clone()
    }

    async fn save_vote(&mut self, vote: &Vote) -> io::Result<()> {
        let (tx, rx) = oneshot::channel();
        {
            let mut inner = self.write().await?;
            let pending = inner.pending_commit.take();
            let callback = Some(Flushed::Await(tx));
            match &mut inner.log {
                Backend::Legacy(log) => {
                    record_commit(log, pending)?;
                    log.save_vote(StoredVote(*vote))?;
                    log.flush(true, callback)?;
                }
                #[cfg(target_os = "linux")]
                Backend::Direct(log) => {
                    log.control(pending, Some(direct::Change::Vote(*vote)), callback)
                        .await?
                }
            }
        }
        rx.await.map_err(io::Error::other)?
    }

    async fn save_committed(&mut self, committed: Option<LogId>) -> io::Result<()> {
        if let Some(id) = committed {
            let mut inner = self.write().await?;
            let persisted = inner.log.state().committed;
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
        Ok(inner.pending_commit.max(inner.log.state().committed))
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
        let mut inner = self.write().await?;
        let pending = inner.pending_commit.take();
        let count = encoded.len() as u64;
        let callback = Flushed::Raft(callback);
        match &mut inner.log {
            Backend::Legacy(log) => {
                record_commit(log, pending)?;
                log.append(encoded)?;
                log.flush(true, Some(callback))?;
            }
            #[cfg(target_os = "linux")]
            Backend::Direct(log) => log.append(pending, encoded, callback).await?,
        }
        inner.appended_entries += count;
        Ok(())
    }

    async fn truncate_after(&mut self, last: Option<LogId>) -> io::Result<()> {
        let rx = {
            let mut inner = self.write().await?;
            let first_removed = last.next_index();
            if first_removed >= inner.log.state().last.next_index() {
                return Ok(());
            }
            let pending = inner.pending_commit.take();
            // OpenRaft can publish a snapshot after truncating a conflicting
            // suffix, without an intervening append. Persist the truncation
            // before that snapshot can become the recovery point.
            let (tx, rx) = oneshot::channel();
            let callback = Some(Flushed::Await(tx));
            match &mut inner.log {
                Backend::Legacy(log) => {
                    record_commit(log, pending)?;
                    log.truncate(first_removed)?;
                    log.flush(true, callback)?;
                }
                #[cfg(target_os = "linux")]
                Backend::Direct(log) => {
                    log.control(pending, Some(direct::Change::Truncate(last)), callback)
                        .await?
                }
            }
            rx
        };
        rx.await.map_err(io::Error::other)?
    }

    async fn purge(&mut self, id: LogId) -> io::Result<()> {
        let mut inner = self.write().await?;
        if id.index >= inner.log.state().purged.next_index() {
            let pending = inner.pending_commit.take();
            match &mut inner.log {
                Backend::Legacy(log) => {
                    record_commit(log, pending)?;
                    log.purge(Packed(id))?;
                    // raft-log only deletes obsolete chunk files after the covering purge is durable.
                    log.flush(true, None)?;
                }
                #[cfg(target_os = "linux")]
                Backend::Direct(log) => {
                    log.control(pending, Some(direct::Change::Purge(id)), None)
                        .await?
                }
            }
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

fn entry_payload(body: &[u8]) -> io::Result<&[u8]> {
    let (version, payload) = version::split(body, "WAL entry").map_err(invalid_data)?;
    match version {
        1 | 2 => Ok(payload),
        _ => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            crate::ClusterError::UnsupportedVersion {
                kind: "WAL entry",
                version,
            },
        )),
    }
}

impl EntryBytes {
    fn payload(&self) -> io::Result<&[u8]> {
        entry_payload(&self.0)
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
