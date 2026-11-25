//! Linux direct WAL. The Raft view sees accepted entries immediately; the
//! worker publishes each completion only after its entire frame is durable.
mod physical;

use std::collections::BTreeMap;
use std::io;
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::Instant;

use openraft::{LogIdOptionExt, vote::RaftVote};
use raft_log::{Callback, chunked_wal::ChunkedWal};
use sha2::{Digest, Sha256};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};

use self::physical::{Base, Journal, MAX_BODY, Replay};
use super::{EntryBytes, Flushed, LogId, Packed, State, Vote, WalMetrics, WalTypes};
use crate::node::Leadership;
use crate::transport::invalid_data;

const CACHE_BYTES: usize = 32 * 1024 * 1024;
const QUEUE_KIB: u32 = 64 * 1024;
const QUEUE_ITEMS: usize = 64;
const GROUP_BYTES: usize = 256 * 1024;
const APPEND_HEADER: usize = 1 + 24 + 4;

impl State {
    fn apply(&mut self, op: Change) -> io::Result<()> {
        match op {
            Change::Append(id)
                if id.index != u64::MAX
                    && Some(id) > self.last
                    && id.index == self.last.next_index() =>
            {
                self.last = Some(id);
            }
            Change::Vote(vote)
                if self.vote.is_none_or(|old| {
                    RaftVote::partial_cmp(&vote, &old).is_some_and(|order| !order.is_lt())
                }) =>
            {
                self.vote = Some(vote)
            }
            Change::Commit(id) if Some(id) >= self.committed && Some(id) <= self.last => {
                self.committed = Some(id);
            }
            Change::Truncate(last)
                if last >= self.committed && last >= self.purged && last <= self.last =>
            {
                self.last = last
            }
            Change::Purge(id) if id.index != u64::MAX && id.index >= self.purged.next_index() => {
                self.purged = Some(id);
                self.last = self.last.max(self.purged);
            }
            _ => return Err(invalid_data("invalid direct WAL Raft transition")),
        }
        Ok(())
    }

    fn validate(self) -> io::Result<()> {
        if [self.committed, self.purged, self.last]
            .into_iter()
            .flatten()
            .any(|id| id.index == u64::MAX)
            || self.committed > self.last
            || self.purged > self.last
        {
            return Err(invalid_data("invalid direct WAL checkpoint"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
pub(super) enum Change {
    Append(LogId),
    Vote(Vote),
    Commit(LogId),
    Truncate(Option<LogId>),
    Purge(LogId),
}

struct Index {
    state: State,
    first_segment: u64,
    entries: BTreeMap<u64, Indexed>,
    cache: BTreeMap<u64, EntryBytes>,
    cache_bytes: usize,
}

impl Index {
    fn new() -> Self {
        Self {
            state: State::default(),
            first_segment: 0,
            entries: BTreeMap::new(),
            cache: BTreeMap::new(),
            cache_bytes: 0,
        }
    }

    fn apply(&mut self, change: Change, entry: Option<(Indexed, Option<EntryBytes>)>) {
        match change {
            Change::Append(id) => {
                let (indexed, body) = entry.unwrap();
                self.entries.insert(id.index, indexed);
                if let Some(body) = body {
                    self.cache_bytes += body.0.len();
                    self.cache.insert(id.index, body);
                }
            }
            Change::Truncate(keep) => {
                drop(self.entries.split_off(&keep.next_index()));
                for (_, body) in self.cache.split_off(&keep.next_index()) {
                    self.cache_bytes -= body.0.len();
                }
            }
            Change::Purge(id) => {
                let mut kept = self.entries.split_off(&id.index.saturating_add(1));
                std::mem::swap(&mut self.entries, &mut kept);
                while self
                    .cache
                    .first_key_value()
                    .is_some_and(|(index, _)| *index <= id.index)
                {
                    self.cache_bytes -= self.cache.pop_first().unwrap().1.0.len();
                }
            }
            Change::Vote(_) | Change::Commit(_) => {}
        }
    }

    fn evict(&mut self) {
        while self.cache_bytes > CACHE_BYTES {
            let index = *self.cache.first_key_value().unwrap().0;
            if self.entries[&index].base.get().is_none() {
                // Pending bytes are additionally bounded by write admission.
                break;
            }
            self.cache_bytes -= self.cache.pop_first().unwrap().1.0.len();
        }
    }

    fn read(&self, start: u64, end: u64) -> impl Iterator<Item = io::Result<EntryBytes>> + '_ {
        self.entries.range(start..end).map(|(index, entry)| {
            self.cache
                .get(index)
                .cloned()
                .map(Ok)
                .unwrap_or_else(|| entry.read())
        })
    }

    fn replay(&mut self, event: Replay<'_>) -> io::Result<Option<u64>> {
        let (base, mut frame) = match event {
            Replay::Start(state, first) => {
                state.validate()?;
                if let Some(first) = first {
                    self.first_segment = first;
                } else if self.state != state {
                    return Err(invalid_data(
                        "direct WAL checkpoint disagrees with predecessor",
                    ));
                }
                self.state = state;
                return Ok(None);
            }
            Replay::Frame(base, frame) => (base, frame),
        };
        let length = frame.len();
        let base = FrameBase::Known(base);
        let mut max = None;
        while let Some((&tag, rest)) = frame.split_first() {
            frame = rest;
            let change = match tag {
                1 => {
                    let id = take_id(&mut frame)?;
                    let len = u32::from_le_bytes(take(&mut frame)?) as usize;
                    let offset = length - frame.len();
                    let body = frame
                        .split_off(..len)
                        .ok_or_else(|| invalid_data("short direct WAL entry"))?;
                    super::entry_payload(body)?;
                    let entry = Indexed::new(id, base.clone(), offset, body);
                    let op = Change::Append(id);
                    self.state.apply(op)?;
                    self.apply(op, Some((entry, None)));
                    max = max.max(Some(id.index));
                    continue;
                }
                2 => {
                    let term = u64::from_le_bytes(take(&mut frame)?);
                    let node_id = u64::from_le_bytes(take(&mut frame)?);
                    let [committed] = take(&mut frame)?;
                    if committed > 1 {
                        return Err(invalid_data("invalid direct WAL vote flag"));
                    }
                    Change::Vote(Vote {
                        leader_id: Leadership { term, node_id },
                        committed: committed != 0,
                    })
                }
                3 => Change::Commit(take_id(&mut frame)?),
                4 => Change::Truncate(Some(take_id(&mut frame)?)),
                5 => Change::Purge(take_id(&mut frame)?),
                6 => Change::Truncate(None),
                _ => return Err(invalid_data("unknown direct WAL operation")),
            };
            self.state.apply(change)?;
            self.apply(change, None);
        }
        Ok(max)
    }

    fn validate(&self) -> io::Result<()> {
        if self.first_segment != 0 && self.state.purged.is_none() {
            return Err(invalid_data(
                "direct WAL lost its first segment without a covering purge",
            ));
        }
        let mut expected = self.state.purged.next_index();
        let mut last = self.state.purged;
        for (&index, entry) in &self.entries {
            if expected != index {
                return Err(invalid_data("direct WAL lost some live log entries"));
            }
            expected = index + 1;
            last = Some(entry.id);
        }
        if last != self.state.last || self.state.committed > self.state.last {
            return Err(invalid_data(
                "direct WAL checkpoint does not match live log",
            ));
        }
        Ok(())
    }
}

#[derive(Clone)]
enum FrameBase {
    Known(Base),
    Pending(Arc<OnceLock<Base>>),
}

impl FrameBase {
    fn get(&self) -> Option<&Base> {
        match self {
            Self::Known(base) => Some(base),
            Self::Pending(base) => base.get(),
        }
    }
}

struct Indexed {
    id: LogId,
    base: FrameBase,
    offset: u32,
    len: u32,
    digest: [u8; 32],
}

impl Indexed {
    fn new(id: LogId, base: FrameBase, offset: usize, body: &[u8]) -> Self {
        Self {
            id,
            base,
            offset: offset as u32,
            len: body.len() as u32,
            digest: Sha256::digest(body).into(),
        }
    }

    fn read(&self) -> io::Result<EntryBytes> {
        let base = self
            .base
            .get()
            .expect("unflushed direct WAL entry must be cached");
        let mut bytes = vec![0; self.len as usize];
        base.file
            .read_exact_at(&mut bytes, base.offset + u64::from(self.offset))?;
        if <[u8; 32]>::from(Sha256::digest(&bytes)) != self.digest {
            return Err(invalid_data("bad direct WAL entry checksum"));
        }
        Ok(EntryBytes(bytes.into()))
    }
}

struct Operation {
    change: Change,
    body: Option<EntryBytes>,
}

impl Operation {
    fn control(change: Change) -> Self {
        Self { change, body: None }
    }

    fn len(&self) -> usize {
        match self.change {
            Change::Append(_) => APPEND_HEADER + self.body.as_ref().unwrap().0.len(),
            Change::Vote(_) => 18,
            Change::Truncate(None) => 1,
            Change::Commit(_) | Change::Purge(_) | Change::Truncate(Some(_)) => 25,
        }
    }

    fn encode(&self, out: &mut [u8]) {
        let tag = match self.change {
            Change::Append(id) => {
                let body = &self.body.as_ref().unwrap().0;
                put_id(&mut out[1..25], id);
                out[25..29].copy_from_slice(&(body.len() as u32).to_le_bytes());
                out[APPEND_HEADER..].copy_from_slice(body);
                1
            }
            Change::Vote(vote) => {
                out[1..9].copy_from_slice(&vote.leader_id.term.to_le_bytes());
                out[9..17].copy_from_slice(&vote.leader_id.node_id.to_le_bytes());
                out[17] = u8::from(vote.committed);
                2
            }
            Change::Commit(id) => {
                put_id(&mut out[1..], id);
                3
            }
            Change::Truncate(Some(id)) => {
                put_id(&mut out[1..], id);
                4
            }
            Change::Purge(id) => {
                put_id(&mut out[1..], id);
                5
            }
            Change::Truncate(None) => 6,
        };
        out[0] = tag;
    }
}

fn put_id(out: &mut [u8], id: LogId) {
    out[..8].copy_from_slice(&id.leader_id.term.to_le_bytes());
    out[8..16].copy_from_slice(&id.leader_id.node_id.to_le_bytes());
    out[16..24].copy_from_slice(&id.index.to_le_bytes());
}

fn take_id(bytes: &mut &[u8]) -> io::Result<LogId> {
    Ok(LogId::new(
        Leadership {
            term: u64::from_le_bytes(take(bytes)?),
            node_id: u64::from_le_bytes(take(bytes)?),
        },
        u64::from_le_bytes(take(bytes)?),
    ))
}

fn take<const N: usize>(bytes: &mut &[u8]) -> io::Result<[u8; N]> {
    bytes
        .split_off(..N)
        .map(|field| field.try_into().unwrap())
        .ok_or_else(|| invalid_data("short direct WAL operation"))
}

struct Request {
    ops: Vec<Operation>,
    bytes: usize,
    base: Arc<OnceLock<Base>>,
    state: State,
    callback: Option<Flushed>,
    queued: Instant,
    _budget: OwnedSemaphorePermit,
}

pub(super) struct DirectLog {
    index: Index,
    queue: Option<mpsc::Sender<Request>>,
    available: Arc<Semaphore>,
    worker: Option<JoinHandle<io::Result<()>>>,
    metrics: Arc<Mutex<WalMetrics>>,
    _lock: raft_log::chunked_wal::WalLock,
}

impl DirectLog {
    pub(super) fn open(path: &Path, config: &raft_log::chunked_wal::Config) -> io::Result<Self> {
        let lock = ChunkedWal::<raft_log::RaftWalTypes<WalTypes>>::acquire_lock(config)?;
        // Recheck after locking so another opener cannot establish a legacy WAL
        // between backend selection and direct segment creation.
        super::select_direct(path, true)?;
        let mut index = Index::new();
        let journal = Journal::open(path, |event| index.replay(event))?;
        index.validate()?;
        let state = index.state;
        let (queue, rx) = mpsc::channel(QUEUE_ITEMS);
        let metrics = Arc::new(Mutex::new(WalMetrics::default()));
        let available = Arc::new(Semaphore::new(QUEUE_KIB as usize));
        let worker = {
            let metrics = Arc::clone(&metrics);
            let available = Arc::clone(&available);
            thread::Builder::new()
                .name("mqx-wal-direct".into())
                .spawn(move || run_worker(journal, state, rx, &available, &metrics))?
        };
        Ok(Self {
            index,
            queue: Some(queue),
            available,
            worker: Some(worker),
            metrics,
            _lock: lock,
        })
    }

    pub(super) fn state(&self) -> State {
        self.index.state
    }

    pub(super) fn metrics(&self) -> WalMetrics {
        *self.metrics.lock().unwrap()
    }

    pub(super) fn read(
        &self,
        start: u64,
        end: u64,
    ) -> impl Iterator<Item = io::Result<EntryBytes>> + '_ {
        self.index.read(start, end)
    }

    pub(super) async fn append(
        &mut self,
        committed: Option<LogId>,
        encoded: Vec<(Packed<LogId>, EntryBytes)>,
        callback: Flushed,
    ) -> io::Result<()> {
        let mut ops = Vec::with_capacity(encoded.len() + usize::from(committed.is_some()));
        if let Some(id) = committed {
            ops.push(Operation::control(Change::Commit(id)));
        }
        let mut bytes = ops.first().map_or(0, Operation::len);
        for (Packed(id), body) in encoded {
            let op = Operation {
                change: Change::Append(id),
                body: Some(body),
            };
            if op.len() > MAX_BODY {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "direct WAL entry exceeds format limit",
                ));
            }
            if bytes + op.len() > MAX_BODY {
                self.submit(std::mem::take(&mut ops), None).await?;
                bytes = 0;
            }
            bytes += op.len();
            ops.push(op);
        }
        self.submit(ops, Some(callback)).await
    }

    pub(super) async fn control(
        &mut self,
        committed: Option<LogId>,
        control: Option<Change>,
        callback: Option<Flushed>,
    ) -> io::Result<()> {
        let ops = committed
            .map(Change::Commit)
            .into_iter()
            .chain(control)
            .map(Operation::control)
            .collect();
        self.submit(ops, callback).await
    }

    async fn submit(&mut self, ops: Vec<Operation>, callback: Option<Flushed>) -> io::Result<()> {
        let mut state = self.index.state;
        let mut bytes = 0;
        for op in &ops {
            if let Change::Truncate(Some(id)) = op.change
                && state.purged != Some(id)
                && self
                    .index
                    .entries
                    .get(&id.index)
                    .is_none_or(|entry| entry.id != id)
            {
                return Err(invalid_data(
                    "direct WAL truncation does not name a live entry",
                ));
            }
            state.apply(op.change)?;
            bytes += op.len();
        }
        let available = Arc::clone(&self.available);
        let weight = bytes.div_ceil(1024).max(1).min(QUEUE_KIB as usize) as u32;
        let budget = available
            .acquire_many_owned(weight)
            .await
            .map_err(|_| io::ErrorKind::BrokenPipe)?;
        let permit = self
            .queue
            .as_ref()
            .unwrap()
            .reserve()
            .await
            .map_err(|_| io::ErrorKind::BrokenPipe)?;
        let base = Arc::new(OnceLock::new());
        let mut offset = 0;
        for op in &ops {
            let indexed = if let Change::Append(id) = op.change {
                let body = op.body.as_ref().unwrap();
                Some((
                    Indexed::new(
                        id,
                        FrameBase::Pending(Arc::clone(&base)),
                        offset + APPEND_HEADER,
                        &body.0,
                    ),
                    Some(body.clone()),
                ))
            } else {
                None
            };
            self.index.apply(op.change, indexed);
            offset += op.len();
        }
        self.index.state = state;
        self.index.evict();
        permit.send(Request {
            ops,
            bytes,
            base,
            state,
            callback,
            queued: Instant::now(),
            _budget: budget,
        });
        Ok(())
    }

    pub(super) fn shutdown(&mut self) -> io::Result<()> {
        drop(self.queue.take());
        if let Some(worker) = self.worker.take() {
            worker
                .join()
                .map_err(|_| io::Error::other("direct WAL worker panicked"))??;
        }
        Ok(())
    }
}

impl Drop for DirectLog {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

fn run_worker(
    mut journal: Journal,
    mut state: State,
    mut rx: mpsc::Receiver<Request>,
    available: &Semaphore,
    metrics: &Mutex<WalMetrics>,
) -> io::Result<()> {
    let mut group = Vec::with_capacity(QUEUE_ITEMS);
    let mut next = None;
    while let Some(first) = next.take().or_else(|| rx.blocking_recv()) {
        let mut bytes = first.bytes;
        group.push(first);
        while group.len() < QUEUE_ITEMS && bytes < GROUP_BYTES {
            let Ok(request) = rx.try_recv() else { break };
            if bytes + request.bytes > GROUP_BYTES {
                next = Some(request);
                break;
            }
            bytes += request.bytes;
            group.push(request);
        }
        let result = write_group(&mut journal, state, &group, bytes, metrics);
        let purged = group.last().unwrap().state.purged;
        state = group.last().unwrap().state;
        complete(group.drain(..), &result);
        let result = result.and_then(|()| {
            if let Some(purged) = purged {
                journal.reap(purged.index)?;
            }
            Ok(())
        });
        if let Err(error) = result {
            available.close();
            rx.close();
            let result = Err(error);
            complete(next.take(), &result);
            while let Some(request) = rx.blocking_recv() {
                complete([request], &result);
            }
            return result;
        }
    }
    Ok(())
}

fn write_group(
    journal: &mut Journal,
    previous: State,
    group: &[Request],
    bytes: usize,
    metrics: &Mutex<WalMetrics>,
) -> io::Result<()> {
    if bytes == 0 {
        return Ok(());
    }
    let started = Instant::now();
    let max_index = group
        .iter()
        .flat_map(|request| &request.ops)
        .filter_map(|op| match op.change {
            Change::Append(id) => Some(id.index),
            _ => None,
        })
        .max();
    let base = journal.frame(bytes, previous, max_index, |frame| {
        let mut offset = 0;
        for op in group.iter().flat_map(|request| &request.ops) {
            let end = offset + op.len();
            op.encode(&mut frame[offset..end]);
            offset = end;
        }
    });
    let elapsed = started.elapsed();
    {
        let mut metrics = metrics.lock().unwrap();
        metrics.sync_batches += 1;
        metrics.sync_time += elapsed;
        metrics.sync_max = metrics.sync_max.max(elapsed);
        // The direct backend fuses write and data sync into one operation.
        metrics.write_max = metrics.write_max.max(elapsed);
        metrics.queue_wait_max = metrics
            .queue_wait_max
            .max(started.duration_since(group[0].queued));
    }
    let mut base = base?;
    for request in group {
        let _ = request.base.set(base.clone());
        base.offset += request.bytes as u64;
    }
    Ok(())
}

fn complete(requests: impl IntoIterator<Item = Request>, result: &io::Result<()>) {
    for Request { callback, .. } in requests {
        if let Some(callback) = callback {
            callback.send(
                result
                    .as_ref()
                    .copied()
                    .map_err(|error| io::Error::new(error.kind(), error.to_string())),
            );
        }
    }
}
