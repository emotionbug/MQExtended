//! An initialized segment is immutable behind its append cursor. No write
//! after a successful DSYNC touches any block in the acknowledged frame.
use std::collections::VecDeque;
use std::fs::{self, File};
use std::io::{self, IoSlice, Write};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread::{self, JoinHandle};

use rustix::fs::{AtFlags, Mode, OFlags, StatxFlags, fstatfs, open, statx};
use rustix::io::{Errno, ReadWriteFlags, pwritev2};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;

use super::State;
use crate::transport::invalid_data;
use crate::wal::{DIRECT_SEGMENT_PREFIX, direct_guard_name, wal_chunk_files};

const BLOCK: usize = 4096;
const SEGMENT_BYTES: usize = 16 * 1024 * 1024;
const VERSION: u8 = 1;
const GUARD: &[u8] = b"MQX-DIRECT-WAL\x01";
const FRAME: &[u8; 8] = b"MQXFRAME";
const END_FRAME: &[u8; 8] = b"MQXF-END";
const HEADER: usize = 12;
const FOOTER: usize = 40;
const SPARE_PREFIX: &str = ".mqx-direct-spare-";

// Physical format bound, independent of the current node's configured packet
// limit. An existing WAL must reopen after a legal packet limit is lowered.
pub(super) const MAX_BODY: usize = crate::MAX_PACKET_SIZE + 4 * crate::PACKET_ENVELOPE;

#[derive(Clone)]
pub(super) struct Base {
    pub(super) file: Arc<File>,
    pub(super) offset: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Seal {
    end: u64,
    digest: [u8; 32],
}

#[derive(Serialize, Deserialize)]
struct Genesis {
    segment: u64,
    capacity: u64,
    previous: Option<Seal>,
    state: State,
}

pub(super) enum Replay<'a> {
    Start(State, Option<u64>),
    Frame(Base, &'a [u8]),
}

struct Segment {
    id: u64,
    file: Arc<File>,
    capacity: u64,
    seal: Seal,
    max_index: Option<u64>,
}

struct Prepared {
    temporary: NamedTempFile,
    direct: File,
}

pub(super) struct Journal {
    dir: PathBuf,
    directory: File,
    closed: VecDeque<(u64, Option<u64>)>,
    active: Segment,
    direct: File,
    spare: Option<JoinHandle<io::Result<Prepared>>>,
    aligned: Aligned,
}

impl Journal {
    pub(super) fn open(
        dir: &Path,
        mut replay: impl FnMut(Replay<'_>) -> io::Result<Option<u64>>,
    ) -> io::Result<Self> {
        // Caller holds the same directory lock as the legacy backend.
        let directory = File::open(dir)?;
        let mut files = wal_chunk_files(dir)?;
        let guarded = if files.last().is_some_and(|(id, _)| *id == u64::MAX) {
            let (_, path) = files.pop().unwrap();
            let mut magic = [0; GUARD.len()];
            let file = File::open(path)?;
            if file.metadata()?.len() != GUARD.len() as u64 {
                return Err(invalid_data("corrupt direct WAL format guard"));
            }
            file.read_exact_at(&mut magic, 0)?;
            if !magic.starts_with(&GUARD[..GUARD.len() - 1]) {
                return Err(invalid_data("corrupt direct WAL format guard"));
            }
            if magic != GUARD {
                return Err(unsupported("unsupported direct WAL format guard version"));
            }
            if files.is_empty() {
                return Err(invalid_data("direct WAL lost all segments"));
            }
            true
        } else {
            false
        };

        remove_stale_spares(dir)?;
        let mut closed = VecDeque::new();
        let mut active: Option<Segment> = None;
        let mut scratch = Vec::new();
        for (id, path) in files {
            let previous = active.as_ref().map(|segment| (segment.id, segment.seal));
            let recovered = scan(id, &path, previous, &mut scratch, &mut replay)?;
            if let Some(segment) = active.replace(recovered) {
                closed.push_back((segment.id, segment.max_index));
            }
        }
        let (active, direct) = if let Some(active) = active {
            let direct = checked_open(&dir.join(chunk_name(active.id)))?;
            // The last complete frame might have reached the device without
            // the original process observing its DSYNC completion.
            direct.sync_data()?;
            (active, direct)
        } else {
            install(
                dir,
                &directory,
                prepare(dir, SEGMENT_BYTES)?,
                0,
                None,
                State::default(),
            )?
        };
        if !guarded {
            // Publish after the first segment: a durable guard with no
            // remaining segments is corruption, not an empty direct store.
            let mut guard = temporary(dir)?;
            guard.write_all(GUARD)?;
            guard.as_file().sync_all()?;
            guard
                .persist_noclobber(dir.join(direct_guard_name()))
                .map_err(|error| error.error)?;
            directory.sync_all()?;
        }
        Ok(Self {
            dir: dir.to_path_buf(),
            directory,
            closed,
            active,
            direct,
            spare: Some(start_spare(dir)?),
            aligned: Aligned::default(),
        })
    }

    pub(super) fn frame(
        &mut self,
        bytes: usize,
        previous_state: State,
        max_index: Option<u64>,
        fill: impl FnOnce(&mut [u8]),
    ) -> io::Result<Base> {
        let size = frame_size(bytes)?;
        if self.active.seal.end + size as u64 > self.active.capacity {
            self.rotate(BLOCK + size, previous_state)?;
        }
        let offset = self.active.seal.end;
        let frame = self.aligned.get(size);
        frame[..8].copy_from_slice(FRAME);
        frame[8..HEADER].copy_from_slice(&(bytes as u32).to_le_bytes());
        fill(&mut frame[HEADER..HEADER + bytes]);
        frame[HEADER + bytes..size - FOOTER].fill(0);
        let digest = checksum(self.active.id, offset, &frame[..size - FOOTER]);
        frame[size - FOOTER..size - 8].copy_from_slice(&digest);
        frame[size - 8..].copy_from_slice(END_FRAME);
        durable_write(&self.direct, frame, offset)?;
        self.active.seal = Seal {
            end: offset + size as u64,
            digest,
        };
        self.active.max_index = self.active.max_index.max(max_index);
        Ok(Base {
            file: Arc::clone(&self.active.file),
            offset: offset + HEADER as u64,
        })
    }

    fn rotate(&mut self, min_size: usize, state: State) -> io::Result<()> {
        let next = self
            .active
            .id
            .checked_add(1)
            .filter(|id| *id != u64::MAX)
            .ok_or_else(|| invalid_data("direct WAL exhausted its segment IDs"))?;
        let prepared = if min_size > SEGMENT_BYTES {
            prepare(&self.dir, min_size)?
        } else {
            let spare = self.spare.take().unwrap();
            spare
                .join()
                .map_err(|_| io::Error::other("direct WAL prewriter panicked"))??
        };
        let (active, direct) = install(
            &self.dir,
            &self.directory,
            prepared,
            next,
            Some(self.active.seal),
            state,
        )?;
        self.closed
            .push_back((self.active.id, self.active.max_index));
        self.active = active;
        self.direct = direct;
        if self.spare.is_none() {
            self.spare = Some(start_spare(&self.dir)?);
        }
        Ok(())
    }

    pub(super) fn reap(&mut self, purged: u64) -> io::Result<()> {
        while let Some((segment, max)) = self.closed.front().copied() {
            if max.is_some_and(|index| index > purged) {
                break;
            }
            fs::remove_file(self.dir.join(chunk_name(segment)))?;
            // Each unlink becomes durable before the next one so a crash
            // cannot leave a gap in the retained segment suffix.
            self.directory.sync_all()?;
            self.closed.pop_front();
        }
        Ok(())
    }
}

impl Drop for Journal {
    fn drop(&mut self) {
        if let Some(spare) = self.spare.take() {
            let _ = spare.join();
        }
    }
}

fn scan(
    id: u64,
    path: &Path,
    previous: Option<(u64, Seal)>,
    scratch: &mut Vec<u8>,
    replay: &mut impl FnMut(Replay<'_>) -> io::Result<Option<u64>>,
) -> io::Result<Segment> {
    let file = Arc::new(File::open(path)?);
    let capacity = file.metadata()?.len();
    // A published segment has a durable genesis and fixed length. Only
    // unpublished temporary inodes can be incomplete.
    if !(BLOCK as u64..=(BLOCK + frame_size(MAX_BODY)?) as u64).contains(&capacity)
        || capacity % BLOCK as u64 != 0
    {
        return Err(invalid_data("wrong direct WAL segment size"));
    }
    let mut page = [0; BLOCK];
    file.read_exact_at(&mut page, 0)?;
    if !page.starts_with(DIRECT_SEGMENT_PREFIX) {
        return Err(invalid_data("missing direct WAL segment header"));
    }
    if page[7] != VERSION {
        return Err(unsupported("unsupported direct WAL segment version"));
    }
    let header_size = u32::from_le_bytes(page[8..12].try_into().unwrap()) as usize;
    if header_size == 0 || header_size > BLOCK - HEADER - 32 {
        return Err(invalid_data("wrong direct WAL segment header length"));
    }
    let digest = checksum(id, 0, &page[..BLOCK - 32]);
    if page[BLOCK - 32..] != digest {
        return Err(invalid_data("invalid direct WAL segment header checksum"));
    }
    let header: Genesis =
        rmp_serde::from_slice(&page[HEADER..HEADER + header_size]).map_err(invalid_data)?;
    if header.segment != id
        || header.capacity != capacity
        || (id == 0) != header.previous.is_none()
        || (id == 0 && header.state != State::default())
        || previous
            .is_some_and(|(prev_id, seal)| id != prev_id + 1 || header.previous != Some(seal))
    {
        return Err(invalid_data("wrong direct WAL segment chain"));
    }
    replay(Replay::Start(
        header.state,
        previous.is_none().then_some(id),
    ))?;
    let mut seal = Seal {
        end: BLOCK as u64,
        digest,
    };
    let mut max_index = None;
    while seal.end < capacity {
        let offset = seal.end;
        file.read_exact_at(&mut page, offset)?;
        if page.iter().all(|byte| *byte == 0) {
            // Do not consider the first zero page EOF until the prewritten
            // suffix is accounted for. A hole before later data is corruption.
            scratch.resize(64 * 1024, 0);
            let mut tail = offset + BLOCK as u64;
            while tail < capacity {
                let len = ((capacity - tail) as usize).min(scratch.len());
                file.read_exact_at(&mut scratch[..len], tail)?;
                if scratch[..len].iter().any(|byte| *byte != 0) {
                    return Err(invalid_data("interior zero gap in direct WAL"));
                }
                tail += len as u64;
            }
            break;
        }
        if !page.starts_with(FRAME) {
            return Err(invalid_data("invalid or torn direct WAL frame header"));
        }
        let bytes = u32::from_le_bytes(page[8..HEADER].try_into().unwrap()) as usize;
        let size = frame_size(bytes).map_err(invalid_data)?;
        if offset + size as u64 > capacity {
            return Err(invalid_data("direct WAL frame exceeds segment"));
        }
        scratch.resize(size, 0);
        scratch[..BLOCK].copy_from_slice(&page);
        if size > BLOCK {
            file.read_exact_at(&mut scratch[BLOCK..], offset + BLOCK as u64)?;
        }
        let digest = checksum(id, offset, &scratch[..size - FOOTER]);
        if &scratch[size - 8..] != END_FRAME
            || scratch[size - FOOTER..size - 8] != digest
            || scratch[HEADER + bytes..size - FOOTER]
                .iter()
                .any(|byte| *byte != 0)
        {
            return Err(invalid_data("invalid or torn direct WAL frame checksum"));
        }
        max_index = max_index.max(replay(Replay::Frame(
            Base {
                file: Arc::clone(&file),
                offset: offset + HEADER as u64,
            },
            &scratch[HEADER..HEADER + bytes],
        ))?);
        seal = Seal {
            end: offset + size as u64,
            digest,
        };
    }
    Ok(Segment {
        id,
        file,
        capacity,
        seal,
        max_index,
    })
}

fn frame_size(bytes: usize) -> io::Result<usize> {
    if !(1..=MAX_BODY).contains(&bytes) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "direct WAL frame size",
        ));
    }
    Ok((HEADER + bytes + FOOTER).next_multiple_of(BLOCK))
}

fn checksum(id: u64, offset: u64, body: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(id.to_le_bytes());
    hash.update(offset.to_le_bytes());
    hash.update(body);
    hash.finalize().into()
}

fn chunk_name(id: u64) -> String {
    raft_log::chunked_wal::Config::chunk_file_name(raft_log::ChunkId(id))
}

fn install(
    dir: &Path,
    directory: &File,
    prepared: Prepared,
    id: u64,
    previous: Option<Seal>,
    state: State,
) -> io::Result<(Segment, File)> {
    let Prepared { temporary, direct } = prepared;
    let capacity = direct.metadata()?.len();
    let header = rmp_serde::to_vec(&Genesis {
        segment: id,
        capacity,
        previous,
        state,
    })
    .map_err(invalid_data)?;
    assert!(
        header.len() <= BLOCK - HEADER - 32,
        "direct WAL genesis must fit one block"
    );
    let mut aligned = Aligned::default();
    let frame = aligned.get(BLOCK);
    frame[..7].copy_from_slice(DIRECT_SEGMENT_PREFIX);
    frame[7] = VERSION;
    frame[8..HEADER].copy_from_slice(&(header.len() as u32).to_le_bytes());
    frame[HEADER..HEADER + header.len()].copy_from_slice(&header);
    let digest = checksum(id, 0, &frame[..BLOCK - 32]);
    frame[BLOCK - 32..].copy_from_slice(&digest);
    durable_write(&direct, frame, 0)?;
    let file = temporary
        .persist_noclobber(dir.join(chunk_name(id)))
        .map_err(|error| error.error)?;
    directory.sync_all()?;
    let segment = Segment {
        id,
        file: Arc::new(file),
        capacity,
        seal: Seal {
            end: BLOCK as u64,
            digest,
        },
        max_index: None,
    };
    Ok((segment, direct))
}

fn temporary(dir: &Path) -> io::Result<NamedTempFile> {
    tempfile::Builder::new()
        .prefix(SPARE_PREFIX)
        .tempfile_in(dir)
}

fn start_spare(dir: &Path) -> io::Result<JoinHandle<io::Result<Prepared>>> {
    let dir = dir.to_owned();
    thread::Builder::new()
        .name("mqx-wal-prepare".into())
        .spawn(move || prepare(&dir, SEGMENT_BYTES))
}

fn prepare(dir: &Path, size: usize) -> io::Result<Prepared> {
    let mut temporary = temporary(dir)?;
    let direct = checked_open(temporary.path())?;
    // Real writes convert the file into initialized extents. set_len or
    // fallocate alone leaves holes/unwritten extents and is not equivalent.
    let zeros = [0; 64 * 1024];
    for offset in (0..size).step_by(zeros.len()) {
        temporary.write_all(&zeros[..(size - offset).min(zeros.len())])?;
    }
    temporary.as_file().sync_data()?;
    Ok(Prepared { temporary, direct })
}

fn remove_stale_spares(dir: &Path) -> io::Result<()> {
    for entry in dir.read_dir()? {
        let entry = entry?;
        if entry
            .file_name()
            .as_encoded_bytes()
            .starts_with(SPARE_PREFIX.as_bytes())
        {
            fs::remove_file(entry.path())?;
        }
    }
    Ok(())
}

fn checked_open(path: &Path) -> io::Result<File> {
    let direct = open(
        path,
        OFlags::RDWR | OFlags::DIRECT | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(required_direct_io)?;
    let stat = statx(&direct, "", AtFlags::EMPTY_PATH, StatxFlags::DIOALIGN)
        .map_err(required_direct_io)?;
    let filesystem = fstatfs(&direct)?;
    let fs_block = usize::try_from(filesystem.f_bsize).unwrap_or(0);
    let aligned = |n: u32| n != 0 && BLOCK.is_multiple_of(n as usize);
    if !StatxFlags::from_bits_retain(stat.stx_mask).contains(StatxFlags::DIOALIGN)
        || !aligned(stat.stx_dio_mem_align)
        || !aligned(stat.stx_dio_offset_align)
        || fs_block == 0
        || !BLOCK.is_multiple_of(fs_block)
    {
        return Err(unsupported(
            "filesystem does not report compatible direct WAL alignment",
        ));
    }
    Ok(direct.into())
}

fn durable_write(file: &File, bytes: &[u8], offset: u64) -> io::Result<()> {
    debug_assert!(bytes.as_ptr().align_offset(BLOCK) == 0);
    debug_assert!(bytes.len().is_multiple_of(BLOCK) && offset.is_multiple_of(BLOCK as u64));
    let len = pwritev2(file, &[IoSlice::new(bytes)], offset, ReadWriteFlags::DSYNC)
        .map_err(required_direct_io)?;
    if len != bytes.len() {
        // Never retry a short write across a block that may already contain
        // torn data. Stop the worker and let recovery validate the frame.
        return Err(io::ErrorKind::WriteZero.into());
    }
    Ok(())
}

fn required_direct_io(error: Errno) -> io::Error {
    if matches!(error, Errno::NOTSUP | Errno::INVAL | Errno::NOSYS) {
        unsupported(format!(
            "direct WAL requires O_DIRECT and RWF_DSYNC: {error}"
        ))
    } else {
        error.into()
    }
}

fn unsupported(message: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, message)
}

#[derive(Default)]
struct Aligned(Vec<u8>);

impl Aligned {
    fn get(&mut self, size: usize) -> &mut [u8] {
        if self.0.len() < size + BLOCK - 1 {
            self.0.resize(size + BLOCK - 1, 0);
        }
        let start = self.0.as_ptr().align_offset(BLOCK);
        &mut self.0[start..start + size]
    }
}
