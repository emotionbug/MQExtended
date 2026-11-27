use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

#[cfg(unix)]
use crate::MAX_STORAGE_RESERVE;
use crate::snapshot::SNAPSHOT_FILE;
use crate::survivor::DISCARDED;

pub(crate) const RESERVE_FILE: &str = "reserve.mqx";
pub(crate) const STAGED_RESERVE_FILE: &str = "reserve.mqx.new";
const ARCHIVE_RETENTION: Duration = Duration::from_secs(7 * 24 * 60 * 60);

pub(crate) struct Space {
    pub(crate) available: u64,
    pub(crate) target: u64,
}

impl Space {
    #[cfg(unix)]
    fn for_volume(available: u64, capacity: u64) -> Self {
        const MIB: u64 = 1024 * 1024;
        Self {
            available,
            target: (capacity / 20).clamp(64 * MIB, MAX_STORAGE_RESERVE),
        }
    }
}

#[cfg(unix)]
pub(crate) fn read_space(dir: &Path) -> io::Result<Space> {
    let volume = nix::sys::statvfs::statvfs(dir)?;
    let bytes = |blocks| {
        (u128::from(blocks) * u128::from(volume.fragment_size())).min(u128::from(u64::MAX)) as u64
    };
    Ok(Space::for_volume(
        bytes(volume.blocks_available()),
        bytes(volume.blocks()),
    ))
}

#[cfg(not(unix))]
pub(crate) fn read_space(_dir: &Path) -> io::Result<Space> {
    Ok(Space {
        available: 0,
        target: 0,
    })
}

#[derive(Default)]
pub(crate) struct StorageMetrics {
    available: AtomicU64,
    reserve: AtomicU64,
    pressure: AtomicBool,
}

impl StorageMetrics {
    pub(crate) fn bytes(&self) -> (u64, u64) {
        (
            self.available.load(Ordering::Relaxed),
            self.reserve.load(Ordering::Relaxed),
        )
    }

    pub(crate) fn under_pressure(&self) -> bool {
        self.pressure.load(Ordering::Relaxed)
    }
}

pub(crate) struct Storage<F> {
    dir: PathBuf,
    reserve_target: Option<u64>,
    read_space: F,
    metrics: Arc<StorageMetrics>,
    startup_compaction: bool,
    compaction_requested: bool,
}

impl<F: Fn(&Path) -> io::Result<Space>> Storage<F> {
    pub(crate) fn start(dir: PathBuf, reserve_target: Option<u64>, read_space: F) -> Self {
        let mut storage = Self {
            dir,
            reserve_target,
            read_space,
            metrics: Arc::default(),
            startup_compaction: false,
            compaction_requested: false,
        };
        // A crash during preallocation can leave all the space in the staging
        // file instead. Remove it before statvfs and before the WAL opens.
        if storage.report(remove_regular(&storage.dir.join(STAGED_RESERVE_FILE))) == Some(true) {
            let _ = storage.report(storage.sync_dir());
        }
        let reserve = storage.dir.join(RESERVE_FILE);
        if let Some(Some(metadata)) = storage.report(regular(&reserve)) {
            let bytes = metadata.len();
            // Release an old reserve before applying a changed fixed size, so
            // those blocks also count towards the new headroom check.
            let obsolete = reserve_target.is_some_and(|target| target == 0 || target != bytes);
            if obsolete && let Some(removed) = storage.report(remove_regular(&reserve)) {
                if removed {
                    let _ = storage.report(storage.sync_dir());
                }
            } else {
                storage.metrics.reserve.store(bytes, Ordering::Relaxed);
            }
        }
        let snapshot_size = storage
            .report(regular(&storage.dir.join(SNAPSHOT_FILE)))
            .flatten()
            .map_or(0, |metadata| metadata.len());
        storage.startup_compaction = storage.check(true, snapshot_size);
        storage
    }

    pub(crate) fn metrics(&self) -> Arc<StorageMetrics> {
        self.metrics.clone()
    }

    pub(crate) fn take_startup_compaction(&mut self) -> bool {
        std::mem::take(&mut self.startup_compaction)
    }

    /// Request emergency compaction once per low-space episode when the reserve is enabled.
    pub(crate) fn check(&mut self, sweep_archive: bool, snapshot_size: u64) -> bool {
        let Some(Space { available, target }) = self.report((self.read_space)(&self.dir)) else {
            if sweep_archive {
                let _ = self.report(self.expire_archive(false));
            }
            return false;
        };
        let target = self.reserve_target.unwrap_or(target);
        let headroom = target.saturating_add(snapshot_size);
        let low = available < headroom;
        // With no reserve, snapshot headroom still protects admission but
        // doesn't authorize emergency compaction or early archive deletion.
        let reclaim = target != 0 && low;
        let was_under_pressure = self.metrics.under_pressure();
        let request_compaction = reclaim && !self.compaction_requested;
        if request_compaction {
            tracing::warn!(path = %self.dir.display(), available_bytes = available, reserve_target_bytes = target,
                "Cluster data volume is low on space; releasing the reserve and discarding recovery archives");
        }
        let mut refresh = false;
        if reclaim
            && self.metrics.reserve.load(Ordering::Relaxed) != 0
            && let Some(removed) = self.report(remove_regular(&self.dir.join(RESERVE_FILE)))
        {
            self.metrics.reserve.store(0, Ordering::Relaxed);
            refresh |= removed;
            if removed {
                let _ = self.report(self.sync_dir());
            }
        }
        if reclaim || sweep_archive {
            // A failed recursive deletion can still have freed space.
            refresh |= self.report(self.expire_archive(reclaim)).unwrap_or(true);
        }
        // Allocating the reserve must leave room for both normal operation
        // and a replacement snapshot, even when the snapshot dwarfs the reserve.
        if target != 0
            && available.saturating_sub(target) > headroom.saturating_mul(2)
            && self.metrics.reserve.load(Ordering::Relaxed) != target
        {
            refresh = true;
            if self.report(self.create_reserve(target)).is_some() {
                self.metrics.reserve.store(target, Ordering::Relaxed);
                let _ = self.report(self.sync_dir());
            }
        }
        let available = if refresh {
            self.report((self.read_space)(&self.dir))
                .map_or(available, |space| space.available)
        } else {
            available
        };
        self.metrics.available.store(available, Ordering::Relaxed);
        let pressure = cfg!(unix) && under_pressure(was_under_pressure || low, available, headroom);
        self.metrics.pressure.store(pressure, Ordering::Relaxed);
        // A refresh can detect pressure before the next poll attempts
        // reclamation. Re-arm when measured pressure clears, not when the
        // reserve is finally restored.
        self.compaction_requested = pressure && (self.compaction_requested || request_compaction);
        if target != 0 && was_under_pressure && !pressure {
            tracing::info!(path = %self.dir.display(), available_bytes = available,
                "Cluster data volume recovered from storage pressure");
        }
        request_compaction
    }

    fn expire_archive(&self, pressure: bool) -> io::Result<bool> {
        let path = self.dir.join(DISCARDED);
        let metadata = match path.symlink_metadata() {
            Ok(metadata) if metadata.is_dir() => metadata,
            Ok(_) => return Ok(false), // Never follow or remove a symlink here.
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
        };
        if pressure
            || metadata
                .modified()?
                .elapsed()
                .is_ok_and(|age| age > ARCHIVE_RETENTION)
        {
            fs::remove_dir_all(path)?;
            let _ = self.report(self.sync_dir());
            return Ok(true);
        }
        Ok(false)
    }

    fn create_reserve(&self, bytes: u64) -> io::Result<()> {
        let path = self.dir.join(RESERVE_FILE);
        regular(&path)?;
        let stage = self.dir.join(STAGED_RESERVE_FILE);
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&stage)?;
        let result = allocate(&mut file, bytes).and_then(|()| file.sync_all());
        drop(file);
        let result = result.and_then(|()| fs::rename(&stage, path));
        if result.is_err() {
            let _ = self.report(remove_regular(&stage));
        }
        result
    }

    fn sync_dir(&self) -> io::Result<()> {
        File::open(&self.dir)?.sync_all()
    }

    fn report<T>(&self, result: io::Result<T>) -> Option<T> {
        result
            .inspect_err(|error| tracing::warn!(path = %self.dir.display(), %error, "Cluster storage maintenance failed"))
            .ok()
    }
}

fn under_pressure(active: bool, available: u64, headroom: u64) -> bool {
    let threshold = if active {
        headroom.saturating_mul(2)
    } else {
        headroom
    };
    available < threshold
}

fn regular(path: &Path) -> io::Result<Option<fs::Metadata>> {
    match path.symlink_metadata() {
        Ok(metadata) if metadata.is_file() => Ok(Some(metadata)),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "storage reserve is not a regular file",
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn remove_regular(path: &Path) -> io::Result<bool> {
    if regular(path)?.is_none() {
        return Ok(false);
    }
    fs::remove_file(path)?;
    Ok(true)
}

fn allocate(file: &mut File, mut bytes: u64) -> io::Result<()> {
    use std::io::Write;

    // Darwin and other Unix targets without posix_fallocate take the write path.
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "freebsd",
        target_os = "dragonfly",
        target_os = "fuchsia"
    ))]
    match nix::fcntl::posix_fallocate(&*file, 0, bytes as nix::libc::off_t) {
        Ok(()) => return Ok(()),
        Err(
            nix::errno::Errno::EOPNOTSUPP | nix::errno::Errno::ENOSYS | nix::errno::Errno::EINVAL,
        ) => {}
        Err(error) => return Err(error.into()),
    }
    static ZEROES: [u8; 64 * 1024] = [0; 64 * 1024];
    while bytes != 0 {
        let chunk = bytes.min(ZEROES.len() as u64) as usize;
        file.write_all(&ZEROES[..chunk])?;
        bytes -= chunk as u64;
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::os::unix::fs::MetadataExt;
    use std::time::SystemTime;

    #[test]
    fn reserve_target_is_five_percent_of_volume_clamped() {
        const MIB: u64 = 1024 * 1024;
        assert_eq!(Space::for_volume(0, 100 * MIB).target, 64 * MIB);
        assert_eq!(Space::for_volume(0, 2000 * MIB).target, 100 * MIB);
        assert_eq!(Space::for_volume(0, 32 * 1024 * MIB).target, 1024 * MIB);
    }

    #[test]
    fn hysteresis_releases_reserve_and_young_archive_without_touching_live_state() {
        const TARGET: u64 = 16 * 1024;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let unreserved = Cell::new(5 * TARGET);
        let reserve = root.join(RESERVE_FILE);
        let archive = root.join(DISCARDED);
        let interrupted = archive.join("interrupted-switch");
        fs::create_dir_all(&interrupted).unwrap();
        fs::write(interrupted.join("archive"), b"partial recovery").unwrap();
        let live = [
            "wal/chunk",
            "snapshot.mpk",
            crate::survivor::IDENTITY_FILE,
            crate::survivor::LOCK_FILE,
            "unrelated",
        ];
        fs::create_dir(root.join("wal")).unwrap();
        for name in live {
            fs::write(root.join(name), name).unwrap();
        }
        let mut storage = Storage::start(root.to_path_buf(), None, |_| {
            Ok(Space {
                available: unreserved.get() - reserve.metadata().map_or(0, |m| m.len()),
                target: TARGET,
            })
        });
        assert!(interrupted.is_dir());
        assert_eq!(storage.metrics.bytes(), (4 * TARGET, TARGET));
        assert!(reserve.metadata().unwrap().blocks() * 512 >= TARGET);

        // A replacement snapshot needs another TARGET of headroom. Waiting
        // until less than the reserve remains would risk ENOSPC during compaction.
        unreserved.set(3 * TARGET);
        assert!(!storage.check(false, TARGET));
        assert!(reserve.is_file());
        unreserved.set(3 * TARGET - 1);
        assert!(storage.check(false, TARGET));
        assert!(!reserve.exists());
        assert!(!archive.exists());
        assert_eq!(storage.metrics.bytes(), (3 * TARGET - 1, 0));
        assert!(storage.metrics.under_pressure());
        assert!(
            !storage.check(false, TARGET),
            "only one compaction request per episode"
        );

        unreserved.set(4 * TARGET - 1);
        assert!(!storage.check(false, TARGET));
        assert!(storage.metrics.under_pressure());
        unreserved.set(4 * TARGET);
        assert!(!storage.check(false, TARGET));
        assert!(!storage.metrics.under_pressure());
        assert!(!reserve.exists());

        unreserved.set(2 * TARGET - 1);
        assert!(
            storage.check(false, TARGET),
            "a new episode must request compaction before the reserve is restored"
        );
        assert!(storage.metrics.under_pressure());
        assert!(!storage.check(false, TARGET));

        unreserved.set(5 * TARGET);
        assert!(!storage.check(false, TARGET));
        assert!(!reserve.exists());
        assert!(!storage.metrics.under_pressure());
        unreserved.set(5 * TARGET + 1);
        assert!(!storage.check(false, TARGET));
        assert!(reserve.metadata().unwrap().blocks() * 512 >= TARGET);
        assert_eq!(storage.metrics.bytes(), (4 * TARGET + 1, TARGET));
        assert!(!storage.metrics.under_pressure());
        for name in live {
            assert_eq!(fs::read(root.join(name)).unwrap(), name.as_bytes());
        }
    }

    #[test]
    fn startup_archive_reclamation_clears_pressure_without_losing_compaction() {
        const TARGET: u64 = 4096;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let reserve = root.join(RESERVE_FILE);
        let archive = root.join(DISCARDED);
        File::create(&reserve).unwrap().set_len(TARGET).unwrap();
        File::create(root.join(SNAPSHOT_FILE))
            .unwrap()
            .set_len(TARGET)
            .unwrap();
        fs::create_dir(&archive).unwrap();
        let unreserved = Cell::new(4 * TARGET);
        let mut storage = Storage::start(root.to_path_buf(), Some(TARGET), |_| {
            let archive_bytes = if archive.is_dir() { 2 * TARGET } else { 0 };
            Ok(Space {
                available: unreserved.get()
                    - archive_bytes
                    - reserve.metadata().map_or(0, |m| m.len()),
                target: TARGET,
            })
        });

        assert!(!reserve.exists());
        assert!(!archive.exists());
        assert_eq!(storage.metrics.bytes(), (4 * TARGET, 0));
        assert!(!storage.metrics.under_pressure());
        assert!(storage.take_startup_compaction());
        assert!(!storage.take_startup_compaction());
        assert!(!storage.check(false, TARGET));

        unreserved.set(2 * TARGET - 1);
        assert!(storage.check(false, TARGET));
        assert!(storage.metrics.under_pressure());
        assert!(!storage.check(false, TARGET));
    }

    #[test]
    fn pressure_detected_after_reserve_allocation_still_requests_compaction() {
        const TARGET: u64 = 4096;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let reserve = root.join(RESERVE_FILE);
        let unreserved = Cell::new(2 * TARGET);
        let mut storage = Storage::start(root.to_path_buf(), Some(TARGET), |_| {
            // Model another writer consuming space by the time allocation finishes.
            let available = if reserve.is_file() {
                TARGET - 1
            } else {
                unreserved.get()
            };
            Ok(Space {
                available,
                target: TARGET,
            })
        });
        unreserved.set(4 * TARGET);
        assert!(!storage.check(false, 0));
        assert_eq!(storage.metrics.bytes(), (TARGET - 1, TARGET));
        assert!(storage.metrics.under_pressure());

        unreserved.set(2 * TARGET - 1);
        assert!(storage.check(false, 0));
        assert_eq!(storage.metrics.bytes(), (2 * TARGET - 1, 0));
        assert!(storage.metrics.under_pressure());
        assert!(!storage.check(false, 0));
    }

    #[test]
    fn archive_age_uses_directory_mtime_and_only_sweeps_directories() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let archive = root.join(DISCARDED);
        let old = SystemTime::now() - ARCHIVE_RETENTION - Duration::from_secs(60);
        let populate = || {
            fs::create_dir(&archive).unwrap();
            fs::write(archive.join("recent-file"), b"state").unwrap();
            File::open(&archive).unwrap().set_modified(old).unwrap();
        };
        populate();
        let reserve = root.join(RESERVE_FILE);
        fs::write(&reserve, b"old reserve").unwrap();
        let available = Cell::new(0);
        let mut storage = Storage::start(root.to_path_buf(), Some(0), |_| {
            Ok(Space {
                available: available.get(),
                target: 4096,
            })
        });
        assert!(!archive.exists());
        assert!(!reserve.exists());
        assert_eq!(storage.metrics.bytes(), (0, 0));
        fs::create_dir(&archive).unwrap();
        assert!(!storage.check(false, 4096));
        assert!(storage.metrics.under_pressure());
        assert!(
            archive.is_dir(),
            "disabled reserve must not discard on pressure"
        );
        fs::remove_dir(&archive).unwrap();
        populate();
        assert!(!storage.check(false, 4096));
        assert!(archive.exists());
        assert!(!storage.check(true, 4096));
        assert!(!archive.exists());
        assert!(storage.metrics.under_pressure());

        available.set(8191);
        assert!(!storage.check(false, 4096));
        assert!(storage.metrics.under_pressure());
        available.set(8192);
        assert!(!storage.check(false, 4096));
        assert!(!storage.metrics.under_pressure());

        let other = root.join("other");
        fs::create_dir(&other).unwrap();
        fs::write(other.join("keep"), b"shared state").unwrap();
        std::os::unix::fs::symlink(&other, &archive).unwrap();
        storage.expire_archive(true).unwrap();
        assert!(archive.is_symlink());
        assert_eq!(fs::read(other.join("keep")).unwrap(), b"shared state");
    }
}
