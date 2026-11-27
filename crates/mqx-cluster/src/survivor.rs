use std::cmp::Reverse;
use std::collections::VecDeque;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::snapshot::{SNAPSHOT_FILE, atomic_write, open_private_file, prepare_dir};
use crate::transport::{CLUSTER_ID_FILE, decode, encode, invalid_data};

pub(crate) const IDENTITY_FILE: &str = "node.mpk";
pub(crate) const IDENTITY_VERSION: u8 = 3;
pub(crate) const RECORD_FILE: &str = "incarnation.mpk";
pub(crate) const LOCK_FILE: &str = ".mqx-survivor-lock";
pub(crate) const DISCARDED: &str = "discarded";
const STAGING: &str = ".mqx-survivor-stage";
const PENDING: &str = ".mqx-survivor-switch";
const DAMAGED: &str = ".mqx-survivor-damaged";
const REPLACEMENT: &str = ".mqx-survivor-replacement";
const INTERRUPTED: &str = "interrupted-switch";
const JOURNAL: &str = "journal";
const INSTALL: &str = "install";
const KEEP_ARCHIVE: &str = "keep_archive";
pub(crate) const JOINED: &str = "recovery.joined";
// The root fork point and a tail fit even a worst-case MessagePack Probe in
// the existing 64 KiB control frame. Never raise the RPC allocation limit to
// accommodate an installation's age.
const MAX_FORK_POINTS: usize = 512;
const ACTIVE: [&str; 6] = [
    IDENTITY_FILE,
    CLUSTER_ID_FILE,
    RECORD_FILE,
    SNAPSHOT_FILE,
    "wal",
    JOINED,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SurvivorReason {
    #[serde(rename = "peer_unreachable")]
    PeerUnreachable,
    #[serde(rename = "peer_won")]
    PeerWon,
    #[serde(rename = "unusable_state")]
    UnusableState,
}

impl SurvivorReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PeerUnreachable => "peer_unreachable",
            Self::PeerWon => "peer_won",
            Self::UnusableState => "unusable_state",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SurvivorEvent {
    pub reason: SurvivorReason,
    pub peer: Option<u64>,
    pub timestamp_seconds: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ForkPoint {
    parent: [u8; 32],
    applied: Option<u64>,
    founder: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Incarnation {
    pub(crate) number: u64,
    pub(crate) founder: u64,
    pub(crate) digest: [u8; 32],
    lineage: Arc<VecDeque<ForkPoint>>,
    #[serde(default, skip_serializing_if = "is_zero")]
    omitted: u64,
}

fn is_zero(value: &u64) -> bool {
    *value == 0
}

impl Incarnation {
    pub(crate) fn original(digest: [u8; 32]) -> Self {
        static EMPTY: LazyLock<Arc<VecDeque<ForkPoint>>> = LazyLock::new(Arc::default);
        Self {
            number: 0,
            founder: 0,
            digest,
            lineage: Arc::clone(&EMPTY),
            omitted: 0,
        }
    }

    pub(crate) fn fork(mut self, node_id: u64, applied: Option<u64>) -> io::Result<Self> {
        self.number = self
            .number
            .checked_add(1)
            .ok_or_else(|| invalid_data("cluster incarnation overflow"))?;
        let mut hash = Sha256::new();
        hash.update(b"MQExtended recovery incarnation\0");
        hash.update(self.digest);
        hash.update(self.number.to_be_bytes());
        hash.update(node_id.to_be_bytes());
        let mut nonce = [0; 32];
        rustls::crypto::ring::default_provider()
            .secure_random
            .fill(&mut nonce)
            .map_err(|_| io::Error::other("unable to generate a cluster identity"))?;
        hash.update(nonce);
        let lineage = Arc::make_mut(&mut self.lineage);
        if lineage.len() == MAX_FORK_POINTS {
            lineage.remove(1);
            self.omitted += 1;
        }
        lineage.push_back(ForkPoint {
            parent: self.digest,
            applied,
            founder: node_id,
        });
        self.digest = hash.finalize().into();
        self.founder = node_id;
        Ok(self)
    }

    fn bound_history(&mut self) {
        if self.lineage.len() > MAX_FORK_POINTS {
            let excess = self.lineage.len() - MAX_FORK_POINTS;
            Arc::make_mut(&mut self.lineage).drain(1..=excess);
            self.omitted += excess as u64;
        }
    }

    fn root(&self) -> [u8; 32] {
        self.lineage.front().map_or(self.digest, |fork| fork.parent)
    }

    pub(crate) fn related(&self, other: &Self) -> bool {
        self.root() == other.root() && self.is_valid() && other.is_valid()
    }

    fn is_valid(&self) -> bool {
        self.number.checked_sub(self.omitted) == Some(self.lineage.len() as u64)
            && (self.omitted == 0 || self.lineage.len() == MAX_FORK_POINTS)
            && self.lineage.back().map_or(self.founder == 0, |fork| {
                self.founder != 0 && fork.founder == self.founder
            })
    }
}

#[derive(Serialize, Deserialize)]
pub(crate) struct ProbeRequest {
    pub(crate) timeout: Option<Duration>,
    pub(crate) digest: Option<[u8; 32]>,
    pub(crate) repair: bool,
    #[serde(default)]
    pub(crate) reuse_digest: bool,
}

#[derive(Clone, Default, Serialize, Deserialize)]
pub(crate) struct Probe {
    pub(crate) timeout: Option<Duration>,
    pub(crate) identity: Option<Incarnation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) shared_digest: Option<[u8; 32]>,
    pub(crate) quorum: bool,
    // Age of the last successful renewal, not of this probe response.
    pub(crate) renewal_age: Option<Duration>,
    pub(crate) voters: usize,
    pub(crate) committed: Option<u64>,
    pub(crate) repair: bool,
    pub(crate) retired: bool,
    pub(crate) learner_at: Option<u64>,
}

impl Probe {
    pub(crate) fn for_request(&mut self, request: &ProbeRequest) {
        if request.reuse_digest
            && self
                .identity
                .as_ref()
                .is_some_and(|id| Some(id.digest) == request.digest)
        {
            self.identity = None;
            self.shared_digest = request.digest;
        }
    }

    pub(crate) fn resolve_history(
        &mut self,
        known: impl FnOnce() -> Option<Incarnation>,
    ) -> io::Result<()> {
        if let Some(digest) = self.shared_digest.take() {
            if self.identity.is_some() {
                return Err(invalid_data("ambiguous peer recovery incarnation"));
            }
            self.identity = Some(
                known()
                    .filter(|id| id.digest == digest)
                    .ok_or_else(|| invalid_data("unknown shared recovery incarnation"))?,
            );
            return Ok(());
        }
        if let Some(identity) = &mut self.identity {
            if !identity.is_valid() {
                return Err(invalid_data("invalid peer recovery incarnation"));
            }
            identity.bound_history();
        }
        Ok(())
    }

    pub(crate) fn wins_over(&self, other: &Self) -> bool {
        let (Some(a), Some(b)) = (&self.identity, &other.identity) else {
            return false;
        };
        if a.digest == b.digest || a.root() != b.root() || !a.is_valid() || !b.is_valid() {
            return false;
        }
        if let Some(fork) = b.lineage.iter().find(|fork| fork.parent == a.digest) {
            return self.committed > fork.applied;
        }
        if let Some(fork) = a.lineage.iter().find(|fork| fork.parent == b.digest) {
            return other.committed <= fork.applied;
        }
        (self.voters, a.number, Reverse(a.founder), Reverse(a.digest))
            > (
                other.voters,
                b.number,
                Reverse(b.founder),
                Reverse(b.digest),
            )
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Record {
    pub(crate) identity: Option<Incarnation>,
    pub(crate) event: SurvivorEvent,
}

impl Record {
    pub(crate) fn new(
        identity: Option<Incarnation>,
        reason: SurvivorReason,
        peer: Option<u64>,
    ) -> Self {
        Self {
            identity,
            event: SurvivorEvent {
                reason,
                peer,
                timestamp_seconds: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            },
        }
    }

    pub(crate) fn read(dir: &Path, digest: Option<[u8; 32]>) -> io::Result<Self> {
        let mut body = Vec::new();
        open_private_file(&dir.join(RECORD_FILE))
            .map_err(|error| {
                if error.kind() == io::ErrorKind::NotFound {
                    invalid_data("missing recovery incarnation record")
                } else {
                    error
                }
            })?
            .read_to_end(&mut body)?;
        let mut record: Self = decode(&body)?;
        if let Some(identity) = &mut record.identity {
            if Some(identity.digest) != digest || !identity.is_valid() {
                return Err(invalid_data("invalid recovery incarnation record"));
            }
            identity.bound_history();
        } else if digest.is_some() || record.event.reason != SurvivorReason::UnusableState {
            return Err(invalid_data("missing recovery incarnation identity"));
        }
        Ok(record)
    }
}

pub(crate) fn join_complete(dir: &Path, applied: Option<u64>) -> io::Result<bool> {
    let mut file = match open_private_file(&dir.join(JOINED)) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    // Only a valid catch-up marker can remove the learner fence. A damaged
    // marker is no proof of catch-up and can be replaced by the next repair.
    let size = file.metadata()?.len();
    let mut body = [0; 9]; // MessagePack u64 marker + 8 bytes.
    if size > body.len() as u64 {
        return Ok(false);
    }
    let body = &mut body[..size as usize];
    file.read_exact(body)?;
    Ok(decode::<u64>(body).is_ok_and(|index| applied >= Some(index)))
}

// The WAL lock lives inside the directory that gets renamed. Keep a separate
// lock across recovery and the switch so another process cannot open a half-install.
pub(crate) fn lock(dir: &Path, enabled: bool) -> io::Result<Option<File>> {
    let path = dir.join(LOCK_FILE);
    if !enabled && !path.try_exists()? {
        return Ok(None);
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path)?;
    file.try_lock().map_err(io::Error::from)?;
    File::open(dir)?.sync_all()?;
    Ok(Some(file))
}

pub(crate) struct Switch {
    root: PathBuf,
    stage: PathBuf,
}

impl Switch {
    pub(crate) fn prepare(root: &Path, node_id: u64, record: Record) -> io::Result<Self> {
        let stage = root.join(STAGING);
        if stage.try_exists()? {
            fs::remove_dir_all(&stage)?;
        }
        let fresh = stage.join("fresh");
        prepare_dir(&fresh, false)?;
        prepare_dir(&stage.join("archive"), false)?;
        for (name, body) in [
            (
                IDENTITY_FILE,
                encode(&(IDENTITY_VERSION, node_id, bytes::Bytes::new()))?,
            ),
            (RECORD_FILE, encode(&record)?),
        ] {
            write_staged(&fresh.join(name), &body)?;
        }
        if let Some(identity) = record.identity {
            write_staged(&fresh.join(CLUSTER_ID_FILE), &identity.digest)?;
        }
        File::open(&fresh)?.sync_all()?;
        Ok(Self {
            root: root.to_path_buf(),
            stage,
        })
    }

    pub(crate) fn fresh(&self) -> PathBuf {
        self.stage.join("fresh")
    }

    pub(crate) fn keep_archive(&self) -> io::Result<()> {
        atomic_write(&self.stage, KEEP_ARCHIVE, |_| Ok(()))
    }

    fn publish(&self) -> io::Result<()> {
        fs::rename(&self.stage, self.root.join(PENDING))
    }

    pub(crate) fn commit(self) -> io::Result<()> {
        self.publish()?;
        Self::recover(&self.root, None)
    }

    pub(crate) fn recover(root: &Path, repair_node: Option<u64>) -> io::Result<()> {
        let pending = root.join(PENDING);
        let replacement = root.join(REPLACEMENT);
        let damaged = root.join(DAMAGED);
        if switch_dir_exists(&pending)? {
            if switch_dir_exists(&replacement)? || switch_dir_exists(&damaged)? {
                return Err(invalid_data("conflicting cluster switch journals"));
            }
            if let Replay::Incomplete(reason) = Self::replay(root, &pending, false)? {
                let node = repair_node.ok_or_else(|| invalid_data(reason))?;
                // Check the archive destination before quarantining anything.
                switch_dir_exists(&root.join(DISCARDED))?;
                tracing::warn!(
                    node,
                    reason,
                    "Incomplete cluster switch; preserving both the live state and journal and rejoining empty"
                );
                fs::rename(&pending, &damaged)?;
                File::open(root)?.sync_all()?;
                return Self::replace_damaged(root, node);
            }
        } else if switch_dir_exists(&replacement)? {
            if repair_node.is_none() {
                return Err(invalid_data(
                    "damaged cluster switch requires automatic recovery",
                ));
            }
            Self::replay(root, &replacement, true)?.finish()?;
        } else if switch_dir_exists(&damaged)? {
            let node = repair_node.ok_or_else(|| {
                invalid_data("damaged cluster switch requires automatic recovery")
            })?;
            // A restart may see the quarantine rename before it was synced.
            File::open(root)?.sync_all()?;
            return Self::replace_damaged(root, node);
        } else {
            let stage = root.join(STAGING);
            if switch_dir_exists(&stage)? {
                remove_stage(&File::open(root)?, &stage)?;
            }
        }
        Ok(())
    }

    fn replace_damaged(root: &Path, node: u64) -> io::Result<()> {
        // Until the replacement is published, leave the quarantine at the
        // root: recovery may discard and rebuild any unpublished stage.
        let record = Record::new(None, SurvivorReason::UnusableState, None);
        let switch = Self::prepare(root, node, record)?;
        let replacement = root.join(REPLACEMENT);
        fs::rename(switch.stage, &replacement)?;
        Self::replay(root, &replacement, true)?.finish()
    }

    fn replay(root: &Path, pending: &Path, replacing: bool) -> io::Result<Replay> {
        let root_dir = File::open(root)?;
        // A previous process may have renamed the journal without syncing it.
        // Make publication durable before moving any of the live files.
        root_dir.sync_all()?;
        let fresh = pending.join("fresh");
        if !switch_dir_exists(&fresh)? {
            return Ok(Replay::Incomplete("missing fresh state in cluster switch"));
        }
        let installing = switch_file_exists(&pending.join(INSTALL))?;
        for name in [IDENTITY_FILE, RECORD_FILE] {
            if !(switch_file_exists(&fresh.join(name))?
                || installing && switch_file_exists(&root.join(name))?)
            {
                return Ok(Replay::Incomplete("missing staged cluster switch metadata"));
            }
        }
        let discarded = root.join(DISCARDED);
        // The original discarded archive might already contain part of the
        // interrupted switch. Keep it and one bounded slot for its other parts.
        let interrupted = replacing.then(|| discarded.join(INTERRUPTED));
        let destination = interrupted.as_deref().unwrap_or(&discarded);
        if !installing {
            let archive = pending.join("archive");
            let keep_archive = switch_file_exists(&pending.join(KEEP_ARCHIVE))?;
            if replacing && keep_archive {
                return Err(invalid_data(
                    "unexpected preserve marker in replacement switch",
                ));
            }
            if switch_dir_exists(&archive)? {
                if replacing {
                    switch_dir_exists(&discarded)?;
                    switch_dir_exists(destination)?;
                    prepare_dir(&discarded, false)?;
                    archive_damaged(root, &archive)?;
                }
                move_active(root, &archive)?;
                if !keep_archive {
                    // The new archive is complete before replacing the previous one.
                    match fs::symlink_metadata(destination) {
                        Ok(metadata) if metadata.is_dir() => fs::remove_dir_all(destination)?,
                        Ok(_) => fs::remove_file(destination)?,
                        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                        Err(error) => return Err(error),
                    }
                    fs::rename(&archive, destination)?;
                    if !replacing {
                        root_dir.sync_all()?;
                    }
                }
            } else {
                if keep_archive || !switch_dir_exists(destination)? {
                    return Ok(Replay::Incomplete("missing archive in cluster switch"));
                }
                // Without the install marker, a promoted archive means all
                // live paths were already moved. An older discarded directory
                // alone does not prove that archiving completed.
                for name in ACTIVE {
                    match fs::symlink_metadata(root.join(name)) {
                        Ok(_) => {
                            return Ok(Replay::Incomplete("incomplete cluster switch archive"));
                        }
                        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                        Err(error) => return Err(error),
                    }
                }
            }
        }
        if replacing {
            if switch_dir_exists(&root.join(DAMAGED))?
                || !switch_dir_exists(&discarded)?
                || !switch_dir_exists(destination)?
                || !switch_dir_exists(&destination.join(JOURNAL))?
            {
                return Err(invalid_data(
                    "missing archived journal in replacement switch",
                ));
            }
            // A crash may have left the promotion rename visible but not durable.
            File::open(&discarded)?.sync_all()?;
        }
        // Persist the archive rename's source directory before writing the
        // marker, or persist an observed marker before resuming installation.
        File::open(pending)?.sync_all()?;
        if !installing {
            atomic_write(pending, INSTALL, |_| Ok(()))?;
        }
        move_active(&fresh, root)?;
        // Removing the journal via rename, rather than recursively, keeps it
        // recoverable until the new root and its discarded predecessor are durable.
        let stage = root.join(STAGING);
        fs::rename(pending, &stage)?;
        remove_stage(&root_dir, &stage)?;
        Ok(Replay::Finished)
    }
}

enum Replay {
    Finished,
    Incomplete(&'static str),
}

impl Replay {
    fn finish(self) -> io::Result<()> {
        match self {
            Self::Finished => Ok(()),
            Self::Incomplete(reason) => Err(invalid_data(reason)),
        }
    }
}

fn archive_damaged(root: &Path, archive: &Path) -> io::Result<()> {
    let damaged = root.join(DAMAGED);
    let journal = archive.join(JOURNAL);
    match (switch_dir_exists(&damaged)?, switch_dir_exists(&journal)?) {
        (true, false) => fs::rename(damaged, journal),
        (false, true) => Ok(()),
        _ => Err(invalid_data(
            "missing or conflicting quarantined switch journal",
        )),
    }
}

fn switch_dir_exists(path: &Path) -> io::Result<bool> {
    switch_path_exists(path, fs::Metadata::is_dir)
}

fn switch_file_exists(path: &Path) -> io::Result<bool> {
    switch_path_exists(path, fs::Metadata::is_file)
}

fn switch_path_exists(
    path: &Path,
    expected: impl FnOnce(&fs::Metadata) -> bool,
) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if expected(&metadata) => Ok(true),
        Ok(_) => Err(invalid_data("unexpected cluster switch path type")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

fn remove_stage(root: &File, stage: &Path) -> io::Result<()> {
    // Do not delete the contents until the root durably names them as staging
    // instead of a pending journal, including when resuming after a crash.
    root.sync_all()?;
    fs::remove_dir_all(stage)?;
    root.sync_all()
}

fn write_staged(path: &Path, body: &[u8]) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(body)?;
    file.sync_all()
}

fn move_active(from: &Path, to: &Path) -> io::Result<()> {
    // The durable phase marker makes partial moves replayable. Flush the two
    // directories once after the batch, before publishing the next phase.
    for name in ACTIVE {
        move_if_present(from, to, name)?;
    }
    File::open(to)?.sync_all()?;
    File::open(from)?.sync_all()
}

fn move_if_present(from: &Path, to: &Path, name: &str) -> io::Result<()> {
    match fs::rename(from.join(name), to.join(name)) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn old_long_histories_still_fit_peer_probes_and_choose_a_winner() {
        let dir = tempfile::tempdir().unwrap();
        let root = Incarnation::original([0xff; 32]);
        let mut identity = root.clone();
        let mut legacy_points = VecDeque::new();
        let mut old_ancestor = None;
        for index in 0..4096 {
            identity = identity.fork(u64::MAX, Some(index)).unwrap();
            legacy_points.push_back(identity.lineage.back().unwrap().clone());
            if index == 1 {
                old_ancestor = Some(identity.clone());
            }
        }
        let mut legacy = identity.clone();
        legacy.lineage = Arc::new(legacy_points);
        legacy.omitted = 0;
        let path = dir.path().join(RECORD_FILE);
        let record = Record::new(Some(legacy), SurvivorReason::PeerUnreachable, None);
        let bytes = encode(&record).unwrap();
        assert!(bytes.len() > crate::transport::MAX_CONTROL_FRAME);
        fs::write(path, bytes).unwrap();
        let loaded = Record::read(dir.path(), Some(identity.digest)).unwrap();
        assert_eq!(loaded.identity.as_ref(), Some(&identity));

        let remote = Probe {
            identity: loaded.identity,
            voters: 2,
            ..Probe::default()
        };
        let bytes = encode(&remote).unwrap();
        assert!(bytes.len() <= crate::transport::MAX_CONTROL_FRAME);
        let mut reply: Probe = decode(&bytes).unwrap();
        reply.resolve_history(|| None).unwrap();
        let ancestor = Probe {
            identity: Some(root),
            committed: Some(1),
            ..Probe::default()
        };
        assert!(ancestor.wins_over(&reply)); // progress past the retained root fork
        let old = Probe {
            identity: old_ancestor,
            voters: 3,
            ..Probe::default()
        };
        assert!(old.wins_over(&reply)); // forgotten fork point: voter-count rule
        assert!(!reply.wins_over(&old));
        let recent = identity.clone().fork(1, None).unwrap();
        assert!(
            Probe {
                identity: Some(recent),
                ..Probe::default()
            }
            .wins_over(&reply)
        );

        reply.for_request(&ProbeRequest {
            digest: Some(identity.digest),
            reuse_digest: true,
            repair: false,
            timeout: None,
        });
        let bytes = encode(&reply).unwrap();
        assert!(bytes.len() < 512);
        let mut shared: Probe = decode(&bytes).unwrap();
        assert!(shared.clone().resolve_history(|| None).is_err());
        shared.resolve_history(|| Some(identity.clone())).unwrap();
        assert_eq!(shared.identity, Some(identity));
    }

    #[test]
    fn progress_breaks_ancestor_ties_and_voter_count_breaks_sibling_ties() {
        let original = Incarnation::original([7; 32]);
        let one = original.clone().fork(1, Some(10)).unwrap();
        let two = original.clone().fork(2, Some(5)).unwrap();
        let newer = two.clone().fork(2, Some(15)).unwrap();
        let unrelated = Incarnation::original([3; 32]);
        let probe = |identity, voters, committed| Probe {
            identity: Some(identity),
            voters,
            committed: Some(committed),
            ..Probe::default()
        };
        let parent = probe(original.clone(), 3, 10);
        let one = probe(one, 1, 12);
        let two = probe(two, 1, 15);
        let newer = probe(newer, 1, 16);
        assert!(one.wins_over(&parent));
        assert!(!parent.wins_over(&one));
        assert!(probe(original, 3, 11).wins_over(&one));
        assert!(one.wins_over(&two));
        assert!(!two.wins_over(&one));
        assert!(newer.wins_over(&one));
        assert!(Probe { voters: 2, ..two }.wins_over(&one));
        assert!(!one.wins_over(&probe(unrelated, 3, 12)));
        assert!(!one.wins_over(&Probe::default()));
    }

    #[test]
    fn damaged_join_marker_leaves_restarted_learner_fenced() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let marker = root.join(JOINED);
        assert!(!join_complete(root, Some(9)).unwrap());
        for body in [&b""[..], &[0xcf, 0], &[0x01, 0x00]] {
            fs::write(&marker, body).unwrap();
            for _ in 0..2 {
                assert!(!join_complete(root, Some(9)).unwrap());
            }
        }
        fs::write(&marker, encode(&9_u64).unwrap()).unwrap();
        assert!(!join_complete(root, None).unwrap());
        assert!(!join_complete(root, Some(8)).unwrap());
        assert!(join_complete(root, Some(9)).unwrap());

        fs::remove_file(&marker).unwrap();
        fs::create_dir(marker).unwrap();
        assert_eq!(
            join_complete(root, Some(9)).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn interrupted_switch_keeps_old_state_or_completes_without_mixing() {
        for interruption in 0..7 {
            let dir = tempfile::tempdir().unwrap();
            let root = dir.path();
            fs::create_dir(root.join("wal")).unwrap();
            fs::write(root.join("wal/log"), b"old log").unwrap();
            fs::write(root.join(SNAPSHOT_FILE), b"old snapshot").unwrap();
            fs::write(root.join(IDENTITY_FILE), b"old identity").unwrap();
            fs::create_dir(root.join(DISCARDED)).unwrap();
            fs::write(root.join(DISCARDED).join("previous"), b"older archive").unwrap();
            let identity = Incarnation::original([7; 32]).fork(1, None).unwrap();
            let record = Record::new(
                Some(identity.clone()),
                SurvivorReason::PeerUnreachable,
                Some(2),
            );
            let switch = Switch::prepare(root, 1, record).unwrap();
            fs::write(switch.fresh().join(SNAPSHOT_FILE), b"fresh snapshot").unwrap();
            let pending = root.join(PENDING);
            let archive = pending.join("archive");
            let fresh = pending.join("fresh");
            if interruption > 0 {
                switch.publish().unwrap();
            }
            if interruption == 2 {
                move_if_present(root, &archive, "wal").unwrap();
            }
            if interruption >= 3 {
                for name in ACTIVE {
                    move_if_present(root, &archive, name).unwrap();
                }
                fs::remove_dir_all(root.join(DISCARDED)).unwrap();
                fs::rename(archive, root.join(DISCARDED)).unwrap();
            }
            if interruption >= 4 {
                atomic_write(&pending, INSTALL, |_| Ok(())).unwrap();
                move_if_present(&fresh, root, IDENTITY_FILE).unwrap();
            }
            if interruption >= 5 {
                move_active(&fresh, root).unwrap();
                fs::rename(&pending, root.join(STAGING)).unwrap();
            }
            if interruption == 6 {
                fs::remove_dir(root.join(STAGING).join("fresh")).unwrap();
            }
            Switch::recover(root, None).unwrap();
            Switch::recover(root, None).unwrap();
            if interruption == 0 {
                assert_eq!(fs::read(root.join(SNAPSHOT_FILE)).unwrap(), b"old snapshot");
                assert_eq!(fs::read(root.join("wal/log")).unwrap(), b"old log");
                assert!(!root.join(CLUSTER_ID_FILE).exists());
                assert!(root.join("discarded/previous").exists());
            } else {
                assert_eq!(
                    fs::read(root.join(SNAPSHOT_FILE)).unwrap(),
                    b"fresh snapshot"
                );
                assert_eq!(
                    Record::read(root, Some(identity.digest)).unwrap().identity,
                    Some(identity)
                );
                assert!(!root.join("wal").exists());
                assert_eq!(
                    fs::read(root.join("discarded/wal/log")).unwrap(),
                    b"old log"
                );
                assert_eq!(
                    fs::read(root.join("discarded/snapshot.mpk")).unwrap(),
                    b"old snapshot"
                );
                assert!(!root.join("discarded/previous").exists());
            }
            assert!(!pending.exists());
            assert!(!root.join(STAGING).exists());
        }
    }

    #[test]
    fn resumed_install_does_not_replace_preserved_archive() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let discarded = root.join(DISCARDED);
        fs::create_dir(&discarded).unwrap();
        fs::write(discarded.join("wal"), b"saved archive").unwrap();
        fs::write(root.join(IDENTITY_FILE), b"repair identity").unwrap();
        let identity = Incarnation::original([7; 32]);
        let record = Record::new(
            Some(identity.clone()),
            SurvivorReason::UnusableState,
            Some(2),
        );
        let switch = Switch::prepare(root, 1, record).unwrap();
        switch.keep_archive().unwrap();
        switch.publish().unwrap();

        let pending = root.join(PENDING);
        let fresh = pending.join("fresh");
        move_active(root, &pending.join("archive")).unwrap();
        // Emulate a restart that observes the install marker before the process
        // which published it could sync the pending directory.
        write_staged(&pending.join(INSTALL), b"").unwrap();
        move_if_present(&fresh, root, IDENTITY_FILE).unwrap();

        for _ in 0..2 {
            Switch::recover(root, None).unwrap();
            assert_eq!(
                Record::read(root, Some(identity.digest)).unwrap().identity,
                Some(identity.clone())
            );
            let node: (u8, u64, bytes::Bytes) =
                decode(&fs::read(root.join(IDENTITY_FILE)).unwrap()).unwrap();
            assert_eq!(node, (IDENTITY_VERSION, 1, bytes::Bytes::new()));
            assert_eq!(fs::read(discarded.join("wal")).unwrap(), b"saved archive");
            assert!(!pending.exists());
            assert!(!root.join(STAGING).exists());
        }
    }

    #[test]
    fn incomplete_pending_switch_fails_closed_without_automatic_recovery() {
        for missing in ["fresh", "archive", "fresh/node.mpk"] {
            let dir = tempfile::tempdir().unwrap();
            let root = dir.path();
            let discarded = root.join(DISCARDED);
            fs::create_dir(&discarded).unwrap();
            fs::write(discarded.join(SNAPSHOT_FILE), b"saved archive").unwrap();
            fs::write(root.join(IDENTITY_FILE), b"live identity").unwrap();
            fs::write(root.join(SNAPSHOT_FILE), b"live snapshot").unwrap();
            let record = Record::new(None, SurvivorReason::UnusableState, None);
            Switch::prepare(root, 1, record).unwrap().publish().unwrap();
            let pending = root.join(PENDING);
            let path = pending.join(missing);
            if path.is_dir() {
                fs::remove_dir_all(path).unwrap();
            } else {
                fs::remove_file(path).unwrap();
            }

            for _ in 0..2 {
                assert_eq!(
                    Switch::recover(root, None).unwrap_err().kind(),
                    io::ErrorKind::InvalidData
                );
                assert_eq!(
                    fs::read(root.join(IDENTITY_FILE)).unwrap(),
                    b"live identity"
                );
                assert_eq!(
                    fs::read(root.join(SNAPSHOT_FILE)).unwrap(),
                    b"live snapshot"
                );
                assert_eq!(
                    fs::read(discarded.join(SNAPSHOT_FILE)).unwrap(),
                    b"saved archive"
                );
                assert!(!pending.join(INSTALL).exists());
            }
        }
    }

    #[test]
    fn damaged_switch_replacement_resumes_without_losing_evidence() {
        for interruption in 0..8 {
            let dir = tempfile::tempdir().unwrap();
            let root = dir.path();
            let discarded = root.join(DISCARDED);
            let interrupted = discarded.join(INTERRUPTED);
            fs::create_dir_all(&interrupted).unwrap();
            fs::write(discarded.join(RECORD_FILE), b"existing archive").unwrap();
            fs::write(interrupted.join("older"), b"older interrupted switch").unwrap();
            fs::write(root.join(IDENTITY_FILE), b"mixed identity").unwrap();
            fs::write(root.join(SNAPSHOT_FILE), b"previous snapshot").unwrap();
            fs::create_dir(root.join("wal")).unwrap();
            fs::write(root.join("wal/log"), b"mixed log").unwrap();

            let record = || Record::new(None, SurvivorReason::UnusableState, None);
            Switch::prepare(root, 1, record())
                .unwrap()
                .publish()
                .unwrap();
            let pending = root.join(PENDING);
            let damaged = root.join(DAMAGED);
            let replacement = root.join(REPLACEMENT);
            let archive = replacement.join("archive");
            let fresh = replacement.join("fresh");
            move_if_present(root, &pending.join("archive"), SNAPSHOT_FILE).unwrap();
            fs::remove_dir_all(pending.join("fresh")).unwrap();
            if interruption >= 1 {
                fs::rename(&pending, &damaged).unwrap();
            }
            if interruption >= 2 {
                Switch::prepare(root, 1, record()).unwrap();
            }
            if interruption >= 3 {
                fs::rename(root.join(STAGING), &replacement).unwrap();
            }
            if interruption >= 4 {
                archive_damaged(root, &archive).unwrap();
                move_if_present(root, &archive, IDENTITY_FILE).unwrap();
            }
            if interruption >= 5 {
                move_active(root, &archive).unwrap();
                fs::remove_dir_all(&interrupted).unwrap();
                fs::rename(&archive, &interrupted).unwrap();
            }
            if interruption >= 6 {
                atomic_write(&replacement, INSTALL, |_| Ok(())).unwrap();
                move_if_present(&fresh, root, IDENTITY_FILE).unwrap();
            }
            if interruption >= 7 {
                move_active(&fresh, root).unwrap();
                fs::rename(&replacement, root.join(STAGING)).unwrap();
            }

            for _ in 0..2 {
                Switch::recover(root, Some(1)).unwrap();
                let node: (u8, u64, bytes::Bytes) =
                    decode(&fs::read(root.join(IDENTITY_FILE)).unwrap()).unwrap();
                assert_eq!(node, (IDENTITY_VERSION, 1, bytes::Bytes::new()));
                let record = Record::read(root, None).unwrap();
                assert!(record.identity.is_none());
                assert_eq!(record.event.reason, SurvivorReason::UnusableState);
                assert_eq!(
                    fs::read(discarded.join(RECORD_FILE)).unwrap(),
                    b"existing archive"
                );
                assert_eq!(
                    fs::read(interrupted.join(IDENTITY_FILE)).unwrap(),
                    b"mixed identity"
                );
                assert_eq!(fs::read(interrupted.join("wal/log")).unwrap(), b"mixed log");
                assert_eq!(
                    fs::read(
                        interrupted
                            .join(JOURNAL)
                            .join("archive")
                            .join(SNAPSHOT_FILE)
                    )
                    .unwrap(),
                    b"previous snapshot"
                );
                assert!(!interrupted.join("older").exists());
                assert!(!root.join("wal").exists());
                assert!(!root.join(SNAPSHOT_FILE).exists());
                for name in [PENDING, REPLACEMENT, DAMAGED, STAGING] {
                    assert!(!root.join(name).exists());
                }
            }
        }
    }

    #[test]
    fn unexpected_journal_path_type_is_not_quarantined() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let record = Record::new(None, SurvivorReason::UnusableState, None);
        Switch::prepare(root, 1, record).unwrap().publish().unwrap();
        let pending = root.join(PENDING);
        fs::create_dir(pending.join(INSTALL)).unwrap();
        assert_eq!(
            Switch::recover(root, Some(1)).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert!(pending.join(INSTALL).is_dir());
        assert!(!root.join(DAMAGED).exists());
        assert!(!root.join(DISCARDED).exists());
    }
}
