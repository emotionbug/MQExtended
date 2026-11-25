use std::fs::{self, OpenOptions};
use std::os::unix::fs::FileExt;
use std::path::Path;

use openraft::alias::EntryPayloadOf;
use openraft::type_config::TypeConfigExt;

use super::*;
use crate::node::{Command, Leadership};

const BLOCK: u64 = 4096;

fn start_direct(path: &Path) -> Option<Wal> {
    match Wal::open_with_direct(path, crate::DEFAULT_MAX_APPEND_SIZE, 2, true) {
        Ok(wal) => Some(wal),
        // Linux CI may place its temporary directories on a non-DIO mount.
        Err(error) if error.kind() == io::ErrorKind::Unsupported => {
            eprintln!("direct WAL unavailable on test filesystem: {error}");
            None
        }
        Err(error) => panic!("failed to create direct WAL: {error}"),
    }
}

fn reopen(path: &Path) -> io::Result<Wal> {
    Wal::open_with_direct(path, crate::DEFAULT_MAX_APPEND_SIZE, 2, false)
}

fn id(index: u64) -> LogId {
    LogId::new(
        Leadership {
            term: 1,
            node_id: 1,
        },
        index,
    )
}

async fn append(wal: &mut Wal, log_id: LogId, payload: EntryPayloadOf<Types>) {
    let (tx, rx) = Types::oneshot();
    wal.append([Entry { log_id, payload }], IOFlushed::signal(tx))
        .await
        .unwrap();
    // The reader must see accepted entries without waiting for the callback.
    assert_eq!(
        wal.try_get_log_entries(log_id.index..=log_id.index)
            .await
            .unwrap()[0]
            .log_id,
        log_id
    );
    rx.await.unwrap().unwrap();
}

#[tokio::test]
async fn direct_wal_reopens_with_or_without_flag_but_cannot_downgrade() {
    let dir = tempfile::tempdir().unwrap();
    let Some(mut wal) = start_direct(dir.path()) else {
        return;
    };
    let vote = Vote::new_committed(1, 1);
    wal.save_vote(&vote).await.unwrap();
    let first = id(0);
    let discarded = id(1);
    let replacement = LogId::new(
        Leadership {
            term: 2,
            node_id: 1,
        },
        1,
    );
    append(&mut wal, first, EntryPayloadOf::<Types>::Blank).await;
    append(&mut wal, discarded, EntryPayloadOf::<Types>::Blank).await;
    wal.save_committed(Some(first)).await.unwrap();
    wal.truncate_after(Some(first)).await.unwrap();
    append(&mut wal, replacement, EntryPayloadOf::<Types>::Blank).await;
    assert!(wal.limited_get_log_entries(2, 1).await.unwrap().is_empty());
    wal.close().await.unwrap();

    let legacy_config = Arc::new(raft_log::Config::new(dir.path().to_str().unwrap()));
    assert!(raft_log::RaftLog::<WalTypes>::open(legacy_config).is_err());
    assert!(start_direct(dir.path()).is_some());
    let mut wal = reopen(dir.path()).unwrap();
    assert_eq!(wal.read_vote().await.unwrap(), Some(vote));
    assert_eq!(wal.read_committed().await.unwrap(), Some(first));
    let ids: Vec<_> = wal
        .try_get_log_entries(..)
        .await
        .unwrap()
        .into_iter()
        .map(|entry| entry.log_id)
        .collect();
    assert_eq!(ids, [first, replacement]);
    wal.close().await.unwrap();
}

#[tokio::test]
async fn requested_direct_mode_refuses_an_established_legacy_wal() {
    let dir = tempfile::tempdir().unwrap();
    let mut wal = reopen(dir.path()).unwrap();
    let vote = Vote::new_committed(1, 1);
    wal.save_vote(&vote).await.unwrap();
    wal.close().await.unwrap();
    assert_eq!(
        Wal::open_with_direct(dir.path(), crate::DEFAULT_MAX_APPEND_SIZE, 2, true)
            .err()
            .unwrap()
            .kind(),
        io::ErrorKind::InvalidInput,
    );
    let mut wal = reopen(dir.path()).unwrap();
    assert_eq!(wal.read_vote().await.unwrap(), Some(vote));
    wal.close().await.unwrap();
}

#[tokio::test]
async fn direct_wal_fails_closed_on_torn_frame_or_interior_zero_gap() {
    for interior in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let Some(mut wal) = start_direct(dir.path()) else {
            return;
        };
        wal.save_vote(&Vote::new(1, 1)).await.unwrap();
        if interior {
            wal.save_vote(&Vote::new(2, 1)).await.unwrap();
        }
        wal.close().await.unwrap();

        let path = dir
            .path()
            .join(raft_log::chunked_wal::Config::chunk_file_name(
                raft_log::ChunkId(0),
            ));
        let file = OpenOptions::new().write(true).open(path).unwrap();
        if interior {
            file.write_all_at(&[0; BLOCK as usize], BLOCK).unwrap();
        } else {
            // Simulate a partial footer at the end of the final nonzero frame.
            file.write_all_at(&[0], 2 * BLOCK - 1).unwrap();
        }
        file.sync_data().unwrap();
        assert_eq!(
            reopen(dir.path()).err().unwrap().kind(),
            io::ErrorKind::InvalidData
        );
    }
}

#[tokio::test]
async fn direct_wal_rotation_needs_a_covering_purge_to_remove_the_prefix() {
    let dir = tempfile::tempdir().unwrap();
    let Some(mut wal) = start_direct(dir.path()) else {
        return;
    };
    let vote = Vote::new(1, 1);
    wal.save_vote(&vote).await.unwrap();
    // Two frames cannot share one segment. Each payload also exercises the
    // on-disk locator reads on reopen, where there is no live payload cache.
    let large = Bytes::from(vec![0xab; 9 * 1024 * 1024]);
    for index in 0..2 {
        append(
            &mut wal,
            id(index),
            EntryPayloadOf::<Types>::Normal(Command::App(large.clone())),
        )
        .await;
    }
    wal.close().await.unwrap();
    let files = wal_chunk_files(dir.path()).unwrap();
    assert_eq!(
        files.iter().map(|(id, _)| *id).collect::<Vec<_>>(),
        [0, 1, u64::MAX]
    );
    let first = &files[0].1;
    let hidden = dir.path().join("hidden-first-segment");
    fs::rename(first, &hidden).unwrap();
    assert_eq!(
        reopen(dir.path()).err().unwrap().kind(),
        io::ErrorKind::InvalidData
    );
    fs::rename(hidden, first).unwrap();

    let mut wal = reopen(dir.path()).unwrap();
    let entries = wal.try_get_log_entries(..).await.unwrap();
    let EntryPayloadOf::<Types>::Normal(Command::App(body)) = &entries[1].payload else {
        panic!("wrong stored payload");
    };
    assert_eq!(body, &large);
    wal.purge(id(0)).await.unwrap();
    wal.close().await.unwrap();
    assert!(!first.exists());

    let mut wal = reopen(dir.path()).unwrap();
    assert_eq!(wal.read_vote().await.unwrap(), Some(vote));
    assert_eq!(
        wal.get_log_state().await.unwrap().last_purged_log_id,
        Some(id(0))
    );
    let entries = wal.try_get_log_entries(..).await.unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].log_id, id(1));
    wal.close().await.unwrap();
}
