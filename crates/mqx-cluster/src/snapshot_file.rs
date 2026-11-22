use std::fs::{self, File};
use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use tempfile::TempPath;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Semaphore, SemaphorePermit};
use tokio::task::spawn_blocking;

use crate::snapshot::SnapshotMeta;
use crate::transport::{Connection, MAX_CONTROL_FRAME, decode, encode, invalid_data, read_length};

const MAGIC: &[u8; 8] = b"MQXSNAP1";
const CHUNK: usize = 64 * 1024;
// Hold the slot through install, not just upload, to bound both staged disk use
// and the number of application snapshots materialized for StateMachine::restore.
static STAGING: Semaphore = Semaphore::const_new(2);

#[derive(Clone, Debug)]
pub(crate) struct SnapshotData {
    file: Arc<Mutex<File>>,
    stage: Option<Arc<Staged>>,
    size: u64,
    app_start: u64,
    pub(crate) leases: Bytes,
}

#[derive(Debug)]
struct Staged {
    path: TempPath,
    _slot: SemaphorePermit<'static>,
}

impl SnapshotData {
    pub(crate) fn open(mut file: File) -> io::Result<(SnapshotMeta, Self)> {
        let size = file.metadata()?.len();
        file.rewind()?;
        let mut reader = BufReader::new(file);
        let mut magic = [0; MAGIC.len()];
        reader.read_exact(&mut magic)?;
        if &magic != MAGIC {
            return Err(invalid_data("unknown snapshot format"));
        }
        let meta = decode(&read_small(&mut reader)?)?;
        let leases = read_small(&mut reader)?;
        let len = read_u64(&mut reader)?;
        let app_start = reader.stream_position()?;
        if app_start.checked_add(len) != Some(size) {
            return Err(invalid_data("wrong application data length in snapshot"));
        }
        Ok((
            meta,
            Self {
                file: Arc::new(Mutex::new(reader.into_inner())),
                stage: None,
                size,
                app_start,
                leases,
            },
        ))
    }

    pub(crate) fn build(
        dir: &Path,
        name: &str,
        meta: &SnapshotMeta,
        leases: Bytes,
        app: &[u8],
    ) -> io::Result<Self> {
        let meta = encode(meta)?;
        let mut temp = crate::snapshot::private_tempfile(dir)?;
        let file = temp.as_file_mut();
        file.write_all(MAGIC)?;
        for body in [meta.as_slice(), &leases] {
            let len = checked_len(body.len(), MAX_CONTROL_FRAME as u64)?;
            file.write_all(&len.to_be_bytes())?;
            file.write_all(body)?;
        }
        file.write_all(&(app.len() as u64).to_be_bytes())?;
        let app_start = file.stream_position()?;
        file.write_all(app)?;
        let size = app_start + app.len() as u64;
        file.sync_all()?;
        let file = temp.persist(dir.join(name))?;
        File::open(dir)?.sync_all()?;
        Ok(Self {
            file: Arc::new(Mutex::new(file)),
            stage: None,
            size,
            app_start,
            leases,
        })
    }

    pub(crate) async fn receive(
        stream: &mut (impl AsyncRead + Unpin),
        dir: PathBuf,
        max: u64,
    ) -> io::Result<(SnapshotMeta, Self)> {
        let size = u64::from(read_length(stream, max).await?);
        let slot = STAGING.try_acquire().map_err(|_| {
            io::Error::new(
                io::ErrorKind::WouldBlock,
                "cluster snapshot staging slots exhausted",
            )
        })?;
        let (file, path) = spawn_blocking(move || {
            crate::snapshot::private_tempfile(&dir).map(tempfile::NamedTempFile::into_parts)
        })
        .await
        .map_err(io::Error::other)??;
        let mut file = tokio::fs::File::from_std(file);
        if tokio::io::copy(&mut stream.take(size), &mut file).await? != size {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        file.flush().await?;
        let file = file.into_std().await;
        spawn_blocking(move || {
            let (meta, mut data) = Self::open(file)?;
            data.stage = Some(Arc::new(Staged { path, _slot: slot }));
            Ok((meta, data))
        })
        .await
        .map_err(io::Error::other)?
    }

    pub(crate) async fn send(&self, stream: &mut Connection, max: u64) -> io::Result<()> {
        if self.size > max {
            return Err(invalid_data("cluster snapshot exceeds the size limit"));
        }
        stream.write_u32(self.size as u32).await?;
        let mut buffer = vec![0; CHUNK.min(self.size as usize)];
        let mut offset = 0;
        while offset < self.size {
            let len = buffer.len().min((self.size - offset) as usize);
            let file = self.file.clone();
            buffer = spawn_blocking(move || {
                let mut file = file.lock().unwrap();
                file.seek(SeekFrom::Start(offset))?;
                file.read_exact(&mut buffer[..len])?;
                Ok::<_, io::Error>(buffer)
            })
            .await
            .map_err(io::Error::other)??;
            stream.write_all(&buffer[..len]).await?;
            offset += len as u64;
        }
        Ok(())
    }

    pub(crate) fn application(&self) -> io::Result<Vec<u8>> {
        let mut file = self.file.lock().unwrap();
        file.seek(SeekFrom::Start(self.app_start))?;
        let len = self.size - self.app_start;
        let mut body = Vec::new();
        if (&mut *file).take(len).read_to_end(&mut body)? as u64 != len {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        Ok(body)
    }

    pub(crate) fn publish(mut self, dir: &Path, name: &str) -> io::Result<Self> {
        if let Some(staged) = self.stage.take() {
            self.file.lock().unwrap().sync_all()?;
            fs::rename(staged.path.as_ref() as &Path, dir.join(name))?;
            File::open(dir)?.sync_all()?;
        }
        Ok(self)
    }
}

fn read_u64(reader: &mut impl Read) -> io::Result<u64> {
    let mut bytes = [0; 8];
    reader.read_exact(&mut bytes)?;
    Ok(u64::from_be_bytes(bytes))
}

fn read_small(reader: &mut impl Read) -> io::Result<Bytes> {
    let len = read_u64(reader)?;
    if len > MAX_CONTROL_FRAME as u64 {
        return Err(invalid_data("snapshot metadata exceeds the size limit"));
    }
    let mut bytes = vec![0; len as usize];
    reader.read_exact(&mut bytes)?;
    Ok(bytes.into())
}

fn checked_len(len: usize, limit: u64) -> io::Result<u64> {
    let len = len as u64;
    if len > limit {
        return Err(invalid_data("snapshot metadata exceeds the size limit"));
    }
    Ok(len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn snapshot_limit_is_checked_before_opening_destination() {
        let root = tempfile::tempdir().unwrap();
        let len = 1025u32.to_be_bytes();
        let mut input = len.as_slice();
        let result = SnapshotData::receive(&mut input, root.path().to_path_buf(), 1024).await;
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
        assert_eq!(root.path().read_dir().unwrap().count(), 0);
    }
}
