use mqx_auth::external::BoxFuture;

use crate::backend::{Backend, BackendResult, GetUser, LoadError, Options};

struct Cdb(Vec<u8>);

pub(crate) async fn create(options: &Options) -> Result<Box<dyn Backend>, LoadError> {
    // be-cdb.c: be_cdb_init. Open and read the same snapshot with safe I/O.
    let path = options
        .get("cdbname")
        .ok_or_else(|| LoadError::new("Mandatory parameter `cdbname' missing"))?;
    let bytes = tokio::fs::read(path).await.map_err(|error| {
        eprintln!("{path}: {error}");
        LoadError::new("cdb init returns NULL")
    })?;
    if bytes.len() < 2048 {
        return Err(LoadError::new("cdb init returns NULL"));
    }
    Ok(Box::new(Cdb(bytes)))
}

fn word(data: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        data.get(offset..offset.checked_add(4)?)?.try_into().ok()?,
    ))
}

fn hash(key: &[u8]) -> u32 {
    key.iter().fold(5381u32, |hash, byte| {
        hash.wrapping_mul(33) ^ u32::from(*byte)
    })
}

impl Cdb {
    // tinycdb/cdb_init.c: cdb_init; cdb_find.c: cdb_find. Each of the
    // 256 tables is open-addressed; use the first probe matching the key.
    fn find(&self, key: &[u8]) -> Option<&[u8]> {
        let bytes = self.0.get(..self.0.len().min(u32::MAX as usize))?;
        let records_end = (word(bytes, 0)? as usize).clamp(2048, bytes.len());
        let h = hash(key);
        let toc = (h as usize & 255) * 8;
        let start = word(bytes, toc)? as usize;
        let slots = word(bytes, toc + 4)? as usize;
        if slots == 0 || start < records_end {
            return None;
        }
        let table = bytes.get(start..start.checked_add(slots.checked_mul(8)?)?)?;
        let records = &bytes[..records_end];
        let first = (h as usize >> 8) % slots;
        for slot in (first..slots).chain(0..first) {
            let record = word(table, slot * 8 + 4)? as usize;
            if record == 0 {
                return None;
            }
            if word(table, slot * 8)? != h || word(records, record)? as usize != key.len() {
                continue;
            }
            let value_start = record.checked_add(8)?.checked_add(key.len())?;
            if records.get(record + 8..value_start)? == key {
                let length = word(records, record + 4)? as usize;
                return records.get(value_start..value_start.checked_add(length)?);
            }
        }
        None
    }
}

impl Backend for Cdb {
    fn name(&self) -> &'static str {
        "cdb"
    }

    fn getuser<'a>(&'a self, username: &'a str, _: &'a [u8], _: &'a str) -> BoxFuture<'a, GetUser> {
        Box::pin(async move {
            // be-cdb.c: be_cdb_getuser. Keys are literal and case-sensitive.
            self.find(username.as_bytes()).map_or_else(
                || GetUser::result(BackendResult::Defer),
                |value| super::hash_reply(value.to_vec()),
            )
        })
    }

    fn superuser<'a>(&'a self, _: &'a str) -> BoxFuture<'a, BackendResult> {
        Box::pin(async { BackendResult::Defer })
    }

    fn aclcheck<'a>(
        &'a self,
        _: &'a str,
        _: &'a str,
        _: &'a str,
        _: i32,
    ) -> BoxFuture<'a, BackendResult> {
        // be-cdb.c: be_cdb_aclcheck always grants; be_cdb_access is unused.
        Box::pin(async { BackendResult::Allow })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_key_after_probe_collision_and_rejects_truncation() {
        let key = b"fred";
        let h = hash(key);
        let mut cdb = vec![0; 2048];
        cdb.extend_from_slice(b"\x04\0\0\0\x03\0\0\0fredkey");
        let table = cdb.len();
        cdb[..4].copy_from_slice(&(table as u32).to_le_bytes());
        let toc = (h as usize & 255) * 8;
        cdb[toc..toc + 4].copy_from_slice(&(table as u32).to_le_bytes());
        cdb[toc + 4..toc + 8].copy_from_slice(&2u32.to_le_bytes());
        cdb.resize(table + 16, 0);
        let first = ((h >> 8) % 2) as usize;
        cdb[table + 8 * first + 4..table + 8 * first + 8].copy_from_slice(&2048u32.to_le_bytes());
        let second = table + 8 * (1 - first);
        cdb[second..second + 4].copy_from_slice(&h.to_le_bytes());
        cdb[second + 4..second + 8].copy_from_slice(&2048u32.to_le_bytes());
        let mut cdb = Cdb(cdb);
        assert_eq!(cdb.find(key), Some(b"key".as_slice()));
        assert_eq!(cdb.find(b"fred2"), None);
        cdb.0.pop();
        assert_eq!(cdb.find(key), None);
    }
}
