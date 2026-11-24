use std::collections::HashMap;
use std::fmt;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use mqx_auth::external::Verdict;
use sha1::{Digest, Sha1};

use super::log;

type Key = [u8; 20];

pub(super) fn now() -> u64 {
    wall_time().as_secs()
}

pub(super) fn wall_time() -> Duration {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
}

// cache.c: a verdict lives through its whole expiry second. Convert the
// wall-clock deadline to an interval measured from the check's start.
pub(super) fn acl_reuse(ttl: Duration, started: Duration) -> Duration {
    if ttl.is_zero() {
        return Duration::ZERO;
    }
    ttl.saturating_add(Duration::from_nanos(
        1_000_000_000 - u64::from(started.subsec_nanos()),
    ))
}

pub(crate) fn c_string(bytes: &[u8]) -> &[u8] {
    &bytes[..bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len())]
}

// cache.c: hexify, auth_cache. Use the raw digest as the key; only encode
// it as uppercase hex when it is printed.
pub(super) fn key<const N: usize>(parts: [&[u8]; N]) -> Key {
    let mut sha = Sha1::new();
    for part in parts {
        sha.update(part);
    }
    sha.finalize().into()
}

pub(super) struct Hex<'a>(pub(super) &'a Key);

impl fmt::Display for Hex<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02X}")?;
        }
        Ok(())
    }
}

const RAND_MAX: u32 = i32::MAX as u32;

#[derive(Debug, PartialEq, Eq)]
pub(super) struct Lifetime {
    pub(super) seconds: i64,
    pub(super) jitter: i64,
}

impl Lifetime {
    pub(super) fn duration(&self) -> Duration {
        if self.seconds <= 0 || self.jitter <= 0 {
            return self.at(0);
        }
        let mut bytes = [0; 4];
        // Uniform integer over the range of POSIX rand(). The wider
        // arithmetic below keeps C's truncation without signed overflow.
        let rand = if getrandom::fill(&mut bytes).is_ok() {
            u32::from_ne_bytes(bytes) & RAND_MAX
        } else {
            RAND_MAX / 2 + 1
        };
        self.at(rand)
    }

    // cache.c: auth_cache and acl_cache sample the jitter on insertion.
    fn at(&self, rand: u32) -> Duration {
        if self.seconds <= 0 {
            return Duration::ZERO;
        }
        let mut seconds = i128::from(self.seconds);
        if self.jitter > 0 {
            let jitter = i128::from(self.jitter);
            seconds += i128::from(rand) * (2 * jitter) / i128::from(RAND_MAX) - jitter;
        }
        Duration::from_secs(seconds.max(0) as u64)
    }
}

#[derive(Default)]
pub(super) struct AuthCache(Mutex<HashMap<Key, (Verdict, u64)>>);

impl AuthCache {
    pub(super) fn query(&self, key: Key, username: &str, now: u64) -> Option<Verdict> {
        let mut entries = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let &(verdict, expiry) = entries.get(&key)?;
        // cache.c: auth_cache_q expires after, not on, the expiry second.
        if now > expiry {
            log(format_args!(" Expired [<redacted>] for ({username})"));
            entries.remove(&key);
            None
        } else {
            // MOSQ_ERR_UNKNOWN is both stored and the miss sentinel.
            (verdict != Verdict::Error).then_some(verdict)
        }
    }

    pub(super) fn insert(&self, key: Key, username: &str, verdict: Verdict, now: u64, ttl: u64) {
        let mut entries = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        use std::collections::hash_map::Entry;
        // cache.c: auth_cache updates an existing decision, not its expiry.
        match entries.entry(key) {
            Entry::Occupied(mut entry) => {
                if now > entry.get().1 {
                    log(format_args!(" Expired [<redacted>] for ({username})"));
                    entry.remove();
                } else {
                    entry.get_mut().0 = verdict;
                }
            }
            Entry::Vacant(entry) => {
                entry.insert((verdict, now.saturating_add(ttl)));
                log(format_args!(" Cached  [<redacted>] for ({username})"));
            }
        }
        entries.retain(|_, (_, expiry)| {
            let live = now <= *expiry;
            if !live {
                log(format_args!(" Cleanup [<redacted>]"));
            }
            live
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jitter_is_integer_and_nonpositive_lifetime_disables_insert() {
        let ttl = Lifetime {
            seconds: 10,
            jitter: 3,
        };
        for (random, seconds) in [
            (0, 7),
            (RAND_MAX / 2, 9),
            (RAND_MAX / 2 + 1, 10),
            (RAND_MAX, 13),
        ] {
            assert_eq!(ttl.at(random).as_secs(), seconds);
        }
        assert!(
            Lifetime {
                seconds: 3,
                jitter: 3
            }
            .at(0)
            .is_zero()
        );
        assert!(
            Lifetime {
                seconds: 0,
                jitter: 3
            }
            .at(RAND_MAX)
            .is_zero()
        );
        assert_eq!(
            Lifetime {
                seconds: 3,
                jitter: -7
            }
            .at(RAND_MAX)
            .as_secs(),
            3
        );
    }

    #[test]
    fn cache_defer_expiry_and_unknown_sentinel() {
        let cache = AuthCache::default();
        let key = key([b"a:b"]);
        assert_eq!(
            Hex(&key).to_string(),
            "DCEA6D9CCD3D20BA1549F6D9B5DDE60742158882"
        );
        cache.insert(key, "a", Verdict::Error, 100, 10);
        assert_eq!(cache.query(key, "a", 105), None);
        cache.insert(key, "a", Verdict::Defer, 105, 10);
        assert_eq!(cache.query(key, "a", 110), Some(Verdict::Defer));
        assert_eq!(cache.query(key, "a", 111), None);
    }
}
