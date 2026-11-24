//! go-auth caches; memory ACL reuse is owned by the broker.

use std::{
    collections::{BTreeSet, HashMap},
    fmt::{self, Write as _},
    sync::{Arc, Mutex},
    time::Duration,
};

use base64::prelude::*;
use tokio::time::Instant;

use crate::net::resp::Value;

use super::{
    backend::{BackendError, Level, Log, Options},
    exact_true, parse_int_error,
    redis::Client,
    spaces_true,
};

pub(super) enum Cache {
    Disabled,
    Memory {
        settings: Settings,
        records: Mutex<Memory>,
    },
    Redis {
        settings: Settings,
        client: Client,
    },
}

#[derive(Clone, Copy)]
pub(super) struct Settings {
    auth: Lifetime,
    acl: Lifetime,
    refresh: bool,
}

#[derive(Clone, Copy)]
struct Lifetime {
    nanos: i64,
    jitter: u64,
}

impl Lifetime {
    fn new(seconds: i64, jitter: i64) -> Self {
        // go-auth.go: setCache converts seconds to signed time.Duration.
        Self {
            nanos: seconds.wrapping_mul(1_000_000_000),
            // rand.Int63n panics on negative/overflowing jitter; treat that
            // configuration as zero jitter rather than crashing the broker.
            jitter: u64::try_from(jitter.wrapping_mul(1_000_000_000)).unwrap_or_default(),
        }
    }

    // cache/cache.go: expirationWithJitter; upper bound is exclusive.
    fn jittered(self) -> i64 {
        if self.jitter == 0 {
            return self.nanos;
        }
        let range = self.jitter * 2;
        let threshold = range.wrapping_neg() % range;
        let mut bytes = [0; 8];
        let sample = loop {
            if getrandom::fill(&mut bytes).is_err() {
                return self.nanos.max(0);
            }
            let value = u64::from_ne_bytes(bytes);
            if value >= threshold {
                break value % range;
            }
        };
        let result = i128::from(self.nanos) + i128::from(sample) - i128::from(self.jitter);
        result.clamp(0, i128::from(i64::MAX)) as i64
    }
}

impl Cache {
    // go-auth.go: setCache; cache/cache.go: goStore.Connect, redisStore.Connect.
    pub(super) async fn new(options: &Options, log: &Log) -> Self {
        if !spaces_true(options, "cache") {
            log.info(format_args!("No cache set."));
            return Self::Disabled;
        }
        log.info(format_args!("redisCache activated"));
        let auth = lifetime(options, "auth", log);
        let acl = lifetime(options, "acl", log);
        let settings = Settings {
            auth,
            acl,
            refresh: exact_true(options, "cache_refresh"),
        };
        let reset = exact_true(options, "cache_reset");
        if options.get("cache_type").is_none_or(|kind| kind != "redis") {
            log.info(format_args!("started go-cache"));
            if reset {
                log.info(format_args!("flushed go-cache"));
            }
            return Self::Memory {
                settings,
                records: Mutex::default(),
            };
        }
        let password = options.get("cache_password").cloned().unwrap_or_default();
        let client = if exact_true(options, "cache_mode") {
            let Some(addresses) = options
                .get("redis_cluster_addresses")
                .filter(|addresses| !addresses.is_empty())
            else {
                log.error(format_args!(
                    "cache Redis cluster addresses missing, defaulting to no cache."
                ));
                return Self::Disabled;
            };
            Client::cluster(
                addresses
                    .split(',')
                    .map(|address| address.trim().to_owned())
                    .collect(),
                password,
            )
        } else {
            let host = options
                .get("cache_host")
                .map_or("localhost", String::as_str);
            let port = options.get("cache_port").map_or("6379", String::as_str);
            let db = options.get("cache_db").map_or(3, |value| {
                value.parse::<i32>().map_or_else(|err| {
                    let err = parse_int_error(&err);
                    log.warn(format_args!("couldn't parse cache db (err: strconv.ParseInt: parsing {value:?}: {err}), defaulting to 3"));
                    3
                }, i64::from)
            });
            Client::standalone(format!("{host}:{port}"), password, db)
        };
        if let Err(err) = client.ping().await {
            log.error(format_args!("couldn't start redis. error: {err}"));
            log.info(format_args!("couldn't start cache, defaulting to no cache"));
            return Self::Disabled;
        }
        log.info(format_args!("started redis cache"));
        if reset {
            let _ = client.command(&[b"flushdb"], None).await;
            log.info(format_args!("flushed redis cache"));
        }
        Self::Redis { settings, client }
    }

    pub(super) fn auth_record(&self, username: &str, password: &[u8], log: &Log) -> Option<Record> {
        if matches!(self, Self::Disabled) {
            return None;
        }
        log.debug(format_args!("checking auth cache for {username}"));
        Some(Record::auth(username, password))
    }

    pub(super) fn acl_record(
        &self,
        username: &str,
        topic: &str,
        client_id: &str,
        access: i32,
        log: &Log,
    ) -> Option<Record> {
        if matches!(self, Self::Disabled) {
            return None;
        }
        log.debug(format_args!("checking acl cache for {username}"));
        // Memory ACL is cached by the broker. Keep the record only to print
        // the same trace when debugging a fresh external check.
        if matches!(self, Self::Redis { .. }) || log.enabled(Level::Debug) {
            let record = Record::acl(username, topic, client_id, access);
            if matches!(self, Self::Memory { .. }) {
                record.log(log);
            }
            Some(record)
        } else {
            None
        }
    }

    pub(super) async fn get_auth(&self, record: &Record, log: &Log) -> Option<bool> {
        record.log(log);
        match self {
            Self::Memory { settings, records } => records
                .lock()
                .unwrap_or_else(|err| err.into_inner())
                .get(&record.key, settings.refresh, Instant::now()),
            Self::Redis { settings, client } => {
                get_redis(client, record, settings.auth, settings.refresh, log).await
            }
            Self::Disabled => None,
        }
    }

    pub(super) async fn get_acl(&self, record: &Record, log: &Log) -> Option<bool> {
        let Self::Redis { settings, client } = self else {
            return None;
        };
        record.log(log);
        get_redis(client, record, settings.acl, settings.refresh, log).await
    }

    pub(super) async fn put_auth(
        &self,
        record: Record,
        allowed: bool,
        log: &Log,
    ) -> Result<(), BackendError> {
        record.log(log);
        match self {
            Self::Memory { settings, records } => {
                let ttl = settings.auth.jittered();
                records.lock().unwrap_or_else(|err| err.into_inner()).put(
                    record.key,
                    allowed,
                    ttl,
                    Instant::now(),
                );
                Ok(())
            }
            Self::Redis { settings, client } => {
                put_redis(client, &record, allowed, settings.auth.jittered()).await
            }
            Self::Disabled => Ok(()),
        }
    }

    pub(super) async fn put_acl(
        &self,
        record: &Record,
        allowed: bool,
        log: &Log,
    ) -> Result<(), BackendError> {
        record.log(log);
        match self {
            Self::Redis { settings, client } => {
                put_redis(client, record, allowed, settings.acl.jittered()).await
            }
            _ => Ok(()),
        }
    }

    pub(super) fn acl_reuse(&self) -> Duration {
        match self {
            Self::Memory { settings, .. } => {
                Duration::from_nanos(settings.acl.jittered().max(0) as u64)
            }
            _ => Duration::ZERO,
        }
    }

    // cache/cache.go: redisStore.Close; the Go memory store has no cleanup.
    pub(super) fn close(&self) {
        if let Self::Redis { client, .. } = self {
            client.close();
        }
    }
}

// go-auth.go: setCache reads both signed values and clamps jitter to the TTL.
fn lifetime(options: &Options, kind: &str, log: &Log) -> Lifetime {
    let parse = |setting, camel_case, default| {
        options.get(&format!("{kind}_{setting}_seconds")).map_or(default, |value| {
            value.parse::<i64>().unwrap_or_else(|err| {
                let err = parse_int_error(&err);
                log.warn(format_args!("couldn't parse {kind}{camel_case}Seconds (err: strconv.ParseInt: parsing {value:?}: {err}), defaulting to {default}"));
                default
            })
        })
    };
    let seconds = parse("cache", "Cache", 30);
    let jitter = parse("jitter", "Jitter", 0);
    if jitter > seconds {
        log.warn(format_args!(
            "{kind}JitterSeconds is larger than {kind}CacheSeconds, defaulting to {seconds}"
        ));
    }
    Lifetime::new(seconds, jitter.min(seconds))
}

// cache/cache.go: toAuthRecord, toACLRecord use hash.Sum(...) on an empty
// SHA-1 state. Preserve byte-for-byte keys for compatibility with go-auth.
const EMPTY_SHA1: [u8; 20] = [
    0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55, 0xbf, 0xef, 0x95, 0x60, 0x18, 0x90,
    0xaf, 0xd8, 0x07, 0x09,
];

pub(super) struct Record {
    bytes: Vec<u8>,
    key: String,
}

impl Record {
    fn auth(username: &str, password: &[u8]) -> Self {
        let mut bytes = Vec::with_capacity(6 + username.len() + password.len() + EMPTY_SHA1.len());
        bytes.extend_from_slice(b"auth-");
        bytes.extend_from_slice(username.as_bytes());
        bytes.push(b'-');
        bytes.extend_from_slice(password);
        Self::from_prefix(bytes)
    }

    fn acl(username: &str, topic: &str, client_id: &str, access: i32) -> Self {
        let mut bytes = Vec::with_capacity(
            7 + username.len() + topic.len() + client_id.len() + 11 + EMPTY_SHA1.len(),
        );
        use std::io::Write as _;
        let _ = write!(bytes, "acl-{username}-{topic}-{client_id}-{access}");
        Self::from_prefix(bytes)
    }

    fn from_prefix(mut bytes: Vec<u8>) -> Self {
        bytes.extend_from_slice(&EMPTY_SHA1);
        let key = BASE64_STANDARD.encode(&bytes);
        Self { bytes, key }
    }

    fn log(&self, log: &Log) {
        struct GoSlice<'a>(&'a [u8]);
        impl fmt::Display for GoSlice<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_char('[')?;
                for (index, byte) in self.0.iter().enumerate() {
                    if index != 0 {
                        f.write_char(' ')?;
                    }
                    write!(f, "{byte}")?;
                }
                f.write_char(']')
            }
        }
        log.debug(format_args!("to auth record: {}\n", GoSlice(&self.bytes)));
    }
}

// cache/cache.go: redisStore.getAndRefresh and checkRecord. Any read error
// (including EXPIRE after a hit) is treated as a miss.
async fn get_redis(
    client: &Client,
    record: &Record,
    ttl: Lifetime,
    refresh: bool,
    log: &Log,
) -> Option<bool> {
    let key = record.key.as_bytes();
    let result = async {
        let allowed = match client.command(&[b"get", key], Some(key)).await? {
            Value::Bulk(value) => value == b"true",
            Value::Nil => return Err(BackendError::new("redis: nil")),
            _ => return Err(BackendError::new("invalid Redis GET response")),
        };
        if refresh {
            let seconds = (ttl.nanos / 1_000_000_000).to_string();
            if !matches!(
                client
                    .command(&[b"expire", key, seconds.as_bytes()], Some(key))
                    .await?,
                Value::Integer(_)
            ) {
                return Err(BackendError::new("invalid Redis EXPIRE response"));
            }
        }
        Ok(allowed)
    }
    .await;
    match result {
        Ok(allowed) => Some(allowed),
        Err(err) => {
            log.debug(format_args!("set cache error: {err}"));
            None
        }
    }
}

// cache/cache.go: redisStore.set uses go-redis Set: zero removes TTL, whole
// seconds use EX, subsecond/nonintegral seconds use PX (minimum positive 1ms).
async fn put_redis(
    client: &Client,
    record: &Record,
    allowed: bool,
    ns: i64,
) -> Result<(), BackendError> {
    let key = record.key.as_bytes();
    let value: &[u8] = if allowed { b"true" } else { b"false" };
    let reply = if ns > 0 {
        let (unit, amount): (&[u8], _) = if ns % 1_000_000_000 == 0 {
            (b"ex", ns / 1_000_000_000)
        } else {
            (b"px", (ns / 1_000_000).max(1))
        };
        client
            .command(
                &[b"set", key, value, unit, amount.to_string().as_bytes()],
                Some(key),
            )
            .await?
    } else if ns == -1 {
        client
            .command(&[b"set", key, value, b"keepttl"], Some(key))
            .await?
    } else {
        client.command(&[b"set", key, value], Some(key)).await?
    };
    match reply {
        Value::Simple(_) => Ok(()),
        _ => Err(BackendError::new("invalid Redis SET response")),
    }
}

#[derive(Default)]
pub(super) struct Memory {
    entries: HashMap<Arc<str>, Entry>,
    expiries: BTreeSet<(Instant, Arc<str>)>,
}

struct Entry {
    allowed: bool,
    ttl: Duration,
    deadline: Option<Instant>,
}

impl Memory {
    fn prune(&mut self, now: Instant) {
        while self
            .expiries
            .first()
            .is_some_and(|(deadline, _)| *deadline <= now)
        {
            let (_, key) = self.expiries.pop_first().expect("an expired entry");
            self.entries.remove(&key);
        }
    }

    fn get(&mut self, key: &str, refresh: bool, now: Instant) -> Option<bool> {
        self.prune(now);
        let (key, entry) = self.entries.get_key_value(key)?;
        let allowed = entry.allowed;
        // cache/cache.go: goStore.checkRecord; ttlcache extends by the
        // original jittered TTL (not the unjittered configuration value).
        if refresh && let Some(expiry) = entry.deadline {
            let key = key.clone();
            self.expiries.remove(&(expiry, key.clone()));
            let deadline = now + entry.ttl;
            self.entries
                .get_mut(&key)
                .expect("the looked up entry")
                .deadline = Some(deadline);
            self.expiries.insert((deadline, key));
        }
        Some(allowed)
    }

    fn put(&mut self, key: String, allowed: bool, ns: i64, now: Instant) {
        self.prune(now);
        let key: Arc<str> = key.into();
        if let Some(old) = self.entries.get(&key).and_then(|entry| entry.deadline) {
            self.expiries.remove(&(old, key.clone()));
        }
        // cache/cache.go: NewGoStore sets ttlcache's default to 60 seconds;
        // ttlcache Set interprets zero as the default and negatives as no TTL.
        let ttl = if ns == 0 {
            Duration::from_secs(60)
        } else {
            Duration::from_nanos(ns.max(0) as u64)
        };
        let deadline = (ns >= 0).then(|| now + ttl);
        if let Some(deadline) = deadline {
            self.expiries.insert((deadline, key.clone()));
        }
        self.entries.insert(
            key,
            Entry {
                allowed,
                ttl,
                deadline,
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_append_the_empty_sha1_and_keep_delimiter_collisions() {
        assert_eq!(
            Record::auth("bob", b"pw").key,
            "YXV0aC1ib2ItcHfaOaPuXmtLDTJVv++VYBiQr9gHCQ=="
        );
        assert_eq!(
            Record::acl("bob", "a/b", "cid", 4).key,
            "YWNsLWJvYi1hL2ItY2lkLTTaOaPuXmtLDTJVv++VYBiQr9gHCQ=="
        );
        assert_eq!(Record::auth("a-b", b"c").key, Record::auth("a", b"b-c").key);
        assert_ne!(
            Record::acl("bob", "a/b", "cid", 1).key,
            Record::acl("bob", "a/b", "cid", 4).key
        );
    }

    #[tokio::test]
    async fn acl_ttl_defaults_jitter_clamp_and_disable() {
        let log = Log::new(Level::Panic, Box::new(std::io::sink()));
        let mut opts = Options::new();
        assert_eq!(Cache::new(&opts, &log).await.acl_reuse(), Duration::ZERO);
        opts.insert("cache".into(), " true ".into());
        opts.insert("auth_cache_seconds".into(), "invalid".into());
        assert_eq!(
            Cache::new(&opts, &log).await.acl_reuse(),
            Duration::from_secs(30)
        );
        opts.insert("acl_cache_seconds".into(), "2".into());
        opts.insert("acl_jitter_seconds".into(), "1000".into());
        let cache = Cache::new(&opts, &log).await;
        for _ in 0..50 {
            assert!(cache.acl_reuse() < Duration::from_secs(4));
        }
        opts.insert("acl_cache_seconds".into(), "-1".into());
        assert_eq!(Cache::new(&opts, &log).await.acl_reuse(), Duration::ZERO);
    }

    #[test]
    fn auth_cache_records_denials_refresh_and_use_go_zero_ttl() {
        let then = Instant::now();
        let seconds = |delta| then + Duration::from_secs(delta);
        let mut cache = Memory::default();
        cache.put("touch".into(), false, 2_000_000_000, then);
        cache.put("no-touch".into(), true, 2_000_000_000, then);
        cache.put("zero".into(), true, 0, then);
        cache.put("negative".into(), false, -1, then);
        assert_eq!(cache.get("touch", true, seconds(1)), Some(false));
        assert_eq!(cache.get("no-touch", false, seconds(1)), Some(true));
        assert_eq!(cache.get("touch", false, seconds(2)), Some(false));
        assert_eq!(cache.get("no-touch", false, seconds(2)), None);
        assert_eq!(cache.get("touch", false, seconds(3)), None);
        assert_eq!(cache.get("zero", false, seconds(59)), Some(true));
        assert_eq!(cache.get("zero", false, seconds(60)), None);
        assert_eq!(cache.get("negative", true, seconds(100)), Some(false));
    }
}
