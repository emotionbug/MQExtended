//! Redis transports shared by the go-auth backend and its caches.

use std::{
    collections::HashMap,
    io,
    ops::RangeInclusive,
    sync::{Arc, Mutex},
    time::Duration,
};

use crate::net::resp::{Connection, Value};

use super::backend::BackendError;

const SLOTS: u16 = 16384;
// go-redis v8 options.go: Options.init.
const DIAL_TIMEOUT: Duration = Duration::from_secs(5);
const IO_TIMEOUT: Duration = Duration::from_secs(3);

pub(crate) struct Client {
    password: String,
    mode: Mode,
    idle: Mutex<HashMap<Arc<str>, Connection>>,
}

enum Mode {
    Standalone {
        address: Arc<str>,
        db: i64,
    },
    Cluster {
        seeds: Vec<Arc<str>>,
        routes: Mutex<Routes>,
    },
}

type SlotRange = (RangeInclusive<u16>, Arc<str>);

#[derive(Default)]
struct Routes {
    ranges: Vec<SlotRange>,
    moved: HashMap<u16, Arc<str>>,
}

impl Client {
    pub(crate) fn standalone(address: String, password: String, db: i64) -> Self {
        Self {
            password,
            mode: Mode::Standalone {
                address: address.into(),
                db,
            },
            idle: Mutex::default(),
        }
    }

    pub(crate) fn cluster(addresses: Vec<String>, password: String) -> Self {
        Self {
            password,
            mode: Mode::Cluster {
                seeds: addresses.into_iter().map(Arc::from).collect(),
                routes: Mutex::default(),
            },
            idle: Mutex::default(),
        }
    }

    pub(crate) async fn ping(&self) -> Result<(), BackendError> {
        if let Mode::Cluster { seeds, routes } = &self.mode {
            self.refresh_routes(seeds, routes).await?;
        }
        match self.command(&[b"ping"], None).await? {
            Value::Simple(status) if status == b"PONG" => Ok(()),
            _ => Err(BackendError::new("invalid Redis PING response")),
        }
    }

    pub(crate) fn close(&self) {
        self.idle
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .clear();
    }

    // backends/redis.go: GetUser, GetSuperuser, CheckAcl and cache/cache.go:
    // checkRecord, setRecord reload the cluster state and retry on a redirect.
    pub(crate) async fn command(
        &self,
        parts: &[&[u8]],
        key: Option<&[u8]>,
    ) -> Result<Value, BackendError> {
        let (seeds, routes) = match &self.mode {
            Mode::Standalone { address, .. } => {
                return checked(self.send(address, parts, false).await?);
            }
            Mode::Cluster { seeds, routes } => (seeds, routes),
        };
        let slot = key.map(hash_slot);
        // A successful PING populated slots; if a slot was not in the
        // advertised ranges, try the first reachable seed or primary.
        let address = {
            let routes = routes.lock().unwrap_or_else(|err| err.into_inner());
            slot.and_then(|slot| {
                routes.moved.get(&slot).or_else(|| {
                    routes
                        .ranges
                        .iter()
                        .find(|(range, _)| range.contains(&slot))
                        .map(|(_, addr)| addr)
                })
            })
            .or_else(|| routes.ranges.first().map(|(_, addr)| addr))
            .or_else(|| seeds.first())
            .cloned()
        }
        .ok_or_else(|| BackendError::new("redis: no cluster nodes"))?;
        let reply = self.send(&address, parts, false).await?;
        let Value::Error(error) = &reply else {
            return Ok(reply);
        };
        let Some((redirect_slot, asking, target)) = redirect(error, &address) else {
            return checked(reply);
        };
        // ASK is temporary and applies only to the very next command on the
        // same connection. MOVED persists even if the topology refresh fails.
        let _ = self.refresh_routes(seeds, routes).await;
        if !asking {
            routes
                .lock()
                .unwrap_or_else(|err| err.into_inner())
                .moved
                .insert(redirect_slot, target.clone());
        }
        checked(self.send(&target, parts, asking).await?)
    }

    async fn refresh_routes(
        &self,
        seeds: &[Arc<str>],
        routes: &Mutex<Routes>,
    ) -> Result<(), BackendError> {
        let mut last = BackendError::new("redis: no cluster nodes");
        for address in seeds {
            match self
                .send(address, &[b"cluster", b"slots"], false)
                .await
                .and_then(checked)
                .and_then(|reply| parse_slots(reply, address))
            {
                Ok(ranges) => {
                    *routes.lock().unwrap_or_else(|err| err.into_inner()) = Routes {
                        ranges,
                        moved: HashMap::new(),
                    };
                    return Ok(());
                }
                Err(err) => last = err,
            }
        }
        Err(last)
    }

    async fn send(
        &self,
        address: &Arc<str>,
        parts: &[&[u8]],
        asking: bool,
    ) -> Result<Value, BackendError> {
        let pooled = self
            .idle
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .remove(address);
        let reused = pooled.is_some();
        let mut connection = match pooled {
            Some(connection) => connection,
            None => self.connect(address).await?,
        };
        // A cancelled or interrupted read drops its connection rather than
        // leaving a later caller to read its reply.
        let value = match self.execute(&mut connection, parts, asking).await {
            Ok(value) => value,
            Err(err)
                if reused
                    && matches!(
                        err.kind(),
                        io::ErrorKind::ConnectionReset
                            | io::ErrorKind::BrokenPipe
                            | io::ErrorKind::UnexpectedEof
                    ) =>
            {
                connection = self.connect(address).await?;
                self.execute(&mut connection, parts, asking)
                    .await
                    .map_err(redis_error)?
            }
            Err(err) => return Err(redis_error(err)),
        };
        self.idle
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .insert(address.clone(), connection);
        Ok(value)
    }

    async fn connect(&self, address: &str) -> Result<Connection, BackendError> {
        let (host, port) = endpoint(address)
            .ok_or_else(|| BackendError::new(format!("invalid Redis address {address:?}")))?;
        let mut connection = Connection::connect_with_timeout(host, port, DIAL_TIMEOUT)
            .await
            .map_err(redis_error)?;
        if !self.password.is_empty() {
            checked(
                self.execute(&mut connection, &[b"auth", self.password.as_bytes()], false)
                    .await
                    .map_err(redis_error)?,
            )?;
        }
        if let Mode::Standalone { db, .. } = self.mode
            && db > 0
        {
            checked(
                self.execute(
                    &mut connection,
                    &[b"select", db.to_string().as_bytes()],
                    false,
                )
                .await
                .map_err(redis_error)?,
            )?;
        }
        Ok(connection)
    }

    async fn execute(
        &self,
        connection: &mut Connection,
        parts: &[&[u8]],
        asking: bool,
    ) -> io::Result<Value> {
        tokio::time::timeout(IO_TIMEOUT, async {
            if asking {
                let reply = connection.command_value(&[b"asking"]).await?;
                if matches!(reply, Value::Error(_)) {
                    return Ok(reply);
                }
            }
            connection.command_value(parts).await
        })
        .await?
    }
}

fn checked(value: Value) -> Result<Value, BackendError> {
    match value {
        Value::Error(err) => Err(BackendError::new(err)),
        value => Ok(value),
    }
}

fn redis_error(error: io::Error) -> BackendError {
    BackendError::new(error.to_string())
}

fn endpoint(address: &str) -> Option<(&str, u16)> {
    let (host, port) = address.rsplit_once(':')?;
    Some((
        host.trim_start_matches('[').trim_end_matches(']'),
        port.parse().ok()?,
    ))
}

fn redirect(message: &str, origin: &str) -> Option<(u16, bool, Arc<str>)> {
    let mut words = message.split_ascii_whitespace();
    let asking = match words.next()? {
        "MOVED" => false,
        "ASK" => true,
        _ => return None,
    };
    let slot = words.next()?.parse().ok()?;
    let target = words.next()?;
    Some((
        slot,
        asking,
        if target.starts_with(':') {
            let (host, _) = origin.rsplit_once(':')?;
            format!("{host}{target}").into()
        } else {
            target.into()
        },
    ))
}

fn parse_slots(reply: Value, origin: &str) -> Result<Vec<SlotRange>, BackendError> {
    fn invalid() -> BackendError {
        BackendError::new("invalid Redis CLUSTER SLOTS response")
    }
    let Value::Array(ranges) = reply else {
        return Err(invalid());
    };
    let mut parsed = Vec::with_capacity(ranges.len());
    for range in ranges {
        let Value::Array(fields) = range else {
            return Err(invalid());
        };
        let [
            Value::Integer(start),
            Value::Integer(end),
            Value::Array(primary),
            ..,
        ] = fields.as_slice()
        else {
            return Err(invalid());
        };
        if *start < 0 || *end < *start || *end >= i64::from(SLOTS) {
            return Err(invalid());
        }
        let [host, Value::Integer(port), ..] = primary.as_slice() else {
            return Err(invalid());
        };
        let host = match host {
            Value::Bulk(host) | Value::Simple(host) if !host.is_empty() && host != b"?" => {
                std::str::from_utf8(host).map_err(|_| invalid())?
            }
            Value::Bulk(_) | Value::Simple(_) | Value::Nil => {
                endpoint(origin).ok_or_else(invalid)?.0
            }
            _ => return Err(invalid()),
        };
        let address = if host.contains(':') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        };
        parsed.push((*start as u16..=*end as u16, address.into()));
    }
    Ok(parsed)
}

// go-redis v8 internal/hashtag/hashtag.go: Slot. Redis hash tags select the
// text between the first matching nonempty pair, then use CRC16-XMODEM.
fn hash_slot(key: &[u8]) -> u16 {
    let key = key
        .iter()
        .position(|&byte| byte == b'{')
        .and_then(|start| {
            let rest = &key[start + 1..];
            let end = rest.iter().position(|&byte| byte == b'}')?;
            (end > 0).then(|| &rest[..end])
        })
        .unwrap_or(key);
    let mut crc: u16 = 0;
    for &byte in key {
        crc ^= u16::from(byte) << 8;
        for _ in 0..8 {
            crc = (crc << 1) ^ if crc & 0x8000 != 0 { 0x1021 } else { 0 };
        }
    }
    crc % SLOTS
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    #[test]
    fn redis_slot_and_redirect() {
        assert_eq!(hash_slot(b"123456789"), 12739);
        assert_eq!(hash_slot(b"one{same}"), hash_slot(b"two{same}"));
        assert_ne!(hash_slot(b"one{}{same}"), hash_slot(b"two{}{same}"));
        assert_eq!(
            redirect("MOVED 7 :1234", "[::1]:8900"),
            Some((7, false, "[::1]:1234".into()))
        );
        assert_eq!(
            redirect("ASK 42 127.0.0.1:9001", "127.0.0.1:8900"),
            Some((42, true, "127.0.0.1:9001".into()))
        );
    }

    #[tokio::test]
    async fn cluster_follows_ask_once_and_remembers_moved() {
        let seed = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let target = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let seed_addr = seed.local_addr().unwrap();
        let target_addr = target.local_addr().unwrap();
        let slot = hash_slot(b"k");
        let slots = format!(
            "*1\r\n*3\r\n:0\r\n:16383\r\n*3\r\n$9\r\n127.0.0.1\r\n:{}\r\n$4\r\nseed\r\n",
            seed_addr.port()
        );
        let ask = format!("-ASK {slot} {target_addr}\r\n");
        let moved = format!("-MOVED {slot} {target_addr}\r\n");
        let seed_task = tokio::spawn(async move {
            let (mut client, _) = seed.accept().await.unwrap();
            let get: &[u8] = b"*2\r\n$3\r\nget\r\n$1\r\nk\r\n";
            let topology: &[u8] = b"*2\r\n$7\r\ncluster\r\n$5\r\nslots\r\n";
            for (command, response) in [
                (topology, slots.as_bytes()),
                (b"*1\r\n$4\r\nping\r\n", b"+PONG\r\n"),
                (get, ask.as_bytes()),
                (topology, slots.as_bytes()),
                (get, moved.as_bytes()),
                (topology, slots.as_bytes()),
            ] {
                let mut bytes = vec![0; command.len()];
                client.read_exact(&mut bytes).await.unwrap();
                assert_eq!(bytes, command);
                client.write_all(response).await.unwrap();
            }
        });
        let target_task = tokio::spawn(async move {
            let (mut client, _) = target.accept().await.unwrap();
            let get: &[u8] = b"*2\r\n$3\r\nget\r\n$1\r\nk\r\n";
            for (command, response) in [
                (b"*1\r\n$6\r\nasking\r\n".as_slice(), b"+OK\r\n".as_slice()),
                (get, b"$3\r\nask\r\n"),
                (get, b"$5\r\nmoved\r\n"),
                (get, b"$6\r\ndirect\r\n"),
            ] {
                let mut bytes = vec![0; command.len()];
                client.read_exact(&mut bytes).await.unwrap();
                assert_eq!(bytes, command);
                client.write_all(response).await.unwrap();
            }
        });
        let client = Client::cluster(vec![seed_addr.to_string()], String::new());
        client.ping().await.unwrap();
        for expected in [b"ask".as_slice(), b"moved", b"direct"] {
            assert_eq!(
                client.command(&[b"get", b"k"], Some(b"k")).await.unwrap(),
                Value::Bulk(expected.to_vec())
            );
        }
        seed_task.await.unwrap();
        target_task.await.unwrap();
    }
}
