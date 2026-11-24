use std::borrow::Cow;

use mqx_auth::external::BoxFuture;
use tokio::sync::Mutex;

use crate::authplug::{atoi, log};
use crate::backend::{Backend, BackendResult, GetUser, LoadError, Options};
use crate::net::resp::Connection;

struct Redis {
    host: String,
    port: i32,
    db: i32,
    password: String,
    user_query: String,
    acl_query: String,
    connection: Mutex<Option<Connection>>,
}

pub(crate) async fn create(options: &Options) -> Result<Box<dyn Backend>, LoadError> {
    // be-redis.c: be_redis_init.
    log(format_args!("}}}}}}}} Redis"));
    let user_query = options
        .get("redis_userquery")
        .filter(|s| !s.is_empty())
        .unwrap_or("GET %s");
    let redis = Redis {
        host: options.get("redis_host").unwrap_or("localhost").into(),
        port: atoi(options.get("redis_port").unwrap_or("6379").as_bytes()),
        db: atoi(options.get("redis_db").unwrap_or("0").as_bytes()),
        password: options.get("redis_pass").unwrap_or_default().into(),
        user_query: user_query.into(),
        acl_query: options.get("redis_aclquery").unwrap_or_default().into(),
        connection: Mutex::new(None),
    };
    *redis.connection.lock().await = Some(
        redis
            .connect()
            .await
            .ok_or_else(|| LoadError::new("redis init returns NULL"))?,
    );
    Ok(Box::new(redis))
}

impl Redis {
    // be-redis.c: be_redis_reconnect sends AUTH then SELECT. A Redis error
    // reply is not a hiredis context error; AUTH/SELECT ignore reply types.
    async fn connect(&self) -> Option<Connection> {
        let mut connection = match Connection::connect(&self.host, self.port as u16).await {
            Ok(connection) => connection,
            Err(error) => {
                let error = error.to_string();
                let error = error
                    .strip_prefix("failed to lookup address information: ")
                    .unwrap_or(&error);
                let error = error
                    .rsplit_once(" (os error ")
                    .map_or(error, |(description, _)| description);
                log(format_args!(
                    "Redis connection error: {} for {}:{}\n",
                    error, self.host, self.port
                ));
                return None;
            }
        };
        if !self.password.is_empty() {
            log(format_args!("Using password protected redis\n"));
            if let Err(error) = connection
                .command(&[b"AUTH".as_slice(), self.password.as_bytes()])
                .await
            {
                log(format_args!("Redis authentication error: {error}\n"));
                return None;
            }
        }
        connection
            .command(&["SELECT", &self.db.to_string()])
            .await
            .ok()?;
        Some(connection)
    }

    async fn query(
        &self,
        template: &str,
        args: &[&str],
        acl: Option<(&str, i32)>,
    ) -> Result<Option<Vec<u8>>, BackendResult> {
        let mut socket = self.connection.lock().await;
        if let Some(mut connected) = socket.take()
            && let Some(query) = sprintf(template, args)
            && let Some(command) = hiredis(&query, acl)
            && let Ok(reply) = connected.command(&command).await
        {
            *socket = Some(connected);
            return Ok(reply);
        }
        // be-redis.c: getuser/aclcheck reconnect after an I/O/format error,
        // but never retry the command whose result was lost.
        *socket = self.connect().await;
        Err(BackendResult::Error)
    }
}

// be-redis.c: be_redis_getuser, be_redis_aclcheck first use sprintf, then
// pass the resulting format to hiredis. Double percent signs in client inputs
// to preserve literal bytes instead of using them as new format directives.
fn sprintf(template: &str, args: &[&str]) -> Option<Vec<u8>> {
    let mut next = 0;
    let capacity = template.len() + args.iter().map(|s| s.len()).sum::<usize>();
    let mut output = Vec::with_capacity(capacity);
    let mut rest = template.as_bytes();
    while let Some(at) = rest.iter().position(|&b| b == b'%') {
        output.extend_from_slice(&rest[..at]);
        rest = &rest[at + 1..];
        if let Some(tail) = rest.strip_prefix(b"%") {
            output.push(b'%');
            rest = tail;
            continue;
        }
        let (position, tail) = decimal(rest)?;
        let index = if let Some(tail) = tail.strip_prefix(b"$") {
            rest = tail;
            position?.checked_sub(1)?
        } else {
            let index = next;
            next += 1;
            index
        };
        let left_align = rest.starts_with(b"-");
        if left_align {
            rest = &rest[rest.iter().take_while(|&&b| b == b'-').count()..];
        }
        let (width, tail) = decimal(rest)?;
        rest = tail;
        let mut field = args.get(index)?.as_bytes();
        if let Some(tail) = rest.strip_prefix(b".") {
            let (precision, tail) = decimal(tail)?;
            field = &field[..field.len().min(precision.unwrap_or(0))];
            rest = tail;
        }
        rest = rest.strip_prefix(b"s")?;
        // The C caller reserves only fixed extra space. Do not allow a
        // field width to request arbitrary allocations.
        let width = width.unwrap_or(0);
        if width > capacity.saturating_add(127) {
            return None;
        }
        let padding = width.saturating_sub(field.len());
        if !left_align {
            output.resize(output.len() + padding, b' ');
        }
        for &byte in field {
            output.push(byte);
            if byte == b'%' {
                output.push(b'%');
            }
        }
        if left_align {
            output.resize(output.len() + padding, b' ');
        }
    }
    output.extend_from_slice(rest);
    Some(output)
}

fn decimal(bytes: &[u8]) -> Option<(Option<usize>, &[u8])> {
    let end = bytes.iter().take_while(|b| b.is_ascii_digit()).count();
    if end == 0 {
        return Some((None, bytes));
    }
    let value = std::str::from_utf8(&bytes[..end]).ok()?.parse().ok()?;
    Some((Some(value), &bytes[end..]))
}

fn hiredis<'a>(query: &'a [u8], acl: Option<(&str, i32)>) -> Option<Vec<Cow<'a, [u8]>>> {
    let mut field = 0;
    query
        .split(|&b| b == b' ')
        .filter(|word| !word.is_empty())
        .map(|word| {
            if !word.contains(&b'%') {
                return Some(Cow::Borrowed(word));
            }
            let mut output = Vec::with_capacity(word.len());
            let mut rest = word;
            while let Some(at) = rest.iter().position(|&b| b == b'%') {
                output.extend_from_slice(&rest[..at]);
                match &rest[at + 1..] {
                    [b'%', tail @ ..] => {
                        output.push(b'%');
                        rest = tail;
                    }
                    [b's', tail @ ..] if field == 0 => {
                        output.extend_from_slice(acl?.0.as_bytes());
                        field += 1;
                        rest = tail;
                    }
                    [b'd' | b'i', tail @ ..] if field == 1 => {
                        output.extend_from_slice(acl?.1.to_string().as_bytes());
                        field += 1;
                        rest = tail;
                    }
                    [] => {
                        output.push(b'%');
                        rest = &[];
                    }
                    _ => return None,
                }
            }
            output.extend_from_slice(rest);
            Some(Cow::Owned(output))
        })
        .collect()
}

impl Backend for Redis {
    fn name(&self) -> &'static str {
        "redis"
    }

    fn getuser<'a>(&'a self, username: &'a str, _: &'a [u8], _: &'a str) -> BoxFuture<'a, GetUser> {
        Box::pin(async move {
            match self.query(&self.user_query, &[username], None).await {
                Ok(Some(bytes)) => super::hash_reply(bytes),
                Ok(None) => GetUser::result(BackendResult::Defer),
                Err(error) => GetUser::result(error),
            }
        })
    }

    fn superuser<'a>(&'a self, _: &'a str) -> BoxFuture<'a, BackendResult> {
        Box::pin(async { BackendResult::Defer })
    }

    fn aclcheck<'a>(
        &'a self,
        _: &'a str,
        username: &'a str,
        topic: &'a str,
        access: i32,
    ) -> BoxFuture<'a, BackendResult> {
        Box::pin(async move {
            if self.acl_query.is_empty() {
                return BackendResult::Allow;
            }
            match self
                .query(
                    &self.acl_query,
                    &[username, topic],
                    Some((username, access)),
                )
                .await
            {
                Ok(Some(bytes)) if atoi(&bytes) >= access => BackendResult::Allow,
                Ok(_) => BackendResult::Defer,
                Err(error) => error,
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_in_two_passes_but_does_not_read_format_directives_from_users() {
        let text = sprintf("GET  prefixes:%s:%s%%%%", &["some user", "%secret"]).unwrap();
        assert_eq!(
            hiredis(&text, None).unwrap(),
            [b"GET".as_slice(), b"prefixes:some", b"user:%secret%"]
        );
        let text = sprintf("EVAL %%s %%d", &[]).unwrap();
        assert_eq!(
            hiredis(&text, Some(("a b", 4))).unwrap(),
            [b"EVAL".as_slice(), b"a b", b"4"]
        );
        let text = sprintf("GET p:%2$-8.3s:%1$s", &["one", "second"]).unwrap();
        assert_eq!(text, b"GET p:sec     :one");
        assert!(sprintf("GET %99999999s", &["one"]).is_none());
    }
}
