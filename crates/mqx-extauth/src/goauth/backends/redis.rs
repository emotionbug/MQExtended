use std::{sync::Arc, time::Duration};

use mqx_auth::external::BoxFuture;

use super::sql::{expand, option};
use crate::{
    backend::LoadError,
    goauth::{
        backend::{Backend, BackendError, Hasher, Init, Log},
        redis::Client,
        topics,
    },
    net::resp::Value,
};

struct Redis {
    client: Client,
    disable_superuser: bool,
    hasher: Arc<dyn Hasher>,
    log: Log,
}

// redis.go: NewRedis. Cluster mode uses only its seed addresses, ignoring
// the standalone host, port and database index. PING retries forever.
pub(crate) async fn create(init: Init<'_>) -> Result<Box<dyn Backend>, LoadError> {
    init.log.set_level(init.log.level());
    let opts = init.options;
    let password = option(opts, "redis_password", "").to_owned();
    let client = if option(opts, "redis_mode", "") == "cluster" {
        let addresses = option(opts, "redis_cluster_addresses", "");
        if addresses.is_empty() {
            return Err(LoadError::new(
                "redis backend: missing Redis Cluster addresses",
            ));
        }
        Client::cluster(
            addresses
                .split(',')
                .map(|address| address.trim().to_owned())
                .collect(),
            password,
        )
    } else {
        let host = option(opts, "redis_host", "localhost");
        let port = option(opts, "redis_port", "6379");
        let db = option(opts, "redis_db", "1").parse::<i32>().unwrap_or(1);
        Client::standalone(format!("{host}:{port}"), password, i64::from(db))
    };
    while let Err(err) = client.ping().await {
        init.log
            .error(format_args!("ping redis error, will retry in 2s: {err}"));
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    Ok(Box::new(Redis {
        client,
        disable_superuser: option(opts, "redis_disable_superuser", "false") == "true",
        hasher: init.hasher,
        log: init.log,
    }))
}

impl Redis {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, BackendError> {
        let key = key.as_bytes();
        match self.client.command(&[b"get", key], Some(key)).await? {
            Value::Nil => Ok(None),
            Value::Bulk(value) | Value::Simple(value) => Ok(Some(value)),
            _ => Err(BackendError::new("redis: invalid GET response")),
        }
    }

    async fn members(&self, key: &str) -> Result<Option<Vec<Value>>, BackendError> {
        let key = key.as_bytes();
        match self.client.command(&[b"smembers", key], Some(key)).await? {
            Value::Array(values)
                if values
                    .iter()
                    .all(|value| matches!(value, Value::Bulk(_) | Value::Simple(_))) =>
            {
                Ok(Some(values))
            }
            Value::Nil => Ok(None),
            _ => Err(BackendError::new("redis: invalid SMEMBERS response")),
        }
    }

    // redis.go: checkAcl. Fetch *all* relevant sets before trying a match;
    // errors from common sets aren't masked by an earlier matching user rule.
    async fn acl(
        &self,
        username: &str,
        topic: &str,
        client_id: &str,
        access: i32,
    ) -> Result<bool, BackendError> {
        let (user_suffix, common_key) = match access {
            1 => (":racls", "common:racls"),
            2 => (":wacls", "common:wacls"),
            4 => (":sacls", "common:sacls"),
            _ => return Ok(false),
        };
        let mut key = String::with_capacity(username.len() + ":rwacls".len());
        key.push_str(username);
        key.push_str(user_suffix);
        let Some(user) = self.members(&key).await? else {
            return Ok(false);
        };
        let mut user_rw = Vec::new();
        if access != 4 {
            key.truncate(username.len());
            key.push_str(":rwacls");
            let Some(values) = self.members(&key).await? else {
                return Ok(false);
            };
            user_rw = values;
        }
        let Some(common) = self.members(common_key).await? else {
            return Ok(false);
        };
        let mut common_rw = Vec::new();
        if access != 4 {
            let Some(values) = self.members("common:rwacls").await? else {
                return Ok(false);
            };
            common_rw = values;
            // The Go read/write paths prepend as many empty patterns as they
            // fetch. Empty topics are rejected on MQTT, but callers of the
            // direct broker authorization interface can observe this behavior.
            if topic.is_empty()
                && (!user.is_empty()
                    || !user_rw.is_empty()
                    || !common.is_empty()
                    || !common_rw.is_empty())
            {
                return Ok(true);
            }
        }
        let patterns = |value| match value {
            Value::Bulk(value) | Value::Simple(value) => String::from_utf8(value).ok(),
            _ => None,
        };
        Ok(user
            .into_iter()
            .chain(user_rw)
            .filter_map(patterns)
            .any(|pattern| topics::matches(&pattern, topic))
            || common
                .into_iter()
                .chain(common_rw)
                .filter_map(patterns)
                .any(|pattern| topics::matches(&expand(&pattern, client_id, username), topic)))
    }

    fn report(
        &self,
        action: &str,
        result: Result<bool, BackendError>,
    ) -> Result<bool, BackendError> {
        result.inspect_err(|err| self.log.debug(format_args!("redis {action} error: {err}")))
    }
}

impl Backend for Redis {
    fn name(&self) -> String {
        "Redis".to_owned()
    }

    // redis.go: GetUser, getUser. The shared Redis transport owns cluster
    // routing and handles MOVED/ASK without leaking a connection's state.
    fn get_user<'a>(
        &'a self,
        username: &'a str,
        password: &'a [u8],
        _: &str,
    ) -> BoxFuture<'a, Result<bool, BackendError>> {
        Box::pin(async move {
            let result = self.get(username).await.map(|value| {
                value
                    .as_deref()
                    .is_some_and(|hash| self.hasher.compare_bytes(password, hash))
            });
            self.report("get user", result)
        })
    }

    // redis.go: GetSuperuser, getSuperuser.
    fn get_superuser<'a>(&'a self, username: &'a str) -> BoxFuture<'a, Result<bool, BackendError>> {
        Box::pin(async move {
            if self.disable_superuser {
                return Ok(false);
            }
            let result = self
                .get(&format!("{username}:su"))
                .await
                .map(|value| value.as_deref() == Some(b"true"));
            self.report("get superuser", result)
        })
    }

    fn check_acl<'a>(
        &'a self,
        username: &'a str,
        topic: &'a str,
        client_id: &'a str,
        access: i32,
    ) -> BoxFuture<'a, Result<bool, BackendError>> {
        Box::pin(async move {
            self.report(
                "check acl",
                self.acl(username, topic, client_id, access).await,
            )
        })
    }

    // redis.go: Halt closes the connection pool.
    fn halt(&self) -> BoxFuture<'_, ()> {
        Box::pin(async { self.client.close() })
    }
}
