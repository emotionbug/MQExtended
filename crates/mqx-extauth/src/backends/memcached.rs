use mqx_auth::external::BoxFuture;
use tokio::sync::Mutex;

use crate::authplug::{atoi, log};
use crate::backend::{Backend, BackendResult, GetUser, LoadError, Options};
use crate::net::memcached::Connection;

struct Memcached {
    host: String,
    port: u16,
    check_acl: bool,
    socket: Mutex<Option<Connection>>,
}

pub(crate) async fn create(options: &Options) -> Result<Box<dyn Backend>, LoadError> {
    // be-memcached.c: be_memcached_init. db, pass and userquery are not used.
    log(format_args!("}}}}}}}} Memcached"));
    let host = options.get("memcached_host").unwrap_or("localhost");
    let port = atoi(options.get("memcached_port").unwrap_or("11211").as_bytes()) as u16;
    let port = if port == 0 { 11211 } else { port };
    // libmemcached returns an allocated stats array on per-server
    // connection errors. The C init check therefore succeeds even offline.
    let socket = Connection::connect(host, port, true).await.ok();
    let check_acl = options
        .get("memcached_aclquery")
        .is_some_and(|query| !query.is_empty());
    Ok(Box::new(Memcached {
        host: host.into(),
        port,
        check_acl,
        socket: Mutex::new(socket),
    }))
}

impl Memcached {
    async fn query(&self, key: &[u8]) -> Option<Vec<u8>> {
        let mut socket = self.socket.lock().await;
        // Keep the stream out of the slot while a request is in progress:
        // if canceled, another client must not read its pending reply.
        let connected = match socket.take() {
            Some(connection) => Some(connection),
            None => Connection::connect(&self.host, self.port, false).await.ok(),
        };
        if let Some(mut connected) = connected
            && let Ok(Some(reply)) = connected.get(key).await
        {
            *socket = Some(connected);
            return Some(reply);
        }
        // be-memcached.c: getuser/aclcheck reconnect even on a clean miss.
        *socket = Connection::connect(&self.host, self.port, true).await.ok();
        None
    }
}

impl Backend for Memcached {
    fn name(&self) -> &'static str {
        "memcached"
    }

    fn getuser<'a>(&'a self, username: &'a str, _: &'a [u8], _: &'a str) -> BoxFuture<'a, GetUser> {
        Box::pin(async move {
            // be-memcached.c: be_memcached_getuser defers on failed lookup.
            self.query(username.as_bytes())
                .await
                .map_or_else(|| GetUser::result(BackendResult::Defer), super::hash_reply)
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
            // be-memcached.c: be_memcached_aclcheck uses the literal key
            // username-topic, not the configured query string.
            if !self.check_acl {
                return BackendResult::Allow;
            }
            let key = format!("{username}-{topic}");
            match self.query(key.as_bytes()).await {
                Some(reply) if atoi(&reply) >= access => BackendResult::Allow,
                Some(_) => BackendResult::Defer,
                None => BackendResult::Error,
            }
        })
    }
}
