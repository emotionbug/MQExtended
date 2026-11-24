//! auth-plug back-ends by `auth_opt_backends` name.

mod cdb;
mod files;
mod http;
mod jwt;
mod memcached;
mod redis;

pub(crate) mod databases;

use crate::backend::{Backend, BackendResult, GetUser, LoadError, Options};

pub(crate) async fn create(name: &str, options: &Options) -> Result<Box<dyn Backend>, LoadError> {
    match name {
        "files" => files::create(options).await,
        "http" => http::create(options).await,
        "jwt" => jwt::create(options).await,
        "cdb" => cdb::create(options).await,
        "redis" => redis::create(options).await,
        "memcached" => memcached::create(options).await,
        _ => databases::create(name, options).await.unwrap_or_else(|| {
            Err(LoadError::new(format!(
                "ERROR: configured back-end `{name}' is not compiled in this plugin"
            )))
        }),
    }
}

fn hash_reply(mut bytes: Vec<u8>) -> GetUser {
    bytes.truncate(crate::authplug::c_string(&bytes).len());
    String::from_utf8(bytes).map_or_else(|_| GetUser::result(BackendResult::Defer), GetUser::hash)
}
