//! go-auth back-ends by `auth_opt_backends` name
//! (`backends/backends.go: addBackends`).

use crate::backend::LoadError;

use super::backend::{Backend, Init};

mod files;
mod grpc;
mod http;
mod jwt;
mod ldap;
mod mongo;
mod mysql;
mod postgres;
mod redis;
mod sql;
mod sqlite;

/// Builds the back-end `name` names. The error is the `err` go-auth logs in
/// `Backend register error: couldn't initialize <name> backend with error <err>.`
pub(crate) async fn create(name: &str, init: Init<'_>) -> Result<Box<dyn Backend>, LoadError> {
    match name {
        "files" => files::create(init).await,
        "grpc" => grpc::create(init).await,
        "http" => http::create(init).await,
        "jwt" => jwt::create(init).await,
        "ldap" => ldap::create(init).await,
        "mongo" => mongo::create(init).await,
        "mysql" => mysql::create(init).await,
        "postgres" => postgres::create(init).await,
        "redis" => redis::create(init).await,
        "sqlite" => sqlite::create(init).await,
        _ => Err(LoadError::new(format!("unknown backend {name}"))),
    }
}
