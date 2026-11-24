use std::sync::Arc;
use std::time::Duration;

use mqx_auth::external::BoxFuture;
use rusqlite::{Connection, ErrorCode, OpenFlags, types::ValueRef};
use tokio::sync::Mutex;

use crate::backend::{Backend, BackendResult, GetUser, LoadError, Options};

struct Sqlite(MutexConnection);

type MutexConnection = Arc<Mutex<(Connection, String)>>;

pub(crate) async fn create(options: &Options) -> Result<Box<dyn Backend>, LoadError> {
    // be-sqlite.c: be_sqlite_init, prepareStatement. A failed initial prepare
    // does not fail plugin init: getuser re-prepares the statement later.
    let path = options
        .get("dbpath")
        .ok_or_else(|| LoadError::new("Mandatory parameter `dbpath' missing"))?
        .to_owned();
    let query = options
        .get("sqliteuserquery")
        .ok_or_else(|| LoadError::new("Mandatory parameter `sqliteuserquery' missing"))?
        .to_owned();
    let state = tokio::task::spawn_blocking(move || {
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_SHARED_CACHE,
        )
        .map_err(|_| LoadError::new("sqlite init returns NULL"))?;
        // rusqlite installs a busy timeout by default; auth-plug retries steps
        // itself instead of waiting inside SQLite.
        connection
            .busy_timeout(Duration::ZERO)
            .map_err(|_| LoadError::new("sqlite init returns NULL"))?;
        connection.set_prepared_statement_cache_capacity(1);
        let _ = connection.prepare_cached(&query);
        Ok::<_, LoadError>((connection, query))
    })
    .await
    .map_err(|_| LoadError::new("sqlite init returns NULL"))??;
    Ok(Box::new(Sqlite(Arc::new(Mutex::new(state)))))
}

fn query_user(connection: &Connection, query: &str, username: &str) -> GetUser {
    // be-sqlite.c: be_sqlite_getuser. Reset/clear, bind slot 1 (other slots
    // remain NULL), then step once per attempt, ignoring all later rows.
    let mut result = BackendResult::Defer;
    for _ in 0..4 {
        let Ok(mut stmt) = connection.prepare_cached(query) else {
            return GetUser::result(BackendResult::Error);
        };
        if stmt.raw_bind_parameter(1, username).is_err() {
            return GetUser::result(BackendResult::Error);
        }
        let row = {
            let mut rows = stmt.raw_query();
            rows.next()
                .and_then(|row| row.map(|row| row.get_ref(0).map(text)).transpose())
        };
        match row {
            Ok(Some(Some(hash))) => {
                return GetUser {
                    result,
                    hash: Some(hash),
                };
            }
            Ok(_) => (),
            Err(err) => {
                if !matches!(
                    err.sqlite_error_code(),
                    Some(ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked)
                ) {
                    stmt.discard();
                    result = BackendResult::Error;
                }
            }
        }
    }
    GetUser::result(result)
}

fn text(value: ValueRef<'_>) -> Option<String> {
    match value {
        ValueRef::Null => None,
        ValueRef::Text(bytes) | ValueRef::Blob(bytes) => {
            let c_string = bytes.split(|&b| b == 0).next().unwrap_or_default();
            std::str::from_utf8(c_string).ok().map(str::to_owned)
        }
        ValueRef::Integer(n) => Some(n.to_string()),
        ValueRef::Real(n) => Some(n.to_string()),
    }
}

impl Backend for Sqlite {
    fn name(&self) -> &'static str {
        "sqlite"
    }

    fn getuser<'a>(&'a self, username: &'a str, _: &[u8], _: &str) -> BoxFuture<'a, GetUser> {
        Box::pin(async move {
            let state = self.0.clone().lock_owned().await;
            let username = super::c_str(username).to_owned();
            tokio::task::spawn_blocking(move || query_user(&state.0, &state.1, &username))
                .await
                .unwrap_or_else(|_| GetUser::result(BackendResult::Error))
        })
    }

    fn superuser<'a>(&'a self, _: &str) -> BoxFuture<'a, BackendResult> {
        // be-sqlite.c: be_sqlite_superuser.
        Box::pin(async { BackendResult::Defer })
    }

    fn aclcheck<'a>(&'a self, _: &str, _: &str, _: &str, _: i32) -> BoxFuture<'a, BackendResult> {
        // be-sqlite.c: be_sqlite_aclcheck.
        Box::pin(async { BackendResult::Allow })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binds_username_and_returns_first_cell_of_first_row() {
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch(
            "CREATE TABLE users(name TEXT, hash TEXT);
            INSERT INTO users VALUES ('al''ice', 'first'), ('al''ice', 'second');",
        )
        .unwrap();
        let sql = "SELECT hash, ?2 FROM users WHERE name = ?1 ORDER BY rowid";
        assert_eq!(
            query_user(&db, sql, "al'ice"),
            GetUser::hash("first".to_owned())
        );
        assert_eq!(
            query_user(&db, sql, "missing"),
            GetUser::result(BackendResult::Defer)
        );
        assert_eq!(
            query_user(&db, "SELECT NULL WHERE ?1 IS NOT NULL", "al'ice"),
            GetUser::result(BackendResult::Defer)
        );
        assert_eq!(
            query_user(&db, "SELECT 'unbound'", "al'ice"),
            GetUser::result(BackendResult::Error)
        );
        assert_eq!(
            query_user(&db, "this is not sql", "al'ice"),
            GetUser::result(BackendResult::Error)
        );
    }
}
