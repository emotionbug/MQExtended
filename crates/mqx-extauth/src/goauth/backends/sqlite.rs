use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use rusqlite::{Batch, ToSql, fallible_iterator::FallibleIterator, types::ValueRef};

use super::sql::{self, Cells, Connector, require};
use crate::{
    backend::LoadError,
    goauth::backend::{Backend, BackendError, Init, Log},
};

type Live = Arc<Mutex<Option<(Instant, rusqlite::Connection)>>>;

pub(super) struct Connection {
    source: Arc<str>,
    live: Live,
    lifetime: Option<Duration>,
}

// sqlite.go: NewSqlite, db.go: OpenDatabase.
pub(crate) async fn create(init: Init<'_>) -> Result<Box<dyn Backend>, LoadError> {
    init.log.set_level(init.log.level());
    let opts = init.options;
    require(
        opts,
        "sqlite backend error: missing options: ",
        ["sqlite_source", "sqlite_userquery"],
    )?;
    let source: Arc<str> = match opts["sqlite_source"].as_str() {
        "memory" => ":memory:",
        source => source,
    }
    .into();
    let live = sql::ping(
        "sqlite3",
        opts.get("sqlite_connect_tries"),
        &init.log,
        || {
            let source = source.clone();
            async move {
                tokio::task::spawn_blocking(move || open(&source))
                    .await
                    .map_err(|err| BackendError::new(err.to_string()))?
            }
        },
    )
    .await
    .map_err(|err| {
        LoadError::new(format!(
            "sqlite backend error: couldn't open db {source}: {err}"
        ))
    })?;
    let lifetime = sql::lifetime(opts, "sqlite_max_life_time");
    let db = Connection {
        source,
        live: Arc::new(Mutex::new(Some(live))),
        lifetime,
    };
    Ok(sql::backend(init, "Sqlite", "sqlite", db))
}

fn open(source: &str) -> Result<(Instant, rusqlite::Connection), BackendError> {
    let (filename, options) = source.split_once('?').unwrap_or((source, ""));
    let source = if filename.starts_with("file:") {
        source
    } else {
        filename
    };
    let db = rusqlite::Connection::open(source).map_err(database_error)?;
    // go-sqlite3 sqlite3.go: Open. SQLite handles its native URI parameters;
    // the driver also applies underscore options as connection PRAGMAs.
    let options: std::collections::HashMap<_, _> =
        url::form_urlencoded::parse(options.as_bytes()).collect();
    let busy = options
        .get("_timeout")
        .or_else(|| options.get("_busy_timeout"))
        .map_or(Ok(5000), |n| n.parse::<i32>())
        .map_err(|err| BackendError::new(format!("invalid sqlite busy timeout: {err}")))?;
    db.busy_timeout(Duration::from_millis(busy.max(0) as u64))
        .map_err(database_error)?;
    db.pragma_update(None, "synchronous", "NORMAL")
        .map_err(database_error)?;
    for (pragma, names) in [
        ("auto_vacuum", &["_auto_vacuum", "_vacuum"][..]),
        ("case_sensitive_like", &["_case_sensitive_like", "_cslike"]),
        ("defer_foreign_keys", &["_defer_foreign_keys", "_defer_fk"]),
        ("foreign_keys", &["_foreign_keys", "_fk"]),
        ("ignore_check_constraints", &["_ignore_check_constraints"]),
        ("journal_mode", &["_journal_mode", "_journal"]),
        ("locking_mode", &["_locking_mode", "_locking"]),
        ("query_only", &["_query_only"]),
        ("recursive_triggers", &["_recursive_triggers", "_rt"]),
        ("secure_delete", &["_secure_delete"]),
        ("synchronous", &["_synchronous", "_sync"]),
        ("writable_schema", &["_writable_schema"]),
        ("cache_size", &["_cache_size"]),
    ] {
        if let Some(value) = names
            .iter()
            .filter_map(|name| options.get(*name))
            .next_back()
        {
            db.pragma_update(None, pragma, value.as_ref())
                .map_err(database_error)?;
        }
    }
    // go-sqlite3 sqlite3_go18.go: Ping checks the connection is open.
    Ok((Instant::now(), db))
}

fn database_error(error: rusqlite::Error) -> BackendError {
    BackendError::new(error.to_string())
}

impl Connector for Connection {
    async fn query(
        &self,
        sql: &str,
        username: &str,
        access: Option<i32>,
    ) -> Result<Cells, BackendError> {
        let live = self.live.clone();
        let source = self.source.clone();
        let max = self.lifetime;
        let username = username.to_owned();
        let sql = sql.to_owned();
        tokio::task::spawn_blocking(move || {
            let mut live = live.lock().unwrap_or_else(|error| error.into_inner());
            if live
                .as_ref()
                .is_none_or(|(born, _)| max.is_some_and(|max| born.elapsed() >= max))
            {
                // A :memory: database is per connection, so expiration loses its schema.
                *live = None;
                *live = Some(open(&source)?);
            }
            let (_, conn) = live.as_ref().expect("opened a connection above");
            query(conn, &sql, &username, access)
        })
        .await
        .map_err(|err| BackendError::new(err.to_string()))?
    }

    async fn halt(&self, log: &Log) {
        let live = self.live.clone();
        let result = tokio::task::spawn_blocking(move || {
            if let Some((_, conn)) = live
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .take()
            {
                conn.close().map_err(|(_, err)| database_error(err))?;
            }
            Ok::<_, BackendError>(())
        })
        .await;
        if let Err(err) = result
            .map_err(|err| BackendError::new(err.to_string()))
            .and_then(|result| result)
        {
            log.error(format_args!("sqlite cleanup error: {err}"));
        }
    }
}

fn query(
    conn: &rusqlite::Connection,
    sql: &str,
    username: &str,
    access: Option<i32>,
) -> Result<Cells, BackendError> {
    let username = &username as &dyn ToSql;
    let all: [&dyn ToSql; 2] = [username, &access];
    let mut args = &all[..if access.is_some() { 2 } else { 1 }];
    let mut batch = Batch::new(conn, sql);
    let mut last = None;
    // go-sqlite3 sqlite3.go: query prepares and binds each statement, only
    // returning the rows from the last one. Unused positional args are ignored.
    while let Some(mut stmt) = batch.next().map_err(database_error)? {
        let count = stmt.parameter_count();
        let Some(bound) = args.get(..count) else {
            return Err(BackendError::new(format!(
                "not enough args to execute query: want {count} got {}",
                args.len()
            )));
        };
        for (i, value) in bound.iter().enumerate() {
            stmt.raw_bind_parameter(i + 1, *value)
                .map_err(database_error)?;
        }
        args = &args[count..];
        last = Some(stmt);
    }
    let mut cells = Cells::new(access);
    let Some(mut stmt) = last else {
        return Ok(cells);
    };
    let columns = stmt.column_count();
    if columns > 1 {
        return Err(BackendError::new(format!(
            "scannable destination with >1 columns ({columns}) in result"
        )));
    }
    let mut rows = stmt.raw_query();
    while let Some(row) = rows.next().map_err(database_error)? {
        if columns != 0 {
            cells.push(|| cell(row.get_ref(0).map_err(database_error)?))?;
        }
        if access.is_none() {
            break;
        }
    }
    Ok(cells)
}

fn cell(value: ValueRef<'_>) -> Result<Option<String>, BackendError> {
    Ok(Some(match value {
        ValueRef::Null => return Ok(None),
        ValueRef::Text(bytes) | ValueRef::Blob(bytes) => std::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|err| BackendError::new(err.to_string()))?,
        ValueRef::Integer(value) => value.to_string(),
        ValueRef::Real(value) => value.to_string(),
    }))
}
