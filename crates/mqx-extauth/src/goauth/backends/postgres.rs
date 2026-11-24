use std::{
    env,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use bytes::Bytes;
use pgwire::{
    api::client::{Config, auth::DefaultStartupHandler, query::DefaultSimpleQueryHandler},
    error::PgWireClientError,
    tokio::client::PgWireClient,
};
use rustls::RootCertStore;
use tokio::sync::Mutex;
use tokio_rustls::TlsConnector;

use super::sql::{self, Cells, Connector, option, require};
use crate::{
    backend::LoadError,
    backends::databases::postgres::{QueryError, pg_roots, pg_tls_connector, query},
    goauth::backend::{Backend, BackendError, Init, Options},
};

pub(super) struct Connection {
    settings: Settings,
    live: Mutex<Option<(Instant, PgWireClient)>>,
    lifetime: Option<Duration>,
}

struct Settings {
    config: Arc<Config>,
    tls: Option<Arc<Options>>,
    timeout: Option<Duration>,
}

impl Settings {
    async fn open(&self) -> Result<(Instant, PgWireClient), BackendError> {
        // lib/pq ssl.go: ssl loads certificate files while establishing each
        // connection, not when OpenDatabase parses the DSN.
        let connector = if let Some(opts) = &self.tls {
            let opts = opts.clone();
            Some(
                tokio::task::spawn_blocking(move || tls(&opts))
                    .await
                    .map_err(|err| BackendError::new(err.to_string()))?
                    .map_err(|err| BackendError::new(err.to_string()))?,
            )
        } else {
            None
        };
        let start =
            PgWireClient::connect(self.config.clone(), DefaultStartupHandler::new(), connector);
        let client = match self.timeout {
            Some(duration) => tokio::time::timeout(duration, start)
                .await
                .map_err(|err| BackendError::new(err.to_string()))?,
            None => start.await,
        }
        .map_err(|err| BackendError::new(err.to_string()))?;
        Ok((Instant::now(), client))
    }

    async fn ping(&self) -> Result<(Instant, PgWireClient), BackendError> {
        // db.go: OpenDatabase; lib/pq conn_go18.go: Ping sends a simple ';'.
        let (born, mut client) = self.open().await?;
        client
            .simple_query(DefaultSimpleQueryHandler::new(), ";")
            .await
            .map_err(|err| BackendError::new(err.to_string()))?;
        Ok((born, client))
    }
}

pub(crate) async fn create(init: Init<'_>) -> Result<Box<dyn Backend>, LoadError> {
    let db = connect(&init).await?;
    Ok(sql::backend(init, "Postgres", "pg", db))
}

// postgres.go: NewPostgres. lib/pq parses an unquoted keyword/value DSN;
// callers can use its single-quote/backslash syntax in option values.
pub(super) async fn connect(init: &Init<'_>) -> Result<Connection, LoadError> {
    init.log.set_level(init.log.level());
    let opts = init.options;
    let mode = match option(opts, "pg_sslmode", "verify-full") {
        mode @ ("disable" | "require" | "verify-ca" | "verify-full") => mode,
        unknown => {
            init.log.warn(format_args!(
                "PG backend warning: using unknown pg_sslmode: '{unknown}'"
            ));
            "verify-full"
        }
    };
    require(
        opts,
        "PG backend error: missing options: ",
        ["pg_dbname", "pg_user", "pg_password", "pg_userquery"],
    )?;
    let mut dsn = format!(
        "user={} password={} dbname={} host={} port={} sslmode={mode}",
        opts["pg_user"],
        opts["pg_password"],
        opts["pg_dbname"],
        option(opts, "pg_host", "localhost"),
        option(opts, "pg_port", "5432")
    );
    for (key, name) in [
        ("sslrootcert", "pg_sslrootcert"),
        ("sslkey", "pg_sslkey"),
        ("sslcert", "pg_sslcert"),
    ] {
        let value = option(opts, name, "");
        if !value.is_empty() {
            use std::fmt::Write as _;
            let _ = write!(dsn, " {key}={value}");
        }
    }
    let settings = settings(&dsn).map_err(|err| {
        LoadError::new(format!(
            "PG backend error: couldn't open db: database connection error: {err}"
        ))
    })?;
    let live = sql::ping("postgres", opts.get("pg_connect_tries"), &init.log, || {
        settings.ping()
    })
    .await
    .map_err(|err| LoadError::new(format!("PG backend error: couldn't open db: {err}")))?;
    Ok(Connection {
        settings,
        live: Mutex::new(Some(live)),
        lifetime: sql::lifetime(opts, "pg_max_life_time"),
    })
}

// lib/pq conn.go: parseOpts. In particular, an empty unquoted value before
// another key consumes that key=value as its value.
fn parse_dsn(dsn: &str) -> Result<Options, LoadError> {
    let mut input = dsn.chars().peekable();
    let mut out = Options::new();
    while let Some(first) = input.find(|c| !c.is_whitespace()) {
        let mut name = String::new();
        let mut c = first;
        while c != '=' && !c.is_whitespace() {
            name.push(c);
            c = input
                .next()
                .ok_or_else(|| LoadError::new("missing '=' in connection info string"))?;
        }
        if c != '=' && input.find(|c| !c.is_whitespace()) != Some('=') {
            return Err(LoadError::new("missing '=' in connection info string"));
        }
        let first = input.find(|c| !c.is_whitespace());
        let quoted = first == Some('\'');
        let mut chars = first.filter(|_| !quoted).into_iter().chain(input.by_ref());
        let mut value = String::new();
        loop {
            match chars.next() {
                Some('\'') if quoted => break,
                Some(c) if !quoted && c.is_whitespace() => break,
                Some('\\') => value.push(
                    chars
                        .next()
                        .ok_or_else(|| LoadError::new("missing character after backslash"))?,
                ),
                Some(c) => value.push(c),
                None if quoted => {
                    return Err(LoadError::new(
                        "unterminated quoted string literal in connection string",
                    ));
                }
                None => break,
            }
        }
        out.insert(name, value);
    }
    Ok(out)
}

fn settings(dsn: &str) -> Result<Settings, LoadError> {
    let opts = parse_dsn(dsn)?;
    let mode = option(&opts, "sslmode", "verify-full");
    let host = option(&opts, "host", "localhost");
    let disable = mode == "disable" || (cfg!(unix) && host.starts_with('/'));
    let mut config: Config = if disable {
        "sslmode=disable"
    } else {
        "sslmode=require"
    }
    .parse()
    .map_err(|err: PgWireClientError| LoadError::new(err.to_string()))?;
    let port = option(&opts, "port", "5432")
        .parse::<u16>()
        .map_err(|_| LoadError::new("invalid postgres port"))?;
    config.host(host).port(port).user(option(&opts, "user", ""));
    for (key, var) in [
        ("dbname", "PGDATABASE"),
        ("password", "PGPASSWORD"),
        ("application_name", "PGAPPNAME"),
        ("options", "PGOPTIONS"),
    ] {
        if let Some(value) = opts.get(key).cloned().or_else(|| env::var(var).ok()) {
            match key {
                "dbname" => {
                    config.dbname(value);
                }
                "password" => {
                    config.password(value);
                }
                "application_name" => {
                    config.application_name(value);
                }
                _ => {
                    config.options(value);
                }
            }
        }
    }
    let timeout = opts
        .get("connect_timeout")
        .cloned()
        .or_else(|| env::var("PGCONNECT_TIMEOUT").ok())
        .map(|value| value.parse::<u64>())
        .transpose()
        .map_err(|err| LoadError::new(format!("invalid connect_timeout: {err}")))?
        .filter(|seconds| *seconds > 0)
        .map(Duration::from_secs);
    let tls = (!disable).then(|| Arc::new(opts));
    Ok(Settings {
        config: Arc::new(config),
        tls,
        timeout,
    })
}

// lib/pq ssl.go: ssl, sslClientCertificates, sslVerifyCertificateAuthority.
fn tls(opts: &Options) -> Result<TlsConnector, LoadError> {
    let mode = option(opts, "sslmode", "verify-full");
    let host = option(opts, "host", "localhost");
    let path = |key, var, default| {
        opts.get(key)
            .cloned()
            .or_else(|| env::var(var).ok())
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .or_else(|| {
                env::var_os("HOME")
                    .map(|home| PathBuf::from(home).join(".postgresql").join(default))
            })
    };
    let cert = path("sslcert", "PGSSLCERT", "postgresql.crt").filter(|path| path.exists());
    let key = path("sslkey", "PGSSLKEY", "postgresql.key");
    #[cfg(unix)]
    if let (Some(_), Some(key)) = (&cert, &key) {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let metadata = key
            .metadata()
            .map_err(|err| LoadError::new(err.to_string()))?;
        let allowed = if metadata.uid() == 0 { 0o640 } else { 0o600 };
        if metadata.permissions().mode() & 0o777 & !allowed != 0 {
            return Err(LoadError::new(
                "pq: permissions for the private key file are too open",
            ));
        }
    }
    let root = opts
        .get("sslrootcert")
        .cloned()
        .or_else(|| env::var("PGSSLROOTCERT").ok())
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .filter(|path| mode != "require" || path.exists());
    let roots = match root {
        Some(root) => Some(pg_roots(&root)?),
        None if mode == "require" => None,
        None => {
            let mut roots = RootCertStore::empty();
            roots.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);
            Some(roots)
        }
    };
    // lib/pq also checks the hostname in verify-ca (and require with a
    // CA) when its default SNI is enabled, by using ConnectionState.ServerName.
    let sni = opts
        .get("sslsni")
        .cloned()
        .or_else(|| env::var("PGSSLSNI").ok());
    let sni = sni
        .as_deref()
        .is_none_or(|value| value.is_empty() || value.starts_with('1'));
    let verify_name = mode == "verify-full" || (sni && host.parse::<std::net::IpAddr>().is_err());
    pg_tls_connector(roots, verify_name, sni || mode == "verify-full", cert, key)
}

impl Connector for Connection {
    async fn query(
        &self,
        sql: &str,
        username: &str,
        access: Option<i32>,
    ) -> Result<Cells, BackendError> {
        let mut live = self.live.lock().await;
        // db.go: OpenDatabase sets the connection's maximum lifetime. Drop a
        // cancelled connection as well, so an outstanding query is never reused.
        let (born, mut client) = match live.take() {
            Some((born, client)) if self.lifetime.is_none_or(|max| born.elapsed() < max) => {
                (born, client)
            }
            _ => self.settings.open().await?,
        };
        let mut params = Vec::with_capacity(if access.is_some() { 2 } else { 1 });
        params.push(Some(Bytes::copy_from_slice(username.as_bytes())));
        if let Some(access) = access {
            params.push(Some(Bytes::from(access.to_string())));
        }
        let mut cells = Cells::new(access);
        let mut scan = Ok(());
        let result = query(&mut client, sql, params, true, |_, value, ty| {
            if scan.is_ok() {
                scan = cells.push(|| value.map(|bytes| text(bytes, ty)).transpose());
            }
        })
        .await;
        if !matches!(result, Err(QueryError::Connection)) {
            *live = Some((born, client));
        }
        result.map_err(|err| BackendError::new(err.to_string()))?;
        scan?;
        Ok(cells)
    }

    async fn halt(&self, _: &crate::goauth::backend::Log) {
        self.live.lock().await.take();
    }
}

// lib/pq encode.go: textDecode converts bytea and bool before database/sql
// performs Scan conversion. Other textual SQL values can be scanned as text.
fn text(bytes: &[u8], ty: u32) -> Result<String, BackendError> {
    let bytes: &[u8] = match (ty, bytes) {
        (16, b"t") => b"true",
        (16, b"f") => b"false",
        (17, bytes) => {
            return String::from_utf8(bytea(bytes)?)
                .map_err(|err| BackendError::new(err.to_string()));
        }
        _ => bytes,
    };
    std::str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|err| BackendError::new(err.to_string()))
}

fn bytea(mut input: &[u8]) -> Result<Vec<u8>, BackendError> {
    let invalid = || BackendError::new("pq: invalid bytea value");
    if let Some(hex) = input.strip_prefix(b"\\x") {
        let (pairs, remainder) = hex.as_chunks::<2>();
        if !remainder.is_empty() {
            return Err(invalid());
        }
        return pairs
            .iter()
            .map(|pair| {
                let digit = |index| char::from(pair[index]).to_digit(16).ok_or_else(invalid);
                Ok((digit(0)? * 16 + digit(1)?) as u8)
            })
            .collect();
    }
    let mut bytes = Vec::with_capacity(input.len());
    while let Some((&byte, rest)) = input.split_first() {
        input = rest;
        if byte != b'\\' {
            bytes.push(byte);
        } else if let Some(rest) = input.strip_prefix(b"\\") {
            bytes.push(b'\\');
            input = rest;
        } else if let [a @ b'0'..=b'3', b @ b'0'..=b'7', c @ b'0'..=b'7', rest @ ..] = input {
            bytes.push((a - b'0') * 64 + (b - b'0') * 8 + c - b'0');
            input = rest;
        } else {
            return Err(invalid());
        }
    }
    Ok(bytes)
}
