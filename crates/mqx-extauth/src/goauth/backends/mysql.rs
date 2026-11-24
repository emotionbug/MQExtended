use std::path::{Path, PathBuf};

use mysql_async::{
    DriverError, Error, Opts, OptsBuilder, Pool, PoolConstraints, PoolOpts, SslOpts, Value,
    prelude::Queryable,
};

use super::sql::{self, Cells, Connector, option, require};
use crate::{
    backend::LoadError,
    backends::databases::mysql::identity,
    goauth::backend::{Backend, BackendError, Init, Log},
};

pub(super) struct Connection(Pool);

pub(crate) async fn create(init: Init<'_>) -> Result<Box<dyn Backend>, LoadError> {
    let db = connect(&init).await?;
    Ok(sql::backend(init, "Mysql", "mysql", db))
}

// mysql.go: NewMysql. Build the DSN from the separate network, address,
// credentials and TLS options, without falling back to a local socket for TCP.
pub(super) async fn connect(init: &Init<'_>) -> Result<Connection, LoadError> {
    init.log.set_level(init.log.level());
    let opts = init.options;
    let protocol = option(opts, "mysql_protocol", "tcp");
    let socket = option(opts, "mysql_socket", "");
    let mut required = vec![
        "mysql_dbname",
        "mysql_user",
        "mysql_password",
        "mysql_userquery",
    ];
    if protocol == "unix" {
        if opts.contains_key("mysql_socket") && socket.is_empty() {
            require(opts, "MySql backend error: missing options: ", required)?;
            return Err(LoadError::new(
                "MySql backend error: missing options:  mysql_socket",
            ));
        }
        required.push("mysql_socket");
    }
    let mode = option(opts, "mysql_sslmode", "false");
    let root = opts.get("mysql_sslrootcert").map(PathBuf::from);
    if mode == "custom" && root.is_none() {
        init.log.warn(format_args!("MySQL backend warning: TLS was disabled due to missing root certificate (mysql_sslrootcert)"));
    }
    require(opts, "MySql backend error: missing options: ", required)?;
    let tls = match mode {
        "1" | "true" | "TRUE" | "True" | "t" | "T" => Some(SslOpts::default()),
        "skip-verify" | "preferred" => Some(
            SslOpts::default()
                .with_danger_accept_invalid_certs(true)
                .with_danger_skip_domain_validation(true),
        ),
        "" | "0" | "false" | "FALSE" | "False" | "f" | "F" => None,
        "custom" if root.is_some() => {
            let root = root.unwrap();
            let cert = opts.get("mysql_sslcert").map(PathBuf::from);
            let key = opts.get("mysql_sslkey").map(PathBuf::from);
            let log = init.log.clone();
            Some(
                tokio::task::spawn_blocking(move || custom_tls(root, cert, key, &log))
                    .await
                    .map_err(|err| LoadError::new(err.to_string()))??,
            )
        }
        mode => {
            return Err(LoadError::new(format!(
                "MySql backend error: couldn't open db: database connection error: invalid value / unknown config name: {mode}"
            )));
        }
    };
    let host = option(opts, "mysql_host", "localhost");
    let port = option(opts, "mysql_port", "3306");
    let mut builder = OptsBuilder::default()
        .ip_or_hostname(host.trim_start_matches('[').trim_end_matches(']'))
        .user(Some(opts["mysql_user"].as_str()))
        .pass(Some(opts["mysql_password"].as_str()))
        .db_name(Some(opts["mysql_dbname"].as_str()))
        .prefer_socket(false)
        .pool_opts(
            PoolOpts::default()
                .with_constraints(PoolConstraints::new(2, 100).expect("ordered bounds"))
                .with_reset_connection(false)
                .with_abs_conn_ttl(sql::lifetime(opts, "mysql_max_life_time")),
        );
    if protocol == "unix" {
        builder = builder.socket(Some(socket));
    }
    // mysql_async cannot disable mysql_native_password; secure_auth only
    // rejects mysql_old_password. Other schemes remain available either way.
    let pool = sql::ping("mysql", opts.get("mysql_connect_tries"), &init.log, || {
        open(
            builder.clone(),
            protocol,
            host,
            port,
            tls.clone(),
            mode == "preferred",
        )
    })
    .await
    .map_err(|err| LoadError::new(format!("MySql backend error: couldn't open db: {err}")))?;
    Ok(Connection(pool))
}

fn custom_tls(
    root: PathBuf,
    cert: Option<PathBuf>,
    key: Option<PathBuf>,
    log: &Log,
) -> Result<SslOpts, LoadError> {
    // mysql.go: NewMysql only loads a mutual TLS identity when both nonempty
    // paths are supplied; the custom CA replaces the system roots.
    let pem = std::fs::read(&root)
        .map_err(|err| LoadError::new(format!("Mysql read root CA error: {err}")))?;
    if openssl::x509::X509::stack_from_pem(&pem).map_or(true, |certs| certs.is_empty()) {
        return Err(LoadError::new(
            "Mysql failed to append root CA pem error: %!s(<nil>)",
        ));
    }
    let configured = cert.is_some() || key.is_some();
    let nonempty = |p: &Path| !p.as_os_str().is_empty();
    let identity = match (
        cert.as_deref().filter(|p| nonempty(p)),
        key.as_deref().filter(|p| nonempty(p)),
    ) {
        (Some(cert), Some(key)) => Some(identity(cert, key).ok_or_else(|| {
            LoadError::new("Mysql load key and cert error: invalid client certificate or key")
        })?),
        _ => {
            if configured {
                log.warn(format_args!("MySQL backend warning: mutual TLS was disabled due to missing client certificate (mysql_sslcert) or client key (mysql_sslkey)"));
            }
            None
        }
    };
    Ok(SslOpts::default()
        .with_disable_built_in_roots(true)
        .with_root_certs(vec![root.into()])
        .with_client_identity(identity))
}

async fn open(
    mut builder: OptsBuilder,
    protocol: &str,
    host: &str,
    port: &str,
    tls: Option<SslOpts>,
    preferred: bool,
) -> Result<Pool, BackendError> {
    match protocol {
        "unix" => (),
        "" | "tcp" | "tcp4" | "tcp6" => {
            let port = port
                .parse::<u16>()
                .map_err(|err| BackendError::new(format!("invalid mysql port: {err}")))?;
            builder = builder.tcp_port(port);
            if matches!(protocol, "tcp4" | "tcp6") {
                let host = host.trim_start_matches('[').trim_end_matches(']');
                let socket = tokio::net::lookup_host((host, port))
                    .await
                    .map_err(|err| BackendError::new(err.to_string()))?
                    .find(|addr| addr.is_ipv4() == (protocol == "tcp4"))
                    .ok_or_else(|| BackendError::new("no address matches mysql_protocol"))?;
                builder = builder.resolved_ips(Some(vec![socket.ip()]));
            }
        }
        other => return Err(BackendError::new(format!("unknown network {other}"))),
    }
    let pool = Pool::new(Opts::from(builder.clone().ssl_opts(tls)));
    match ping(&pool).await {
        Ok(()) => Ok(pool),
        Err(Error::Driver(DriverError::NoClientSslFlagFromServer)) if preferred => {
            let pool = Pool::new(Opts::from(builder));
            ping(&pool).await.map_err(database_error)?;
            Ok(pool)
        }
        Err(error) => Err(database_error(error)),
    }
}

async fn ping(pool: &Pool) -> mysql_async::Result<()> {
    pool.get_conn().await?.ping().await
}

fn database_error(error: Error) -> BackendError {
    BackendError::new(error.to_string())
}

impl Connector for Connection {
    async fn query(
        &self,
        query: &str,
        username: &str,
        access: Option<i32>,
    ) -> Result<Cells, BackendError> {
        let mut conn = self.0.get_conn().await.map_err(database_error)?;
        let mut rows = match access {
            None => conn.exec_iter(query, (username,)).await,
            Some(access) => conn.exec_iter(query, (username, access)).await,
        }
        .map_err(database_error)?;
        let columns = rows.columns_ref().len();
        let mut cells = Cells::new(access);
        if columns > 1 {
            rows.drop_result().await.map_err(database_error)?;
            return Err(BackendError::new(format!(
                "scannable destination with >1 columns ({columns}) in result"
            )));
        }
        while let Some(mut row) = rows.next().await.map_err(database_error)? {
            cells.push(|| cell(row.take(0).unwrap_or(Value::NULL)))?;
            if access.is_none() {
                break;
            }
        }
        rows.drop_result().await.map_err(database_error)?;
        Ok(cells)
    }

    async fn halt(&self, log: &Log) {
        if let Err(err) = self.0.clone().disconnect().await {
            log.error(format_args!("Mysql cleanup error: {err}"));
        }
    }
}

// database/sql convert.go: convertAssignRows converts numeric and byte
// values to a decimal string when scanning into sql.NullString or a string.
fn cell(value: Value) -> Result<Option<String>, BackendError> {
    Ok(Some(match value {
        Value::NULL => return Ok(None),
        Value::Bytes(bytes) => {
            String::from_utf8(bytes).map_err(|err| BackendError::new(err.to_string()))?
        }
        Value::Int(value) => value.to_string(),
        Value::UInt(value) => value.to_string(),
        Value::Float(value) => value.to_string(),
        Value::Double(value) => value.to_string(),
        // MySQL DATE/TIME values scan as their textual SQL representation.
        Value::Date(y, m, d, h, min, s, micros) => {
            if h == 0 && min == 0 && s == 0 && micros == 0 {
                format!("{y:04}-{m:02}-{d:02}")
            } else if micros == 0 {
                format!("{y:04}-{m:02}-{d:02} {h:02}:{min:02}:{s:02}")
            } else {
                format!("{y:04}-{m:02}-{d:02} {h:02}:{min:02}:{s:02}.{micros:06}")
            }
        }
        Value::Time(negative, days, h, m, s, micros) => {
            let sign = if negative { "-" } else { "" };
            let hours = u64::from(days) * 24 + u64::from(h);
            if micros == 0 {
                format!("{sign}{hours:02}:{m:02}:{s:02}")
            } else {
                format!("{sign}{hours:02}:{m:02}:{s:02}.{micros:06}")
            }
        }
    }))
}
