use std::{
    borrow::Cow,
    env,
    path::{Path, PathBuf},
};

use mqx_auth::external::BoxFuture;
use mysql_async::{ClientIdentity, Conn, Opts, OptsBuilder, SslOpts, Value, prelude::Queryable};
use openssl::{pkcs12::Pkcs12, pkey::PKey, stack::Stack, x509::X509};
use tokio::sync::Mutex;

use crate::{
    authplug::{atoi, log},
    backend::{Backend, BackendResult, GetUser, LoadError, Options},
};

struct Mysql {
    opts: Opts,
    connection: Mutex<Option<Conn>>,
    reconnect: bool,
    user_query: String,
    super_query: Option<String>,
    acl_query: Option<String>,
}

fn bool_option(options: &Options, name: &str, default: bool) -> bool {
    // be-mysql.c: get_bool accepts exactly "true" and "false".
    match options.get(name) {
        Some("true") => true,
        Some("false") => false,
        Some(value) => {
            log(format_args!("WARN: {name} is unexpected value -> {value}"));
            default
        }
        None => default,
    }
}

fn mysql_tls(options: &Options) -> Result<SslOpts, LoadError> {
    let invalid = || LoadError::new("Invalid MySQL TLS certificate or key options");
    // be-mysql.c: be_mysql_init passes these options to mysql_ssl_set.
    // mysql_async's native TLS implementation does not expose a cipher list;
    // do not silently connect with an unrestricted TLS profile.
    if options
        .get("ssl_cipher")
        .is_some_and(|cipher| !cipher.is_empty())
    {
        return Err(LoadError::new(
            "mysql ssl_cipher is not supported by the native TLS connector",
        ));
    }
    let mut roots = Vec::new();
    if let Some(ca) = options.get("ssl_ca") {
        roots.push(PathBuf::from(ca).into());
    }
    if let Some(capath) = options.get("ssl_capath") {
        // OpenSSL's CA path uses c_rehash names (subject hash plus index).
        for dir in std::fs::read_dir(capath).map_err(|_| invalid())? {
            let entry = dir.map_err(|_| invalid())?;
            let name = entry.file_name();
            if name
                .to_str()
                .and_then(|name| name.split_once('.'))
                .is_some_and(|(hash, index)| {
                    hash.len() == 8
                        && hash.bytes().all(|b| b.is_ascii_hexdigit())
                        && !index.is_empty()
                        && index.bytes().all(|b| b.is_ascii_digit())
                })
            {
                roots.push(entry.path().into());
            }
        }
    }
    let verify = options.get("ssl_ca").is_some() || options.get("ssl_capath").is_some();
    let identity = match (options.get("ssl_cert"), options.get("ssl_key")) {
        (None, None) => None,
        (Some(cert), Some(key)) => {
            Some(identity(Path::new(cert), Path::new(key)).ok_or_else(invalid)?)
        }
        _ => return Err(invalid()),
    };
    Ok(SslOpts::default()
        .with_root_certs(roots)
        .with_client_identity(identity)
        .with_disable_built_in_roots(verify)
        .with_danger_accept_invalid_certs(!verify)
        .with_danger_skip_domain_validation(!verify))
}

pub(crate) fn identity(cert: &Path, key: &Path) -> Option<ClientIdentity> {
    // mysql_async's native TLS client identity is PKCS#12 rather than two
    // PEM paths. Pack the configured chain and key in memory, not on disk.
    let certs = X509::stack_from_pem(&std::fs::read(cert).ok()?).ok()?;
    let key = PKey::private_key_from_pem(&std::fs::read(key).ok()?).ok()?;
    let mut certs = certs.into_iter();
    let cert = certs.next()?;
    let mut chain = Stack::new().ok()?;
    for entry in certs {
        chain.push(entry).ok()?;
    }
    let pkcs = Pkcs12::builder()
        .pkey(&key)
        .cert(&cert)
        .ca(chain)
        .build2("")
        .ok()?;
    Some(ClientIdentity::new(pkcs.to_der().ok()?.into()))
}

pub(crate) async fn create(options: &Options) -> Result<Box<dyn Backend>, LoadError> {
    // be-mysql.c: be_mysql_init uses a persistent connection and tolerates
    // initial connection failure when either reconnect flag is enabled.
    let user_query = options
        .get("userquery")
        .ok_or_else(|| LoadError::new("Mandatory option 'userquery' is missing"))?
        .to_owned();
    let host = options
        .get("host")
        .filter(|host| !host.is_empty())
        .unwrap_or("localhost");
    let port = options.get("port").map_or(3306, |p| atoi(p.as_bytes()));
    let port = if port == 0 {
        env::var("MYSQL_TCP_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(3306)
    } else {
        port
    };
    let port = u16::try_from(port)
        .map_err(|_| LoadError::new("mysql init returns NULL (invalid port)"))?;
    let user = options
        .get("user")
        .map(str::to_owned)
        .or_else(|| env::var("USER").ok());
    let mut builder = OptsBuilder::default()
        .ip_or_hostname(host)
        .tcp_port(port)
        .user(user)
        .pass(options.get("pass"))
        .db_name(options.get("dbname"))
        .prefer_socket(false);
    if cfg!(unix) && host == "localhost" {
        let socket =
            env::var("MYSQL_UNIX_PORT").unwrap_or_else(|_| "/run/mysqld/mysqld.sock".to_owned());
        builder = builder.socket(Some(socket));
    }
    if bool_option(options, "ssl_enabled", false) {
        let options = options.clone();
        let ssl = tokio::task::spawn_blocking(move || mysql_tls(&options))
            .await
            .map_err(|_| LoadError::new("mysql init returns NULL"))??;
        builder = builder.ssl_opts(ssl);
    }
    let opts: Opts = builder.into();
    let auto_connect = bool_option(options, "mysql_auto_connect", true);
    let opt_reconnect = bool_option(options, "mysql_opt_reconnect", true);
    let reconnect = auto_connect || opt_reconnect;
    let connection = match Conn::new(opts.clone()).await {
        Ok(conn) => Some(conn),
        Err(_) if reconnect => None,
        Err(_) => return Err(LoadError::new("mysql init returns NULL")),
    };
    Ok(Box::new(Mysql {
        opts,
        connection: Mutex::new(connection),
        reconnect,
        user_query,
        super_query: options.get("superquery").map(str::to_owned),
        acl_query: options.get("aclquery").map(str::to_owned),
    }))
}

// be-mysql.c: escape uses mysql_real_escape_string. MariaDB library doubles
// single quotes instead of backslash escaping under NO_BACKSLASH_ESCAPES.
fn escape(value: &str, no_backslash: bool) -> Cow<'_, str> {
    let replaced = |ch| {
        if no_backslash {
            (ch == '\'').then_some("''")
        } else {
            match ch {
                '\0' => Some("\\0"),
                '\n' => Some("\\n"),
                '\r' => Some("\\r"),
                '\\' => Some("\\\\"),
                '\'' => Some("\\'"),
                '"' => Some("\\\""),
                '\x1a' => Some("\\Z"),
                _ => None,
            }
        }
    };
    let mut rest = value;
    let mut output = String::new();
    while let Some((index, ch)) = rest.char_indices().find(|&(_, ch)| replaced(ch).is_some()) {
        output.push_str(&rest[..index]);
        output.push_str(replaced(ch).unwrap_or_default());
        rest = &rest[index + ch.len_utf8()..];
    }
    if rest.len() == value.len() {
        Cow::Borrowed(value)
    } else {
        output.push_str(rest);
        Cow::Owned(output)
    }
}

#[derive(Clone, Copy)]
enum Arg<'a> {
    Text(&'a str),
    Int(i32),
}

// be-mysql.c: be_mysql_getuser, be_mysql_superuser and be_mysql_aclcheck
// use sprintf with one/two known arguments. Reject type-mismatched or
// unsupported format directives rather than reading arbitrary memory.
fn substitute(sql: &str, first: &str, second: Option<Arg<'_>>) -> Option<String> {
    let mut rest = super::c_str(sql);
    let mut out = String::with_capacity(rest.len() + first.len());
    let mut next = 0;
    let args = [Some(Arg::Text(first)), second];
    while let Some(index) = rest.find('%') {
        out.push_str(&rest[..index]);
        rest = &rest[index + 1..];
        if let Some(tail) = rest.strip_prefix('%') {
            rest = tail;
            out.push('%');
            continue;
        }
        let pos_len = rest.bytes().take_while(u8::is_ascii_digit).count();
        let pos = if let Some(tail) = rest[pos_len..].strip_prefix('$') {
            let pos: usize = rest[..pos_len].parse().ok()?;
            rest = tail;
            pos.checked_sub(1)?
        } else {
            let pos = next;
            next += 1;
            pos
        };
        let flag_len = rest.bytes().take_while(|ch| b"-+ 0".contains(ch)).count();
        let (flags, remainder) = rest.split_at(flag_len);
        rest = remainder;
        let (width, remainder) = number(rest)?;
        rest = remainder;
        let precision = if let Some(tail) = rest.strip_prefix('.') {
            let (precision, remainder) = number(tail)?;
            rest = remainder;
            Some(precision)
        } else {
            None
        };
        let arg = args.get(pos).copied().flatten()?;
        match (rest.as_bytes().first().copied()?, arg) {
            (b's', Arg::Text(value)) => {
                let len = precision.map_or(value.len(), |n| n.min(value.len()));
                pad(
                    &mut out,
                    value.get(..len)?,
                    width,
                    0,
                    flags.contains('-'),
                    ("", false),
                );
            }
            (ty @ (b'd' | b'i' | b'u'), Arg::Int(value)) => {
                let negative = ty != b'u' && value < 0;
                let mag = if ty == b'u' {
                    value as u32
                } else {
                    value.unsigned_abs()
                };
                let digits = if mag == 0 && precision == Some(0) {
                    String::new()
                } else {
                    mag.to_string()
                };
                let sign = if negative {
                    "-"
                } else if ty != b'u' && flags.contains('+') {
                    "+"
                } else if ty != b'u' && flags.contains(' ') {
                    " "
                } else {
                    ""
                };
                pad(
                    &mut out,
                    &digits,
                    width,
                    precision.unwrap_or(0),
                    flags.contains('-'),
                    (sign, precision.is_none() && flags.contains('0')),
                );
            }
            _ => return None,
        }
        // Every supported conversion is a one-byte specifier.
        let remaining = &rest[1..];
        rest = remaining;
    }
    out.push_str(rest);
    Some(out)
}

fn number(input: &str) -> Option<(usize, &str)> {
    let count = input.bytes().take_while(u8::is_ascii_digit).count();
    let value = if count == 0 {
        0
    } else {
        input[..count].parse().ok()?
    };
    Some((value, &input[count..]))
}

fn pad(
    out: &mut String,
    value: &str,
    width: usize,
    precision: usize,
    left: bool,
    sign_with_zero_flag: (&str, bool),
) {
    let (sign, zero) = sign_with_zero_flag;
    let digit_pad = precision.saturating_sub(value.len());
    let space_pad = width.saturating_sub(sign.len() + value.len() + digit_pad);
    if !left && !zero {
        out.extend(std::iter::repeat_n(' ', space_pad));
    }
    out.push_str(sign);
    out.extend(std::iter::repeat_n(
        '0',
        digit_pad + if !left && zero { space_pad } else { 0 },
    ));
    out.push_str(value);
    if left {
        out.extend(std::iter::repeat_n(' ', space_pad));
    }
}

fn with_text(value: &Value, mut visit: impl FnMut(&[u8])) {
    match value {
        Value::Bytes(bytes) => visit(bytes),
        Value::NULL => (),
        other => visit(other.as_sql(false).as_bytes()),
    }
}

enum QueryError {
    Connection,
    Format,
    Sql,
}

impl Mysql {
    async fn query(
        &self,
        sql: &str,
        username: &str,
        second: Option<Arg<'_>>,
        mut visit: impl FnMut(usize, &[u8]) + Send,
    ) -> Result<usize, QueryError> {
        // be-mysql.c: mysql_ping reconnects before the query. A failed ping
        // with no successful reconnect is an ERROR, including for getuser.
        let mut guard = self.connection.lock().await;
        let mut connection = guard.take();
        let alive = match &mut connection {
            Some(conn) => !conn.is_disconnected() && conn.ping().await.is_ok(),
            None => false,
        };
        if !alive {
            if !self.reconnect {
                return Err(QueryError::Connection);
            }
            connection = Conn::new(self.opts.clone()).await.ok();
        }
        let mut conn = connection.ok_or(QueryError::Connection)?;
        let no_backslash = conn
            .last_ok_packet()
            .is_some_and(|packet| packet.status_flags().bits() & 0x0200 != 0);
        let username = escape(super::c_str(username), no_backslash);
        let result = match substitute(sql, &username, second) {
            Some(query) => query_rows(&mut conn, query, &mut visit).await,
            None => Err(QueryError::Format),
        };
        *guard = Some(conn);
        result
    }
}

async fn query_rows(
    conn: &mut Conn,
    query: String,
    mut visit: impl FnMut(usize, &[u8]) + Send,
) -> Result<usize, QueryError> {
    // mysql_async advertises MULTI_STATEMENTS; mysql_real_connect(..., 0)
    // did not. Preparing the already-expanded SQL enforces one statement.
    let mut results = conn
        .exec_iter(query, ())
        .await
        .map_err(|_| QueryError::Sql)?;
    let columns = results.columns_ref().len();
    let mut rows = 0;
    if columns == 1 {
        while let Some(row) = results.next().await.map_err(|_| QueryError::Sql)? {
            if let Some(value) = row.as_ref(0) {
                with_text(value, |value| visit(rows, value));
            }
            rows += 1;
        }
    }
    results.drop_result().await.map_err(|_| QueryError::Sql)?;
    if columns == 0 {
        Err(QueryError::Sql)
    } else {
        Ok(rows)
    }
}

impl Backend for Mysql {
    fn name(&self) -> &'static str {
        "mysql"
    }

    fn getuser<'a>(
        &'a self,
        username: &'a str,
        _: &[u8],
        client_id: &'a str,
    ) -> BoxFuture<'a, GetUser> {
        Box::pin(async move {
            if username.is_empty() {
                return GetUser::result(BackendResult::Defer);
            }
            let mut hash = None;
            // be-mysql.c: be_mysql_getuser substitutes the client id raw.
            match self
                .query(
                    &self.user_query,
                    username,
                    Some(Arg::Text(super::c_str(client_id))),
                    |row, value| {
                        if row == 0 {
                            hash = std::str::from_utf8(value)
                                .ok()
                                .map(|s| super::c_str(s).to_owned());
                        }
                    },
                )
                .await
            {
                Ok(1) => GetUser {
                    result: BackendResult::Defer,
                    hash,
                },
                Ok(_) | Err(QueryError::Sql) => GetUser::result(BackendResult::Defer),
                Err(QueryError::Connection | QueryError::Format) => {
                    GetUser::result(BackendResult::Error)
                }
            }
        })
    }

    fn superuser<'a>(&'a self, username: &'a str) -> BoxFuture<'a, BackendResult> {
        Box::pin(async move {
            let Some(query) = self.super_query.as_deref() else {
                return BackendResult::Defer;
            };
            let mut allowed = false;
            match self
                .query(query, username, None, |row, value| {
                    if row == 0 {
                        allowed = atoi(value) != 0;
                    }
                })
                .await
            {
                Ok(1) if allowed => BackendResult::Allow,
                Ok(_) => BackendResult::Defer,
                Err(_) => BackendResult::Error,
            }
        })
    }

    fn aclcheck<'a>(
        &'a self,
        client_id: &'a str,
        username: &'a str,
        topic: &'a str,
        access: i32,
    ) -> BoxFuture<'a, BackendResult> {
        Box::pin(async move {
            let Some(query) = self.acl_query.as_deref() else {
                return BackendResult::Defer;
            };
            let mut allowed = false;
            match self
                .query(query, username, Some(Arg::Int(access)), |_, value| {
                    if !allowed && let Ok(filter) = std::str::from_utf8(value) {
                        allowed = super::matches(filter, topic, client_id, username);
                    }
                })
                .await
            {
                Ok(_) if allowed => BackendResult::Allow,
                Ok(_) => BackendResult::Defer,
                Err(_) => BackendResult::Error,
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mysql_real_escape_string() {
        assert_eq!(
            escape("é\0\n\r\\\"'\x1a", false),
            "é\\0\\n\\r\\\\\\\"\\'\\Z"
        );
        assert_eq!(escape("a\\'b\"", true), "a\\''b\"");
        assert!(matches!(escape("alice", false), Cow::Borrowed("alice")));
    }

    #[test]
    fn sprintf_keeps_raw_client_id_and_handles_access_and_percents() {
        assert_eq!(
            substitute(
                "SELECT u='%s', c=\"%s\", '%%u'",
                &escape("u'", false),
                Some(Arg::Text("client'"))
            )
            .as_deref(),
            Some("SELECT u='u\\'', c=\"client'\", '%u'")
        );
        assert_eq!(
            substitute("SELECT %2$+03d, '%1$s'", "alice", Some(Arg::Int(4))).as_deref(),
            Some("SELECT +04, 'alice'")
        );
        assert!(substitute("SELECT %s, %d", "alice", None).is_none());
        assert!(substitute("SELECT %n", "alice", None).is_none());
    }
}
