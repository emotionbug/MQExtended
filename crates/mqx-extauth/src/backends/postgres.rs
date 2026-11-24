use std::{env, io::BufReader, path::PathBuf, sync::Arc, time::Duration};

use bytes::{Buf, Bytes};
use futures_util::{SinkExt, StreamExt};
use mqx_auth::external::BoxFuture;
use pgwire::{
    api::client::{ClientInfo, Config, auth::DefaultStartupHandler},
    messages::{
        PgWireBackendMessage as Reply, PgWireFrontendMessage as Request,
        data::DataRow,
        extendedquery::{
            Bind, Describe, Execute, Parse, Sync as SyncRequest, TARGET_TYPE_BYTE_PORTAL,
        },
    },
    tokio::client::PgWireClient,
};
use rustls::{
    ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme,
    client::{
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        verify_server_cert_signed_by_trust_anchor, verify_server_name,
    },
    crypto::{WebPkiSupportedAlgorithms, verify_tls12_signature, verify_tls13_signature},
    pki_types::{CertificateDer, ServerName, UnixTime},
    server::ParsedCertificate,
};
use tokio::sync::Mutex;
use tokio_rustls::TlsConnector;

use crate::{
    authplug::{atoi, log},
    backend::{Backend, BackendResult, GetUser, LoadError, Options},
};

const CONNECTION_ERROR: &str = "We were unable to connect to the database";

struct ConnectionSettings {
    hosts: Vec<Arc<Config>>,
    tls: Option<TlsConnector>,
    timeout: Option<Duration>,
}

struct Postgres {
    settings: ConnectionSettings,
    client: Mutex<Option<PgWireClient>>,
    user_query: String,
    super_query: Option<String>,
    acl_query: Option<String>,
}

fn option(options: &Options, name: &str, var: &str) -> Option<String> {
    options
        .get(name)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .or_else(|| env::var(var).ok().filter(|value| !value.is_empty()))
}

impl ConnectionSettings {
    // be-postgres.c: be_pg_init passes host, port, dbname, user, password,
    // sslcert and sslkey to libpq. Empty options use the environment/default.
    fn new(options: &Options) -> Result<Self, LoadError> {
        let error = || LoadError::new(CONNECTION_ERROR);
        let host = option(options, "host", "PGHOST");
        let port = option(options, "port", "PGPORT");
        let addresses = env::var("PGHOSTADDR").ok();
        let hosts: Vec<_> = host.as_deref().unwrap_or_default().split(',').collect();
        let ports: Vec<_> = port.as_deref().unwrap_or_default().split(',').collect();
        let addresses: Vec<_> = addresses
            .as_deref()
            .unwrap_or_default()
            .split(',')
            .collect();
        let count = hosts.len().max(addresses.len());
        if (hosts.len() != count && host.is_some())
            || (addresses.len() != count && addresses != [""])
            || (ports.len() != 1 && ports.len() != count)
        {
            return Err(error());
        }
        let sslmode = env::var("PGSSLMODE").unwrap_or_else(|_| "prefer".to_owned());
        let modes = match sslmode.as_str() {
            "disable" => &["disable"][..],
            "allow" => &["disable", "require"][..],
            "prefer" => &["prefer", "disable"][..],
            "require" | "verify-ca" | "verify-full" => &["require"][..],
            _ => return Err(error()),
        };
        let user = option(options, "user", "PGUSER")
            .or_else(|| env::var("USER").ok())
            .or_else(|| env::var("USERNAME").ok())
            .ok_or_else(error)?;
        let database = option(options, "dbname", "PGDATABASE");
        let password = option(options, "pass", "PGPASSWORD");
        let timeout = env::var("PGCONNECT_TIMEOUT")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .filter(|&secs| secs != 0)
            .map(|secs| Duration::from_secs(secs.max(2)));
        let mut configs = Vec::with_capacity(count * modes.len());
        let mut needs_tls = false;
        for index in 0..count {
            let address = addresses.get(index).copied().unwrap_or_default();
            let host = match hosts.get(index).copied().unwrap_or_default() {
                "" if !address.is_empty() => address,
                "" if cfg!(unix) => "/var/run/postgresql",
                "" => "localhost",
                host => host,
            };
            let port = match ports[if ports.len() == 1 { 0 } else { index }] {
                "" => 5432,
                port => port
                    .parse::<u16>()
                    .ok()
                    .filter(|port| *port != 0)
                    .ok_or_else(error)?,
            };
            let socket = cfg!(unix) && host.starts_with('/');
            needs_tls |= !socket && sslmode != "disable";
            for mode in modes.iter().take(if socket { 1 } else { modes.len() }) {
                let mut config: Config = format!("sslmode={mode}").parse().map_err(|_| error())?;
                config.user(&user).port(port);
                if let Some(database) = &database {
                    config.dbname(database);
                }
                if let Some(password) = &password {
                    config.password(password);
                }
                if !address.is_empty() {
                    config.hostaddr(address.parse().map_err(|_| error())?);
                }
                config.host(host);
                configs.push(Arc::new(config));
            }
        }
        let tls = if needs_tls {
            Some(pg_tls(options, &sslmode)?)
        } else {
            None
        };
        Ok(Self {
            hosts: configs,
            tls,
            timeout,
        })
    }

    async fn connect(&self) -> Option<PgWireClient> {
        for config in &self.hosts {
            let result = PgWireClient::connect(
                config.clone(),
                DefaultStartupHandler::new(),
                self.tls.clone(),
            );
            let result = if let Some(timeout) = self.timeout {
                match tokio::time::timeout(timeout, result).await {
                    Ok(result) => result,
                    Err(_) => continue,
                }
            } else {
                result.await
            };
            match result {
                Ok(client) => return Some(client),
                Err(pgwire::error::PgWireClientError::RemoteError(error))
                    if error.code.starts_with("28") =>
                {
                    return None;
                }
                Err(_) => (),
            }
        }
        None
    }
}

fn pg_tls(options: &Options, mode: &str) -> Result<TlsConnector, LoadError> {
    let error = || LoadError::new(CONNECTION_ERROR);
    let home = env::var_os("HOME").map(|home| PathBuf::from(home).join(".postgresql"));
    if env::var("PGSSLROOTCERT").as_deref() == Ok("system") {
        return Err(LoadError::new(
            "PostgreSQL PGSSLROOTCERT=system is not supported",
        ));
    }
    let path = |setting: Option<&str>, var, default| {
        setting
            .and_then(|name| options.get(name))
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .or_else(|| env::var(var).ok().filter(|value| !value.is_empty()))
            .map(PathBuf::from)
            .or_else(|| {
                home.as_ref()
                    .map(|dir| dir.join(default))
                    .filter(|path| path.exists())
            })
    };
    let root = path(None, "PGSSLROOTCERT", "root.crt");
    let roots =
        if matches!(mode, "verify-ca" | "verify-full") || (mode == "require" && root.is_some()) {
            Some(pg_roots(root.as_deref().ok_or_else(error)?)?)
        } else {
            None
        };
    pg_tls_connector(
        roots,
        mode == "verify-full",
        true,
        path(Some("sslcert"), "PGSSLCERT", "postgresql.crt"),
        path(Some("sslkey"), "PGSSLKEY", "postgresql.key"),
    )
}

fn read_certs(
    file: impl AsRef<std::path::Path>,
) -> Result<Vec<CertificateDer<'static>>, LoadError> {
    let error = || LoadError::new(CONNECTION_ERROR);
    let file = std::fs::File::open(file).map_err(|_| error())?;
    rustls_pemfile::certs(&mut BufReader::new(file))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| error())
}

pub(crate) fn pg_roots(file: &std::path::Path) -> Result<RootCertStore, LoadError> {
    let error = || LoadError::new(CONNECTION_ERROR);
    let mut store = RootCertStore::empty();
    for root in read_certs(file)? {
        store.add(root).map_err(|_| error())?;
    }
    if store.is_empty() {
        return Err(error());
    }
    Ok(store)
}

pub(crate) fn pg_tls_connector(
    roots: Option<RootCertStore>,
    verify_name: bool,
    enable_sni: bool,
    cert: Option<PathBuf>,
    key: Option<PathBuf>,
) -> Result<TlsConnector, LoadError> {
    let error = || LoadError::new(CONNECTION_ERROR);
    let provider = rustls::crypto::ring::default_provider();
    let verifier = PgVerifier {
        algorithms: provider.signature_verification_algorithms,
        roots,
        verify_name,
    };
    let builder = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .map_err(|_| error())?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier));
    let mut config = if let Some(cert) = cert {
        let key = key.ok_or_else(error)?;
        let mut file = BufReader::new(std::fs::File::open(key).map_err(|_| error())?);
        let key = rustls_pemfile::private_key(&mut file)
            .map_err(|_| error())?
            .ok_or_else(error)?;
        builder
            .with_client_auth_cert(read_certs(cert)?, key)
            .map_err(|_| error())?
    } else {
        builder.with_no_client_auth()
    };
    config.enable_sni = enable_sni;
    Ok(Arc::new(config).into())
}

// libpq's default sslmode=prefer negotiates TLS without checking the server
// certificate. The TLS CertificateVerify signature is checked in every mode.
#[derive(Debug)]
struct PgVerifier {
    algorithms: WebPkiSupportedAlgorithms,
    roots: Option<RootCertStore>,
    verify_name: bool,
}

impl ServerCertVerifier for PgVerifier {
    fn verify_server_cert(
        &self,
        end: &CertificateDer<'_>,
        chain: &[CertificateDer<'_>],
        name: &ServerName<'_>,
        _: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if let Some(roots) = &self.roots {
            let cert = ParsedCertificate::try_from(end)?;
            verify_server_cert_signed_by_trust_anchor(
                &cert,
                roots,
                chain,
                now,
                self.algorithms.all,
            )?;
            if self.verify_name {
                verify_server_name(&cert, name)?;
            }
        }
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        msg: &[u8],
        cert: &CertificateDer<'_>,
        signed: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(msg, cert, signed, &self.algorithms)
    }
    fn verify_tls13_signature(
        &self,
        msg: &[u8],
        cert: &CertificateDer<'_>,
        signed: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(msg, cert, signed, &self.algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

pub(crate) async fn create(options: &Options) -> Result<Box<dyn Backend>, LoadError> {
    let user_query = options
        .get("userquery")
        .ok_or_else(|| LoadError::new("Mandatory option 'userquery' is missing"))?
        .to_owned();
    let config_options = options.clone();
    let settings = tokio::task::spawn_blocking(move || ConnectionSettings::new(&config_options))
        .await
        .map_err(|_| LoadError::new(CONNECTION_ERROR))??;
    let client = settings
        .connect()
        .await
        .ok_or_else(|| LoadError::new(CONNECTION_ERROR))?;
    Ok(Box::new(Postgres {
        settings,
        client: Mutex::new(Some(client)),
        user_query,
        super_query: options.get("superquery").map(str::to_owned),
        acl_query: options.get("aclquery").map(str::to_owned),
    }))
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum QueryError {
    #[error("PostgreSQL query failed")]
    Sql,
    #[error("PostgreSQL connection lost")]
    Connection,
    #[error("scannable destination with >1 columns ({0}) in result")]
    Shape(usize),
    #[error("pq: {0}")]
    Remote(String),
}

fn cell(row: &DataRow) -> Result<Option<&[u8]>, QueryError> {
    let mut data = row.data.as_ref();
    let len = data.try_get_i32().map_err(|_| QueryError::Connection)?;
    if len == -1 {
        Ok(None)
    } else {
        usize::try_from(len)
            .ok()
            .and_then(|n| data.get(..n).map(Some))
            .ok_or(QueryError::Connection)
    }
}

// be-postgres.c: be_pg_getuser, be_pg_superuser, be_pg_aclcheck use
// PQexecParams: unnamed statement/portal, inferred parameter types, *text*
// parameters and results. RowDescription distinguishes tuple-bearing result
// sets (including 0 rows) from commands that did not return rows.
pub(crate) async fn query(
    client: &mut PgWireClient,
    sql: &str,
    params: Vec<Option<Bytes>>,
    strict: bool,
    mut visit: impl FnMut(usize, Option<&[u8]>, u32),
) -> Result<usize, QueryError> {
    let messages = [
        Request::Parse(Parse::new(None, sql.to_owned(), vec![])),
        Request::Bind(Bind::new(None, None, vec![], params, vec![])),
        Request::Describe(Describe::new(TARGET_TYPE_BYTE_PORTAL, None)),
        Request::Execute(Execute::new(None, 0)),
        Request::Sync(SyncRequest::new()),
    ];
    for message in messages {
        client
            .feed(message)
            .await
            .map_err(|_| QueryError::Connection)?;
    }
    client.flush().await.map_err(|_| QueryError::Connection)?;
    let mut columns = None;
    let mut rows = 0;
    let mut ty = 0;
    let mut failed = None;
    while let Some(reply) = client.next().await {
        match reply.map_err(|_| QueryError::Connection)? {
            Reply::RowDescription(desc) => {
                columns = Some(desc.fields.len());
                ty = desc.fields.first().map_or(0, |field| field.type_id);
            }
            Reply::DataRow(row) if columns == Some(1) => {
                visit(rows, cell(&row)?, ty);
                rows += 1;
            }
            Reply::ParameterStatus(status) => {
                client.set_server_parameter(status.name, status.value)
            }
            Reply::ErrorResponse(error) => {
                let error = pgwire::error::ErrorInfo::from(error);
                let severity = error
                    .severity_nonlocalized
                    .as_deref()
                    .unwrap_or(&error.severity);
                if matches!(severity, "FATAL" | "PANIC") {
                    return Err(QueryError::Connection);
                }
                failed = Some(if strict {
                    QueryError::Remote(error.message)
                } else {
                    QueryError::Sql
                });
            }
            Reply::ReadyForQuery(ready) => {
                client.set_transaction_status(ready.status);
                return if let Some(error) = failed {
                    Err(error)
                } else if !strict && columns.is_none() {
                    Err(QueryError::Sql)
                } else if strict && let Some(count @ 2..) = columns {
                    Err(QueryError::Shape(count))
                } else {
                    Ok(rows)
                };
            }
            Reply::CopyInResponse(_) | Reply::CopyOutResponse(_) | Reply::CopyBothResponse(_) => {
                return Err(QueryError::Connection);
            }
            _ => (),
        }
    }
    Err(QueryError::Connection)
}

impl Postgres {
    async fn query(
        &self,
        sql: &str,
        username: &str,
        access: Option<i32>,
        visit: impl FnMut(usize, &[u8]) + Send,
    ) -> Result<usize, QueryError> {
        let mut guard = self.client.lock().await;
        // Dropping a cancelled query closes its connection instead of letting
        // the next request read an outstanding query's messages.
        if let Some(mut conn) = guard.take() {
            let mut params = Vec::with_capacity(if access.is_some() { 2 } else { 1 });
            params.push(Some(Bytes::copy_from_slice(
                super::c_str(username).as_bytes(),
            )));
            if let Some(access) = access {
                params.push(Some(Bytes::from(access.to_string())));
            }
            let mut visit = visit;
            let result = query(
                &mut conn,
                super::c_str(sql),
                params,
                false,
                |row, value, _| {
                    visit(row, value.unwrap_or(b"")); // libpq exposes NULL as an empty string.
                },
            )
            .await;
            if !matches!(result, Err(QueryError::Connection)) {
                *guard = Some(conn);
                return result;
            }
        }
        // PQreset after a connection loss: reconnect for later operations,
        // never re-run the SQL from the failed operation.
        log(format_args!(
            "Noticed a postgres connection loss. Trying to reconnect ..."
        ));
        *guard = self.settings.connect().await;
        Err(QueryError::Connection)
    }
}

impl Backend for Postgres {
    fn name(&self) -> &'static str {
        "postgres"
    }

    fn getuser<'a>(&'a self, username: &'a str, _: &[u8], _: &str) -> BoxFuture<'a, GetUser> {
        Box::pin(async move {
            if username.is_empty() {
                return GetUser::result(BackendResult::Defer);
            }
            let mut hash = None;
            let result = self
                .query(&self.user_query, username, None, |row, value| {
                    if row == 0 {
                        hash = std::str::from_utf8(value)
                            .ok()
                            .map(|s| super::c_str(s).to_owned());
                    }
                })
                .await;
            // be-postgres.c: be_pg_getuser defers even on query failure.
            GetUser {
                result: BackendResult::Defer,
                hash: if let Ok(1) = result { hash } else { None },
            }
        })
    }

    fn superuser<'a>(&'a self, username: &'a str) -> BoxFuture<'a, BackendResult> {
        Box::pin(async move {
            let Some(sql) = self.super_query.as_deref().filter(|_| !username.is_empty()) else {
                return BackendResult::Defer;
            };
            let mut allowed = false;
            match self
                .query(sql, username, None, |row, value| {
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
            let Some(sql) = self.acl_query.as_deref() else {
                return BackendResult::Defer;
            };
            let mut allowed = false;
            match self
                .query(sql, username, Some(access), |_, value| {
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
