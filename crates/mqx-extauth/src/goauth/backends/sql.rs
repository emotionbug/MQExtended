//! Shared SQL checks for postgres, mysql, sqlite and JWT local.

use std::{borrow::Cow, future::Future, sync::Arc, time::Duration};

use mqx_auth::external::BoxFuture;

use super::{mysql, postgres};
use crate::{
    backend::LoadError,
    goauth::{
        backend::{Backend, BackendError, Hasher, Init, Log, Options},
        topics,
    },
};

pub(super) fn option<'a>(options: &'a Options, name: &str, default: &'a str) -> &'a str {
    options.get(name).map_or(default, String::as_str)
}

pub(super) fn require(
    options: &Options,
    error: &str,
    names: impl IntoIterator<Item = &'static str>,
) -> Result<(), LoadError> {
    let mut missing = String::new();
    for name in names {
        if !options.contains_key(name) {
            missing.push(' ');
            missing.push_str(name);
        }
    }
    if missing.is_empty() {
        Ok(())
    } else {
        Err(LoadError::new(format!("{error}{missing}")))
    }
}

// postgres.go: CheckAcl, mysql.go: CheckAcl, sqlite.go: CheckAcl,
// mongo.go: CheckAcl, redis.go: checkAcl. Replacement values from the
// first pass also participate in the second pass, but never vice versa.
pub(super) fn expand<'a>(pattern: &'a str, client_id: &str, username: &str) -> Cow<'a, str> {
    let pattern = if pattern.contains("%c") {
        Cow::Owned(pattern.replace("%c", client_id))
    } else {
        Cow::Borrowed(pattern)
    };
    if pattern.contains("%u") {
        Cow::Owned(pattern.replace("%u", username))
    } else {
        pattern
    }
}

// db.go: OpenDatabase. Zero means one attempt; negative means unbounded.
pub(super) async fn ping<T, E, F>(
    engine: &str,
    tries: Option<&String>,
    log: &Log,
    mut attempt: impl FnMut() -> F,
) -> Result<T, LoadError>
where
    E: std::fmt::Display,
    F: Future<Output = Result<T, E>>,
{
    let mut remaining = match tries.map(|value| value.parse::<i64>()) {
        Some(Ok(tries)) if tries != 0 => tries,
        Some(Err(err)) => {
            log.warn(format_args!(
                "invalid {engine} connect tries options: {err}"
            ));
            1
        }
        _ => 1,
    };
    loop {
        match attempt().await {
            Ok(value) => return Ok(value),
            Err(error) => {
                log.error(format_args!(
                    "ping database {engine} error, will retry in 2s: {error}"
                ));
                tokio::time::sleep(Duration::from_secs(2)).await;
                if remaining > 0 {
                    remaining -= 1;
                    if remaining == 0 {
                        return Err(LoadError::new(format!(
                            "couldn't ping database {engine}: {error}"
                        )));
                    }
                }
            }
        }
    }
}

// db.go: OpenDatabase. time.Duration multiplication wraps before the driver
// interprets a nonpositive lifetime as unlimited.
pub(super) fn lifetime(options: &Options, name: &str) -> Option<Duration> {
    let seconds = options.get(name)?.parse::<i64>().ok()?.max(0);
    let nanos = seconds.wrapping_mul(1_000_000_000);
    (nanos > 0).then(|| Duration::from_nanos(nanos as u64))
}

pub(super) trait Connector: Send + Sync + 'static {
    fn query(
        &self,
        query: &str,
        username: &str,
        access: Option<i32>,
    ) -> impl Future<Output = Result<Cells, BackendError>> + Send;

    fn halt(&self, log: &Log) -> impl Future<Output = ()> + Send;
}

// database/sql and sqlx read a single row for Get but scan *all* rows for
// Select before ACL matching. A bad later ACL row invalidates earlier grants.
pub(super) enum Cells {
    Scalar(Option<Option<String>>),
    Acls(Vec<String>),
}

impl Cells {
    pub(super) fn new(access: Option<i32>) -> Self {
        if access.is_some() {
            Self::Acls(Vec::new())
        } else {
            Self::Scalar(None)
        }
    }

    pub(super) fn push(
        &mut self,
        get: impl FnOnce() -> Result<Option<String>, BackendError>,
    ) -> Result<(), BackendError> {
        match self {
            Self::Scalar(target @ None) => *target = Some(get()?),
            Self::Scalar(Some(_)) => (),
            Self::Acls(patterns) => patterns
                .push(get()?.ok_or_else(|| {
                    BackendError::new("converting NULL to string is unsupported")
                })?),
        }
        Ok(())
    }

    fn scalar(self) -> Option<Option<String>> {
        match self {
            Self::Scalar(value) => value,
            Self::Acls(_) => unreachable!("scalar query produced ACLs"),
        }
    }

    fn acls(self) -> Vec<String> {
        match self {
            Self::Acls(patterns) => patterns,
            Self::Scalar(_) => unreachable!("ACL query produced scalar"),
        }
    }
}

struct Sql<C> {
    name: &'static str,
    db: C,
    user_query: String,
    jwt: bool,
    super_query: String,
    acl_query: String,
    hasher: Arc<dyn Hasher>,
    log: Log,
}

pub(super) fn backend(
    init: Init<'_>,
    name: &'static str,
    prefix: &str,
    db: impl Connector,
) -> Box<dyn Backend> {
    from_connector(init, name, prefix, db, None)
}

fn from_connector(
    init: Init<'_>,
    name: &'static str,
    prefix: &str,
    db: impl Connector,
    jwt_query: Option<&str>,
) -> Box<dyn Backend> {
    let query = |name| option(init.options, &format!("{prefix}_{name}"), "").to_owned();
    Box::new(Sql {
        name,
        db,
        user_query: jwt_query.map_or_else(|| query("userquery"), str::to_owned),
        jwt: jwt_query.is_some(),
        super_query: query("superquery"),
        acl_query: query("aclquery"),
        hasher: init.hasher,
        log: init.log,
    })
}

// jwt_local.go: NewLocalJWTChecker, extractOpts.
pub(super) async fn create_jwt_local(init: Init<'_>) -> Result<Box<dyn Backend>, LoadError> {
    let query = init.options.get("jwt_userquery").ok_or_else(|| {
        LoadError::new("JWT backend error: missing local options:  jwt_userquery")
    })?;
    let is_mysql = option(init.options, "jwt_db", "postgres") == "mysql";
    let (name, prefix) = if is_mysql {
        ("Mysql", "mysql")
    } else {
        ("Postgres", "pg")
    };
    let jwt_prefix = format!("jwt_{prefix}");
    let mut options: Options = init
        .options
        .iter()
        .filter(|(key, _)| key.starts_with(&jwt_prefix))
        .map(|(key, value)| (key[4..].to_owned(), value.to_owned()))
        .collect();
    options.insert(format!("{prefix}_userquery"), "dummy".to_owned());
    let init = Init {
        options: &options,
        ..init
    };
    let error = |err| {
        LoadError::new(format!(
            "JWT backend error: couldn't create {} connector for local jwt: {err}",
            if is_mysql { "mysql" } else { "postgres" }
        ))
    };
    if is_mysql {
        let db = mysql::connect(&init).await.map_err(error)?;
        Ok(from_connector(init, name, prefix, db, Some(query)))
    } else {
        let db = postgres::connect(&init).await.map_err(error)?;
        Ok(from_connector(init, name, prefix, db, Some(query)))
    }
}

fn positive(value: Option<String>) -> Result<bool, BackendError> {
    value.map_or(Ok(false), |value| {
        value
            .parse::<i64>()
            .map(|n| n > 0)
            .map_err(|_| BackendError::new(format!("converting {value:?} to int64 is unsupported")))
    })
}

impl<C> Sql<C> {
    fn report(
        &self,
        action: &str,
        result: Result<bool, BackendError>,
    ) -> Result<bool, BackendError> {
        if let Err(error) = &result {
            self.log
                .debug(format_args!("{} {action} error: {error}", self.name));
        }
        result
    }
}

impl<C: Connector> Backend for Sql<C> {
    fn name(&self) -> String {
        self.name.to_owned()
    }

    // postgres.go: GetUser, mysql.go: GetUser, sqlite.go: GetUser.
    // jwt_local.go: getLocalUser returns the missing-row error rather than hiding it.
    fn get_user<'a>(
        &'a self,
        username: &'a str,
        password: &'a [u8],
        _: &str,
    ) -> BoxFuture<'a, Result<bool, BackendError>> {
        Box::pin(async move {
            if self.jwt && self.user_query.is_empty() {
                return Ok(false);
            }
            let result = self
                .db
                .query(&self.user_query, username, None)
                .await
                .and_then(|cells| {
                    let value = cells.scalar();
                    if self.jwt {
                        positive(
                            value.ok_or_else(|| BackendError::new("sql: no rows in result set"))?,
                        )
                    } else {
                        Ok(value
                            .flatten()
                            .is_some_and(|hash| self.hasher.compare(password, &hash)))
                    }
                });
            self.report(
                if self.jwt {
                    "local JWT get user"
                } else {
                    "get user"
                },
                result,
            )
        })
    }

    // postgres.go: GetSuperuser, mysql.go: GetSuperuser, sqlite.go: GetSuperuser.
    fn get_superuser<'a>(&'a self, username: &'a str) -> BoxFuture<'a, Result<bool, BackendError>> {
        Box::pin(async move {
            if self.super_query.is_empty() {
                return Ok(false);
            }
            let result = self
                .db
                .query(&self.super_query, username, None)
                .await
                .and_then(|cells| positive(cells.scalar().flatten()));
            self.report("get superuser", result)
        })
    }

    // postgres.go: CheckAcl, mysql.go: CheckAcl, sqlite.go: CheckAcl.
    fn check_acl<'a>(
        &'a self,
        username: &'a str,
        topic: &'a str,
        client_id: &'a str,
        access: i32,
    ) -> BoxFuture<'a, Result<bool, BackendError>> {
        Box::pin(async move {
            if self.acl_query.is_empty() {
                return Ok(true);
            }
            let result = self
                .db
                .query(&self.acl_query, username, Some(access))
                .await
                .map(|cells| {
                    cells.acls().iter().any(|pattern| {
                        topics::matches(&expand(pattern, client_id, username), topic)
                    })
                });
            self.report("check acl", result)
        })
    }

    fn halt(&self) -> BoxFuture<'_, ()> {
        Box::pin(self.db.halt(&self.log))
    }
}
