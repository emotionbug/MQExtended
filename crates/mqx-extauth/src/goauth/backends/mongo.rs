use std::{borrow::Cow, sync::Arc, time::Duration};

use mongodb::{
    Client, Collection,
    bson::{
        doc,
        raw::{RawBsonRef, RawDocument, RawDocumentBuf},
        spec::BinarySubtype,
    },
    options::{ClientOptions, Credential, Tls, TlsOptions},
};
use mqx_auth::external::BoxFuture;

use super::sql::{expand, option};
use crate::{
    backend::LoadError,
    goauth::{
        backend::{Backend, BackendError, Hasher, Init, Log},
        topics,
    },
};

struct Mongo {
    client: Client,
    users: Collection<RawDocumentBuf>,
    acls: Collection<RawDocumentBuf>,
    disable_superuser: bool,
    hasher: Arc<dyn Hasher>,
    log: Log,
}

// mongo.go: NewMongo. Apply URI and 60s connection timeout without a ping;
// mongo_insecure_skip_verify is read by Go but never affects its tls.Config.
pub(crate) async fn create(init: Init<'_>) -> Result<Box<dyn Backend>, LoadError> {
    init.log.set_level(init.log.level());
    let opts = init.options;
    let host = option(opts, "mongo_host", "localhost");
    let port = option(opts, "mongo_port", "27017");
    let database = option(opts, "mongo_dbname", "mosquitto");
    let username = option(opts, "mongo_username", "");
    let password = option(opts, "mongo_password", "");
    let load_error = |err| LoadError::new(format!("couldn't start mongo backend: {err}"));
    let mut driver = ClientOptions::parse(format!("mongodb://{host}:{port}"))
        .await
        .map_err(load_error)?;
    driver.connect_timeout = Some(Duration::from_secs(60));
    if option(opts, "mongo_use_tls", "false") == "true" && driver.tls.is_none() {
        driver.tls = Some(Tls::Enabled(TlsOptions::default()));
    }
    if !username.is_empty() && !password.is_empty() {
        let authsource = option(opts, "mongo_authsource", "");
        let source = if authsource.is_empty() {
            database
        } else {
            init.log.info(format_args!(
                "mongo backend: set authentication db to: {authsource}"
            ));
            authsource
        };
        driver.credential = Some(
            Credential::builder()
                .username(username.to_owned())
                .password(password.to_owned())
                .source(source.to_owned())
                .build(),
        );
    }
    let client = Client::with_options(driver).map_err(load_error)?;
    let database = client.database(database);
    Ok(Box::new(Mongo {
        users: database.collection(option(opts, "mongo_users", "users")),
        acls: database.collection(option(opts, "mongo_acls", "acls")),
        client,
        disable_superuser: option(opts, "mongo_disable_superuser", "false") == "true",
        hasher: init.hasher,
        log: init.log,
    }))
}

impl Mongo {
    async fn lookup(
        &self,
        username: &str,
        action: &str,
    ) -> Result<Option<RawDocumentBuf>, BackendError> {
        self.users
            .find_one(doc! { "username": username })
            .await
            .map_err(|err| {
                self.log.debug(format_args!("Mongo {action} error: {err}"));
                error(err)
            })
    }

    fn decode<'a>(&self, doc: &'a RawDocument, action: &str) -> Result<User<'a>, BackendError> {
        User::decode(doc)
            .inspect_err(|err| self.log.debug(format_args!("Mongo {action} error: {err}")))
    }
}

impl Backend for Mongo {
    fn name(&self) -> String {
        "Mongo".to_owned()
    }

    // mongo.go: GetUser.
    fn get_user<'a>(
        &'a self,
        username: &'a str,
        password: &'a [u8],
        _: &str,
    ) -> BoxFuture<'a, Result<bool, BackendError>> {
        Box::pin(async move {
            let Some(doc) = self.lookup(username, "get user").await? else {
                return Ok(false);
            };
            Ok(self
                .hasher
                .compare(password, &self.decode(&doc, "get user")?.password))
        })
    }

    // mongo.go: GetSuperuser.
    fn get_superuser<'a>(&'a self, username: &'a str) -> BoxFuture<'a, Result<bool, BackendError>> {
        Box::pin(async move {
            if self.disable_superuser {
                return Ok(false);
            }
            let Some(doc) = self.lookup(username, "get superuser").await? else {
                return Ok(false);
            };
            Ok(self.decode(&doc, "get superuser")?.superuser)
        })
    }

    // mongo.go: CheckAcl. A missing user denies even if a common pattern
    // would match; read-write patterns grant subscribe as well.
    fn check_acl<'a>(
        &'a self,
        username: &'a str,
        topic: &'a str,
        client_id: &'a str,
        access: i32,
    ) -> BoxFuture<'a, Result<bool, BackendError>> {
        Box::pin(async move {
            let Some(doc) = self.lookup(username, "get superuser").await? else {
                return Ok(false);
            };
            let user = self.decode(&doc, "get superuser")?;
            if user.acls.iter().any(|acl| {
                (acl.access == access || acl.access == 3) && topics::matches(&acl.topic, topic)
            }) {
                return Ok(true);
            }
            let mut cursor = self
                .acls
                .find(doc! { "acc": { "$in": [access, 3] } })
                .await
                .map_err(|err| {
                    self.log.debug(format_args!("Mongo check acl error: {err}"));
                    error(err)
                })?;
            // Go ignores cur.Err after Next stops and logs/skips bad documents.
            while matches!(cursor.advance().await, Ok(true)) {
                match Acl::decode(cursor.current()) {
                    Ok(acl) if topics::matches(&expand(&acl.topic, client_id, username), topic) => {
                        return Ok(true);
                    }
                    Ok(_) => (),
                    Err(err) => self
                        .log
                        .error(format_args!("mongo cursor decode error: {err}")),
                }
            }
            Ok(false)
        })
    }

    fn halt(&self) -> BoxFuture<'_, ()> {
        Box::pin(async { self.client.clone().shutdown().await })
    }
}

fn error(err: impl std::fmt::Display) -> BackendError {
    BackendError::new(err.to_string())
}

#[derive(Default)]
struct Acl<'a> {
    topic: Cow<'a, str>,
    access: i32,
}

impl<'a> Acl<'a> {
    fn decode(doc: &'a RawDocument) -> Result<Self, BackendError> {
        let mut acl = Self::default();
        for field in doc {
            let (key, value) = field.map_err(error)?;
            if key.eq_ignore_ascii_case("topic") {
                acl.topic = string_value(value)?;
            } else if key.eq_ignore_ascii_case("acc") {
                acl.access = int_value(value)?;
            }
        }
        Ok(acl)
    }
}

#[derive(Default)]
struct User<'a> {
    password: Cow<'a, str>,
    superuser: bool,
    acls: Vec<Acl<'a>>,
}

impl<'a> User<'a> {
    fn decode(doc: &'a RawDocument) -> Result<Self, BackendError> {
        let mut user = Self::default();
        for field in doc {
            let (name, value) = field.map_err(error)?;
            if name.eq_ignore_ascii_case("username") {
                string_value(value)?;
            } else if name.eq_ignore_ascii_case("password") {
                user.password = string_value(value)?;
            } else if name.eq_ignore_ascii_case("superuser") {
                user.superuser = bool_value(value)?;
            } else if name.eq_ignore_ascii_case("acls") {
                user.acls = match value {
                    RawBsonRef::Array(array) => array
                        .into_iter()
                        .map(|value| match value.map_err(error)? {
                            RawBsonRef::Document(doc) => Acl::decode(doc),
                            RawBsonRef::Null | RawBsonRef::Undefined => Ok(Acl::default()),
                            value => Err(decode_error(value, "MongoAcl")),
                        })
                        .collect::<Result<_, _>>()?,
                    RawBsonRef::Null | RawBsonRef::Undefined => Vec::new(),
                    value => return Err(decode_error(value, "[]MongoAcl")),
                };
            }
        }
        Ok(user)
    }
}

fn decode_error(value: RawBsonRef<'_>, target: &str) -> BackendError {
    BackendError::new(format!(
        "cannot decode {:?} into {target}",
        value.element_type()
    ))
}

// Go's bsoncodec accepts numbers into bools and booleans into ints. Null
// and undefined decode to the type's zero value, like a missing field.
fn bool_value(value: RawBsonRef<'_>) -> Result<bool, BackendError> {
    Ok(match value {
        RawBsonRef::Boolean(value) => value,
        RawBsonRef::Int32(value) => value != 0,
        RawBsonRef::Int64(value) => value != 0,
        RawBsonRef::Double(value) => value != 0.0,
        RawBsonRef::Null | RawBsonRef::Undefined => false,
        value => return Err(decode_error(value, "a boolean")),
    })
}

fn int_value(value: RawBsonRef<'_>) -> Result<i32, BackendError> {
    Ok(match value {
        RawBsonRef::Int32(value) => value,
        RawBsonRef::Int64(value) => i32::try_from(value).map_err(error)?,
        RawBsonRef::Double(value)
            if value.fract() == 0.0
                && (f64::from(i32::MIN)..=f64::from(i32::MAX)).contains(&value) =>
        {
            value as i32
        }
        RawBsonRef::Boolean(value) => i32::from(value),
        RawBsonRef::Null | RawBsonRef::Undefined => 0,
        value => return Err(decode_error(value, "an integer")),
    })
}

fn string_value(value: RawBsonRef<'_>) -> Result<Cow<'_, str>, BackendError> {
    Ok(match value {
        RawBsonRef::String(value) | RawBsonRef::Symbol(value) => Cow::Borrowed(value),
        RawBsonRef::ObjectId(oid) => Cow::Owned(oid.to_hex()),
        RawBsonRef::Binary(value)
            if matches!(
                value.subtype,
                BinarySubtype::Generic | BinarySubtype::BinaryOld
            ) =>
        {
            Cow::Borrowed(std::str::from_utf8(value.bytes).map_err(error)?)
        }
        RawBsonRef::Null | RawBsonRef::Undefined => Cow::Borrowed(""),
        value => return Err(decode_error(value, "a string type")),
    })
}
