use mongodb::{
    Client, Collection,
    bson::{
        Bson, Document,
        raw::{RawBsonRef, RawDocument, RawDocumentBuf},
    },
    options::{ClientOptions, Credential, ServerAddress},
};
use mqx_auth::external::BoxFuture;

use crate::{
    authplug::{atoi, log},
    backend::{Backend, BackendResult, GetUser, LoadError, Options},
};

struct Settings {
    database: String,
    users: String,
    lists: String,
    username: String,
    password: String,
    superuser: String,
    user_topics: String,
    user_foreign_key: String,
    list_key: String,
    list_topics: String,
}

impl Settings {
    fn from_options(options: &Options) -> Self {
        // be-mongo.c: be_mongo_init, be_mongo_get_option. The fallback for
        // mongo_topiclist_key_prop (unusually) aliases the superuser field.
        let get = |name, alias, default: &str| {
            options
                .get(name)
                .or_else(|| {
                    let alias = alias?;
                    let value = options.get(alias)?;
                    log(format_args!(
                        "[mongo] Warning: Option '{name}' is deprecated. Use '{alias}' instead."
                    ));
                    Some(value)
                })
                .unwrap_or(default)
                .to_owned()
        };
        Self {
            database: get("mongo_database", None, "mqGate"),
            users: get("mongo_user_coll", Some("mongo_collection_users"), "users"),
            lists: get(
                "mongo_topiclist_coll",
                Some("mongo_collection_topics"),
                "topics",
            ),
            username: get("mongo_user_username_prop", None, "username"),
            password: get(
                "mongo_user_password_prop",
                Some("mongo_location_password"),
                "password",
            ),
            superuser: get(
                "mongo_user_superuser_prop",
                Some("mongo_location_superuser"),
                "superuser",
            ),
            user_topics: get("mongo_user_topics_prop", None, "topics"),
            user_foreign_key: get(
                "mongo_user_topiclist_fk_prop",
                Some("mongo_location_topic"),
                "topics",
            ),
            list_key: get(
                "mongo_topiclist_key_prop",
                Some("mongo_location_superuser"),
                "_id",
            ),
            list_topics: get(
                "mongo_topiclist_topics_prop",
                Some("mongo_location_topic"),
                "topics",
            ),
        }
    }
}

struct Mongo {
    settings: Settings,
    users: Collection<RawDocumentBuf>,
    lists: Collection<RawDocumentBuf>,
}

pub(crate) async fn create(options: &Options) -> Result<Box<dyn Backend>, LoadError> {
    // be-mongo.c: be_mongo_new_uri_from_options. mongo_uri trumps every
    // piecemeal connection setting; neither configuration pings at startup.
    let invalid = |_| LoadError::new("MongoDB connection options invalid");
    let connection = if let Some(uri) = options.get("mongo_uri") {
        ClientOptions::parse(uri).await.map_err(invalid)?
    } else {
        let port = options.get("mongo_port").map_or(0, |s| atoi(s.as_bytes()));
        let host = options.get("mongo_host").unwrap_or("localhost").to_owned();
        if host.is_empty() || host.contains([',', '/', '\0']) {
            return Err(LoadError::new("MongoDB connection options invalid"));
        }
        let host = host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_owned();
        let address = ServerAddress::Tcp {
            host,
            port: Some(if port == 0 { 27017 } else { port as u16 }),
        };
        let credential = options.get("mongo_user").map(|user| {
            Credential::builder()
                .username(user.to_owned())
                .password(options.get("mongo_password").map(str::to_owned))
                .source(options.get("mongo_authSource").map(str::to_owned))
                .build()
        });
        ClientOptions::builder()
            .hosts(vec![address])
            .credential(credential)
            .build()
    };
    let settings = Settings::from_options(options);
    let client = Client::with_options(connection).map_err(invalid)?;
    let database = client.database(&settings.database);
    let users = database.collection(&settings.users);
    let lists = database.collection(&settings.lists);
    Ok(Box::new(Mongo {
        settings,
        users,
        lists,
    }))
}

async fn lookup(
    collection: &Collection<RawDocumentBuf>,
    key: &str,
    value: impl Into<Bson>,
) -> Option<RawDocumentBuf> {
    let mut query = Document::new();
    query.insert(key, value);
    match collection.find_one(query).await {
        Ok(document) => document,
        Err(_) => {
            // be-mongo.c: be_mongo_getuser, be_mongo_superuser and
            // be_mongo_aclcheck log cursor failures, then defer.
            eprintln!("[mongo] Cursor Failure");
            None
        }
    }
}

fn field<'a>(document: &'a RawDocument, name: &str) -> Option<RawBsonRef<'a>> {
    document.get(name).ok().flatten()
}

fn as_bool(value: RawBsonRef<'_>) -> bool {
    // be-mongo.c: be_mongo_superuser calls bson-iter.c: bson_iter_as_bool.
    // Even an empty string or a decimal128 zero is truthy.
    match value {
        RawBsonRef::Boolean(value) => value,
        RawBsonRef::Double(value) => value != 0.0,
        RawBsonRef::Int32(value) => value != 0,
        RawBsonRef::Int64(value) => value != 0,
        RawBsonRef::Null | RawBsonRef::Undefined => false,
        _ => true,
    }
}

fn foreign_key(value: RawBsonRef<'_>) -> Option<Bson> {
    // be-mongo.c: be_mongo_aclcheck sends both integer widths as BSON int64.
    // Unlike the C cursor's borrowed string/OID, the returned key owns bytes.
    match value {
        RawBsonRef::ObjectId(value) => Some(Bson::ObjectId(value)),
        RawBsonRef::String(value) => Some(Bson::String(super::c_str(value).to_owned())),
        RawBsonRef::Int32(value) if value != 0 => Some(Bson::Int64(i64::from(value))),
        RawBsonRef::Int64(value) if value != 0 => Some(Bson::Int64(value)),
        _ => None,
    }
}

fn check_topics(
    value: Option<RawBsonRef<'_>>,
    topic: &str,
    access: i32,
    client_id: &str,
    username: &str,
) -> bool {
    let matches = |filter| super::matches(filter, topic, client_id, username);
    match value {
        // be-mongo.c: be_mongo_check_acl_topics_array grants all access bits.
        Some(RawBsonRef::Array(array)) => array
            .into_iter()
            .any(|item| matches!(item, Ok(RawBsonRef::String(filter)) if matches(filter))),
        // be-mongo.c: be_mongo_check_acl_topics_map. "rw" is unconditional
        // for a matching filter: it grants SUBSCRIBE (4), unlike "r" or "w".
        Some(RawBsonRef::Document(map)) => map.iter().any(|item| {
            let Ok((filter, RawBsonRef::String(permission))) = item else {
                return false;
            };
            let granted = match super::c_str(permission) {
                "r" => access & 1 != 0,
                "w" => access & 2 != 0,
                "rw" => true,
                _ => false,
            };
            granted && matches(filter)
        }),
        _ => false,
    }
}

impl Mongo {
    async fn user(&self, username: &str) -> Option<RawDocumentBuf> {
        lookup(&self.users, &self.settings.username, super::c_str(username)).await
    }
}

impl Backend for Mongo {
    fn name(&self) -> &'static str {
        "mongo"
    }

    fn getuser<'a>(&'a self, username: &'a str, _: &[u8], _: &str) -> BoxFuture<'a, GetUser> {
        Box::pin(async move {
            if let Some(user) = self.user(username).await
                && let Some(RawBsonRef::String(hash)) = field(&user, &self.settings.password)
            {
                return GetUser::hash(super::c_str(hash).to_owned());
            }
            GetUser::result(BackendResult::Defer)
        })
    }

    fn superuser<'a>(&'a self, username: &'a str) -> BoxFuture<'a, BackendResult> {
        Box::pin(async move {
            if self
                .user(username)
                .await
                .is_some_and(|user| field(&user, &self.settings.superuser).is_some_and(as_bool))
            {
                BackendResult::Allow
            } else {
                BackendResult::Defer
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
            // be-mongo.c: be_mongo_aclcheck. Embedded grants short-circuit;
            // otherwise look up the first topic-list document by foreign key.
            if let Some(user) = self.user(username).await {
                let grants = |value| check_topics(value, topic, access, client_id, username);
                if grants(field(&user, &self.settings.user_topics)) {
                    return BackendResult::Allow;
                }
                if let Some(key) =
                    field(&user, &self.settings.user_foreign_key).and_then(foreign_key)
                    && let Some(list) = lookup(&self.lists, &self.settings.list_key, key).await
                    && check_topics(
                        field(&list, &self.settings.list_topics),
                        topic,
                        access,
                        client_id,
                        username,
                    )
                {
                    return BackendResult::Allow;
                }
            }
            BackendResult::Defer
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mongodb::bson::{oid::ObjectId, rawdoc};

    #[test]
    fn honors_legacy_aliases_and_key_quirk() {
        let options = Options::new(
            [
                ("mongo_collection_users", "users-old"),
                ("mongo_user_coll", "users-new"),
                ("mongo_location_superuser", "admin"),
                ("mongo_location_topic", "access"),
            ]
            .map(|(key, value)| (key.to_owned(), value.to_owned()))
            .to_vec(),
        );
        let s = Settings::from_options(&options);
        assert_eq!(s.users, "users-new");
        assert_eq!(s.superuser, "admin");
        assert_eq!(s.list_key, "admin");
        assert_eq!(s.user_topics, "topics");
        assert_eq!(s.user_foreign_key, "access");
        assert_eq!(s.list_topics, "access");
    }

    #[test]
    fn handles_bson_topics_and_typed_foreign_keys() {
        let doc = rawdoc! { "embedded": ["public/#", 7, "private/%u/%c"], "map": {
            "read/#": "r", "write/#": "w", "any/#": "rw", "other/#": 1,
        }};
        let grants =
            |key, topic, access| check_topics(field(&doc, key), topic, access, "client", "alice");
        assert!(grants("embedded", "private/alice/client", 4));
        assert!(grants("map", "read/a", 1));
        assert!(!grants("map", "read/a", 4));
        assert!(!grants("map", "write/a", 1));
        assert!(grants("map", "write/a", 2));
        assert!(grants("map", "any/a", 4));
        assert!(!grants("map", "other/a", 1));
        let id = ObjectId::new();
        assert_eq!(
            foreign_key(RawBsonRef::ObjectId(id)),
            Some(Bson::ObjectId(id))
        );
        assert_eq!(foreign_key(RawBsonRef::Int32(-5)), Some(Bson::Int64(-5)));
        assert_eq!(foreign_key(RawBsonRef::Int64(0)), None);
        assert_eq!(
            foreign_key(RawBsonRef::String("")),
            Some(Bson::String(String::new()))
        );
    }

    #[test]
    fn superuser_matches_libbson_truthiness() {
        assert!(!as_bool(RawBsonRef::Undefined));
        assert!(!as_bool(RawBsonRef::Double(-0.0)));
        assert!(as_bool(RawBsonRef::Double(f64::NAN)));
        assert!(as_bool(RawBsonRef::String("false")));
        assert!(as_bool(RawBsonRef::String("")));
    }
}
