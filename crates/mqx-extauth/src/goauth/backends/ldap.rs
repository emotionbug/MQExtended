use std::{borrow::Cow, fmt::Write as _, time::Duration};

use ldap3::{Ldap, LdapConnAsync, LdapConnSettings, Scope, SearchEntry};
use mqx_auth::external::BoxFuture;
use tokio::sync::Mutex;

use super::sql::{option, require};
use crate::{
    backend::LoadError,
    goauth::{
        backend::{Backend, BackendError, Init, Log},
        topics,
    },
};

struct Directory {
    url: String,
    service: Mutex<Ldap>,
    user_dn: String,
    group_dn: String,
    user_filter: String,
    group_filter: String,
    super_filter: String,
    attributes: Vec<String>,
    topic_attribute: String,
    access_attribute: String,
    log: Log,
}

// ldap.go: NewLDAP, NewLDAPWithFactory.
pub(crate) async fn create(init: Init<'_>) -> Result<Box<dyn Backend>, LoadError> {
    init.log.set_level(init.log.level());
    let opts = init.options;
    require(
        opts,
        "LDAP backend error: missing options:",
        [
            "ldap_user_dn",
            "ldap_bind_dn",
            "ldap_bind_password",
            "ldap_user_filter",
        ],
    )?;
    let url = option(opts, "ldap_url", "ldap://localhost:389");
    let mut service = connect(url).await.map_err(|err| {
        init.log.error(format_args!("LDAP connection error: {err}"));
        LoadError::new(err.to_string())
    })?;
    if let Err(err) = bind(
        &mut service,
        &opts["ldap_bind_dn"],
        &opts["ldap_bind_password"],
    )
    .await
    {
        init.log.error(format_args!("LDAP bind error: {err}"));
        close(&mut service, &init.log, "cleanup").await;
        return Err(LoadError::new(err.to_string()));
    }
    let topic_attribute = option(opts, "ldap_acl_topic_pattern_attribute", "").to_owned();
    let access_attribute = option(opts, "ldap_acl_acc_attribute", "").to_owned();
    let attributes = [&topic_attribute, &access_attribute]
        .into_iter()
        .filter(|name| !name.is_empty())
        .cloned()
        .collect();
    Ok(Box::new(Directory {
        url: url.to_owned(),
        service: Mutex::new(service),
        user_dn: opts["ldap_user_dn"].to_owned(),
        group_dn: option(opts, "ldap_group_dn", "").to_owned(),
        user_filter: opts["ldap_user_filter"].to_owned(),
        group_filter: option(opts, "ldap_group_filter", "(member=%s)").to_owned(),
        super_filter: option(opts, "ldap_superuser_filter", "").to_owned(),
        attributes,
        topic_attribute,
        access_attribute,
        log: init.log,
    }))
}

async fn connect(url: &str) -> ldap3::result::Result<Ldap> {
    let settings = LdapConnSettings::new().set_conn_timeout(Duration::from_secs(60));
    let (conn, ldap) = LdapConnAsync::with_settings(settings, url).await?;
    tokio::spawn(async move {
        let _ = conn.drive().await;
    });
    Ok(ldap)
}

async fn bind(ldap: &mut Ldap, dn: &str, password: &str) -> Result<(), BackendError> {
    // go-ldap bind.go: Bind denies an empty password before contacting LDAP.
    if password.is_empty() {
        return Err(BackendError::new(
            "LDAP Result Code 206 \"Empty password not allowed by the client\": ldap: empty password not allowed by the client",
        ));
    }
    ldap.simple_bind(dn, password)
        .await
        .and_then(ldap3::LdapResult::success)
        .map(|_| ())
        .map_err(|err| BackendError::new(err.to_string()))
}

async fn close(ldap: &mut Ldap, log: &Log, operation: &str) {
    if let Err(err) = ldap.unbind().await {
        log.error(format_args!("LDAP {operation} error: {err}"));
    }
}

// go-ldap ldap.go: EscapeFilter escapes each non-ASCII byte as well as the
// filter metacharacters; the username cannot modify the search syntax.
fn escape(username: &str) -> Cow<'_, str> {
    let must_escape = |b: u8| b > 0x7f || matches!(b, b'(' | b')' | b'\\' | b'*' | 0);
    if !username.bytes().any(must_escape) {
        return Cow::Borrowed(username);
    }
    let mut escaped = String::with_capacity(username.len());
    for byte in username.bytes() {
        if must_escape(byte) {
            let _ = write!(escaped, "\\{byte:02x}");
        } else {
            escaped.push(char::from(byte));
        }
    }
    Cow::Owned(escaped)
}

// ldap.go: GetUser, GetSuperuser, CheckAcl. Filters are a Go string format
// applied to one argument. Support string verbs and explicit argument 1.
fn filter(mut format: &str, username: &str) -> Result<String, BackendError> {
    let username = escape(username);
    let mut result = String::with_capacity(format.len() + username.len());
    let mut used = false;
    while let Some((prefix, mut rest)) = format.split_once('%') {
        result.push_str(prefix);
        let indexed = rest.starts_with("[1]");
        if indexed {
            rest = &rest[3..];
        }
        let mut chars = rest.chars();
        let Some(verb) = chars.next() else {
            return Err(BackendError::new("ldap: filter format has a missing verb"));
        };
        if verb == '%' {
            result.push('%');
        } else if used && !indexed {
            let _ = write!(result, "%!{verb}(MISSING)");
        } else {
            used = true;
            match verb {
                's' | 'v' => result.push_str(&username),
                'q' => {
                    let _ = write!(result, "{username:?}");
                }
                'x' => {
                    for byte in username.bytes() {
                        let _ = write!(result, "{byte:02x}");
                    }
                }
                'X' => {
                    for byte in username.bytes() {
                        let _ = write!(result, "{byte:02X}");
                    }
                }
                _ => {
                    let _ = write!(result, "%!{verb}(string={username})");
                }
            }
        }
        format = chars.as_str();
    }
    result.push_str(format);
    if !used {
        return Err(BackendError::new(format!(
            "ldap: finished compiling filter with extra at end: %!(EXTRA string={username})"
        )));
    }
    Ok(result)
}

impl Directory {
    async fn search(
        &self,
        action: &str,
        base: &str,
        format: &str,
        username: &str,
        attrs: &[&str],
    ) -> Result<Vec<ldap3::ResultEntry>, BackendError> {
        let result = async {
            let filter = filter(format, username)?;
            let search = self
                .service
                .lock()
                .await
                .search(base, Scope::Subtree, &filter, attrs)
                .await
                .map_err(|err| BackendError::new(err.to_string()))?;
            if search.1.rc == 32 {
                self.log.debug(format_args!(
                    "LDAP {action} search returned no such object (code 32)"
                ));
                return Ok(Vec::new());
            }
            let (mut entries, _) = search
                .success()
                .map_err(|err| BackendError::new(err.to_string()))?;
            entries.retain(|entry| !entry.is_ref() && !entry.is_intermediate());
            Ok(entries)
        }
        .await;
        if let Err(err) = &result {
            self.log
                .error(format_args!("LDAP {action} search error: {err}"));
        }
        result
    }
}

impl Backend for Directory {
    fn name(&self) -> String {
        "LDAP".to_owned()
    }

    // ldap.go: GetUser. A fresh connection preserves the service bind;
    // failure to open it is an error, while bind errors are denials.
    fn get_user<'a>(
        &'a self,
        username: &'a str,
        password: &'a [u8],
        _: &str,
    ) -> BoxFuture<'a, Result<bool, BackendError>> {
        Box::pin(async move {
            let mut entries = self
                .search("user", &self.user_dn, &self.user_filter, username, &["dn"])
                .await?;
            if entries.len() != 1 {
                self.log.debug(format_args!(
                    "LDAP user search returned {} entries",
                    entries.len()
                ));
                return Ok(false);
            }
            let entry = SearchEntry::construct(entries.swap_remove(0));
            let mut user = connect(&self.url).await.map_err(|err| {
                self.log
                    .error(format_args!("LDAP user connection error: {err}"));
                BackendError::new(err.to_string())
            })?;
            let result = match std::str::from_utf8(password) {
                Ok(password) => bind(&mut user, &entry.dn, password).await,
                Err(err) => Err(BackendError::new(err.to_string())),
            };
            if let Err(err) = &result {
                self.log.error(format_args!("LDAP user bind error: {err}"));
            }
            close(&mut user, &self.log, "user cleanup").await;
            Ok(result.is_ok())
        })
    }

    // ldap.go: GetSuperuser.
    fn get_superuser<'a>(&'a self, username: &'a str) -> BoxFuture<'a, Result<bool, BackendError>> {
        Box::pin(async move {
            if self.super_filter.is_empty() {
                return Ok(false);
            }
            let count = self
                .search(
                    "superuser",
                    &self.user_dn,
                    &self.super_filter,
                    username,
                    &["dn"],
                )
                .await?
                .len();
            if count != 1 {
                self.log.debug(format_args!(
                    "LDAP superuser search returned {count} entries"
                ));
            }
            Ok(count == 1)
        })
    }

    // ldap.go: CheckAcl. Access is a bitmask, unlike the SQL and Mongo
    // checks. Missing/empty access attributes impose no restriction.
    fn check_acl<'a>(
        &'a self,
        username: &'a str,
        topic: &'a str,
        _: &str,
        requested: i32,
    ) -> BoxFuture<'a, Result<bool, BackendError>> {
        Box::pin(async move {
            if self.attributes.is_empty() {
                return Ok(true);
            }
            if self.group_dn.is_empty() {
                self.log
                    .error(format_args!("ldap_group_base_dn not set, cannot check ACL"));
                return Ok(false);
            }
            let attrs: Vec<_> = self.attributes.iter().map(String::as_str).collect();
            let entries = self
                .search("acl", &self.group_dn, &self.group_filter, username, &attrs)
                .await?;
            if entries.is_empty() {
                self.log
                    .debug(format_args!("LDAP acl search returned no entries"));
            }
            for entry in entries.into_iter().map(SearchEntry::construct) {
                if let Some(access) = entry
                    .attrs
                    .get(&self.access_attribute)
                    .and_then(|values| values.first())
                    .filter(|value| !value.is_empty())
                {
                    match access.parse::<i32>() {
                        Ok(access) if access & requested == requested => (),
                        Ok(_) => continue,
                        Err(err) => {
                            self.log.error(format_args!(
                                "LDAP acl failed to parse {access} as int32: {err}"
                            ));
                            continue;
                        }
                    }
                }
                if entry
                    .attrs
                    .get(&self.topic_attribute)
                    .is_some_and(|patterns| {
                        patterns
                            .iter()
                            .any(|pattern| topics::matches(pattern, topic))
                    })
                {
                    return Ok(true);
                }
            }
            Ok(false)
        })
    }

    // ldap.go: Halt.
    fn halt(&self) -> BoxFuture<'_, ()> {
        Box::pin(async { close(&mut *self.service.lock().await, &self.log, "cleanup").await })
    }
}
