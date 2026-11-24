use std::borrow::Cow;

use ldap3::{Ldap, LdapConnAsync, Scope};
use mqx_auth::external::BoxFuture;
use percent_encoding::percent_decode_str;
use tokio::sync::Mutex;
use url::Url;

use crate::backend::{Backend, BackendResult, GetUser, LoadError, Options};

struct SearchUrl {
    connection: Url,
    base: String,
    scope: Scope,
    subordinate: bool,
    filter: String,
    attrs: Vec<String>,
}

impl SearchUrl {
    // be-ldap.c: be_ldap_init uses ldap_url_parse and reconnects using only
    // the connection part. URL extensions are parsed but never applied.
    fn parse(uri: &str) -> Result<Self, LoadError> {
        let invalid = || LoadError::new("Cannot parse ldap_uri");
        let uri = uri
            .strip_prefix('<')
            .and_then(|s| s.strip_suffix('>'))
            .unwrap_or(uri);
        let uri = uri
            .split_once(':')
            .filter(|(prefix, _)| prefix.eq_ignore_ascii_case("URL"))
            .map_or(uri, |(_, rest)| rest);
        let mut url = Url::parse(uri).map_err(|_| invalid())?;
        match url.scheme() {
            "ldap" | "ldaps" | "ldapi" => (),
            _ => {
                return Err(LoadError::new(
                    "Mandatory option 'ldap_uri' doesn't look like an LDAP URI",
                ));
            }
        }
        if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
            return Err(invalid());
        }
        if url.scheme() != "ldapi" && url.host_str().is_none_or(str::is_empty) {
            url.set_host(Some("localhost")).map_err(|_| invalid())?;
        }
        let decode = |part| {
            percent_decode_str(part)
                .decode_utf8()
                .map(|value| super::c_str(&value).to_owned())
                .map_err(|_| invalid())
        };
        let base = decode(url.path().strip_prefix('/').unwrap_or(url.path()))?;
        let mut query = url.query().unwrap_or_default().split('?');
        let attrs = match query.next().filter(|part| !part.is_empty()) {
            Some(part) => part.split(',').map(decode).collect::<Result<_, _>>()?,
            None => Vec::new(), // Empty attribute sequence requests all user attributes.
        };
        let scope = query.next().unwrap_or_default().to_ascii_lowercase();
        let subordinate = matches!(scope.as_str(), "children" | "subordinate");
        let scope = match scope.as_str() {
            "" | "base" => Scope::Base,
            "one" => Scope::OneLevel,
            "sub" | "children" | "subordinate" => Scope::Subtree,
            _ => return Err(invalid()),
        };
        let filter = decode(
            query
                .next()
                .filter(|part| !part.is_empty())
                .unwrap_or("(objectClass=*)"),
        )?;
        let _extensions = query.next();
        if query.next().is_some() {
            return Err(invalid());
        }
        url.set_query(None);
        url.set_path("");
        Ok(Self {
            connection: url,
            base,
            scope,
            subordinate,
            filter,
            attrs,
        })
    }

    fn filter_for(&self, username: &str) -> Cow<'_, str> {
        // be-ldap.c: be_ldap_getuser replaces every @, with no LDAP escaping.
        let filter = if self.filter.contains('@') {
            Cow::Owned(self.filter.replace('@', super::c_str(username)))
        } else {
            Cow::Borrowed(self.filter.as_str())
        };
        if !self.subordinate {
            return filter;
        }
        // ldap3 exposes only the three RFC scopes. OpenLDAP's subordinate
        // scope is a subtree without its base object; match its normalized
        // DN server-side so escaped and case-folded DNs are handled correctly.
        let dn = ldap3::ldap_escape(&self.base);
        if filter.starts_with('(') {
            Cow::Owned(format!("(&{filter}(!(entryDN={dn})))"))
        } else {
            Cow::Owned(format!("(&({filter})(!(entryDN={dn})))"))
        }
    }
}

struct Directory {
    url: SearchUrl,
    service: Mutex<Ldap>,
    deny: bool,
}

async fn connect(url: &Url) -> ldap3::result::Result<Ldap> {
    let (conn, ldap) = LdapConnAsync::from_url(url).await?;
    tokio::spawn(async move {
        // Driver failures are reported to the pending bind/search operation.
        let _ = conn.drive().await;
    });
    Ok(ldap)
}

pub(crate) async fn create(options: &Options) -> Result<Box<dyn Backend>, LoadError> {
    let uri = options
        .get("ldap_uri")
        .ok_or_else(|| LoadError::new("Mandatory option 'ldap_uri' is missing"))?;
    let url = SearchUrl::parse(uri)?;
    let mut service = connect(&url.connection)
        .await
        .map_err(|_| LoadError::new("Cannot ldap_initialize"))?;
    service
        .simple_bind(
            options.get("binddn").unwrap_or_default(),
            options.get("bindpw").unwrap_or_default(),
        )
        .await
        .and_then(ldap3::LdapResult::success)
        .map_err(|_| LoadError::new("Cannot bind to LDAP"))?;
    let deny = options.get("ldap_acl_deny") == Some("true");
    Ok(Box::new(Directory {
        url,
        service: Mutex::new(service),
        deny,
    }))
}

impl Backend for Directory {
    fn name(&self) -> &'static str {
        "ldap"
    }

    fn getuser<'a>(
        &'a self,
        username: &'a str,
        password: &'a [u8],
        _: &str,
    ) -> BoxFuture<'a, GetUser> {
        Box::pin(async move {
            let filter = self.url.filter_for(username);
            let search = self
                .service
                .lock()
                .await
                .search(&self.url.base, self.url.scope, &filter, &self.url.attrs)
                .await
                .and_then(ldap3::SearchResult::success);
            let Ok((mut entries, _)) = search else {
                // be-ldap.c: be_ldap_getuser aborts the process on search failure.
                // Return a stable error instead of exiting the broker.
                return GetUser::result(BackendResult::Error);
            };
            entries.retain(|entry| !entry.is_ref() && !entry.is_intermediate());
            if entries.len() != 1 {
                return GetUser::result(BackendResult::Defer);
            }
            let dn = entries
                .swap_remove(0)
                .0
                .match_id(4)
                .and_then(|tag| tag.expect_constructed())
                .and_then(|tags| tags.into_iter().next())
                .and_then(|tag| tag.expect_primitive())
                .and_then(|bytes| String::from_utf8(bytes).ok());
            let (Some(dn), Ok(password)) = (dn, std::str::from_utf8(password)) else {
                return GetUser::result(BackendResult::Defer);
            };
            // be-ldap.c: user_bind uses a fresh connection, leaving the
            // service connection bound as the search identity.
            let Ok(mut user) = connect(&self.url.connection).await else {
                return GetUser::result(BackendResult::Defer);
            };
            let bound = user
                .simple_bind(&dn, password)
                .await
                .and_then(ldap3::LdapResult::success)
                .is_ok();
            let _ = user.unbind().await;
            GetUser::result(if bound {
                BackendResult::Allow
            } else {
                BackendResult::Defer
            })
        })
    }

    fn superuser<'a>(&'a self, _: &str) -> BoxFuture<'a, BackendResult> {
        // be-ldap.c: be_ldap_superuser.
        Box::pin(async { BackendResult::Defer })
    }

    fn aclcheck<'a>(&'a self, _: &str, _: &str, _: &str, _: i32) -> BoxFuture<'a, BackendResult> {
        // be-ldap.c: be_ldap_aclcheck denies only when ldap_acl_deny=true.
        Box::pin(async {
            if self.deny {
                BackendResult::Deny
            } else {
                BackendResult::Allow
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_openldap_url_and_expands_all_filter_placeholders() {
        let url = SearchUrl::parse("<URL:LDAPS://[::1]:1636/dc%3Dexample%2Cdc%3Dto?cn,uid?sub?%28%7C%28uid=%40%29%28cn=@%29%29?!ignored>").unwrap();
        assert_eq!(url.connection.as_str(), "ldaps://[::1]:1636");
        assert_eq!(url.base, "dc=example,dc=to");
        assert_eq!(url.attrs, ["cn", "uid"]);
        assert_eq!(url.scope, Scope::Subtree);
        assert_eq!(url.filter_for("u@ser"), "(|(uid=u@ser)(cn=u@ser))");
        let children = SearchUrl::parse("ldap://localhost/dc=test??children?cn=@").unwrap();
        assert_eq!(
            children.filter_for("alice"),
            "(&(cn=alice)(!(entryDN=dc=test)))"
        );
        assert_eq!(
            SearchUrl::parse("ldap:///dc=example").unwrap().scope,
            Scope::Base
        );
        assert_eq!(
            SearchUrl::parse("ldapi://%2Ftmp%2Fsock/dc=example")
                .unwrap()
                .connection
                .as_str(),
            "ldapi://%2Ftmp%2Fsock"
        );
        assert!(SearchUrl::parse("ldap://server/??bogus?(uid=@)").is_err());
        assert!(SearchUrl::parse("https://server").is_err());
    }
}
