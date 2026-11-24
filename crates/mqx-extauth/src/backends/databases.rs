//! Database and directory back-ends: sqlite, postgres, mysql, ldap, mongo.

use std::borrow::Cow;

use crate::backend::{Backend, LoadError, Options};

#[path = "ldap.rs"]
mod ldap;
#[path = "mongo.rs"]
mod mongo;
#[path = "mysql.rs"]
mod mysql;
#[path = "postgres.rs"]
mod postgres;
#[path = "sqlite.rs"]
mod sqlite;

/// Create the named back-end, or `None` if `name` is not one of these.
pub(crate) async fn create(
    name: &str,
    options: &Options,
) -> Option<Result<Box<dyn Backend>, LoadError>> {
    Some(match name {
        "sqlite" => sqlite::create(options).await,
        "postgres" => postgres::create(options).await,
        "mysql" => mysql::create(options).await,
        "ldap" => ldap::create(options).await,
        "mongo" => mongo::create(options).await,
        _ => return None,
    })
}

fn c_str(value: &str) -> &str {
    value.split_once('\0').map_or(value, |(prefix, _)| prefix)
}

// backends.c: t_expand replaces substrings, not just whole topic levels,
// and leaves unknown escapes (including %% and a trailing %) intact.
fn expand<'a>(filter: &'a str, client_id: &str, username: &str) -> Cow<'a, str> {
    let filter = c_str(filter);
    let mut tokens = filter.match_indices('%').filter_map(|(index, _)| {
        Some((
            index,
            match filter.as_bytes().get(index + 1) {
                Some(b'c') => c_str(client_id),
                Some(b'u') => c_str(username),
                _ => return None,
            },
        ))
    });
    let Some((index, replacement)) = tokens.next() else {
        return Cow::Borrowed(filter);
    };
    let mut output = String::with_capacity(filter.len() + replacement.len().saturating_sub(2));
    output.push_str(&filter[..index]);
    output.push_str(replacement);
    let mut start = index + 2;
    for (index, replacement) in tokens {
        output.push_str(&filter[start..index]);
        output.push_str(replacement);
        start = index + 2;
    }
    output.push_str(&filter[start..]);
    Cow::Owned(output)
}

fn matches(filter: &str, topic: &str, client_id: &str, username: &str) -> bool {
    mqx_topic::matches(&expand(filter, client_id, username), topic).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expansion_preserves_unknown_escapes_and_does_not_expand_replacement_text() {
        assert_eq!(
            expand("前/%c%u/%%u/%x/%", "id%u", "user"),
            "前/id%uuser/%user/%x/%"
        );
        assert_eq!(expand("prefix%u\0ignored", "id", "user"), "prefixuser");
        assert!(matches("pre%u/%c/#", "prealice/id/data", "id", "alice"));
        assert!(!matches("#", "$SYS/data", "id", "alice"));
    }
}
