use mqx_topic::MatchError;

use crate::Access;

use super::{AclType, DynamicSecurity, Membership};

impl DynamicSecurity {
    /// `acl.c: acl_check`, `dynsec__acl_check_callback`: direct roles first,
    /// then groups, then defaults. Only an explicit ACL can grant $CONTROL.
    pub fn authorize(
        &self,
        client_id: &str,
        username: Option<&str>,
        topic: &str,
        access: Access,
    ) -> Option<bool> {
        let check =
            |roles: &[Membership]| self.check_roles(roles, client_id, username, topic, access);
        let specific = if let Some(username) = username {
            let client = self.clients.get(username)?;
            check(&client.roles).or_else(|| {
                client.groups.iter().find_map(|membership| {
                    self.groups
                        .get(&membership.name)
                        .and_then(|group| check(&group.roles))
                })
            })
        } else {
            self.anonymous_group
                .as_ref()
                .and_then(|name| self.groups.get(name))
                .and_then(|group| check(&group.roles))
        };
        let index = match access {
            Access::Write => 0,
            Access::Read => 1,
            Access::Subscribe => 2,
            Access::Unsubscribe => 3,
        };
        specific
            .or_else(|| (self.defaults[index] && !topic.starts_with("$CONTROL")).then_some(true))
    }

    // acl.c: literal subscription entries beat patterns within the same role,
    // and allow_wildcard_subs is tested before either kind of entry.
    fn check_roles(
        &self,
        roles: &[Membership],
        client_id: &str,
        username: Option<&str>,
        topic: &str,
        access: Access,
    ) -> Option<bool> {
        let (literal, pattern) = match access {
            Access::Read => (None, AclType::Receive),
            Access::Write => (None, AclType::Send),
            Access::Subscribe => (Some(AclType::SubLiteral), AclType::SubPattern),
            Access::Unsubscribe => (Some(AclType::UnsubLiteral), AclType::UnsubPattern),
        };
        for role in roles
            .iter()
            .filter_map(|membership| self.roles.get(&membership.name))
        {
            if access == Access::Subscribe && !role.allow_wildcards && topic.contains(['+', '#']) {
                return Some(false);
            }
            if let Some(kind) = literal
                && let Some(acl) = role
                    .acls
                    .iter()
                    .find(|entry| entry.kind == kind && entry.topic == topic)
            {
                return Some(acl.allow);
            }
            let begin = role.acls.partition_point(|acl| acl.kind < pattern);
            for acl in role.acls[begin..]
                .iter()
                .take_while(|acl| acl.kind == pattern)
            {
                let matched = if literal.is_some() {
                    sub_matches_acl(&acl.topic, topic, client_id, username)
                } else {
                    mqx_topic::matches_with_pattern(&acl.topic, topic, Some(client_id), username)
                };
                match matched {
                    Ok(true) => return Some(acl.allow),
                    Ok(false) => (),
                    Err(_) => return Some(false),
                }
            }
        }
        None
    }
}

// libcommon/topic_common.c: sub_matches_acl. Unlike the publish matcher, the
// second argument may contain + or #, but the ACL's + cannot cover its #.
fn sub_matches_acl(
    acl: &str,
    sub: &str,
    client_id: &str,
    username: Option<&str>,
) -> Result<bool, MatchError> {
    let acl = acl.as_bytes();
    let sub = sub.as_bytes();
    if acl.is_empty() || sub.is_empty() {
        return Err(MatchError);
    }
    if (acl[0] == b'$') != (sub[0] == b'$') {
        return Ok(false);
    }
    let a = |i: usize| acl.get(i).copied().unwrap_or(0);
    let s = |i: usize| sub.get(i).copied().unwrap_or(0);
    let (mut ai, mut si) = (0, 0);
    while a(ai) != 0 {
        if (ai == 0 || a(ai - 1) == b'/')
            && a(ai) == b'%'
            && matches!(a(ai + 1), b'c' | b'u')
            && matches!(a(ai + 2), b'/' | 0)
        {
            let name = if a(ai + 1) == b'c' {
                Some(client_id)
            } else {
                username
            };
            let Some(name) = name.filter(|&name| !matches!(name, "" | "+" | "#" | "/")) else {
                return Ok(false);
            };
            for byte in name.bytes() {
                if matches!(s(si), 0 | b'/') || s(si) != byte {
                    return Ok(false);
                }
                si += 1;
            }
            ai += 2;
            if s(si) == 0 && (a(ai) == 0 || acl.get(ai..) == Some(b"/#")) {
                return Ok(true);
            }
        }
        if a(ai) != s(si) || s(si) == 0 {
            match a(ai) {
                b'+' => {
                    if s(si) == b'#' {
                        return Ok(false);
                    }
                    if (ai > 0 && a(ai - 1) != b'/') || !matches!(a(ai + 1), 0 | b'/') {
                        return Err(MatchError);
                    }
                    ai += 1;
                    while !matches!(s(si), 0 | b'/') {
                        si += 1;
                    }
                    if s(si) == 0 && a(ai) == 0 {
                        return Ok(true);
                    }
                }
                b'#' => {
                    if (ai > 0 && a(ai - 1) != b'/') || a(ai + 1) != 0 {
                        return Err(MatchError);
                    }
                    return Ok(true);
                }
                _ => {
                    if s(si) == 0
                        && ai > 0
                        && a(ai - 1) == b'+'
                        && a(ai) == b'/'
                        && a(ai + 1) == b'#'
                    {
                        return Ok(true);
                    }
                    if acl[ai..]
                        .iter()
                        .position(|&byte| byte == b'#')
                        .is_some_and(|offset| ai + offset + 1 < acl.len())
                    {
                        return Err(MatchError);
                    }
                    return Ok(false);
                }
            }
        } else {
            if s(si + 1) == 0 && acl.get(ai + 1..) == Some(b"/#") {
                return Ok(true);
            }
            ai += 1;
            si += 1;
            if a(ai) == 0 && s(si) == 0 {
                return Ok(true);
            }
            if s(si) == 0 && acl.get(ai..) == Some(b"+") {
                return if a(ai - 1) == b'/' {
                    Ok(true)
                } else {
                    Err(MatchError)
                };
            }
        }
    }
    Ok(s(si) == 0)
}
