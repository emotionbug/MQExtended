//! MQTT topic name / topic filter validation and matching.
//!
//! Every function here is a byte-for-byte port of the corresponding Mosquitto
//! 2.1.4 routine in `libcommon/topic_common.c`, including its quirks, because
//! MQExtended must accept and reject exactly what Mosquitto does for clients
//! that cannot be changed. Inputs are treated like C strings: anything after
//! an embedded NUL byte is ignored, as Mosquitto would never see it.

mod subscription_index;

pub use subscription_index::SubscriptionIndex;

use thiserror::Error;

/// Maximum topic length in bytes (`mosquitto_pub_topic_check`).
pub const MAX_TOPIC_LEN: usize = 65_535;

/// Maximum number of `/` separators in a topic (`TOPIC_HIERARCHY_LIMIT` in
/// Mosquitto's `config.h`).
pub const TOPIC_HIERARCHY_LIMIT: usize = 200;

/// Why a topic name or filter was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum TopicError {
    #[error("topic is empty")]
    Empty,
    #[error("topic is longer than {MAX_TOPIC_LEN} bytes")]
    TooLong,
    #[error("topic has more than {TOPIC_HIERARCHY_LIMIT} levels separators")]
    TooManyLevels,
    #[error("topic name contains a wildcard")]
    WildcardInTopicName,
    #[error("wildcard in an invalid position")]
    InvalidWildcard,
}

/// A filter/topic pair that Mosquitto's matcher reports as `MOSQ_ERR_INVAL`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("invalid topic or subscription for matching")]
pub struct MatchError;

/// Bytes up to (not including) the first NUL, mirroring C string semantics.
fn c_bytes(s: &str) -> &[u8] {
    let b = s.as_bytes();
    match b.iter().position(|&c| c == 0) {
        Some(end) => &b[..end],
        None => b,
    }
}

/// Validates a topic used for PUBLISH (`mosquitto_pub_topic_check`).
pub fn validate_topic_name(topic: &str) -> Result<(), TopicError> {
    let bytes = c_bytes(topic);
    let mut levels = 0usize;
    for &c in bytes {
        match c {
            b'+' | b'#' => return Err(TopicError::WildcardInTopicName),
            b'/' => levels += 1,
            _ => {}
        }
    }
    check_len_and_levels(bytes.len(), levels)
}

/// Validates a topic filter used for SUBSCRIBE or in ACLs
/// (`mosquitto_sub_topic_check`).
pub fn validate_topic_filter(filter: &str) -> Result<(), TopicError> {
    let bytes = c_bytes(filter);
    let at = |i: usize| bytes.get(i).copied().unwrap_or(0);
    let mut prev = 0u8;
    let mut levels = 0usize;
    for (i, &c) in bytes.iter().enumerate() {
        match c {
            b'+' => {
                if (prev != 0 && prev != b'/') || (at(i + 1) != 0 && at(i + 1) != b'/') {
                    return Err(TopicError::InvalidWildcard);
                }
            }
            b'#' => {
                if (prev != 0 && prev != b'/') || at(i + 1) != 0 {
                    return Err(TopicError::InvalidWildcard);
                }
            }
            b'/' => levels += 1,
            _ => {}
        }
        prev = c;
    }
    check_len_and_levels(bytes.len(), levels)
}

fn check_len_and_levels(len: usize, levels: usize) -> Result<(), TopicError> {
    if len == 0 {
        return Err(TopicError::Empty);
    }
    if len > MAX_TOPIC_LEN {
        return Err(TopicError::TooLong);
    }
    if levels > TOPIC_HIERARCHY_LIMIT {
        return Err(TopicError::TooManyLevels);
    }
    Ok(())
}

/// Does `topic` match subscription `filter`? (`mosquitto_topic_matches_sub`).
///
/// Filters starting with `$` only match topics starting with `$` and vice
/// versa, so `#` never matches `$SYS/...`.
pub fn matches(filter: &str, topic: &str) -> Result<bool, MatchError> {
    topic_matches_sub(c_bytes(filter), c_bytes(topic), None, None, false)
}

/// [`matches`] with ACL pattern substitution of whole `%c` (client id) and
/// `%u` (username) levels (`mosquitto_topic_matches_sub_with_pattern`).
/// A pattern level whose substitute is absent or empty never matches.
pub fn matches_with_pattern(
    filter: &str,
    topic: &str,
    client_id: Option<&str>,
    username: Option<&str>,
) -> Result<bool, MatchError> {
    topic_matches_sub(
        c_bytes(filter),
        c_bytes(topic),
        client_id.map(c_bytes),
        username.map(c_bytes),
        true,
    )
}

/// Port of `topic_matches_sub` from `libcommon/topic_common.c`. `si`/`ti`
/// replace the C `sub`/`topic` pointers; reading past the end yields 0 like
/// the C terminator. `last` replaces `lastchar` (index of the previously
/// consumed filter byte).
fn topic_matches_sub(
    sub: &[u8],
    topic: &[u8],
    client_id: Option<&[u8]>,
    username: Option<&[u8]>,
    match_patterns: bool,
) -> Result<bool, MatchError> {
    let s = |i: usize| sub.get(i).copied().unwrap_or(0);
    let t = |i: usize| topic.get(i).copied().unwrap_or(0);

    if sub.is_empty() || topic.is_empty() {
        return Err(MatchError);
    }
    if (s(0) == b'$' && t(0) != b'$') || (t(0) == b'$' && s(0) != b'$') {
        return Ok(false);
    }

    let mut si = 0usize;
    let mut ti = 0usize;
    let mut last: Option<usize> = None;

    while s(si) != 0 {
        if t(ti) == b'+' || t(ti) == b'#' {
            return Err(MatchError);
        }
        if match_patterns
            && last.is_none_or(|l| s(l) == b'/')
            && s(si) == b'%'
            && (s(si + 1) == b'c' || s(si + 1) == b'u')
            && (s(si + 2) == b'/' || s(si + 2) == 0)
        {
            let substitute = if s(si + 1) == b'c' {
                client_id
            } else {
                username
            };
            let substitute = match substitute {
                Some(p) if !p.is_empty() => p,
                _ => return Ok(false),
            };
            si += 2;
            let mut pi = 0usize;
            while pi < substitute.len() && t(ti) != 0 && t(ti) != b'/' {
                if substitute[pi] != t(ti) {
                    return Ok(false);
                }
                pi += 1;
                ti += 1;
            }
            if pi < substitute.len() {
                // Substituted level is longer than the topic level.
                return Ok(false);
            }
            if (s(si) == 0 && t(ti) == 0)
                || (s(si) == b'/' && s(si + 1) == b'#' && s(si + 2) == 0 && t(ti) == 0)
            {
                return Ok(true);
            }
        }
        if s(si) != t(ti) || t(ti) == 0 {
            match s(si) {
                b'+' => {
                    // "+foo" / "a/+foo" and "foo+" / "foo+/a" are invalid.
                    if si > 0 && s(si - 1) != b'/' {
                        return Err(MatchError);
                    }
                    if s(si + 1) != 0 && s(si + 1) != b'/' {
                        return Err(MatchError);
                    }
                    si += 1;
                    while t(ti) != 0 && t(ti) != b'/' {
                        if t(ti) == b'+' || t(ti) == b'#' {
                            return Err(MatchError);
                        }
                        ti += 1;
                    }
                    if t(ti) == 0 && s(si) == 0 {
                        return Ok(true);
                    }
                }
                b'#' => {
                    if si > 0 && s(si - 1) != b'/' {
                        return Err(MatchError);
                    }
                    if s(si + 1) != 0 {
                        return Err(MatchError);
                    }
                    while t(ti) != 0 {
                        if t(ti) == b'+' || t(ti) == b'#' {
                            return Err(MatchError);
                        }
                        ti += 1;
                    }
                    return Ok(true);
                }
                _ => {
                    // "foo/bar" matching "foo/+/#".
                    if t(ti) == 0
                        && si > 0
                        && s(si - 1) == b'+'
                        && s(si) == b'/'
                        && s(si + 1) == b'#'
                    {
                        return Ok(true);
                    }
                    // No match; still report an invalid filter as such.
                    while s(si) != 0 {
                        if s(si) == b'#' && s(si + 1) != 0 {
                            return Err(MatchError);
                        }
                        si += 1;
                    }
                    return Ok(false);
                }
            }
        } else {
            // "foo" matching "foo/#".
            if t(ti + 1) == 0 && s(si + 1) == b'/' && s(si + 2) == b'#' && s(si + 3) == 0 {
                return Ok(true);
            }
            si += 1;
            ti += 1;
            if s(si) == 0 && t(ti) == 0 {
                return Ok(true);
            } else if t(ti) == 0 && s(si) == b'+' && s(si + 1) == 0 {
                if si > 0 && s(si - 1) != b'/' {
                    return Err(MatchError);
                }
                return Ok(true);
            }
        }
        last = Some(si - 1);
    }
    while t(ti) != 0 {
        if t(ti) == b'+' || t(ti) == b'#' {
            return Err(MatchError);
        }
        ti += 1;
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn topic_name_rules() {
        assert_eq!(validate_topic_name("a/b/c"), Ok(()));
        assert_eq!(validate_topic_name("/"), Ok(()));
        assert_eq!(validate_topic_name(""), Err(TopicError::Empty));
        assert_eq!(
            validate_topic_name("a/+"),
            Err(TopicError::WildcardInTopicName)
        );
        assert_eq!(
            validate_topic_name("a#"),
            Err(TopicError::WildcardInTopicName)
        );
        assert_eq!(validate_topic_name(&"a".repeat(65_535)), Ok(()));
        assert_eq!(
            validate_topic_name(&"a".repeat(65_536)),
            Err(TopicError::TooLong)
        );
        assert_eq!(validate_topic_name(&"/".repeat(200)), Ok(()));
        assert_eq!(
            validate_topic_name(&"/".repeat(201)),
            Err(TopicError::TooManyLevels)
        );
        // C string semantics: an embedded NUL ends the topic.
        assert_eq!(validate_topic_name("a\0+"), Ok(()));
        assert_eq!(validate_topic_name("\0a"), Err(TopicError::Empty));
    }

    #[test]
    fn topic_filter_rules() {
        for ok in [
            "#", "+", "a/#", "a/+/b", "+/+", "/#", "a//b", "$SYS/#", "+/",
        ] {
            assert_eq!(validate_topic_filter(ok), Ok(()), "{ok}");
        }
        for bad in ["a#", "a/#/b", "#/", "a+", "+a", "a/+b", "a/b+", "##"] {
            assert_eq!(
                validate_topic_filter(bad),
                Err(TopicError::InvalidWildcard),
                "{bad}"
            );
        }
        assert_eq!(validate_topic_filter(""), Err(TopicError::Empty));
    }

    #[test]
    fn pattern_substitution() {
        let cid = Some("client1");
        let user = Some("alice");
        assert_eq!(
            matches_with_pattern("%c/data", "client1/data", cid, user),
            Ok(true)
        );
        assert_eq!(
            matches_with_pattern("%u/#", "alice/a/b", cid, user),
            Ok(true)
        );
        assert_eq!(matches_with_pattern("%u/#", "alice", cid, user), Ok(true));
        assert_eq!(matches_with_pattern("a/%u", "a/alice", cid, user), Ok(true));
        assert_eq!(
            matches_with_pattern("a/%u/+", "a/alice/x", cid, user),
            Ok(true)
        );
        assert_eq!(
            matches_with_pattern("%c/data", "client2/data", cid, user),
            Ok(false)
        );
        assert_eq!(
            matches_with_pattern("%c/data", "client/data", cid, user),
            Ok(false)
        );
        assert_eq!(
            matches_with_pattern("%c/data", "client11/data", cid, user),
            Ok(false)
        );
        assert_eq!(
            matches_with_pattern("%u/x", "alice/x", cid, None),
            Ok(false)
        );
        assert_eq!(matches_with_pattern("%u/x", "/x", cid, Some("")), Ok(false));
        // Only whole levels are substituted.
        assert_eq!(
            matches_with_pattern("a%u/x", "aalice/x", cid, user),
            Ok(false)
        );
        assert_eq!(matches_with_pattern("a%u/x", "a%u/x", cid, user), Ok(true));
        // Without pattern matching %c is literal.
        assert_eq!(matches("%c/data", "%c/data"), Ok(true));
        assert_eq!(matches("%c/data", "client1/data"), Ok(false));
    }

    mod props {
        use super::super::*;
        use proptest::prelude::*;

        fn literal_level() -> impl Strategy<Value = String> {
            prop_oneof![Just(String::new()), "[a-c$%]{1,3}"]
        }

        fn topic_name() -> impl Strategy<Value = String> {
            prop::collection::vec(literal_level(), 1..5)
                .prop_map(|v| v.join("/"))
                .prop_filter("topic names are non-empty", |s| !s.is_empty())
        }

        fn topic_filter() -> impl Strategy<Value = String> {
            let level = prop_oneof![3 => literal_level(), 1 => Just("+".to_string())];
            (prop::collection::vec(level, 1..5), any::<bool>())
                .prop_map(|(mut v, hash)| {
                    if hash {
                        v.push("#".to_string());
                    }
                    v.join("/")
                })
                .prop_filter("topic filters are non-empty", |s| !s.is_empty())
        }

        /// Straightforward level-based reference matcher, valid for inputs that
        /// both validators accept.
        fn reference(filter: &str, topic: &str) -> bool {
            if filter.starts_with('$') != topic.starts_with('$') {
                return false;
            }
            let f: Vec<&str> = filter.split('/').collect();
            let t: Vec<&str> = topic.split('/').collect();
            let mut i = 0;
            loop {
                match (f.get(i), t.get(i)) {
                    (Some(&"#"), _) => return true,
                    (Some(&"+"), Some(_)) => {}
                    (Some(a), Some(b)) if a == b => {}
                    (None, None) => return true,
                    _ => return false,
                }
                i += 1;
            }
        }

        proptest! {
            #[test]
            fn agrees_with_reference_on_valid_input(filter in topic_filter(), topic in topic_name()) {
                prop_assert_eq!(validate_topic_filter(&filter), Ok(()));
                prop_assert_eq!(validate_topic_name(&topic), Ok(()));
                prop_assert_eq!(matches(&filter, &topic), Ok(reference(&filter, &topic)));
            }

            #[test]
            fn never_panics(filter in ".{0,12}", topic in ".{0,12}", c in ".{0,4}", u in ".{0,4}") {
                let _ = matches(&filter, &topic);
                let _ = matches_with_pattern(&filter, &topic, Some(&c), Some(&u));
                let _ = validate_topic_filter(&filter);
                let _ = validate_topic_name(&topic);
            }
        }
    }
}
