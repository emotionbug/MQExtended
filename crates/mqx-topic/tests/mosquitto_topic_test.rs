//! Parity cases extracted from Mosquitto v2.1.4 `test/unit/libcommon/topic_test.c`
//! (EPL-2.0 OR BSD-3-Clause) by `scripts/extract_mosquitto_topic_tests.py`.
//! Do not edit by hand; regenerate from the Mosquitto source.

use mqx_topic::{
    MatchError, matches, matches_with_pattern, validate_topic_filter, validate_topic_name,
};

type MatchCase = (&'static str, &'static str, Result<bool, MatchError>);
type PatternCase = (
    &'static str,
    &'static str,
    Option<&'static str>,
    Option<&'static str>,
    Result<bool, MatchError>,
);

#[rustfmt::skip]
const MATCH: &[MatchCase] = &[
    ("foo/#", "foo/", Ok(true)),
    ("foo/#", "foo", Ok(true)),
    ("foo//bar", "foo//bar", Ok(true)),
    ("foo//+", "foo//bar", Ok(true)),
    ("foo/+/+/baz", "foo///baz", Ok(true)),
    ("foo/bar/+", "foo/bar/", Ok(true)),
    ("foo/bar", "foo/bar", Ok(true)),
    ("foo/+", "foo/bar", Ok(true)),
    ("foo/+/baz", "foo/bar/baz", Ok(true)),
    ("A/B/+/#", "A/B/B/C", Ok(true)),
    ("foo/+/#", "foo/bar/baz", Ok(true)),
    ("foo/+/#", "foo/bar", Ok(true)),
    ("#", "foo/bar/baz", Ok(true)),
    ("#", "foo/bar/baz", Ok(true)),
    ("#", "/foo/bar", Ok(true)),
    ("/#", "/foo/bar", Ok(true)),
    ("+foo", "+foo", Err(MatchError)),
    ("fo+o", "fo+o", Err(MatchError)),
    ("foo+", "foo+", Err(MatchError)),
    ("+foo/bar", "+foo/bar", Err(MatchError)),
    ("foo+/bar", "foo+/bar", Err(MatchError)),
    ("foo/+bar", "foo/+bar", Err(MatchError)),
    ("foo/bar+", "foo/bar+", Err(MatchError)),
    ("+foo", "afoo", Err(MatchError)),
    ("fo+o", "foao", Err(MatchError)),
    ("foo+", "fooa", Err(MatchError)),
    ("+foo/bar", "afoo/bar", Err(MatchError)),
    ("foo+/bar", "fooa/bar", Err(MatchError)),
    ("foo/+bar", "foo/abar", Err(MatchError)),
    ("foo/bar+", "foo/bara", Err(MatchError)),
    ("#foo", "#foo", Err(MatchError)),
    ("fo#o", "fo#o", Err(MatchError)),
    ("foo#", "foo#", Err(MatchError)),
    ("#foo/bar", "#foo/bar", Err(MatchError)),
    ("foo#/bar", "foo#/bar", Err(MatchError)),
    ("foo/#bar", "foo/#bar", Err(MatchError)),
    ("foo/bar#", "foo/bar#", Err(MatchError)),
    ("foo+", "fooa", Err(MatchError)),
    ("foo/+", "foo/+", Err(MatchError)),
    ("foo/#", "foo/+", Err(MatchError)),
    ("foo/+", "foo/bar/+", Err(MatchError)),
    ("foo/#", "foo/bar/+", Err(MatchError)),
    ("foo/+", "foo/#", Err(MatchError)),
    ("foo/#", "foo/#", Err(MatchError)),
    ("foo/+", "foo/bar/#", Err(MatchError)),
    ("foo/#", "foo/bar/#", Err(MatchError)),
    ("test/6/#", "test/3", Ok(false)),
    ("foo/bar", "foo", Ok(false)),
    ("foo/+", "foo/bar/baz", Ok(false)),
    ("foo/+/baz", "foo/bar/bar", Ok(false)),
    ("foo/+/#", "fo2/bar/baz", Ok(false)),
    ("/#", "foo/bar", Ok(false)),
    ("#", "$SYS/bar", Ok(false)),
    ("$BOB/bar", "$SYS/bar", Ok(false)),
    ("foo#", "foo", Err(MatchError)),
    ("fo#o/", "foo", Err(MatchError)),
    ("foo#", "fooa", Err(MatchError)),
    ("foo+", "foo", Err(MatchError)),
    ("foo/#a", "foo", Err(MatchError)),
    ("#a", "foo", Err(MatchError)),
    ("foo/#abc", "foo", Err(MatchError)),
    ("#abc", "foo", Err(MatchError)),
    ("/#a", "foo/bar", Err(MatchError)),
];

#[rustfmt::skip]
const PATTERN: &[PatternCase] = &[
    ("sub", "", Some(""), Some(""), Err(MatchError)),
    ("", "topic", Some(""), Some(""), Err(MatchError)),
    ("", "", Some("clientid"), Some(""), Err(MatchError)),
    ("", "", Some(""), Some("username"), Err(MatchError)),
    ("%c", "topic", None, None, Ok(false)),
    ("%u", "topic", None, None, Ok(false)),
    ("%c", "", Some(""), None, Err(MatchError)),
    ("%u", "", None, Some(""), Err(MatchError)),
    ("test/%c/test", "test//test", Some(""), None, Ok(false)),
    ("test/%u/test", "test//test", None, Some(""), Ok(false)),
    ("%c", "clientid", Some("clientid"), None, Ok(true)),
    ("%c", "clientid", Some("nomatch"), None, Ok(false)),
    ("%c/test", "clientid/test", Some("clientid"), None, Ok(true)),
    ("%c/test", "clientid/test", Some("nomatch"), None, Ok(false)),
    ("test/%c", "test/clientid", Some("clientid"), None, Ok(true)),
    ("test/%c", "test/clientid", Some("nomatch"), None, Ok(false)),
    ("test/%c/test", "test/clientid/test", Some("clientid"), None, Ok(true)),
    ("test/%c/test", "test/clientid/test", Some("nomatch"), None, Ok(false)),
    ("test/%c/%c/test", "test/clientid/clientid/test", Some("clientid"), None, Ok(true)),
    ("test/%c/%c/test", "test/clientid/clientid/test", Some("nomatch"), None, Ok(false)),
    ("test/%count", "test/clientid", Some("clientid"), None, Ok(false)),
    ("%u", "username", None, Some("username"), Ok(true)),
    ("%u", "username", None, Some("nomatch"), Ok(false)),
    ("%u/test", "username/test", None, Some("username"), Ok(true)),
    ("%u/test", "username/test", None, Some("nomatch"), Ok(false)),
    ("test/%u", "test/username", None, Some("username"), Ok(true)),
    ("test/%u", "test/username", None, Some("nomatch"), Ok(false)),
    ("test/%u/test", "test/username/test", None, Some("username"), Ok(true)),
    ("test/%u/test", "test/username/test", None, Some("nomatch"), Ok(false)),
    ("test/%u/%u/test", "test/username/username/test", None, Some("username"), Ok(true)),
    ("test/%u/%u/test", "test/username/username/test", None, Some("nomatch"), Ok(false)),
    ("test/%username", "test/username", None, Some("username"), Ok(false)),
    ("%u/%c", "username/clientid", Some("clientid"), Some("username"), Ok(true)),
    ("%u/%c", "username/clientid", Some("clientid"), Some("nomatch"), Ok(false)),
    ("%u/%c", "username/clientid", Some("nomatch"), Some("username"), Ok(false)),
    ("%u/%c", "username/clientid", Some("nomatch"), Some("nomatch"), Ok(false)),
    ("test/%c/%u/test", "test/clientid/username/test", Some("clientid"), Some("username"), Ok(true)),
    ("test/%c/%u/test", "test/clientid/username/test", Some("clientid"), Some("nomatch"), Ok(false)),
    ("test/%c/%u/test", "test/clientid/username/test", Some("nomatch"), Some("username"), Ok(false)),
    ("test/%c/%u/test", "test/clientid/username/test", Some("nomatch"), Some("nomatch"), Ok(false)),
    ("test/%u/%c/%c/%u/test", "test/username/clientid/clientid/username/test", Some("clientid"), Some("username"), Ok(true)),
    ("test/%username/%client", "test/username/clientid", Some("clientid"), Some("username"), Ok(false)),
    ("test/a%u/a%c", "test/ausername/aclientid", Some("clientid"), Some("username"), Ok(false)),
    ("%c", "clientid/test", Some("clientid/test"), None, Ok(false)),
    ("%u", "username/test", None, Some("username/test"), Ok(false)),
    ("%c", "clientid", Some("+"), None, Ok(false)),
    ("username/%u/+", "username/test/+", None, Some("+"), Ok(false)),
    ("clientid/%c/+", "clientid/test/topic", Some("test"), None, Ok(true)),
    ("clientid/%c/+", "clientid/test/topic", Some("nomatch"), None, Ok(false)),
    ("username/%u/+", "username/test/topic", None, Some("test"), Ok(true)),
    ("username/%u/+", "username/test/topic", None, Some("nomatch"), Ok(false)),
    ("clientid/%c/#", "clientid/test/topic", Some("test"), None, Ok(true)),
    ("clientid/%c/#", "clientid/test/topic", Some("nomatch"), None, Ok(false)),
    ("username/%u/#", "username/test/topic", None, Some("test"), Ok(true)),
    ("username/%u/#", "username/test/topic", None, Some("nomatch"), Ok(false)),
    ("clientid/%c/#", "clientid/test", Some("test"), None, Ok(true)),
    ("clientid/%c/#", "clientid/test", Some("nomatch"), None, Ok(false)),
    ("pattern/%u/#", "pattern/username", None, Some("username"), Ok(true)),
    ("username/%u/#", "username/test", None, Some("nomatch"), Ok(false)),
    ("%c/#", "g/test", Some("guest"), None, Ok(false)),
    ("%c/#", "gu/test", Some("guest"), None, Ok(false)),
    ("%c/#", "gue/test", Some("guest"), None, Ok(false)),
    ("%c/#", "gues/test", Some("guest"), None, Ok(false)),
    ("%c/#", "guest/test", Some("guest"), None, Ok(true)),
    ("%c/#", "guestt/test", Some("guest"), None, Ok(false)),
    ("%c/#", "geest/test", Some("guest"), None, Ok(false)),
    ("%u/#", "g/test", None, Some("guest"), Ok(false)),
    ("%u/#", "gu/test", None, Some("guest"), Ok(false)),
    ("%u/#", "gue/test", None, Some("guest"), Ok(false)),
    ("%u/#", "gues/test", None, Some("guest"), Ok(false)),
    ("%u/#", "guest/test", None, Some("guest"), Ok(true)),
    ("%u/#", "guestt/test", None, Some("guest"), Ok(false)),
    ("%u/#", "geest/test", None, Some("guest"), Ok(false)),
    ("clients/%c/#", "clients/g/test", Some("guest"), None, Ok(false)),
    ("clients/%c/#", "clients/gu/test", Some("guest"), None, Ok(false)),
    ("clients/%c/#", "clients/gue/test", Some("guest"), None, Ok(false)),
    ("clients/%c/#", "clients/gues/test", Some("guest"), None, Ok(false)),
    ("clients/%c/#", "clients/guest/test", Some("guest"), None, Ok(true)),
    ("clients/%c/#", "clients/guestt/test", Some("guest"), None, Ok(false)),
    ("clients/%c/#", "clients/geest/test", Some("guest"), None, Ok(false)),
    ("clients/%u/#", "clients/g/test", None, Some("guest"), Ok(false)),
    ("clients/%u/#", "clients/gu/test", None, Some("guest"), Ok(false)),
    ("clients/%u/#", "clients/gue/test", None, Some("guest"), Ok(false)),
    ("clients/%u/#", "clients/gues/test", None, Some("guest"), Ok(false)),
    ("clients/%u/#", "clients/guest/test", None, Some("guest"), Ok(true)),
    ("clients/%u/#", "clients/guestt/test", None, Some("guest"), Ok(false)),
    ("clients/%u/#", "clients/geest/test", None, Some("guest"), Ok(false)),
    ("clients/%c", "clients/g", Some("guest"), None, Ok(false)),
    ("clients/%c", "clients/gu", Some("guest"), None, Ok(false)),
    ("clients/%c", "clients/gue", Some("guest"), None, Ok(false)),
    ("clients/%c", "clients/gues", Some("guest"), None, Ok(false)),
    ("clients/%c", "clients/guest", Some("guest"), None, Ok(true)),
    ("clients/%c", "clients/guestt", Some("guest"), None, Ok(false)),
    ("clients/%c", "clients/geest", Some("guest"), None, Ok(false)),
    ("clients/%u", "clients/g", None, Some("guest"), Ok(false)),
    ("clients/%u", "clients/gu", None, Some("guest"), Ok(false)),
    ("clients/%u", "clients/gue", None, Some("guest"), Ok(false)),
    ("clients/%u", "clients/gues", None, Some("guest"), Ok(false)),
    ("clients/%u", "clients/guest", None, Some("guest"), Ok(true)),
    ("clients/%u", "clients/guestt", None, Some("guest"), Ok(false)),
    ("clients/%u", "clients/geest", None, Some("guest"), Ok(false)),
    ("%c", "g", Some("guest"), None, Ok(false)),
    ("%c", "gu", Some("guest"), None, Ok(false)),
    ("%c", "gue", Some("guest"), None, Ok(false)),
    ("%c", "gues", Some("guest"), None, Ok(false)),
    ("%c", "guest", Some("guest"), None, Ok(true)),
    ("%c", "guestt", Some("guest"), None, Ok(false)),
    ("%c", "geest", Some("guest"), None, Ok(false)),
    ("%u", "g", None, Some("guest"), Ok(false)),
    ("%u", "gu", None, Some("guest"), Ok(false)),
    ("%u", "gue", None, Some("guest"), Ok(false)),
    ("%u", "gues", None, Some("guest"), Ok(false)),
    ("%u", "guest", None, Some("guest"), Ok(true)),
    ("%u", "guestt", None, Some("guest"), Ok(false)),
    ("%u", "geest", None, Some("guest"), Ok(false)),
];

#[rustfmt::skip]
const PUB_TOPIC: &[(&str, bool)] = &[
    ("pub/topic", true),
    ("pub//topic", true),
    ("pub/ /topic", true),
    ("+pub/topic", false),
    ("pub+/topic", false),
    ("pub/+topic", false),
    ("pub/topic+", false),
    ("pub/topic/+", false),
    ("#pub/topic", false),
    ("pub#/topic", false),
    ("pub/#topic", false),
    ("pub/topic#", false),
    ("pub/topic/#", false),
    ("+/pub/topic", false),
    ("//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////a", false),
];

#[rustfmt::skip]
const SUB_TOPIC: &[(&str, bool)] = &[
    ("sub/topic", true),
    ("sub//topic", true),
    ("sub/ /topic", true),
    ("sub/+/topic", true),
    ("+/+/+", true),
    ("+", true),
    ("sub/topic/#", true),
    ("sub//topic/#", true),
    ("sub/ /topic/#", true),
    ("sub/+/topic/#", true),
    ("+/+/+/#", true),
    ("#", true),
    ("+sub/topic", false),
    ("sub+/topic", false),
    ("sub/+topic", false),
    ("sub/topic+", false),
    ("#sub/topic", false),
    ("sub#/topic", false),
    ("sub/#topic", false),
    ("sub/topic#", false),
    ("#/sub/topic", false),
    ("//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////a", false),
];

#[test]
fn topic_matches_sub() {
    for (filter, topic, expected) in MATCH {
        assert_eq!(
            matches(filter, topic),
            *expected,
            "filter {filter:?} topic {topic:?}"
        );
    }
}

#[test]
fn topic_matches_sub_with_pattern() {
    for (filter, topic, client_id, username, expected) in PATTERN {
        assert_eq!(
            matches_with_pattern(filter, topic, *client_id, *username),
            *expected,
            "filter {filter:?} topic {topic:?} client_id {client_id:?} username {username:?}"
        );
    }
}

#[test]
fn pub_topic_check() {
    for (topic, valid) in PUB_TOPIC {
        assert_eq!(validate_topic_name(topic).is_ok(), *valid, "{topic:?}");
    }
}

#[test]
fn sub_topic_check() {
    for (topic, valid) in SUB_TOPIC {
        assert_eq!(validate_topic_filter(topic).is_ok(), *valid, "{topic:?}");
    }
}
