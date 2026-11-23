//! Mosquitto `acl_file` support.
//!
//! Parsing mirrors `plugins/acl-file/acl_parse.c` and checking mirrors
//! `plugins/acl-file/acl_check.c` from Mosquitto 2.1.4.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use mqx_topic::{matches, matches_with_pattern, validate_topic_filter};
use thiserror::Error;

use crate::ctext::{Fgets, Strtok, trim_blanks, trim_end};

const ACL_READ: u8 = 0x01;
const ACL_WRITE: u8 = 0x02;
/// `MOSQ_ACL_NONE`, written as `deny` in the file.
const ACL_DENY: u8 = 0x00;

/// The operation being authorised.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// A message is about to be delivered to a subscriber.
    Read,
    /// A client published a message (also checked for will messages).
    Write,
    /// A SUBSCRIBE request. Mosquitto's acl_file always allows it and enforces
    /// `read` access per delivered message instead.
    Subscribe,
    /// An UNSUBSCRIBE request; always allowed, like Mosquitto.
    Unsubscribe,
}

#[derive(Debug, Clone)]
struct Entry {
    topic: String,
    access: u8,
}

#[derive(Debug, Clone)]
struct PatternEntry {
    topic: String,
    access: u8,
    /// Number of `%u` occurrences (`ucount`); such patterns are skipped for
    /// clients without a username.
    username_refs: usize,
}

/// Non-fatal findings Mosquitto logs as warnings while loading.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AclWarning {
    /// A `pattern` line without `%c` or `%u`.
    PatternWithoutSubstitution { line: usize, topic: String },
}

/// Why an ACL file was rejected (Mosquitto refuses to start).
#[derive(Debug, Error)]
pub enum AclFileError {
    #[error("unable to open acl_file {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("line {line}: empty topic")]
    EmptyTopic { line: usize },
    #[error("line {line}: invalid topic access type")]
    InvalidAccess { line: usize },
    #[error("line {line}: invalid ACL topic")]
    InvalidTopic { line: usize },
    #[error("line {line}: missing username")]
    MissingUsername { line: usize },
    #[error("line {line}: invalid line")]
    InvalidLine { line: usize },
}

/// A loaded Mosquitto ACL file.
#[derive(Debug, Clone, Default)]
pub struct AclFile {
    /// Topic lines before the first `user` line; they apply to clients
    /// without a username only.
    anonymous: Vec<Entry>,
    /// Keyed by raw bytes: Mosquitto does not require the file to be UTF-8.
    users: HashMap<Vec<u8>, Vec<Entry>>,
    patterns: Vec<PatternEntry>,
    warnings: Vec<AclWarning>,
}

impl AclFile {
    /// Reads and parses `path`.
    pub fn load(path: &Path) -> Result<Self, AclFileError> {
        let text = std::fs::read(path).map_err(|source| AclFileError::Io {
            path: path.to_owned(),
            source,
        })?;
        Self::parse(&text)
    }

    /// Port of `acl_file__parse`.
    pub fn parse(text: &[u8]) -> Result<Self, AclFileError> {
        let mut acl = Self::default();
        // `None` until the first `user` line: entries go to `anonymous`.
        let mut user: Option<Vec<u8>> = None;

        // `while(mosquitto_fgets(..))`: a NULL ends the file, even before EOF.
        for (index, raw) in Fgets::new(text).map_while(|line| line).enumerate() {
            let line_no = index + 1;
            let line = trim_end(raw);
            if line.first() == Some(&b'#') {
                continue;
            }
            // Mosquitto tokenises on ' ' only; tabs are part of tokens.
            let mut tokens = Strtok::new(line, b' ');
            let Some(keyword) = tokens.next() else {
                continue;
            };
            match keyword {
                b"topic" | b"pattern" => {
                    let access_word = tokens
                        .next()
                        .ok_or(AclFileError::EmptyTopic { line: line_no })?;
                    let (access, topic) = match tokens.rest() {
                        Some(rest) => {
                            let access = parse_access(access_word)
                                .ok_or(AclFileError::InvalidAccess { line: line_no })?;
                            (access, trim_blanks(rest))
                        }
                        None => (ACL_READ | ACL_WRITE, access_word),
                    };
                    // The C check runs on raw bytes and only looks at the ASCII
                    // `+`, `#` and `/`. Replacing every non-ASCII byte with one
                    // ASCII byte keeps those positions and the byte length;
                    // a lossy UTF-8 view would triple invalid bytes.
                    let ascii: String = topic
                        .iter()
                        .map(|&b| if b.is_ascii() { char::from(b) } else { '?' })
                        .collect();
                    validate_topic_filter(&ascii)
                        .map_err(|_| AclFileError::InvalidTopic { line: line_no })?;
                    // A non-UTF-8 topic can never match a validated UTF-8 MQTT
                    // topic, so dropping it is observably identical.
                    let Ok(topic) = std::str::from_utf8(topic) else {
                        continue;
                    };
                    if keyword == b"topic" {
                        let entries = match &user {
                            Some(name) => acl.users.entry(name.clone()).or_default(),
                            None => &mut acl.anonymous,
                        };
                        add_entry(
                            entries,
                            Entry {
                                topic: topic.to_owned(),
                                access,
                            },
                        );
                    } else {
                        let username_refs = count(topic, "%u");
                        if username_refs == 0 && count(topic, "%c") == 0 {
                            acl.warnings.push(AclWarning::PatternWithoutSubstitution {
                                line: line_no,
                                topic: topic.to_owned(),
                            });
                        }
                        add_entry(
                            &mut acl.patterns,
                            PatternEntry {
                                topic: topic.to_owned(),
                                access,
                                username_refs,
                            },
                        );
                    }
                }
                b"user" => {
                    let name = tokens
                        .rest()
                        .map(trim_blanks)
                        .ok_or(AclFileError::MissingUsername { line: line_no })?;
                    user = Some(name.to_vec());
                }
                _ => return Err(AclFileError::InvalidLine { line: line_no }),
            }
        }
        Ok(acl)
    }

    /// Warnings collected while parsing.
    pub fn warnings(&self) -> &[AclWarning] {
        &self.warnings
    }

    /// Port of `acl_file__check`: may `client_id`/`username` perform `access`
    /// on `topic`? `None` is the anonymous principal. The caller maps a
    /// zero-length CONNECT username to `None` (Mosquitto reads it as absent); a
    /// present empty username (certificate CN) is a named user, as in
    /// `acl_check.c`, and never gets the anonymous entries.
    pub fn check(
        &self,
        client_id: &str,
        username: Option<&str>,
        topic: &str,
        access: Access,
    ) -> bool {
        let wanted = match access {
            Access::Subscribe | Access::Unsubscribe => return true,
            Access::Read => ACL_READ,
            Access::Write => ACL_WRITE,
        };

        let user_entries = match username {
            Some(name) => self.users.get(name.as_bytes()),
            None => Some(&self.anonymous),
        };
        if user_entries.is_none() && self.patterns.is_empty() {
            return false;
        }

        for entry in user_entries.into_iter().flatten() {
            if topic.starts_with('$') && !entry.topic.starts_with('$') {
                continue;
            }
            // acl_check.c ignores the matcher's return code.
            if matches(&entry.topic, topic).unwrap_or(false) {
                if entry.access == ACL_DENY {
                    return false;
                }
                if entry.access & wanted != 0 {
                    return true;
                }
            }
        }

        if !self.patterns.is_empty() {
            // A username or client id containing a wildcard could otherwise
            // widen a pattern to other clients' topics.
            let dangerous = |s: &str| s.contains(['+', '#']);
            if username.is_some_and(dangerous) || dangerous(client_id) {
                return false;
            }
        }

        for pattern in &self.patterns {
            if pattern.username_refs > 0 && username.is_none() {
                continue;
            }
            match matches_with_pattern(&pattern.topic, topic, Some(client_id), username) {
                Err(_) => return false,
                Ok(true) => {
                    if pattern.access == ACL_DENY {
                        return false;
                    }
                    if pattern.access & wanted != 0 {
                        return true;
                    }
                }
                Ok(false) => {}
            }
        }
        false
    }
}

fn parse_access(word: &[u8]) -> Option<u8> {
    match word {
        b"read" => Some(ACL_READ),
        b"write" => Some(ACL_WRITE),
        b"readwrite" => Some(ACL_READ | ACL_WRITE),
        b"deny" => Some(ACL_DENY),
        _ => None,
    }
}

trait HasAccess {
    fn access(&self) -> u8;
}

impl HasAccess for Entry {
    fn access(&self) -> u8 {
        self.access
    }
}

impl HasAccess for PatternEntry {
    fn access(&self) -> u8 {
        self.access
    }
}

/// `deny` entries are prepended so they are checked first; others appended.
fn add_entry<T: HasAccess>(entries: &mut Vec<T>, entry: T) {
    if entry.access() == ACL_DENY {
        entries.insert(0, entry);
    } else {
        entries.push(entry);
    }
}

/// Non-overlapping occurrences, like the `strstr` loops in `acl__add_pattern`.
fn count(haystack: &str, needle: &str) -> usize {
    haystack.matches(needle).count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use Access::{Read, Subscribe, Unsubscribe, Write};

    fn acl(text: &str) -> AclFile {
        AclFile::parse(text.as_bytes()).unwrap()
    }

    #[test]
    fn anonymous_entries_only_apply_without_username() {
        let a = acl("topic read public/#\nuser alice\ntopic alice/#\n");
        assert!(a.check("c1", None, "public/x", Read));
        assert!(!a.check("c1", None, "public/x", Write));
        assert!(!a.check("c1", Some("alice"), "public/x", Read));
        assert!(a.check("c1", Some("alice"), "alice/x", Write));
        assert!(!a.check("c1", None, "alice/x", Read));
        // Unknown users with no patterns are denied outright.
        assert!(!a.check("c1", Some("mallory"), "alice/x", Read));
        // A present empty username (e.g. a certificate CN) is a named user
        // without a section: no anonymous entries (acl_check.c: username != NULL).
        assert!(!a.check("c1", Some(""), "public/x", Read));
    }

    #[test]
    fn subscribe_and_unsubscribe_are_always_allowed() {
        let a = acl("");
        assert!(a.check("c", None, "anything/#", Subscribe));
        assert!(a.check("c", Some("u"), "x", Unsubscribe));
        assert!(!a.check("c", None, "x", Read));
        assert!(!a.check("c", None, "x", Write));
    }

    #[test]
    fn deny_wins_regardless_of_position() {
        let a = acl("user bob\ntopic readwrite a/#\ntopic deny a/secret\n");
        assert!(a.check("c", Some("bob"), "a/open", Read));
        assert!(!a.check("c", Some("bob"), "a/secret", Read));
        assert!(!a.check("c", Some("bob"), "a/secret", Write));
    }

    #[test]
    fn first_match_without_requested_access_falls_through() {
        let a = acl("user bob\ntopic read a/b\ntopic write a/#\n");
        assert!(a.check("c", Some("bob"), "a/b", Write));
        assert!(a.check("c", Some("bob"), "a/b", Read));
        assert!(!a.check("c", Some("bob"), "a/c", Read));
    }

    #[test]
    fn dollar_topics_need_dollar_entries() {
        let a = acl("user bob\ntopic read #\ntopic read $SYS/broker/#\n");
        assert!(a.check("c", Some("bob"), "x/y", Read));
        assert!(!a.check("c", Some("bob"), "$SYS/other", Read));
        assert!(a.check("c", Some("bob"), "$SYS/broker/uptime", Read));
    }

    #[test]
    fn patterns() {
        let a = acl(
            "pattern write devices/%c/out\npattern read users/%u/#\npattern deny devices/%c/locked\n",
        );
        assert!(a.check("dev1", None, "devices/dev1/out", Write));
        assert!(!a.check("dev1", None, "devices/dev2/out", Write));
        assert!(!a.check("dev1", None, "users/x/y", Read));
        assert!(a.check("dev1", Some("ann"), "users/ann/inbox", Read));
        assert!(a.check("dev1", Some("ann"), "users/ann", Read));
        assert!(!a.check("dev1", Some("ann"), "devices/dev1/locked", Write));
        // Patterns also apply to users that have no `user` section.
        assert!(a.check("dev9", Some("nobody"), "devices/dev9/out", Write));
        // Wildcards in identities disable pattern access entirely.
        assert!(!a.check("dev+", None, "devices/dev+/out", Write));
        assert!(!a.check("dev1", Some("a#"), "devices/dev1/out", Write));
    }

    #[test]
    fn line_syntax_follows_mosquitto() {
        let a = acl(concat!(
            "# comment\n\n   \r\n",
            "topic x/anon\n",
            "user   john doe  \n",
            "topic  write  x/y\n",
            "topic read with space/t \t\n",
            "topic x/z\n",
        ));
        assert!(a.check("c", None, "x/anon", Write));
        assert!(a.check("c", Some("john doe"), "x/y", Write));
        assert!(!a.check("c", Some("john doe"), "x/y", Read));
        assert!(a.check("c", Some("john doe"), "with space/t", Read));
        assert!(a.check("c", Some("john doe"), "x/z", Read));
        assert!(a.check("c", Some("john doe"), "x/z", Write));
        assert!(a.warnings().is_empty());
        let p = acl("pattern read fixed/topic\n");
        assert_eq!(
            p.warnings(),
            [AclWarning::PatternWithoutSubstitution {
                line: 1,
                topic: "fixed/topic".into()
            }]
        );
    }

    // libcommon/file_common.c: mosquitto_fgets returns NULL for a line with
    // an embedded NUL, which ends acl_file__parse's read loop: Mosquitto 2.1.4
    // starts with this file and ignores everything after the NUL. A NUL at the
    // start of a line is an empty string instead, and parsing continues.
    #[test]
    fn embedded_nul_ends_the_file_like_mosquitto_fgets() {
        let a =
            AclFile::parse(b"user alice\ntopic read a/#\nfoo\0bar\ntopic write b/#\nnonsense\n")
                .unwrap();
        assert!(a.check("c", Some("alice"), "a/x", Read));
        assert!(!a.check("c", Some("alice"), "b/x", Write));
        assert!(matches!(
            AclFile::parse(b"user alice\n\0foo\nnonsense\n"),
            Err(AclFileError::InvalidLine { line: 3 })
        ));
    }

    // mosquitto_sub_topic_check counts bytes: Mosquitto 2.1.4 loads a topic
    // of 30000 non-UTF-8 bytes. It can never match, but the file is valid.
    #[test]
    fn non_utf8_topic_length_is_counted_in_bytes() {
        let mut text = b"topic read ".to_vec();
        text.extend([0xff; 30_000]);
        text.extend(b"\ntopic read ok/#\n");
        let a = AclFile::parse(&text).unwrap();
        assert!(a.check("c", None, "ok/x", Read));
        let mut text = b"topic read ".to_vec();
        text.extend([0xff; 65_536]);
        assert!(matches!(
            AclFile::parse(&text),
            Err(AclFileError::InvalidTopic { line: 1 })
        ));
    }

    #[test]
    fn parse_errors_match_mosquitto() {
        let err = |t: &str| AclFile::parse(t.as_bytes()).unwrap_err();
        assert!(matches!(
            err("topic\n"),
            AclFileError::EmptyTopic { line: 1 }
        ));
        assert!(matches!(
            err("topic readx a/b\n"),
            AclFileError::InvalidAccess { line: 1 }
        ));
        assert!(matches!(
            err("topic read a/#/b\n"),
            AclFileError::InvalidTopic { line: 1 }
        ));
        assert!(matches!(
            err("user\n"),
            AclFileError::MissingUsername { line: 1 }
        ));
        assert!(matches!(
            err("nonsense\n"),
            AclFileError::InvalidLine { line: 1 }
        ));
        // Tabs are not separators, and indented comments are not comments.
        assert!(matches!(
            err("topic\tread\ta\n"),
            AclFileError::InvalidLine { line: 1 }
        ));
        assert!(matches!(
            err("  # note\n"),
            AclFileError::InvalidLine { line: 1 }
        ));
        assert!(matches!(
            err("# ok\ntopic a\nbad\n"),
            AclFileError::InvalidLine { line: 3 }
        ));
    }
}
