//! go-auth's ACL pattern matching (`backends/topics/topics.go`). It compares
//! the pattern with the checked topic or filter literally, without Mosquitto's
//! `$` rule or filter containment.

/// `topics.Match(savedTopic, givenTopic)`.
pub(crate) fn matches(saved: &str, given: &str) -> bool {
    given == saved || route(saved.split('/'), given.split('/'))
}

fn route<'a>(
    mut saved: impl Iterator<Item = &'a str>,
    mut given: impl Iterator<Item = &'a str>,
) -> bool {
    loop {
        match (saved.next(), given.next()) {
            (None, given) => return given.is_none(),
            // With no level left a '#' matches anywhere in the pattern; with
            // levels left it must be the last pattern level.
            (Some("#"), None) => return true,
            (Some("#"), Some(_)) => return saved.next().is_none(),
            (Some(_), None) => return false,
            (Some(level), Some(topic)) if level == "+" || level == topic => {}
            _ => return false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::matches;

    #[test]
    fn follows_go_auth() {
        // backends/topics/topics_test.go cases and the edge cases of match().
        assert!(matches("test/topic", "test/topic"));
        assert!(matches("test/+", "test/topic"));
        assert!(matches("test/#", "test/topic/sub"));
        assert!(matches("test/#", "test"));
        assert!(matches("#", "anything/at/all"));
        assert!(matches("+/+", "/"));
        assert!(matches("a/#/b", "a/#/b"));
        assert!(matches("a/#/b", "a"));
        assert!(!matches("a/#/b", "a/x/b"));
        assert!(!matches("test/+", "test"));
        assert!(!matches("test/+", "test/a/b"));
        assert!(!matches("test", "test/a"));
        assert!(matches("$SYS/#", "$SYS/x"));
        assert!(matches("#", "$SYS/x"));
        assert!(matches("+/#", "a"));
    }
}
