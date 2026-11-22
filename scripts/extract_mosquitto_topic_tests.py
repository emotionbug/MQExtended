#!/usr/bin/env python3
"""Generate crates/mqx-topic/tests/mosquitto_topic_test.rs from Mosquitto's
test/unit/libcommon/topic_test.c.

Usage: scripts/extract_mosquitto_topic_tests.py /path/to/mosquitto
"""

import pathlib
import re
import sys

STR = r'"(?:[^"\\]|\\.)*"'
REPO = pathlib.Path(__file__).resolve().parent.parent
OUT = REPO / "crates/mqx-topic/tests/mosquitto_topic_test.rs"


def opt(lit: str) -> str:
    lit = lit.strip()
    return "None" if lit == "NULL" else f"Some({lit})"


def expected(rc: str, matched: str) -> str:
    return f"Ok({matched})" if rc == "MOSQ_ERR_SUCCESS" else "Err(MatchError)"


def main() -> None:
    src = (pathlib.Path(sys.argv[1]) / "test/unit/libcommon/topic_test.c").read_text()
    funcs = {
        m.group(1): m.group(2)
        for m in re.finditer(r"static void (TEST_\w+)\(void\)\s*\{(.*?)\n\}", src, re.S)
    }

    matching = []
    for name in ["TEST_valid_matching", "TEST_invalid_but_matching", "TEST_valid_no_matching", "TEST_invalid"]:
        body = funcs[name]
        for m in re.finditer(rf"(?<!no_)match_helper\(({STR}),\s*({STR})\)", body):
            matching.append((m.group(1), m.group(2), "Ok(true)"))
        for m in re.finditer(rf"no_match_helper\((MOSQ_ERR_\w+),\s*({STR}),\s*({STR})\)", body):
            matching.append((m.group(2), m.group(3), expected(m.group(1), "false")))

    pattern = []
    call = (
        rf"rc = mosquitto_topic_matches_sub_with_pattern\(({STR}|NULL),\s*({STR}|NULL),\s*({STR}|NULL),"
        rf"\s*({STR}|NULL),\s*&match\);\s*CU_ASSERT_EQUAL\(rc, (MOSQ_ERR_\w+)\);\s*"
        r"CU_ASSERT_EQUAL\(match, (true|false)\);"
    )
    row = rf"\{{({STR}),\s*({STR}),\s*({STR}|NULL),\s*({STR}|NULL),\s*(MOSQ_ERR_\w+),\s*(true|false)\}}"
    for name, body in funcs.items():
        if not name.startswith("TEST_topic_pattern"):
            continue
        for regex in (call, row):
            for m in re.finditer(regex, body):
                f, t, c, u, rc, matched = m.groups()
                if f == "NULL" or t == "NULL":
                    continue  # C NULL pointers have no Rust &str equivalent
                pattern.append((f, t, opt(c), opt(u), expected(rc, matched)))

    def checks(helper: str):
        return [
            (m.group(1), "true" if m.group(2) == "MOSQ_ERR_SUCCESS" else "false")
            for m in re.finditer(rf"{helper}\(({STR}),\s*(MOSQ_ERR_\w+)\)", src)
        ]

    out = [
        "//! Parity cases extracted from Mosquitto v2.1.4 `test/unit/libcommon/topic_test.c`",
        "//! (EPL-2.0 OR BSD-3-Clause) by `scripts/extract_mosquitto_topic_tests.py`.",
        "//! Do not edit by hand; regenerate from the Mosquitto source.",
        "",
        "use mqx_topic::{MatchError, matches, matches_with_pattern, validate_topic_filter, validate_topic_name};",
        "",
        "type MatchCase = (&'static str, &'static str, Result<bool, MatchError>);",
        "type PatternCase = (",
        "    &'static str,",
        "    &'static str,",
        "    Option<&'static str>,",
        "    Option<&'static str>,",
        "    Result<bool, MatchError>,",
        ");",
        "",
        "#[rustfmt::skip]",
        "const MATCH: &[MatchCase] = &[",
        *[f"    ({f}, {t}, {e})," for f, t, e in matching],
        "];",
        "",
        "#[rustfmt::skip]",
        "const PATTERN: &[PatternCase] = &[",
        *[f"    ({f}, {t}, {c}, {u}, {e})," for f, t, c, u, e in pattern],
        "];",
        "",
        "#[rustfmt::skip]",
        "const PUB_TOPIC: &[(&str, bool)] = &[",
        *[f"    ({t}, {v})," for t, v in checks("pub_topic_helper")],
        "];",
        "",
        "#[rustfmt::skip]",
        "const SUB_TOPIC: &[(&str, bool)] = &[",
        *[f"    ({t}, {v})," for t, v in checks("sub_topic_helper")],
        "];",
        "",
        """#[test]
fn topic_matches_sub() {
    for (filter, topic, expected) in MATCH {
        assert_eq!(matches(filter, topic), *expected, "filter {filter:?} topic {topic:?}");
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
}""",
    ]
    OUT.write_text("\n".join(out) + "\n")
    print(f"{OUT}: {len(matching)} match, {len(pattern)} pattern cases")


if __name__ == "__main__":
    main()
