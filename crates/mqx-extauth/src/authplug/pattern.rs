use std::sync::LazyLock;

// auth-plug.c: mosquitto_auth_acl_check uses fnmatch(pattern, name, 0).
// Mosquitto does not set the process locale, so match bytes with C-locale
// ranges/classes. Flags 0 allow wildcards to consume slash and leading dot.
pub(super) fn matches(mut pattern: &[u8], mut name: &[u8]) -> bool {
    let mut star = None;
    loop {
        if let Some(tail) = pattern.strip_prefix(b"*") {
            pattern = tail;
            if tail.is_empty() {
                return true;
            }
            star = Some((tail, name));
        } else if let Some((&byte, tail)) = name.split_first() {
            if let Some(rest) = atom(pattern, byte) {
                pattern = rest;
                name = tail;
            } else if let Some((retry, [_, rest @ ..])) = star {
                pattern = retry;
                name = rest;
                star = Some((retry, rest));
            } else {
                return false;
            }
        } else {
            return pattern.is_empty();
        }
    }
}

fn atom(pattern: &[u8], byte: u8) -> Option<&[u8]> {
    match pattern {
        [b'?', tail @ ..] => Some(tail),
        [b'\\', quoted, tail @ ..] => (*quoted == byte).then_some(tail),
        [b'\\'] => None,
        [b'[', tail @ ..] => match bracket(tail, byte) {
            Bracket::Parsed(rest, true) => Some(rest),
            Bracket::Unclosed if byte == b'[' => Some(tail),
            _ => None,
        },
        [literal, tail @ ..] => (*literal == byte).then_some(tail),
        [] => None,
    }
}

enum Bracket<'a> {
    Parsed(&'a [u8], bool),
    Unclosed,
    Invalid,
}

fn bracket(mut pattern: &[u8], byte: u8) -> Bracket<'_> {
    static POSIXLY_CORRECT: LazyLock<bool> =
        LazyLock::new(|| std::env::var_os("POSIXLY_CORRECT").is_some());
    let negated = pattern.starts_with(b"!") || (!*POSIXLY_CORRECT && pattern.starts_with(b"^"));
    if negated {
        pattern = &pattern[1..];
    }
    let mut matched = false;
    loop {
        let (element, tail) = match element(pattern, byte) {
            Ok(Some(element)) => element,
            Ok(None) => return Bracket::Unclosed,
            Err(()) => return Bracket::Invalid,
        };
        pattern = tail;
        match (element, pattern) {
            (Element::Literal(start), [b'-', end, ..]) if *end != b']' => {
                match self::element(&pattern[1..], byte) {
                    Ok(Some((Element::Literal(end), tail))) => {
                        matched |= start <= byte && byte <= end;
                        pattern = tail;
                    }
                    _ => return Bracket::Invalid,
                }
            }
            (Element::Literal(literal), _) => matched |= byte == literal,
            (Element::Class(member), _) => matched |= member,
        }
        if let Some(tail) = pattern.strip_prefix(b"]") {
            return Bracket::Parsed(tail, matched != negated);
        }
    }
}

enum Element {
    Literal(u8),
    Class(bool),
}

fn element(pattern: &[u8], byte: u8) -> Result<Option<(Element, &[u8])>, ()> {
    match pattern {
        [b'\\', escaped, tail @ ..] => Ok(Some((Element::Literal(*escaped), tail))),
        [b'\\'] => Err(()),
        [b'[', kind @ (b':' | b'.' | b'='), tail @ ..] => {
            let Some(end) = tail.windows(2).position(|w| w == [*kind, b']']) else {
                return Ok(Some((Element::Literal(b'['), &pattern[1..])));
            };
            let name = &tail[..end];
            let element = match (*kind, name) {
                (b'.', [literal]) => Element::Literal(*literal),
                (b'=', [literal]) => Element::Class(byte == *literal),
                (b':', name) => Element::Class(class(name, byte).ok_or(())?),
                _ => return Err(()),
            };
            Ok(Some((element, &tail[end + 2..])))
        }
        [literal, tail @ ..] => Ok(Some((Element::Literal(*literal), tail))),
        [] => Ok(None),
    }
}

fn class(name: &[u8], byte: u8) -> Option<bool> {
    Some(match name {
        b"alnum" => byte.is_ascii_alphanumeric(),
        b"alpha" => byte.is_ascii_alphabetic(),
        b"blank" => matches!(byte, b' ' | b'\t'),
        b"cntrl" => byte.is_ascii_control(),
        b"digit" => byte.is_ascii_digit(),
        b"graph" => byte.is_ascii_graphic(),
        b"lower" => byte.is_ascii_lowercase(),
        b"print" => byte.is_ascii_graphic() || byte == b' ',
        b"punct" => byte.is_ascii_punctuation(),
        b"space" => matches!(byte, b' ' | b'\t'..=b'\r'),
        b"upper" => byte.is_ascii_uppercase(),
        b"xdigit" => byte.is_ascii_hexdigit(),
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn flags_zero() {
        for (pattern, name, expected) in [
            ("a*?t", "a/.dot", true),
            ("a*?t", "at", false),
            ("a*?t", "aTT", false),
            ("joe,bob", "bob", false),
            ("joe,bob", "joe,bob", true),
            (r"\*", "*", true),
            ("[!a-c]", "d", true),
            ("[^a-c]", "c", false),
            ("[]a]", "]", true),
            ("[a-]", "-", true),
            ("[[]", "[", true),
            ("[abc", "[abc", true),
            ("[[.x.]]", "x", true),
            ("[[=x=]]", "x", true),
            ("[[:alpha:]][[:digit:]]", "z5", true),
            ("[![:digit:]]", "x", true),
            ("?", "é", false),
            ("??", "é", true),
        ] {
            assert_eq!(
                super::matches(pattern.as_bytes(), name.as_bytes()),
                expected,
                "{pattern:?} against {name:?}"
            );
        }
    }
}
