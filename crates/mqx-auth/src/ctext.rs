//! Helpers that reproduce the C string handling Mosquitto uses when parsing
//! its configuration files, so MQExtended accepts and rejects the same files.

/// `isspace()` in the "C" locale. Note that `u8::is_ascii_whitespace` does not
/// include vertical tab (0x0B), which `isspace` does.
pub(crate) fn is_c_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | 0x0B | 0x0C | b'\r')
}

/// `mosquitto_trimblanks()`: strips leading and trailing `isspace` bytes.
pub(crate) fn trim_blanks(s: &[u8]) -> &[u8] {
    let start = s.iter().position(|&b| !is_c_space(b)).unwrap_or(s.len());
    let end = s
        .iter()
        .rposition(|&b| !is_c_space(b))
        .map_or(start, |i| i + 1);
    &s[start..end.max(start)]
}

/// Strips trailing `isspace` bytes only (the loop at the top of
/// `acl_file__parse`).
pub(crate) fn trim_end(s: &[u8]) -> &[u8] {
    let end = s.iter().rposition(|&b| !is_c_space(b)).map_or(0, |i| i + 1);
    &s[..end]
}

/// Lines as returned by repeated `mosquitto_fgets()` calls: each line keeps
/// its trailing `\n`; a final line without newline is still returned.
pub(crate) fn lines(text: &[u8]) -> impl Iterator<Item = &[u8]> {
    text.split_inclusive(|&b| b == b'\n')
}

/// Emulates successive `strtok_r(.., delim, ..)` calls over one buffer:
/// consecutive delimiters are skipped and empty tokens never produced.
pub(crate) struct Strtok<'a> {
    buf: &'a [u8],
    pos: usize,
    delim: u8,
}

impl<'a> Strtok<'a> {
    pub(crate) fn new(buf: &'a [u8], delim: u8) -> Self {
        Self { buf, pos: 0, delim }
    }

    /// `strtok_r(NULL, "", &saveptr)`: the unscanned remainder, or `None`
    /// when the previous token ended the buffer.
    pub(crate) fn rest(&mut self) -> Option<&'a [u8]> {
        if self.pos >= self.buf.len() {
            return None;
        }
        let rest = &self.buf[self.pos..];
        self.pos = self.buf.len();
        Some(rest)
    }
}

impl<'a> Iterator for Strtok<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        while self.pos < self.buf.len() && self.buf[self.pos] == self.delim {
            self.pos += 1;
        }
        if self.pos >= self.buf.len() {
            return None;
        }
        let start = self.pos;
        while self.pos < self.buf.len() && self.buf[self.pos] != self.delim {
            self.pos += 1;
        }
        let token = &self.buf[start..self.pos];
        // strtok overwrites the delimiter that ended the token with NUL and
        // resumes after it.
        if self.pos < self.buf.len() {
            self.pos += 1;
        }
        Some(token)
    }
}

/// glibc `atoi()`: `(int)strtol(s, NULL, 10)` with strtol saturating at
/// the `long` range before the truncating cast to `int`.
pub(crate) fn atoi(s: &[u8]) -> i32 {
    let mut i = 0;
    while i < s.len() && is_c_space(s[i]) {
        i += 1;
    }
    let negative = match s.get(i) {
        Some(b'-') => {
            i += 1;
            true
        }
        Some(b'+') => {
            i += 1;
            false
        }
        _ => false,
    };
    let mut value: i64 = 0;
    while let Some(d) = s.get(i).filter(|b| b.is_ascii_digit()) {
        let digit = i64::from(d - b'0');
        value = if negative {
            value.saturating_mul(10).saturating_sub(digit)
        } else {
            value.saturating_mul(10).saturating_add(digit)
        };
        i += 1;
    }
    value as i32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strtok_skips_empty_tokens_and_exposes_rest() {
        let mut t = Strtok::new(b"::a::b:c", b':');
        assert_eq!(t.next(), Some(&b"a"[..]));
        assert_eq!(t.next(), Some(&b"b"[..]));
        assert_eq!(t.rest(), Some(&b"c"[..]));
        assert_eq!(t.next(), None);

        let mut t = Strtok::new(b"topic read", b' ');
        assert_eq!(t.next(), Some(&b"topic"[..]));
        assert_eq!(t.next(), Some(&b"read"[..]));
        assert_eq!(t.rest(), None);

        let mut t = Strtok::new(b"user  bob smith", b' ');
        assert_eq!(t.next(), Some(&b"user"[..]));
        assert_eq!(t.rest(), Some(&b" bob smith"[..]));
    }

    #[test]
    fn trimming_matches_isspace() {
        assert_eq!(trim_blanks(b" \t\x0bx y\r\n"), b"x y");
        assert_eq!(trim_blanks(b"\n"), b"");
        assert_eq!(trim_end(b"  a \x0c\n"), b"  a");
    }

    #[test]
    fn atoi_like_glibc() {
        assert_eq!(atoi(b"20000"), 20000);
        assert_eq!(atoi(b"  101abc"), 101);
        assert_eq!(atoi(b"abc"), 0);
        assert_eq!(atoi(b"-5"), -5);
        assert_eq!(atoi(b"4294967297"), 1); // low 32 bits of 2^32 + 1
        assert_eq!(atoi(b"99999999999999999999"), -1); // LONG_MAX as int
    }
}
