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

/// Successive `mosquitto_fgets()` calls (`libcommon/file_common.c`) over a
/// file read with glibc `fgets()`, starting from the 256-byte buffer both
/// file plugins allocate. The buffer grows by 1000 bytes whenever a line does
/// not fit and stays grown for later lines.
///
/// `next()` returns `None` once the file is exhausted (`feof`). Otherwise
/// `Some(None)` is a call that returned NULL: a line with an embedded NUL, or
/// a final unterminated line that exactly filled the buffer. `Some(Some(line))`
/// is the buffer as a C string, with the trailing `\n` if there was one.
pub(crate) struct Fgets<'a> {
    text: &'a [u8],
    pos: usize,
    eof: bool,
    buflen: usize,
}

impl<'a> Fgets<'a> {
    pub(crate) fn new(text: &'a [u8]) -> Self {
        Self {
            text,
            pos: 0,
            eof: false,
            buflen: 256,
        }
    }

    /// glibc `fgets(s, size, stream)`: at most `size - 1` bytes, stopping
    /// after `\n`; sets end-of-file when it runs out of input first. `None`
    /// when nothing was read.
    fn fgets(&mut self, size: usize) -> Option<&'a [u8]> {
        let rest = &self.text[self.pos..];
        let limit = rest.len().min(size - 1);
        let len = match rest[..limit].iter().position(|&b| b == b'\n') {
            Some(newline) => newline + 1,
            None => {
                // Filling `size - 1` bytes exactly stops without reading on,
                // so end-of-file is not seen yet.
                if rest.len() < size - 1 {
                    self.eof = true;
                }
                limit
            }
        };
        self.pos += len;
        (len > 0).then(|| &rest[..len])
    }
}

impl<'a> Iterator for Fgets<'a> {
    type Item = Option<&'a [u8]>;

    fn next(&mut self) -> Option<Option<&'a [u8]>> {
        if self.eof {
            return None;
        }
        let start = self.pos;
        let mut offset = 0;
        loop {
            let read = self.fgets(self.buflen - offset);
            // The buffer holds every chunk read by this call.
            let buf = &self.text[start..self.pos];
            let c_str = &buf[..buf.iter().position(|&b| b == 0).unwrap_or(buf.len())];
            if self.eof || read.is_none() {
                return Some(read.map(|_| c_str));
            }
            if c_str.is_empty() || c_str.last() == Some(&b'\n') {
                return Some(Some(c_str));
            }
            if c_str.len() + 1 < self.buflen {
                // "Embedded nulls, invalid string"
                return Some(None);
            }
            offset = self.buflen - 1;
            self.buflen += 1000;
        }
    }
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
