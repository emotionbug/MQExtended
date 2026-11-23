//! Mosquitto `password_file` support.
//!
//! Format and checks mirror Mosquitto 2.1.4 `plugins/password-file/` and the
//! hash handling in `libcommon/password_common.c`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use sha2::{Digest, Sha512};
use subtle::ConstantTimeEq;
use thiserror::Error;

use crate::ctext::{Fgets, Strtok, atoi, trim_blanks};

/// SHA-512 digest length; Mosquitto's `HASH_LEN` (`EVP_MAX_MD_SIZE`).
const HASH_LEN: usize = 64;
/// Mosquitto 2.0 wrote 12-byte salts, 2.1 writes `HASH_LEN`-byte salts; both
/// are accepted on load.
const SALT_LENS: [usize; 2] = [12, HASH_LEN];
/// Usernames and encoded passwords longer than this are rejected.
const MAX_FIELD_LEN: usize = 65_535;

/// A decoded Mosquitto password hash.
#[derive(Clone, PartialEq, Eq)]
pub enum PasswordHash {
    /// `$6$<salt>$<hash>`: `SHA512(password || salt)` (Mosquitto <= 1.6).
    Sha512 { salt: Vec<u8>, hash: [u8; HASH_LEN] },
    /// `$7$<iterations>$<salt>$<hash>`: PBKDF2-HMAC-SHA512 (Mosquitto >= 2.0).
    Sha512Pbkdf2 {
        iterations: u32,
        salt: Vec<u8>,
        hash: [u8; HASH_LEN],
    },
}

impl std::fmt::Debug for PasswordHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print hash material.
        match self {
            Self::Sha512 { .. } => f.write_str("PasswordHash::Sha512"),
            Self::Sha512Pbkdf2 { iterations, .. } => {
                write!(
                    f,
                    "PasswordHash::Sha512Pbkdf2 {{ iterations: {iterations} }}"
                )
            }
        }
    }
}

/// Why an encoded password could not be decoded (`mosquitto_pw_decode`).
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum HashError {
    #[error("password is not hashed (must start with '$')")]
    NotHashed,
    #[error("unknown password hash type")]
    UnknownType,
    #[error("argon2id hashes need a Mosquitto build with WITH_ARGON2, which is not supported")]
    Argon2Unsupported,
    #[error("missing or invalid iteration count")]
    InvalidIterations,
    #[error("missing or invalid salt")]
    InvalidSalt,
    #[error("missing or invalid hash")]
    InvalidHash,
}

impl FromStr for PasswordHash {
    type Err = HashError;

    fn from_str(encoded: &str) -> Result<Self, HashError> {
        Self::decode(encoded.as_bytes())
    }
}

impl PasswordHash {
    /// Port of `mosquitto_pw_decode`.
    pub fn decode(encoded: &[u8]) -> Result<Self, HashError> {
        if encoded.first() != Some(&b'$') {
            return Err(HashError::NotHashed);
        }
        if let Some(rest) = encoded.strip_prefix(b"$6$") {
            let mut fields = Strtok::new(rest, b'$');
            let salt = decode_salt(fields.next())?;
            let hash = decode_hash(fields.next())?;
            Ok(Self::Sha512 { salt, hash })
        } else if let Some(rest) = encoded.strip_prefix(b"$7$") {
            let mut fields = Strtok::new(rest, b'$');
            let iterations = fields
                .next()
                .map(atoi)
                .filter(|&i| i >= 1)
                .ok_or(HashError::InvalidIterations)?;
            let salt = decode_salt(fields.next())?;
            let hash = decode_hash(fields.next())?;
            Ok(Self::Sha512Pbkdf2 {
                iterations: iterations as u32,
                salt,
                hash,
            })
        } else if encoded.starts_with(b"$argon2id$") {
            Err(HashError::Argon2Unsupported)
        } else {
            Err(HashError::UnknownType)
        }
    }

    /// Port of `mosquitto_pw_verify`. Mosquitto hands the password to OpenSSL
    /// with `strlen()`, so bytes after the first NUL are ignored.
    pub fn verify(&self, password: &[u8]) -> bool {
        let password = match password.iter().position(|&b| b == 0) {
            Some(end) => &password[..end],
            None => password,
        };
        let (expected, computed) = match self {
            Self::Sha512 { salt, hash } => {
                let mut digest = Sha512::new();
                digest.update(password);
                digest.update(salt);
                let out: [u8; HASH_LEN] = digest.finalize().into();
                (hash, out)
            }
            Self::Sha512Pbkdf2 {
                iterations,
                salt,
                hash,
            } => {
                let mut out = [0u8; HASH_LEN];
                pbkdf2::pbkdf2_hmac::<Sha512>(password, salt, *iterations, &mut out);
                (hash, out)
            }
        };
        expected.ct_eq(&computed).into()
    }
}

/// `mosquitto_base64_decode`: an OpenSSL base64 BIO with
/// `BIO_FLAGS_BASE64_NO_NL`, i.e. one `EVP_DecodeUpdate` over the whole
/// input followed by `EVP_DecodeFinal` (`crypto/evp/encode.c`). Spaces, tabs,
/// CR and LF are skipped, `-` ends the input, trailing bits are not checked,
/// and a final incomplete group is dropped while earlier output is kept.
/// Any other invalid byte, data after `=`, or more than two `=` is an error.
/// `None` when nothing was decoded, which Mosquitto also treats as failure.
/// Differentially tested against OpenSSL 3 for valid values padded with
/// blanks to any length and for malformed values up to 1024 bytes; the BIO
/// reads 1024-byte chunks, so longer malformed values can still differ.
fn openssl_base64_decode(input: &[u8]) -> Option<Vec<u8>> {
    enum Class {
        Data(u8),
        Skip,
        End,
    }
    let class = |c: u8| match c {
        b'A'..=b'Z' => Some(Class::Data(c - b'A')),
        b'a'..=b'z' => Some(Class::Data(c - b'a' + 26)),
        b'0'..=b'9' => Some(Class::Data(c - b'0' + 52)),
        b'+' => Some(Class::Data(62)),
        b'/' => Some(Class::Data(63)),
        // Decodes as zero; the padding count is subtracted afterwards.
        b'=' => Some(Class::Data(0)),
        b' ' | b'\t' | b'\r' | b'\n' => Some(Class::Skip),
        b'-' => Some(Class::End),
        _ => None,
    };
    // evp_decodeblock_int: groups of four, minus the padding seen so far.
    fn flush(group: &mut Vec<u8>, padding: usize, out: &mut Vec<u8>) -> Option<()> {
        let start = out.len();
        for chunk in group.chunks(4) {
            let bits = chunk.iter().fold(0u32, |acc, &v| (acc << 6) | u32::from(v));
            out.extend(&bits.to_be_bytes()[1..]);
        }
        group.clear();
        let decoded = out.len() - start;
        if padding > decoded {
            return None;
        }
        out.truncate(out.len() - padding);
        Some(())
    }
    let mut out = Vec::new();
    let mut group = Vec::with_capacity(64);
    let mut padding = 0;
    let mut ended = false;
    for &c in input {
        let class = class(c)?;
        if c == b'=' {
            padding += 1;
        } else if padding > 0 && matches!(class, Class::Data(_)) {
            return None;
        }
        if padding > 2 {
            return None;
        }
        match class {
            Class::End => {
                ended = true;
                break;
            }
            Class::Data(v) => group.push(v),
            Class::Skip => {}
        }
        if group.len() == 64 {
            flush(&mut group, padding, &mut out)?;
        }
    }
    if !group.is_empty() {
        if group.len() % 4 == 0 {
            flush(&mut group, padding, &mut out)?;
        } else if ended {
            return None;
        }
        // Otherwise EVP_DecodeFinal rejects the incomplete group, but the
        // BIO still returns what was decoded before it.
    }
    (!out.is_empty()).then_some(out)
}

fn decode_salt(field: Option<&[u8]>) -> Result<Vec<u8>, HashError> {
    field
        .and_then(openssl_base64_decode)
        .filter(|s| SALT_LENS.contains(&s.len()))
        .ok_or(HashError::InvalidSalt)
}

fn decode_hash(field: Option<&[u8]>) -> Result<[u8; HASH_LEN], HashError> {
    field
        .and_then(openssl_base64_decode)
        .and_then(|h| <[u8; HASH_LEN]>::try_from(h).ok())
        .ok_or(HashError::InvalidHash)
}

/// Outcome of a username/password check, mirroring the plugin return codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BasicAuth {
    /// `MOSQ_ERR_PLUGIN_IGNORE`: no username; the broker's `allow_anonymous`
    /// decides.
    Ignore,
    /// `MOSQ_ERR_SUCCESS`.
    Allow,
    /// `MOSQ_ERR_AUTH`: CONNACK "not authorised".
    Deny,
}

/// Why a password file was rejected. Mosquitto refuses to start in all of
/// these cases, and exits with status 3 when one appears on a SIGHUP reload
/// (test/broker/23-security-password-file-reload.py).
#[derive(Debug, Error)]
pub enum PasswordFileError {
    #[error("unable to open password file {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("line {line}: empty username")]
    EmptyUsername { line: usize },
    #[error("line {line}: username too long")]
    UsernameTooLong { line: usize },
    #[error("line {line}: duplicate user")]
    DuplicateUser { line: usize },
    #[error("line {line}: invalid line (missing password)")]
    MissingPassword { line: usize },
    #[error("line {line}: password too long")]
    PasswordTooLong { line: usize },
    #[error("line {line}: unable to decode password: {source}")]
    Decode { line: usize, source: HashError },
}

/// A loaded Mosquitto password file.
#[derive(Debug, Clone, Default)]
pub struct PasswordFile {
    // Keyed by raw bytes: Mosquitto does not require the file to be UTF-8.
    // Non-UTF-8 usernames can never match a (validated UTF-8) MQTT username.
    users: HashMap<Vec<u8>, PasswordHash>,
}

impl PasswordFile {
    /// Reads and parses `path`.
    pub fn load(path: &Path) -> Result<Self, PasswordFileError> {
        let text = std::fs::read(path).map_err(|source| PasswordFileError::Io {
            path: path.to_owned(),
            source,
        })?;
        Self::parse(&text)
    }

    /// Port of `password_file__parse`.
    pub fn parse(text: &[u8]) -> Result<Self, PasswordFileError> {
        let mut users = HashMap::new();
        for (index, line) in Fgets::new(text).enumerate() {
            let line_no = index + 1;
            // A NULL from mosquitto_fgets is skipped; the loop runs until feof.
            let Some(line) = line else {
                continue;
            };
            if line.first() == Some(&b'#') || !line.contains(&b':') {
                continue;
            }
            let mut tokens = Strtok::new(line, b':');
            let Some(username) = tokens.next() else {
                continue;
            };
            let username = trim_blanks(username);
            if username.len() > MAX_FIELD_LEN {
                return Err(PasswordFileError::UsernameTooLong { line: line_no });
            }
            if username.is_empty() {
                return Err(PasswordFileError::EmptyUsername { line: line_no });
            }
            if users.contains_key(username) {
                return Err(PasswordFileError::DuplicateUser { line: line_no });
            }
            let password = tokens
                .next()
                .map(trim_blanks)
                .ok_or(PasswordFileError::MissingPassword { line: line_no })?;
            if password.len() > MAX_FIELD_LEN {
                return Err(PasswordFileError::PasswordTooLong { line: line_no });
            }
            let hash =
                PasswordHash::decode(password).map_err(|source| PasswordFileError::Decode {
                    line: line_no,
                    source,
                })?;
            users.insert(username.to_vec(), hash);
        }
        Ok(Self { users })
    }

    /// Number of users in the file.
    pub fn len(&self) -> usize {
        self.users.len()
    }

    /// Whether the file has no users.
    pub fn is_empty(&self) -> bool {
        self.users.is_empty()
    }

    /// Port of `password_file__check`. `None` means the field is absent. Mosquitto
    /// reads zero-length CONNECT username/password fields as absent
    /// (`packet__read_binary`), so the caller maps those to `None`; a present empty
    /// username (e.g. from a certificate CN) is a real, unknown user.
    pub fn check(&self, username: Option<&str>, password: Option<&[u8]>) -> BasicAuth {
        let Some(username) = username else {
            return BasicAuth::Ignore;
        };
        let Some(hash) = self.users.get(username.as_bytes()) else {
            return BasicAuth::Deny;
        };
        match password {
            Some(password) if hash.verify(password) => BasicAuth::Allow,
            _ => BasicAuth::Deny,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Generated with Mosquitto 2.1.4 `mosquitto_passwd -b`.
    const ALICE: &str = "$7$20000$EgxIgrwetPce1lG1f2j9StYtFSSPa5jNsy+cC+l/neS0oFJYsngUa9uuDRoO/4h3mGTak0TBPwZVbytmo8n+Yw==$6m0VkQQfHmfe3pE+WbnDl7KmtfVXJ+lsaTB7Dh9TwjNzkvPGK8OQhvTogxXkQdc0ztU6de/Fy22JzO2+7i12Ag==";
    // `mosquitto_passwd -b -I 101`.
    const BOB: &str = "$7$101$6b9p5DHy+HZ/sd4YgiADThddgF4qwiTYS+RLK38MAtaSgo1LNYFEIFjSg4e4O+4qRCSqwd9aRQfND+t3A+q2cg==$PAsktMHFTboLeAy6kM+EAeasyKCAOKpO2hH6/IMzRw0OUEDkfjhI/RjDOfI26ZsmxHowJglZ7CmfGMp4M5ni5w==";
    // `mosquitto_passwd -b -H sha512`.
    const DAVE: &str = "$6$sOkz5sFCd1B4nFc91d7JgPc+TOlpgJy77pu05ZesiEjQp/3dp8DaNXdiKh3aHjycDHOxg/jVgfaFTHxe/id3TA==$KGmwE3shNepn1Pf8bHHumadxPIU8iOegC2cPvKZ3FEiJ25x3bZ5Ofr7GCTygzKt0XlwlR3WLHJvMGuY1xf+yXg==";
    // From Mosquitto's test/broker/09-pwfile-parse-invalid.py: user "test"
    // with password "test", user "empty" with the empty password.
    const TEST_6: &str = "$6$njERlZMi/7DzNB9E$iiavfuXvUm8iyDZArTy7smTxh07GXXOrOsqxfW6gkOYVXHGk+W+i/8d3xDxrMwEPygEBhoA8A/gjQC0N2M4Lkw==";
    const EMPTY_6: &str = "$6$o+53eGXtmlfHeYrg$FY7X9DNQ4uU1j0NiPmGOOSU05ZSzhqNmNhXIof/0nLpVb1zDhcRHdaC72E3YryH7dtTiG/r6jH6C8J+30cZBgA==";
    // Mosquitto 2.0 style: 12-byte salt, 101 iterations, password "pw2.0"
    // (computed with Python's hashlib.pbkdf2_hmac).
    const V20: &str = "$7$101$AAECAwQFBgcICQoL$LEnW8zwfF4cCuyzDDbguMu0WiShvJoLN1ow0N5mlrhuvfkdVgxd9ob0TCoOtCu/JFc18GGuYT7d+AwQFRHBkrQ==";

    fn hash(s: &str) -> PasswordHash {
        s.parse().unwrap()
    }

    #[test]
    fn verifies_mosquitto_generated_hashes() {
        assert!(hash(ALICE).verify(b"Secr3t!pass"));
        assert!(!hash(ALICE).verify(b"Secr3t!pas"));
        assert!(hash(BOB).verify(b"b0b"));
        assert!(hash(DAVE).verify(b"dpw"));
        assert!(!hash(DAVE).verify(b"dpW"));
        assert!(hash(TEST_6).verify(b"test"));
        assert!(hash(EMPTY_6).verify(b""));
        assert!(hash(V20).verify(b"pw2.0"));
        // Bytes after NUL are ignored, like strlen() in Mosquitto.
        assert!(hash(BOB).verify(b"b0b\0trailing"));
    }

    #[test]
    fn decode_rejections_match_mosquitto() {
        // Cases from test/broker/09-pwfile-parse-invalid.py.
        let bad = [
            ("", HashError::NotHashed),
            ("bad", HashError::NotHashed),
            ("$", HashError::UnknownType),
            ("$6", HashError::UnknownType),
            ("$6$", HashError::InvalidSalt),
            ("$6$njERlZMi/7DzNB9E", HashError::InvalidHash),
            ("$6$njERlZMi/7DzNB9E$", HashError::InvalidHash),
            (
                "$5$njERlZMi/7DzNB9E$iiavfuXvUm8iyDZArTy7smTxh07GXXOrOsqxfW6gkOYVXHGk+W+i/8d3xDxrMwEPygEBhoA8A/gjQC0N2M4Lkw==",
                HashError::UnknownType,
            ),
            (
                "$6$njER{ZMi/7DzNB9E$iiavfuXvUm8iyDZArTy7smTxh07GXXOrOsqxfW6gkOYVXHGk+W+i/8d3xDxrMwEPygEBhoA8A/gjQC0N2M4Lkw==",
                HashError::InvalidSalt,
            ),
            (
                "$6$njERlZMi/7DzNB9E$iiavfuXv{}8iyDZArTy7smTxh07GXXOrOsqxfW6gkOYVXHGk+W+i/8d3xDxrMwEPygEBhoA8A/gjQC0N2M4Lkw==",
                HashError::InvalidHash,
            ),
            (
                "$7$0$AAECAwQFBgcICQoL$LEnW8zwfF4cCuyzDDbguMu0WiShvJoLN1ow0N5mlrhuvfkdVgxd9ob0TCoOtCu/JFc18GGuYT7d+AwQFRHBkrQ==",
                HashError::InvalidIterations,
            ),
            ("$7$abc$x$y", HashError::InvalidIterations),
            (
                "$argon2id$v=19$m=47104,t=1,p=1$c2FsdA$aGFzaA",
                HashError::Argon2Unsupported,
            ),
        ];
        for (encoded, err) in bad {
            assert_eq!(PasswordHash::from_str(encoded), Err(err), "{encoded:?}");
        }
    }

    // libcommon/base64_common.c: mosquitto_base64_decode goes through an
    // OpenSSL BIO, which skips blanks and ignores the unused low bits of the
    // last character. Mosquitto 2.1.4 loads this file and accepts "b0b".
    #[test]
    fn hashes_decode_like_openssl() {
        let lenient = "$7$101$6b9p5DHy+HZ/s \td4YgiADThddgF4qwiTYS+RLK38MAtaSgo1LNYFEIFjSg4e4O+4qRCSqwd9aRQfND+t3A+q2cg==$PAsktMHF \r TboLeAy6kM+EAeasyKCAOKpO2hH6/IMzRw0OUEDkfjhI/RjDOfI26ZsmxHowJglZ7CmfGMp4M5ni5x==";
        let pw = file(&[&format!("bob:{lenient}")]).unwrap();
        assert_eq!(pw.check(Some("bob"), Some(b"b0b")), BasicAuth::Allow);

        // Outputs of mosquitto_base64_decode, with OpenSSL 3.
        let salt = |s: &str| decode_salt(Some(s.as_bytes()));
        assert_eq!(salt("AA AA AA AA AA AA AA AA").unwrap(), [0; 12]);
        // `-` ends the input.
        assert_eq!(salt("AAAAAAAAAAAAAAAA-*").unwrap(), [0; 12]);
        assert_eq!(openssl_base64_decode(b"AAAA===="), None);
        assert_eq!(openssl_base64_decode(b"AAA=AAAA"), None);
        assert_eq!(openssl_base64_decode(b"AA*A"), None);
        // An incomplete final group is dropped: 86 characters decode to 48 bytes.
        let unpadded = &BOB.as_bytes()[BOB.len() - 88..BOB.len() - 2];
        assert_eq!(openssl_base64_decode(unpadded).map(|d| d.len()), Some(48));
        let padded = &BOB.as_bytes()[BOB.len() - 88..];
        assert_eq!(openssl_base64_decode(&[padded, b"AAAA"].concat()), None);
    }

    fn file(lines: &[&str]) -> Result<PasswordFile, PasswordFileError> {
        PasswordFile::parse(
            lines
                .iter()
                .map(|l| format!("{l}\n"))
                .collect::<String>()
                .as_bytes(),
        )
    }

    #[test]
    fn mosquitto_username_password_table() {
        // test/broker/09-pwfile-parse-invalid.py `username_password_tests`:
        // only test/test connects; everything else gets CONNACK 5 with
        // allow_anonymous false (Ignore => anonymous => refused).
        // (first line, last line) around the two valid users, as written by
        // `write_pwfile` in that test; all of these files load.
        let variants = [
            (None, None),
            (Some(""), None),
            (None, Some("")),
            (Some(""), Some("")),
            (Some("#comment"), None),
            (None, Some("#comment")),
            (Some("#comment"), Some("#comment")),
            (Some(""), Some("#comment")),
        ];
        let test_line = format!("test:{TEST_6}");
        let empty_line = format!("empty:{EMPTY_6}");
        for (first, last) in variants {
            let mut lines: Vec<&str> = first.into_iter().collect();
            lines.extend([test_line.as_str(), empty_line.as_str()]);
            lines.extend(last);
            let pw = file(&lines).unwrap();
            // The Python test sends these over the wire, where zero-length fields
            // arrive as absent; apply the same mapping the broker does.
            let wire_user = |u: Option<&'static str>| u.filter(|u| !u.is_empty());
            let wire_pass = |p: Option<&'static [u8]>| p.filter(|p| !p.is_empty());
            for user in [Some("test"), Some("empty"), Some("bad"), Some(""), None] {
                for pass in [Some(&b"test"[..]), Some(b"bad"), Some(b""), None] {
                    let allowed = pw.check(wire_user(user), wire_pass(pass)) == BasicAuth::Allow;
                    assert_eq!(
                        allowed,
                        user == Some("test") && pass == Some(b"test"),
                        "{user:?} {pass:?}"
                    );
                }
            }
            assert_eq!(pw.check(None, Some(b"test")), BasicAuth::Ignore);
            // A present empty username (certificate CN) is looked up like any other
            // name, as Mosquitto's HASH_FIND does, and is unknown here.
            assert_eq!(pw.check(Some(""), None), BasicAuth::Deny);
        }
    }

    #[test]
    fn invalid_files_are_rejected_like_mosquitto() {
        let decode = |l: &str| matches!(file(&[l]), Err(PasswordFileError::Decode { line: 1, .. }));
        assert!(decode("bad:"));
        assert!(decode("bad:bad"));
        assert!(decode("bad:$"));
        assert!(decode("bad:$6$njERlZMi/7DzNB9E$"));
        // strtok skips the leading ':' so the hash becomes the username.
        assert!(matches!(
            file(&[&format!(":{TEST_6}")]),
            Err(PasswordFileError::MissingPassword { line: 1 })
        ));
        assert!(matches!(
            file(&[&format!("test:{TEST_6}"), &format!("test:{TEST_6}")]),
            Err(PasswordFileError::DuplicateUser { line: 2 })
        ));
        assert!(matches!(
            file(&[&format!("  :{TEST_6}")]),
            Err(PasswordFileError::EmptyUsername { line: 1 })
        ));
        // strtok returns the trailing "\n" as the username, which trims to "".
        assert!(matches!(
            file(&[":::"]),
            Err(PasswordFileError::EmptyUsername { line: 1 })
        ));
        // Without a newline there is no token at all and the line is skipped.
        assert!(PasswordFile::parse(b":::").unwrap().is_empty());
        // Final line without newline and without password.
        assert!(matches!(
            PasswordFile::parse(b"bad:"),
            Err(PasswordFileError::MissingPassword { line: 1 })
        ));
    }

    // libcommon/file_common.c: mosquitto_fgets returns NULL for a line with
    // an embedded NUL, which password_file__parse skips, and for a final
    // unterminated line that exactly fills its 256-byte buffer. Both checked
    // against Mosquitto 2.1.4 with these files.
    #[test]
    fn line_reading_follows_mosquitto_fgets() {
        let pw = PasswordFile::parse(
            format!("alice:{ALICE}\nbob:{ALICE}\0junk\ncarol:{ALICE}\n").as_bytes(),
        )
        .unwrap();
        assert_eq!(
            pw.check(Some("alice"), Some(b"Secr3t!pass")),
            BasicAuth::Allow
        );
        assert_eq!(pw.check(Some("bob"), Some(b"Secr3t!pass")), BasicAuth::Deny);
        assert_eq!(
            pw.check(Some("carol"), Some(b"Secr3t!pass")),
            BasicAuth::Allow
        );

        let padded = |user: &str, len: usize| format!("{:len$}", format!("{user}:{ALICE}"));
        for (len, loaded) in [(254, true), (255, false), (256, true)] {
            let text = format!("{}\n{}", padded("alice", 100), padded("bob", len));
            let pw = PasswordFile::parse(text.as_bytes()).unwrap();
            let expected = if loaded {
                BasicAuth::Allow
            } else {
                BasicAuth::Deny
            };
            assert_eq!(
                pw.check(Some("bob"), Some(b"Secr3t!pass")),
                expected,
                "{len}"
            );
        }
        // Once a long line has grown the buffer to 1256 bytes, the boundary moves.
        let text = format!("{}\n{}", padded("alice", 300), padded("bob", 1255));
        let pw = PasswordFile::parse(text.as_bytes()).unwrap();
        assert_eq!(
            pw.check(Some("alice"), Some(b"Secr3t!pass")),
            BasicAuth::Allow
        );
        assert_eq!(pw.check(Some("bob"), Some(b"Secr3t!pass")), BasicAuth::Deny);
    }

    #[test]
    fn line_handling_quirks() {
        let pw = file(&[
            "no colon here is skipped",
            &format!("  carol smith \t: {BOB} :ignored"),
            &format!("bob:{BOB}\r"),
        ])
        .unwrap();
        assert_eq!(pw.len(), 2);
        assert_eq!(
            pw.check(Some("carol smith"), Some(b"b0b")),
            BasicAuth::Allow
        );
        assert_eq!(pw.check(Some("bob"), Some(b"b0b")), BasicAuth::Allow);
        assert_eq!(pw.check(Some("bob"), Some(b"\0b0b")), BasicAuth::Deny);
    }
}
