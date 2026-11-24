//! Password checks use the algorithm and work factors recorded in each hash.

use std::{borrow::Cow, sync::Arc};

use argon2::{Algorithm, Argon2, Params, Version};
use base64::{alphabet, engine::GeneralPurpose, engine::GeneralPurposeConfig, prelude::*};
use sha2::{Sha256, Sha512};
use subtle::ConstantTimeEq;

use super::backend::{Hasher, Log, Options};

// hashing/hashing.go: NewHasher, processHashOpts. Generation-only options
// (cost, iteration count, key/salt size, preferred algorithm) are not needed.
pub(super) fn new(options: &Options, backend: &str, log: &Log) -> Arc<dyn Hasher> {
    let prefix = format!("{backend}_");
    let specific = options.contains_key(&format!("{prefix}hasher"));
    let get = |key| {
        if specific {
            options.get(&format!("{prefix}{key}"))
        } else {
            options.get(key)
        }
        .map(String::as_str)
    };
    let hasher = get("hasher").unwrap_or_default();
    let scheme = match hasher {
        "bcrypt" => Scheme::Bcrypt,
        "argon2id" => Scheme::Argon2,
        _ => Scheme::Pbkdf2,
    };
    match hasher {
        "bcrypt" | "argon2id" | "pbkdf2" => log.debug(format_args!("new hasher: {hasher}")),
        _ => log.warn(format_args!(
            "unknown or empty hasher, defaulting to PBKDF2"
        )),
    }
    Arc::new(Verifier {
        scheme,
        utf8_salt: scheme == Scheme::Pbkdf2 && get("hasher_salt_encoding") == Some("utf-8"),
        log: log.clone(),
    })
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Scheme {
    Bcrypt,
    Argon2,
    Pbkdf2,
}

struct Verifier {
    scheme: Scheme,
    utf8_salt: bool,
    log: Log,
}

impl Hasher for Verifier {
    fn compare(&self, password: &[u8], saved: &str) -> bool {
        match self.scheme {
            // hashing/bcrypt.go: Compare. Go checks the first 72 password bytes.
            Scheme::Bcrypt => bcrypt::verify(password, saved).unwrap_or(false),
            Scheme::Argon2 => self.argon2(password, saved).unwrap_or(false),
            Scheme::Pbkdf2 => self.pbkdf2(password, saved.as_bytes()).unwrap_or(false),
        }
    }

    fn compare_bytes(&self, password: &[u8], saved: &[u8]) -> bool {
        if self.scheme == Scheme::Pbkdf2 {
            self.pbkdf2(password, saved).unwrap_or(false)
        } else {
            std::str::from_utf8(saved).is_ok_and(|saved| self.compare(password, saved))
        }
    }
}

impl Verifier {
    // hashing/pbkdf2.go: Compare, getFields, hashWithSalt.
    fn pbkdf2(&self, password: &[u8], saved: &[u8]) -> Option<bool> {
        let mut fields = saved
            .split(|&byte| byte == b'$')
            .filter(|field| !field.is_empty());
        let format = std::str::from_utf8(fields.next()?).ok()?;
        let (algorithm, rounds, specified_len, raw) = match format {
            "PBKDF2" => {
                let algorithm = std::str::from_utf8(fields.next()?).ok()?;
                let rounds = std::str::from_utf8(fields.next()?)
                    .ok()?
                    .parse::<i64>()
                    .ok()?;
                (algorithm, rounds, None, false)
            }
            "pbkdf2-sha512" => {
                let mut rounds = 0;
                let mut length = 0;
                for field in std::str::from_utf8(fields.next()?).ok()?.split(',') {
                    let mut options = field.split('=');
                    while let Some(name) = options.next() {
                        let value = options.next()?;
                        match name {
                            "i" => rounds = value.parse().unwrap_or_default(),
                            "l" => length = value.parse().ok()?,
                            _ => {
                                self.log
                                    .error(format_args!("unknown options key ({name:?})"));
                                return None;
                            }
                        }
                    }
                }
                ("sha512", rounds, Some(length), true)
            }
            _ => {
                self.log.error(format_args!(
                    "invalid PBKDF2 hash supplied, unrecognized format {format:?}"
                ));
                return None;
            }
        };
        let salt = fields.next()?;
        let salt = if self.utf8_salt {
            Cow::Borrowed(salt)
        } else {
            Cow::Owned(decode(std::str::from_utf8(salt).ok()?, raw)?)
        };
        let expected = decode(std::str::from_utf8(fields.next()?).ok()?, raw)?;
        let size = specified_len.unwrap_or(expected.len());
        if expected.is_empty() || size < expected.len() || size > 1024 * 1024 {
            return None;
        }
        // Go always computes U1, even when iterations <= 0. Legacy Compare
        // matches only the stored key's prefix if it is shorter than `l`.
        let rounds = u32::try_from(rounds.max(1)).ok()?;
        let mut actual = vec![0; expected.len()];
        if algorithm == "sha256" {
            pbkdf2::pbkdf2_hmac::<Sha256>(password, &salt, rounds, &mut actual);
        } else {
            pbkdf2::pbkdf2_hmac::<Sha512>(password, &salt, rounds, &mut actual);
        }
        Some(bool::from(actual.ct_eq(&expected)))
    }

    // hashing/argon2id.go: Compare. The saved label mismatch only logs; the
    // actual derivation is always Argon2id, version 0x13.
    fn argon2(&self, password: &[u8], saved: &str) -> Option<bool> {
        let mut fields = saved.split('$');
        fields.next()?;
        let label = fields.next()?;
        if label != "argon2id" {
            self.log.error(format_args!("unknown hash format: {label}"));
        }
        let version = fields.next()?;
        if version
            .strip_prefix("v=")
            .unwrap_or(version)
            .parse::<u32>()
            .ok()?
            != 19
        {
            return None;
        }
        let mut params = fields.next()?.split(',');
        let memory: u32 = params.next()?.strip_prefix("m=")?.parse().ok()?;
        let iterations = params.next()?.strip_prefix("t=")?.parse().ok()?;
        let parallelism: u8 = params.next()?.strip_prefix("p=")?.parse().ok()?;
        let salt = decode(fields.next()?, true)?;
        let expected = decode(fields.next()?, true)?;
        if fields.next().is_some() || memory > 1024 * 1024 {
            return None;
        }
        let parallelism = u32::from(parallelism);
        let params = Params::new(
            memory.max(8 * parallelism),
            iterations,
            parallelism,
            Some(expected.len()),
        )
        .ok()?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut actual = vec![0; expected.len()];
        argon2
            .hash_password_into(password, &salt, &mut actual)
            .ok()?;
        Some(bool::from(actual.ct_eq(&expected)))
    }
}

// Go's StdEncoding allows nonzero trailing bits and ignores CR/LF.
fn decode(value: &str, raw: bool) -> Option<Vec<u8>> {
    let bytes = if value.contains(['\r', '\n']) {
        Cow::Owned(value.replace(['\r', '\n'], "").into_bytes())
    } else {
        Cow::Borrowed(value.as_bytes())
    };
    let mode = if raw {
        base64::engine::DecodePaddingMode::RequireNone
    } else {
        base64::engine::DecodePaddingMode::RequireCanonical
    };
    GeneralPurpose::new(
        &alphabet::STANDARD,
        GeneralPurposeConfig::new()
            .with_decode_allow_trailing_bits(true)
            .with_decode_padding_mode(mode),
    )
    .decode(bytes)
    .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifies_go_auth_pw_vectors() {
        // go-auth's pw -p test-password -i 1500 -l 32, with each requested scheme.
        let log = Log::new(super::super::log::Level::Panic, Box::new(std::io::sink()));
        let p = b"test-password";
        let opts = Options::from([
            ("hasher".into(), "pbkdf2".into()),
            ("hasher_iterations".into(), "2".into()),
            ("hasher_algorithm".into(), "sha256".into()),
        ]);
        let native = "PBKDF2$sha512$1500$EGZIeoyiVKK510hWonaq+g==$2SPfYXtUIWJSkXWebAW+rASLtM4FQ+Dg+9lowmLJq38=";
        let sha256 = "PBKDF2$sha256$1500$B5l3/UaEJXjHofOT95emcg==$Lg4dmpmNsOTD1mVTHpWKD5L/6GgPxImIzWpRzs00Fac=";
        let phc = "$pbkdf2-sha512$i=1500,l=32$EGZIeoyiVKK510hWonaq+g$2SPfYXtUIWJSkXWebAW+rASLtM4FQ+Dg+9lowmLJq38";
        for value in [native, sha256, phc] {
            assert!(new(&opts, "files", &log).compare(p, value));
            assert!(!new(&opts, "files", &log).compare(b"wrong", value));
        }

        let opts = Options::from([
            ("hasher".into(), "pbkdf2".into()),
            ("hasher_salt_encoding".into(), "utf-8".into()),
            ("files_hasher".into(), "pbkdf2".into()),
            ("redis_hasher".into(), "bcrypt".into()),
            ("pg_hasher".into(), "argon2id".into()),
        ]);
        let utf8 =
            b"PBKDF2$sha512$1500$E\xfb\x06l\xa2$NdaBbaNo6/55R2ud2e3qpdzBkZ2LSi24RY4ZJJ9HLHI=";
        // A backend without its own selector inherits global salt options;
        // files uses the default base64 encoding since its selector is explicit.
        assert!(new(&opts, "sqlite", &log).compare_bytes(p, utf8));
        assert!(!new(&opts, "files", &log).compare_bytes(p, utf8));
        assert!(new(&opts, "files", &log).compare(p, native));
        assert!(new(&opts, "redis", &log).compare(
            p,
            "$2a$04$iMgWqobEXzmb6tgM2EiAiOWcgghullltBfSSO9XQo8qNbly0LMI6m"
        ));
        assert!(new(&opts, "pg", &log).compare(p, "$argon2id$v=19$m=4096,t=3,p=2$t0d8K8xY9FoxWrCwYhmA4g$QUQs3xmlbSbUfbD2SjM4R6hyM2QXssX8HraJVtistdY"));
        for value in [
            "",
            "PBKDF2",
            "PBKDF2$sha512$invalid$salt$hash",
            "$pbkdf2-sha512$i,l=1$salt$YPT5",
        ] {
            assert!(!new(&opts, "files", &log).compare(p, value));
        }
        assert!(!new(&opts, "pg", &log).compare(p, "$argon2id$v=19$m=1,t=0,p=0$$"));
    }
}
