//! Offline verification of KMS-signed MQTT CONNECT credentials.

use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    future::ready,
    io::Read,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use mqx_auth::external::{
    AclAccess, AclIdentity, Authorization, BoxFuture, ExternalSecurity, Subject, Verdict,
};
use openssl::{
    hash::MessageDigest,
    pkey::{Id, PKey, Public},
    rsa::Padding,
    sign::Verifier,
};
use serde::Deserialize;

use crate::LoadError;

const KEY_PREFIX: &str = "public_key_";
const MAX_PEM_BYTES: u64 = 16 * 1024;
const MAX_TOKEN_BYTES: usize = 6 * 1024;
const MAX_SIGNATURE_BYTES: usize = 2048;
const MAX_LIFETIME: u64 = 60;
const MAX_FUTURE_SKEW: u64 = 5;

pub(crate) fn load(options: Vec<(String, String)>) -> Result<Arc<dyn ExternalSecurity>, LoadError> {
    Ok(Arc::new(Kms::from_options(options)?))
}

struct Kms {
    audience: String,
    keys: BTreeMap<String, PKey<Public>>,
}

impl Kms {
    fn from_options(options: Vec<(String, String)>) -> Result<Self, LoadError> {
        let failure = |message| LoadError::new(format!("mqext-kms: {message}"));
        let mut audience = None;
        let mut keys = BTreeMap::new();
        let mut public_keys = BTreeSet::new();
        for (name, value) in options {
            if name == "audience" {
                if audience.is_some() {
                    return Err(failure("duplicate plugin_opt_audience"));
                }
                if !(1..=255).contains(&value.len())
                    || !value.bytes().all(|byte| (b' '..=b'~').contains(&byte))
                {
                    return Err(failure(
                        "plugin_opt_audience must be 1–255 printable ASCII characters",
                    ));
                }
                audience = Some(value);
            } else if let Some(user) = name.strip_prefix(KEY_PREFIX) {
                if !name_part(user, 64) {
                    return Err(failure(
                        "invalid username in a plugin_opt_public_key_ option",
                    ));
                }
                if keys.contains_key(user) {
                    return Err(LoadError::new(format!(
                        "mqext-kms: duplicate public key option for '{user}'"
                    )));
                }
                let (key, modulus) = read_public_key(&value).ok_or_else(|| {
                    LoadError::new(format!(
                        "mqext-kms: cannot load '{value}' for '{user}' as one RSA SPKI PEM public key (2048–16384 bits)"
                    ))
                })?;
                // Principals must have independent moduli, regardless of PEM encoding.
                if !public_keys.insert(modulus) {
                    return Err(LoadError::new(format!(
                        "mqext-kms: public key for '{user}' is already pinned to another username"
                    )));
                }
                keys.insert(user.to_owned(), key);
            } else {
                return Err(LoadError::new(format!(
                    "mqext-kms: unknown option '{name}'"
                )));
            }
        }
        let audience = audience.ok_or_else(|| failure("missing plugin_opt_audience"))?;
        if keys.is_empty() {
            return Err(failure(
                "configure at least one plugin_opt_public_key_<user>",
            ));
        }
        Ok(Self { audience, keys })
    }

    fn verify(&self, client_id: &str, username: &str, token: &[u8], now: u64) -> Option<()> {
        if token.len() > MAX_TOKEN_BYTES
            || !name_part(username, 64)
            || !client_id
                .strip_prefix(username)
                .and_then(|rest| rest.strip_prefix('.'))
                .is_some_and(|suffix| name_part(suffix, 128))
        {
            return None;
        }
        let key = self.keys.get(username)?;
        let mut segments = token.split(|&byte| byte == b'.');
        let protected = segments.next()?;
        let payload = segments.next()?;
        let encoded_signature = segments.next()?;
        if segments.next().is_some() {
            return None;
        }
        let mut header_bytes = [0; 128];
        let header: Header<'_> = decode_object(protected, &mut header_bytes)?;
        if header.alg != "RS256" || header.typ != "JWT" {
            return None;
        }
        let mut claim_bytes = [0; 2048];
        let claims: Claims<'_> = decode_object(payload, &mut claim_bytes)?;
        if claims.aud.as_ref() != self.audience.as_str()
            || claims.sub.as_ref() != username
            || claims.client_id.as_ref() != client_id
            || claims.iat > now.checked_add(MAX_FUTURE_SKEW)?
            || claims.exp <= now
            || !(1..=MAX_LIFETIME).contains(&claims.exp.checked_sub(claims.iat)?)
        {
            return None;
        }
        let mut signature = [0; MAX_SIGNATURE_BYTES];
        let len = URL_SAFE_NO_PAD
            .decode_slice(encoded_signature, &mut signature)
            .ok()?;
        if len != key.size() {
            return None;
        }
        let mut verifier = Verifier::new(MessageDigest::sha256(), key).ok()?;
        verifier.set_rsa_padding(Padding::PKCS1).ok()?;
        let signing_input = &token[..protected.len() + 1 + payload.len()];
        verifier
            .verify_oneshot(&signature[..len], signing_input)
            .ok()?
            .then_some(())
    }
}

fn name_part(value: &str, max: usize) -> bool {
    (1..=max).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn read_public_key(path: &str) -> Option<(PKey<Public>, Vec<u8>)> {
    if !fs::metadata(path).ok()?.is_file() {
        return None;
    }
    let mut pem = Vec::new();
    File::open(path)
        .ok()?
        .take(MAX_PEM_BYTES + 1)
        .read_to_end(&mut pem)
        .ok()?;
    if pem.len() as u64 > MAX_PEM_BYTES {
        return None;
    }
    let body = pem
        .trim_ascii()
        .strip_prefix(b"-----BEGIN PUBLIC KEY-----")?
        .strip_suffix(b"-----END PUBLIC KEY-----")?;
    // Do not let OpenSSL select the first matching block from a bundle.
    if body.contains(&b'-') {
        return None;
    }
    let key = PKey::public_key_from_pem(&pem).ok()?;
    if key.id() != Id::RSA || key.bits() < 2048 || key.size() > MAX_SIGNATURE_BYTES {
        return None;
    }
    let rsa = key.rsa().ok()?;
    let (n, e) = (rsa.n(), rsa.e());
    if n.is_negative()
        || !n.is_odd()
        || e.is_negative()
        || e.num_bits() < 2
        || !e.is_odd()
        || !e.ucmp(n).is_lt()
    {
        return None;
    }
    Some((key, n.to_vec()))
}

fn decode_object<'a, T: Deserialize<'a>>(encoded: &[u8], output: &'a mut [u8]) -> Option<T> {
    let len = URL_SAFE_NO_PAD.decode_slice(encoded, output).ok()?;
    let json = &output[..len];
    if json.trim_ascii_start().first() != Some(&b'{') {
        return None;
    }
    serde_json::from_slice(json).ok()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Header<'a> {
    alg: &'a str,
    typ: &'a str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Claims<'a> {
    #[serde(borrow)]
    aud: Cow<'a, str>,
    #[serde(borrow)]
    sub: Cow<'a, str>,
    #[serde(borrow)]
    client_id: Cow<'a, str>,
    iat: u64,
    exp: u64,
}

impl ExternalSecurity for Kms {
    fn deny_special_chars(&self) -> bool {
        // This plugin never registers an ACL check.
        false
    }

    fn connect_only_authentication(&self) -> bool {
        true
    }

    fn authenticate<'a>(
        &'a self,
        client_id: &'a str,
        username: Option<&'a str>,
        password: Option<&'a [u8]>,
    ) -> BoxFuture<'a, Verdict> {
        let accepted = username.zip(password).is_some_and(|(username, password)| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .ok()
                .is_some_and(|now| {
                    self.verify(client_id, username, password, now.as_secs())
                        .is_some()
                })
        });
        Box::pin(ready(if accepted {
            Verdict::Allow
        } else {
            Verdict::Deny
        }))
    }

    fn acl_identity(&self, _: Subject<'_>) -> Option<AclIdentity> {
        None
    }

    fn authorize<'a>(
        &'a self,
        _: &'a AclIdentity,
        _: &'a str,
        _: AclAccess,
    ) -> BoxFuture<'a, Authorization> {
        Box::pin(ready(Authorization {
            verdict: Verdict::Defer,
            reuse_for: Duration::ZERO,
        }))
    }
}

#[cfg(test)]
mod tests;
