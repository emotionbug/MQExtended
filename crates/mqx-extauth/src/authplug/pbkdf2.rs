use base64::{Engine, engine::general_purpose::STANDARD};
use openssl::{hash::MessageDigest, pkcs5::pbkdf2_hmac};
use subtle::ConstantTimeEq;

// pbkdf2-check.c: detoken, pbkdf2_check. Decode to determine the output
// length, then check those bytes. The decoder requires canonical base64,
// which the C verifier enforces by re-encoding the derived key.
pub(super) fn check(password: &[u8], hash: &str) -> bool {
    let mut fields = hash.split('$');
    let (Some("PBKDF2"), Some(digest), Some(iter), Some(salt), Some(key)) = (
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
    ) else {
        return false;
    };
    let Ok(iterations) = usize::try_from(super::atoi(iter.as_bytes())) else {
        return false;
    };
    if iterations == 0 {
        return false;
    }
    let Ok(key) = STANDARD.decode(key) else {
        return false;
    };
    if key.is_empty() {
        return false;
    }
    let digest = match digest {
        "sha1" => MessageDigest::sha1(),
        "sha512" => MessageDigest::sha512(),
        _ => MessageDigest::sha256(),
    };
    let mut output = vec![0; key.len()];
    pbkdf2_hmac(password, salt.as_bytes(), iterations, digest, &mut output).is_ok()
        && bool::from(key.ct_eq(&output))
}

#[cfg(test)]
mod tests {
    use super::check;

    pub(crate) const NP_HASH: &str =
        "PBKDF2$sha256$901$QrqEwoNkUOWjr3Dg$6CbjEcRO6xEy2Bxa3gXtAYOYGpErf2KH";

    #[test]
    fn reference_np_and_python_hashlib_vectors() {
        // `/tmp/mosquitto-auth-plug/np -p password`.
        assert!(check(b"password", NP_HASH));
        assert!(!check(b"password!", NP_HASH));
        // Python hashlib.pbkdf2_hmac with dklen=20, 24 and 47 respectively.
        assert!(check(
            b"password",
            "PBKDF2$sha1$  +2abc$sa lt$xfgmmQr8qZLBsZXrF94I90J+uRQ="
        ));
        assert!(check(
            b"password",
            "PBKDF2$unknown$9$c2FsdA==$9EQzL3BudMGpmrPsw3yb0IKHkJ6ZzzGv$ignored"
        ));
        assert!(check(
            b"\xffp",
            "PBKDF2$sha512$10$salt$mUw1sdgiBpKQ8lLqM3eJsrhBzIr8oD3VxtoyDKYWc3f9gxfCpJa1mNqLfulg5dI="
        ));
        assert!(!check(
            b"password",
            "PBKDF2$sha1$2$sa lt$xfgmmQr8qZLBsZXrF94I90J+uRR="
        ));
        assert!(!check(b"password", "PBKDF2$sha256$-1$salt$aaaa"));
        assert!(!check(b"password", "PBKDF2$sha256$1$salt$"));
        assert!(!check(
            b"password",
            "pbkdf2_sha1$2$sa lt$xfgmmQr8qZLBsZXrF94I90J+uRQ="
        ));
    }
}
