use super::*;
use openssl::{pkey::Private, rsa::Rsa, sign::Signer};
use serde_json::{Value, json};
use tempfile::NamedTempFile;

const AUDIENCE: &str = "test broker \"a\"\\tls";
const HEADER: &str = r#"{"alg":"RS256","typ":"JWT"}"#;
const NOW: u64 = 12_345;

fn key(bits: u32) -> PKey<Private> {
    PKey::from_rsa(Rsa::generate(bits).unwrap()).unwrap()
}

fn named_pem(pem: &[u8]) -> NamedTempFile {
    let file = NamedTempFile::new().unwrap();
    fs::write(file.path(), pem).unwrap();
    file
}

fn option(name: &str, value: &str) -> (String, String) {
    (name.into(), value.into())
}

fn pin(user: &str, file: &NamedTempFile) -> (String, String) {
    (
        format!("public_key_{user}"),
        file.path().to_str().unwrap().into(),
    )
}

fn claims(iat: u64, exp: u64) -> Value {
    json!({"aud": AUDIENCE, "sub": "sensor", "client_id": "sensor.unit-1", "iat": iat, "exp": exp})
}

fn sign(key: &PKey<Private>, header: &str, claims: &str, padding: Padding) -> String {
    let header = URL_SAFE_NO_PAD.encode(header);
    let claims = URL_SAFE_NO_PAD.encode(claims);
    let input = format!("{header}.{claims}");
    let mut signer = Signer::new(MessageDigest::sha256(), key).unwrap();
    signer.set_rsa_padding(padding).unwrap();
    let sig = signer.sign_oneshot_to_vec(input.as_bytes()).unwrap();
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig))
}

#[test]
fn kms_binds_tokens_to_the_principal_client_audience_time_and_algorithm() {
    let signing_key = key(2048);
    let pem = named_pem(&signing_key.public_key_to_pem().unwrap());
    let plugin =
        Kms::from_options(vec![option("audience", AUDIENCE), pin("sensor", &pem)]).unwrap();
    let signed = |claims: &Value| sign(&signing_key, HEADER, &claims.to_string(), Padding::PKCS1);
    let accepted = |token: &str| plugin.verify("sensor.unit-1", "sensor", token.as_bytes(), NOW);
    let good_claims = claims(NOW, NOW + 60);
    let good = signed(&good_claims);
    assert!(accepted(&good).is_some());
    assert!(
        plugin
            .verify("sensor.unit-2", "sensor", good.as_bytes(), NOW)
            .is_none()
    );
    assert!(
        plugin
            .verify("sensor.unit-1", "other", good.as_bytes(), NOW)
            .is_none()
    );
    assert!(accepted(&signed(&claims(NOW + 5, NOW + 65))).is_some());
    assert!(accepted(&signed(&claims(NOW - 59, NOW + 1))).is_some());
    for (iat, exp) in [
        (NOW + 6, NOW + 66),
        (NOW - 60, NOW),
        (NOW, NOW + 61),
        (NOW + 1, NOW + 1),
        (NOW + 2, NOW + 1),
    ] {
        assert!(
            accepted(&signed(&claims(iat, exp))).is_none(),
            "{iat}, {exp}"
        );
    }
    for (field, value) in [
        ("aud", json!("other broker")),
        ("aud", json!([AUDIENCE])),
        ("sub", json!("other")),
        ("client_id", json!("sensor.unit-2")),
        ("iat", json!(NOW.to_string())),
        ("iat", json!(-1)),
        ("exp", json!(NOW as f64 + 1.5)),
    ] {
        let mut wrong = good_claims.clone();
        wrong[field] = value;
        assert!(accepted(&signed(&wrong)).is_none(), "{field}");
    }
    for invalid_id in [
        "sensor",
        "sensor.",
        "sensor.a.b",
        "sensor.a/b",
        "other.unit-1",
    ] {
        let mut wrong = good_claims.clone();
        wrong["client_id"] = json!(invalid_id);
        assert!(
            plugin
                .verify(invalid_id, "sensor", signed(&wrong).as_bytes(), NOW)
                .is_none()
        );
    }
    let payload = good_claims.to_string();
    assert!(accepted(&sign(&key(2048), HEADER, &payload, Padding::PKCS1)).is_none());
    assert!(accepted(&sign(&signing_key, HEADER, &payload, Padding::PKCS1_PSS)).is_none());
}

#[test]
fn kms_rejects_non_compact_and_ambiguous_tokens() {
    let signing_key = key(2048);
    let pem = named_pem(&signing_key.public_key_to_pem().unwrap());
    let plugin =
        Kms::from_options(vec![option("audience", AUDIENCE), pin("sensor", &pem)]).unwrap();
    let signed = |header: &str, payload: &str| sign(&signing_key, header, payload, Padding::PKCS1);
    let verify = |token: &str| plugin.verify("sensor.unit-1", "sensor", token.as_bytes(), NOW);
    let payload = claims(NOW, NOW + 60).to_string();
    for header in [
        r#"{"alg":"none","typ":"JWT"}"#,
        r#"{"alg":"RS256","typ":"JWT","jku":"https://example.invalid/jwks"}"#,
        r#"{"alg":"RS256","alg":"RS256","typ":"JWT"}"#,
        r#"{"alg":"RS256"}"#,
        r#"["RS256","JWT"]"#,
    ] {
        assert!(verify(&signed(header, &payload)).is_none(), "{header}");
    }
    for claims in [
        format!(r#"{{"sub":"sensor",{}"#, &payload[1..]),
        format!(r#"{{"extra":true,{}"#, &payload[1..]),
        format!("{}{}", " ".repeat(2048), payload),
    ] {
        assert!(verify(&signed(HEADER, &claims)).is_none());
    }
    let good = signed(HEADER, &payload);
    for malformed in [
        String::new(),
        "x".repeat(MAX_TOKEN_BYTES + 1),
        format!("{good}="),
        format!("{good}."),
        format!("{good}\0"),
        format!("{good}\n"),
    ] {
        assert!(verify(&malformed).is_none());
    }
}

#[test]
fn kms_pins_one_distinct_spki_rsa_key_per_username() {
    let signing_key = key(2048);
    let public = signing_key.public_key_to_pem().unwrap();
    let pem = named_pem(&public);
    let same_key = named_pem(&public);
    let weak = named_pem(&key(1024).public_key_to_pem().unwrap());
    let bundle = named_pem(&public.repeat(2));
    let pkcs1 = named_pem(
        &signing_key
            .rsa()
            .unwrap()
            .public_key_to_pem_pkcs1()
            .unwrap(),
    );
    for invalid in [
        vec![pin("sensor", &pem)],
        vec![option("audience", "broker")],
        vec![option("audience", "bad\naudience"), pin("sensor", &pem)],
        vec![
            option("audience", "broker"),
            option("audience", "broker"),
            pin("sensor", &pem),
        ],
        vec![
            option("audience", "broker"),
            pin("sensor", &pem),
            pin("sensor", &pem),
        ],
        vec![
            option("audience", "broker"),
            pin("sensor", &pem),
            pin("other", &same_key),
        ],
        vec![option("audience", "broker"), pin("sensor/other", &pem)],
        vec![option("audience", "broker"), pin("sensor", &weak)],
        vec![option("audience", "broker"), pin("sensor", &bundle)],
        vec![option("audience", "broker"), pin("sensor", &pkcs1)],
        vec![
            option("audience", "broker"),
            pin("sensor", &pem),
            option("algorithm", "RS256"),
        ],
    ] {
        assert!(Kms::from_options(invalid).is_err());
    }
}
