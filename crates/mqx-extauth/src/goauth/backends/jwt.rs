//! The mosquitto-go-auth JWT back-end (`jwt.go`, `jwt_{local,remote,files}.go`).

use std::{borrow::Cow, time::SystemTime};

use base64::{Engine, alphabet, engine::GeneralPurpose, engine::general_purpose::NO_PAD};
use hmac::{Hmac, KeyInit, Mac};
use mqx_auth::external::BoxFuture;
use serde::Deserialize;
use serde_json::{Map, Value};

use super::{
    files::Checker,
    http::{Endpoint, Mode, Param},
    sql,
};
use crate::{
    backend::LoadError,
    goauth::backend::{Backend, BackendError, Init, Log},
};

pub(crate) async fn create(init: Init<'_>) -> Result<Box<dyn Backend>, LoadError> {
    // jwt.go: NewJWT. Option spellings and values are case-sensitive.
    init.log.set_level(init.log.level());
    let option = |key| {
        init.options
            .get(key)
            .map(String::as_str)
            .unwrap_or_default()
    };
    let parse_token = option("jwt_parse_token") == "true";
    let tokens = Tokens {
        secret: option("jwt_secret").as_bytes().to_vec(),
        skip_user_expiration: option("jwt_skip_user_expiration") == "true",
        skip_acl_expiration: option("jwt_skip_acl_expiration") == "true",
        user_field: if option("jwt_userfield") == "Username" {
            "username"
        } else {
            "sub"
        },
    };
    let log = init.log.clone();
    let auth = match option("jwt_mode") {
        "remote" => Auth::Remote(Box::new(Endpoint::new(&init, Mode::Jwt, parse_token)?)),
        "local" => {
            // jwt_local.go: NewLocalJWTChecker requires a nonempty secret.
            if tokens.secret.is_empty() {
                return Err(LoadError::new("JWT backend error: missing jwt secret"));
            }
            Auth::Local(sql::create_jwt_local(init).await?)
        }
        "files" => {
            // jwt_files.go: NewFilesJWTChecker loads an ACL file without a password file.
            let path = option("jwt_acl_path");
            if path.is_empty() {
                return Err(LoadError::new("missing acl file path"));
            }
            Auth::Files(Checker::from_acl(path, log.clone())?)
        }
        "js" => return Err(LoadError::new("JWT JS mode is not supported")),
        _ => return Err(LoadError::new("unknown JWT mode")),
    };
    Ok(Box::new(Jwt {
        auth,
        tokens,
        parse_token,
        log,
    }))
}

struct Jwt {
    auth: Auth,
    tokens: Tokens,
    parse_token: bool,
    log: Log,
}

enum Auth {
    Remote(Box<Endpoint>),
    Local(Box<dyn Backend>),
    Files(Checker),
}

struct Tokens {
    secret: Vec<u8>,
    skip_user_expiration: bool,
    skip_acl_expiration: bool,
    user_field: &'static str,
}

impl Backend for Jwt {
    fn name(&self) -> String {
        match self.auth {
            Auth::Remote(_) => "JWT remote",
            Auth::Local(_) => "JWT local",
            Auth::Files(_) => "JWT files",
        }
        .into()
    }

    // jwt.go: GetUser (the MQTT username is the token; password and ID ignored).
    fn get_user<'a>(
        &'a self,
        token: &'a str,
        _password: &'a [u8],
        _client_id: &'a str,
    ) -> BoxFuture<'a, Result<bool, BackendError>> {
        Box::pin(async move {
            match &self.auth {
                Auth::Remote(endpoint) => {
                    self.remote_auth(
                        endpoint,
                        token,
                        &endpoint.user_uri,
                        "jwt remote get user error",
                    )
                    .await
                }
                Auth::Local(connector) => {
                    let username = self.username(token, false, "jwt local get user error")?;
                    // jwt_local.go: getLocalUser runs jwt_userquery as a count query.
                    connector.get_user(&username, b"", "").await
                }
                Auth::Files(_) => Ok(false), // jwt_files.go: GetUser
            }
        })
    }

    fn get_superuser<'a>(&'a self, token: &'a str) -> BoxFuture<'a, Result<bool, BackendError>> {
        Box::pin(async move {
            match &self.auth {
                Auth::Remote(endpoint) if endpoint.superuser_uri.is_empty() => Ok(false),
                Auth::Remote(endpoint) => {
                    self.remote_auth(
                        endpoint,
                        token,
                        &endpoint.superuser_uri,
                        "jwt remote get superuser error",
                    )
                    .await
                }
                Auth::Local(connector) => {
                    // jwt_local.go: GetSuperuser uses the user-expiration setting.
                    let username = self.username(token, false, "jwt local get superuser error")?;
                    connector.get_superuser(&username).await
                }
                Auth::Files(_) => Ok(false), // jwt_files.go: GetSuperuser
            }
        })
    }

    fn check_acl<'a>(
        &'a self,
        token: &'a str,
        topic: &'a str,
        client_id: &'a str,
        acc: i32,
    ) -> BoxFuture<'a, Result<bool, BackendError>> {
        Box::pin(async move {
            match &self.auth {
                Auth::Remote(endpoint) => {
                    // jwt_remote.go: CheckAcl adds username only when parsing is enabled.
                    let username = self
                        .parse_token
                        .then(|| self.username(token, true, "jwt remote check acl error"))
                        .transpose()?;
                    let mut params = [
                        ("acc", Param::Int(acc)),
                        ("clientid", Param::text(client_id)),
                        ("topic", Param::text(topic)),
                        ("username", Param::text("")),
                    ];
                    let params = if let Some(username) = &username {
                        params[3].1 = Param::text(username);
                        &params[..]
                    } else {
                        &params[..3]
                    };
                    let host = self.remote_host(endpoint, token)?;
                    endpoint
                        .request(&host, &endpoint.acl_uri, token, Some(token), Some(params))
                        .await
                }
                Auth::Local(connector) => {
                    let username = self.username(token, true, "jwt local check acl error")?;
                    connector.check_acl(&username, topic, client_id, acc).await
                }
                Auth::Files(checker) => {
                    // jwt_files.go: CheckAcl always parses, regardless of jwt_parse_token.
                    let username = self.username(token, true, "jwt get user error")?;
                    Ok(checker.check_acl(&username, topic, client_id, acc))
                }
            }
        })
    }

    fn halt(&self) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            // jwt.go: Halt; jwt_local.go: Halt closes the database connector.
            if let Auth::Local(connector) = &self.auth {
                connector.halt().await;
            }
        })
    }
}

impl Jwt {
    async fn remote_auth(
        &self,
        endpoint: &Endpoint,
        token: &str,
        uri: &str,
        error_prefix: &str,
    ) -> Result<bool, BackendError> {
        // jwt_remote.go: GetUser, GetSuperuser. No username sends JSON null.
        let username = self
            .parse_token
            .then(|| self.username(token, false, error_prefix))
            .transpose()?;
        let host = self.remote_host(endpoint, token)?;
        let params = username
            .as_deref()
            .map(|username| [("username", Param::text(username))]);
        endpoint
            .request(
                &host,
                uri,
                token,
                Some(token),
                params.as_ref().map(|array| &array[..]),
            )
            .await
    }

    fn username(&self, token: &str, acl: bool, error_prefix: &str) -> Result<String, BackendError> {
        let skip_expiration = if acl {
            self.tokens.skip_acl_expiration
        } else {
            self.tokens.skip_user_expiration
        };
        self.tokens
            .claim(
                token,
                self.tokens.user_field,
                skip_expiration,
                "username",
                &self.log,
            )
            .inspect_err(|err| {
                self.log.info(format_args!("{error_prefix}: {err}"));
            })
    }

    fn remote_host<'a>(
        &self,
        endpoint: &'a Endpoint,
        token: &str,
    ) -> Result<Cow<'a, str>, BackendError> {
        // jwt_remote.go: getHost deliberately uses skipUserExpiration even for ACL calls.
        if !endpoint.host.is_empty() {
            return Ok(Cow::Borrowed(&endpoint.host));
        }
        if !self.parse_token {
            return Err(BackendError::new(
                "impossible to obtain host for the authorization request - token parsing is turned off",
            ));
        }
        let issuer = self
            .tokens
            .claim(
                token,
                "iss",
                self.tokens.skip_user_expiration,
                "iss",
                &self.log,
            )
            .map_err(|err| {
                BackendError::new(format!(
                    "cannot obtain host for the authorization request from token {token}: {err}"
                ))
            })?;
        if endpoint.whitelist != ["*"] && !endpoint.whitelist.contains(&issuer) {
            return Err(BackendError::new(format!(
                "host {issuer} obtained from host is not whitelisted; rejecting"
            )));
        }
        Ok(Cow::Owned(issuer))
    }
}

impl Tokens {
    // jwt.go: getUsernameForToken, getIssForToken.
    fn claim(
        &self,
        token: &str,
        key: &str,
        skip_expiration: bool,
        label: &str,
        log: &Log,
    ) -> Result<String, BackendError> {
        let claims = self.claims(token, skip_expiration).inspect_err(|err| {
            if !skip_expiration {
                log.debug(format_args!("jwt parse error: {err}"));
            }
        })?;
        match claims.and_then(|mut object| object.remove(key)) {
            None => Ok(String::new()),
            Some(Value::String(value)) => Ok(value),
            Some(_) => Err(BackendError::new(format!("got strange {label}"))),
        }
    }

    // jwt.go: getJWTClaims. golang-jwt parser.go: ParseWithClaims takes
    // a raw byte key, valid only for the built-in HMAC signing methods.
    fn claims(
        &self,
        token: &str,
        skip_expiration: bool,
    ) -> Result<Option<Map<String, Value>>, BackendError> {
        let reject = |error: &str| {
            BackendError::new(if skip_expiration {
                "jwt invalid token"
            } else {
                error
            })
        };
        let (message, signature) = token
            .rsplit_once('.')
            .ok_or_else(|| reject("token contains an invalid number of segments"))?;
        let (header, claims) = message
            .split_once('.')
            .filter(|(_, claims)| !claims.contains('.'))
            .ok_or_else(|| reject("token contains an invalid number of segments"))?;
        let decode =
            |segment| decode_segment(segment).map_err(|_| reject("illegal base64 data in JWT"));
        let header: Value = serde_json::from_slice(&decode(header)?)
            .map_err(|_| reject("invalid JWT header JSON"))?;
        let claims = decode(claims)?;
        // The claims decoder reads only the first JSON value, unlike json.Unmarshal on the header.
        let claims: Option<Map<String, Value>> =
            Deserialize::deserialize(&mut serde_json::Deserializer::from_slice(&claims))
                .map_err(|_| reject("invalid JWT claims JSON"))?;
        let algorithm = header
            .get("alg")
            .and_then(Value::as_str)
            .ok_or_else(|| reject("signing method (alg) is unspecified."))?;
        let signature = decode(signature)?;
        macro_rules! verify {
            ($hash:ty) => {{
                let mut mac = <Hmac<$hash> as KeyInit>::new_from_slice(&self.secret)
                    .expect("HMAC accepts every key length");
                mac.update(message.as_bytes());
                mac.verify_slice(&signature).is_ok()
            }};
        }
        let valid = match algorithm {
            "HS256" => verify!(sha2::Sha256),
            "HS384" => verify!(sha2::Sha384),
            "HS512" => verify!(sha2::Sha512),
            "none" => return Err(reject("'none' signature type is not allowed")),
            _ => return Err(reject("signing method cannot verify a byte key")),
        };
        if !valid {
            return Err(reject("signature is invalid"));
        }
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |time| time.as_secs() as i64);
        if let Some(claims) = &claims {
            // map_claims.go: MapClaims.Valid and claims.go: verifyExp/verifyIat/verifyNbf.
            // A nonnumeric claim is invalid; zero and absent timestamps do not restrict it.
            let time_ok = |key, compare: fn(i64, i64) -> bool| {
                claims.get(key).is_none_or(|value| {
                    value.as_f64().is_some_and(|value| {
                        // Go parses into float64 and truncates toward zero.
                        let time = if value >= 9_223_372_036_854_775_808.0 {
                            i64::MIN
                        } else {
                            value as i64
                        };
                        time == 0 || compare(time, now)
                    })
                })
            };
            if !time_ok("nbf", |time, now| time <= now) {
                return Err(reject("Token is not valid yet"));
            }
            if !time_ok("iat", |time, now| time <= now) {
                return Err(reject("Token used before issued"));
            }
            if !time_ok("exp", |time, now| now <= time) && !skip_expiration {
                return Err(reject("Token is expired"));
            }
        }
        Ok(claims)
    }
}

fn decode_segment(segment: &str) -> Result<Vec<u8>, base64::DecodeError> {
    // token.go: DecodeSegment uses Go RawURLEncoding (accepts trailing bits and CR/LF).
    const ENGINE: GeneralPurpose = GeneralPurpose::new(
        &alphabet::URL_SAFE,
        NO_PAD.with_decode_allow_trailing_bits(true),
    );
    if segment.contains(['\r', '\n']) {
        ENGINE.decode(segment.replace(['\r', '\n'], ""))
    } else {
        ENGINE.decode(segment)
    }
}
