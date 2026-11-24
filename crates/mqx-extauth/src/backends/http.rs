use std::fmt::Write as _;

use mqx_auth::external::BoxFuture;
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, percent_encode};

use crate::authplug::{atoi, log, log_enabled};
use crate::backend::{Backend, BackendResult, GetUser, LoadError, Options};
use crate::net::http::{Auth, Client};

#[derive(Clone, Copy)]
pub(super) enum Method {
    Getuser,
    Superuser,
    Acl,
}

struct Endpoint {
    url: String,
    params: Option<String>,
}

pub(super) struct Post {
    client: Client,
    host_header: Option<String>,
    endpoints: [Endpoint; 3],
}

impl Post {
    pub(super) fn new(options: &Options, jwt: bool) -> Result<Self, LoadError> {
        // be-http.c: be_http_init; be-jwt.c: be_jwt_init. HTTP connects to
        // http_ip first; JWT requires http_ip but prefers http_hostname.
        let ip = options.get("http_ip");
        let hostname = options.get("http_hostname");
        let host = if jwt {
            let ip = ip.ok_or_else(|| LoadError::new("Mandatory parameter `http_ip' missing"))?;
            hostname.unwrap_or(ip)
        } else {
            ip.or(hostname).ok_or_else(|| {
                LoadError::new(
                    "Mandatory parameter: one of either `http_ip' or `http_hostname' required",
                )
            })?
        };
        let uri = |key| {
            options
                .get(key)
                .ok_or_else(|| LoadError::new(format!("Mandatory parameter `{key}' missing")))
        };
        let uris = [
            uri("http_getuser_uri")?,
            uri("http_superuser_uri")?,
            uri("http_aclcheck_uri")?,
        ];
        let params = [
            options.get("http_getuser_params"),
            options.get("http_superuser_params"),
            options.get("http_aclcheck_params"),
        ];
        let with_tls = options.get("http_with_tls").unwrap_or("false");
        let port = atoi(options.get("http_port").unwrap_or("80").as_bytes());
        let scheme = if with_tls == "true" { "https" } else { "http" };
        let client =
            Client::new(with_tls == "true").map_err(|_| LoadError::new("init curl fail"))?;
        let endpoints = std::array::from_fn(|i| Endpoint {
            url: format!("{scheme}://{host}:{port}{}", uris[i]),
            params: params[i].map(str::to_owned),
        });
        log(format_args!("with_tls={with_tls}"));
        log(format_args!("getuser_uri={}", uris[0]));
        log(format_args!("superuser_uri={}", uris[1]));
        log(format_args!("aclcheck_uri={}", uris[2]));
        log(format_args!(
            "getuser_params={}",
            params[0].unwrap_or("(null)")
        ));
        log(format_args!(
            "superuser_params={}",
            params[1].unwrap_or("(null)")
        ));
        let acl_key = if jwt {
            "aclcheck_paramsi"
        } else {
            "aclcheck_params"
        };
        log(format_args!("{acl_key}={}", params[2].unwrap_or("(null)")));
        Ok(Self {
            client,
            host_header: hostname.map(str::to_owned),
            endpoints,
        })
    }

    pub(super) async fn send(
        &self,
        method: Method,
        authorization: Auth<'_>,
        fields: impl Fn(&mut String, bool),
        redact_fields: bool,
    ) -> BackendResult {
        let Endpoint { url, params } = &self.endpoints[method as usize];
        let body = |redact| {
            let mut body = String::new();
            append_env(&mut body, params.as_deref(), redact);
            fields(&mut body, redact);
            body
        };
        let wire = body(false);
        if log_enabled() {
            log(format_args!("url={url}"));
            if params.is_some() || redact_fields {
                log(format_args!("data={}", body(true)));
            } else {
                log(format_args!("data={wire}"));
            }
        }
        // be-http.c and be-jwt.c: http_post. Only 2xx grants; 5xx and
        // transport failures are errors, every other status defers.
        match self
            .client
            .post(url, self.host_header.as_deref(), authorization, wire)
            .await
        {
            Ok(200..=299) => BackendResult::Allow,
            Ok(500..) => BackendResult::Error,
            Ok(_) => BackendResult::Defer,
            Err(error) => {
                log(format_args!("http req fail url={url} re={error}"));
                BackendResult::Error
            }
        }
    }
}

// curl_easy_escape keeps only unreserved ASCII and emits uppercase %HH for
// every other byte (including spaces, never '+').
const CURL_ESCAPE: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

pub(super) fn escape(bytes: &[u8]) -> percent_encoding::PercentEncode<'_> {
    percent_encode(bytes, CURL_ESCAPE)
}

fn append_env(body: &mut String, params: Option<&str>, redact: bool) {
    // envs.c: get_sys_envs uses strtok twice, skips empty pieces, and
    // discards everything after the second equals-delimited token.
    for pair in params
        .into_iter()
        .flat_map(|p| p.split(','))
        .filter(|p| !p.is_empty())
        .take(20)
    {
        let mut fields = pair.split('=').filter(|s| !s.is_empty());
        let Some(key) = fields.next() else { continue };
        let environment = if redact {
            None
        } else {
            fields.next().and_then(std::env::var_os)
        };
        let value = if redact {
            b"<redacted>".as_slice()
        } else {
            environment
                .as_ref()
                .map_or(b"NULL".as_slice(), |value| value.as_encoded_bytes())
        };
        let _ = write!(body, "{}={}&", escape(key.as_bytes()), escape(value));
    }
}

struct Http {
    post: Post,
    auth_override: Option<String>,
    retries: i32,
    redact_username: bool,
}

pub(crate) async fn create(options: &Options) -> Result<Box<dyn Backend>, LoadError> {
    let post = Post::new(options, false)?;
    let retries = atoi(options.get("http_retry_count").unwrap_or("3").as_bytes());
    log(format_args!("retry_count={retries}"));
    let auth_override = options
        .get("http_basic_auth_key")
        .map(|key| format!("Basic {key}"));
    let redact_username = options
        .get("backends")
        .is_some_and(|order| crate::authplug::backend_names(order).any(|name| name == "jwt"));
    Ok(Box::new(Http {
        post,
        auth_override,
        retries,
        redact_username,
    }))
}

impl Http {
    async fn check(
        &self,
        method: Method,
        username: &str,
        password: &[u8],
        client_id: &str,
        topic: &str,
        access: i32,
    ) -> BackendResult {
        // be-http.c: be_http_getuser, be_http_superuser, be_http_aclcheck.
        // Even retry_count=0 tries once; a negative value tries zero times.
        for _ in 0..=self.retries {
            let auth = self
                .auth_override
                .as_deref()
                .map_or(Auth::Basic(username, password), Auth::Header);
            let verdict = self
                .post
                .send(
                    method,
                    auth,
                    |body, redact| {
                        let user = if redact && self.redact_username {
                            b"<redacted>"
                        } else {
                            username.as_bytes()
                        };
                        let password = if redact && !password.is_empty() {
                            b"<redacted>"
                        } else {
                            password
                        };
                        // be-http.c: http_post computes escaped_clientid but uses
                        // the original clientid in the form body.
                        let _ = write!(
                            body,
                            "username={}&password={}&topic={}&acc={access}&clientid={client_id}",
                            escape(user),
                            escape(password),
                            escape(topic.as_bytes())
                        );
                    },
                    self.redact_username || !password.is_empty(),
                )
                .await;
            if verdict != BackendResult::Error {
                return verdict;
            }
        }
        BackendResult::Error
    }
}

impl Backend for Http {
    fn name(&self) -> &'static str {
        "http"
    }

    fn getuser<'a>(
        &'a self,
        username: &'a str,
        password: &'a [u8],
        _: &'a str,
    ) -> BoxFuture<'a, GetUser> {
        Box::pin(async move {
            GetUser::result(
                self.check(Method::Getuser, username, password, "", "", -1)
                    .await,
            )
        })
    }

    fn superuser<'a>(&'a self, username: &'a str) -> BoxFuture<'a, BackendResult> {
        Box::pin(async move {
            self.check(Method::Superuser, username, b"", "", "", -1)
                .await
        })
    }

    fn aclcheck<'a>(
        &'a self,
        client_id: &'a str,
        username: &'a str,
        topic: &'a str,
        access: i32,
    ) -> BoxFuture<'a, BackendResult> {
        Box::pin(async move {
            self.check(Method::Acl, username, b"", client_id, topic, access)
                .await
        })
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn curl_escape_is_bytewise_and_env_parser_skips_delimiters() {
        assert_eq!(
            super::escape(b"a b+c/%?=~\xff").to_string(),
            "a%20b%2Bc%2F%25%3F%3D~%FF"
        );
        let mut body = String::new();
        super::append_env(
            &mut body,
            Some(",frm ==MQX_AUTH_DOES_NOT_EXIST=ignored,,other=MQX_AUTH_ME_NEITHER"),
            false,
        );
        assert_eq!(body, "frm%20=NULL&other=NULL&");
    }
}
