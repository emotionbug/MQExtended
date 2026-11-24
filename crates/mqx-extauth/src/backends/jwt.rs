use std::fmt::Write as _;

use mqx_auth::external::BoxFuture;

use super::http::{Method, Post, escape};
use crate::backend::{Backend, BackendResult, GetUser, LoadError, Options};
use crate::net::http::Auth;

struct Jwt(Post);

pub(crate) async fn create(options: &Options) -> Result<Box<dyn Backend>, LoadError> {
    Ok(Box::new(Jwt(Post::new(options, true)?)))
}

impl Jwt {
    async fn check(
        &self,
        method: Method,
        token: &str,
        client_id: &str,
        topic: &str,
        access: i32,
    ) -> BackendResult {
        // be-jwt.c: http_post. The username is an escaped Bearer token,
        // neither username nor password is in the form, and there are no retries.
        let authorization = format!("Bearer {}", escape(token.as_bytes()));
        self.0
            .send(
                method,
                Auth::Header(&authorization),
                |body, _| {
                    let _ = write!(
                        body,
                        "topic={}&acc={access}&clientid={client_id}",
                        escape(topic.as_bytes())
                    );
                },
                false,
            )
            .await
    }
}

impl Backend for Jwt {
    fn name(&self) -> &'static str {
        "jwt"
    }

    fn getuser<'a>(&'a self, token: &'a str, _: &'a [u8], _: &'a str) -> BoxFuture<'a, GetUser> {
        Box::pin(
            async move { GetUser::result(self.check(Method::Getuser, token, "", "", -1).await) },
        )
    }

    fn superuser<'a>(&'a self, token: &'a str) -> BoxFuture<'a, BackendResult> {
        Box::pin(async move { self.check(Method::Superuser, token, "", "", -1).await })
    }

    fn aclcheck<'a>(
        &'a self,
        client_id: &'a str,
        token: &'a str,
        topic: &'a str,
        access: i32,
    ) -> BoxFuture<'a, BackendResult> {
        Box::pin(async move {
            self.check(Method::Acl, token, client_id, topic, access)
                .await
        })
    }
}
