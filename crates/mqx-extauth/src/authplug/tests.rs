use std::sync::Mutex;

use mqx_auth::external::Binding;

use crate::backend::GetUser;

use super::*;
use BackendResult::*;

#[test]
fn options_follow_the_c_tokenizer_and_alias_order() {
    let options = [
        ("superusers", "a,b"),
        ("anonusername", "guest"),
        ("acl_cacheseconds", "20"),
        ("cacheseconds", "7seconds"),
        ("auth_cacheseconds", " -1"),
        ("acl_cachejitter", "5"),
        ("auth_cachejitter", "23"),
        ("auth_cacheijitter", "4"),
        ("auth_cachejitter", "99"),
    ]
    .map(|(k, v)| (k.into(), v.into()));
    let settings = Settings::parse(&options);
    assert_eq!(settings.superusers.as_deref(), Some("a,b"));
    assert_eq!(settings.anonymous, "guest");
    assert_eq!(
        settings.acl,
        Lifetime {
            seconds: 7,
            jitter: 5
        }
    );
    assert_eq!(
        settings.auth,
        Lifetime {
            seconds: -1,
            jitter: 4
        }
    );
    assert_eq!(
        backend_names("files,http, jwt,cdb,redis,unknown").collect::<Vec<_>>(),
        ["files", "http", " jwt", "cdb", "redis"]
    );
    assert_eq!(
        backend_names("files,,unknown").collect::<Vec<_>>(),
        ["files"]
    );
    assert_eq!(backend_names(",files").next(), None);
}

#[tokio::test]
async fn mandatory_options_and_backend_load_order() {
    for (options, error) in [
        (vec![], "No backends configured."),
        (
            vec![("backends", " files")],
            "ERROR: configured back-end ` files' is not compiled in this plugin",
        ),
        (
            vec![("backends", "jwt")],
            "Mandatory parameter `http_ip' missing",
        ),
    ] {
        let options = options
            .into_iter()
            .map(|(k, v)| (k.into(), v.into()))
            .collect();
        assert_eq!(load(options, true).await.err().unwrap().0, error);
    }
    let options = vec![
        ("backends".into(), "typographical error".into()),
        ("backends".into(), "files,,not compiled".into()),
    ];
    assert!(load(options, true).await.is_ok());
}

type Calls = Arc<Mutex<Vec<(&'static str, &'static str)>>>;

struct Fake {
    name: &'static str,
    decisions: [BackendResult; 3],
    hash: Option<&'static str>,
    calls: Calls,
}

impl Fake {
    fn answer(&self, stage: usize) -> BackendResult {
        self.calls
            .lock()
            .unwrap()
            .push((self.name, ["auth", "su", "acl"][stage]));
        self.decisions[stage]
    }
}

impl Backend for Fake {
    fn name(&self) -> &'static str {
        self.name
    }

    fn getuser<'a>(&'a self, _: &'a str, _: &'a [u8], _: &'a str) -> BoxFuture<'a, GetUser> {
        Box::pin(async move {
            let result = self.answer(0);
            GetUser {
                result,
                hash: self.hash.map(str::to_owned),
            }
        })
    }

    fn superuser<'a>(&'a self, _: &'a str) -> BoxFuture<'a, BackendResult> {
        Box::pin(async move { self.answer(1) })
    }

    fn aclcheck<'a>(
        &'a self,
        _: &'a str,
        _: &'a str,
        _: &'a str,
        _: i32,
    ) -> BoxFuture<'a, BackendResult> {
        Box::pin(async move { self.answer(2) })
    }
}

fn fake_chain(
    decisions: &[[BackendResult; 3]],
    hash: Option<(usize, &'static str)>,
) -> (AuthPlug, Calls) {
    let calls: Calls = Arc::new(Mutex::new(Vec::new()));
    let backends = decisions
        .iter()
        .enumerate()
        .map(|(index, &decisions)| {
            Box::new(Fake {
                name: ["first", "second", "third"][index],
                decisions,
                hash: hash.filter(|(at, _)| *at == index).map(|(_, h)| h),
                calls: calls.clone(),
            }) as Box<dyn Backend>
        })
        .collect();
    (
        AuthPlug {
            settings: Settings::default(),
            backends,
            auth_cache: AuthCache::default(),
            deny_special_chars: true,
            redact_username: false,
        },
        calls,
    )
}

#[tokio::test]
async fn authenticate_allow_after_error_and_nul_tail() {
    let hash = "PBKDF2$sha256$901$QrqEwoNkUOWjr3Dg$6CbjEcRO6xEy2Bxa3gXtAYOYGpErf2KH";
    let (plugin, calls) = fake_chain(
        &[
            [Error, Defer, Defer],
            [Defer, Defer, Defer],
            [Deny, Defer, Defer],
        ],
        Some((1, hash)),
    );
    assert_eq!(
        plugin
            .authenticate("real", Some("user"), Some(b"\0password"))
            .await,
        Verdict::Defer
    );
    assert_eq!(
        plugin.authenticate("real", None, Some(b"password")).await,
        Verdict::Defer
    );
    assert_eq!(
        plugin
            .authenticate("real", Some("user"), Some(b"password\0ignored"))
            .await,
        Verdict::Allow
    );
    assert_eq!(
        *calls.lock().unwrap(),
        [("first", "auth"), ("second", "auth")]
    );
    calls.lock().unwrap().clear();
    assert_eq!(
        plugin
            .authenticate("real", Some("user"), Some(b"wrong"))
            .await,
        Verdict::Error
    );
    assert_eq!(
        *calls.lock().unwrap(),
        [("first", "auth"), ("second", "auth"), ("third", "auth")]
    );
}

#[tokio::test]
async fn authenticate_caches_defer_but_not_error_and_deny_stops_chain() {
    for (decision, result, count) in [(Deny, Verdict::Defer, 1), (Error, Verdict::Allow, 2)] {
        let (mut plugin, calls) =
            fake_chain(&[[decision, Defer, Defer], [Allow, Defer, Defer]], None);
        plugin.settings.auth.seconds = 100;
        for id in ["one", "two"] {
            assert_eq!(
                plugin
                    .authenticate(id, Some("user"), Some(b"password"))
                    .await,
                result
            );
        }
        assert_eq!(calls.lock().unwrap().len(), count);
    }
    let (mut plugin, calls) = fake_chain(&[[Error, Defer, Defer]], None);
    plugin.settings.auth.seconds = 100;
    for _ in 0..2 {
        assert_eq!(
            plugin.authenticate("id", Some("user"), Some(b"pass")).await,
            Verdict::Error
        );
    }
    assert_eq!(calls.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn acl_identity_and_special_chars() {
    let (mut plugin, calls) = fake_chain(&[[Allow, Allow, Allow]], None);
    plugin.settings.anonymous = "anon/unsafe".into();
    let subject = |binding| Subject {
        client_id: "a/b",
        username: Some(""),
        binding,
    };
    let certificate = Binding {
        certificate: true,
        ..Binding::default()
    };
    assert!(plugin.acl_identity(subject(Binding::default())).is_none());
    assert!(
        plugin
            .acl_identity(subject(Binding {
                synthetic: true,
                ..certificate
            }))
            .is_none()
    );
    let identity = plugin.acl_identity(subject(certificate)).unwrap();
    assert_eq!(identity.client_id.as_deref(), Some("a/b"));
    let auth = plugin
        .authorize(&identity, "topic", AclAccess::Subscribe)
        .await;
    assert_eq!(
        auth,
        Authorization {
            verdict: Verdict::Defer,
            reuse_for: Duration::ZERO
        }
    );
    let credentials = Binding {
        credentials: true,
        ..certificate
    };
    let identity = plugin
        .acl_identity(Subject {
            username: Some("user"),
            ..subject(credentials)
        })
        .unwrap();
    assert_eq!(
        identity.client_id.as_deref(),
        Some("client id not available")
    );
    assert_eq!(identity.username.as_deref(), Some("user"));
    assert!(calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn acl_all_superuser_checks_precede_all_acl_checks_and_errors_accumulate() {
    let identity = AclIdentity {
        username: Some("user".into()),
        client_id: Some("id".into()),
    };
    let (mut plugin, calls) = fake_chain(&[[Allow, Error, Defer], [Defer, Defer, Allow]], None);
    let authorization = plugin
        .authorize(&identity, "topic", AclAccess::Subscribe)
        .await;
    assert_eq!(authorization.verdict, Verdict::Allow);
    assert!(authorization.reuse_for > Duration::from_secs(300));
    assert!(authorization.reuse_for <= Duration::from_secs(301));
    assert_eq!(
        *calls.lock().unwrap(),
        [
            ("first", "su"),
            ("second", "su"),
            ("first", "acl"),
            ("second", "acl")
        ]
    );
    plugin.settings.superusers = Some("us?r".into());
    plugin.settings.acl.seconds = 0;
    calls.lock().unwrap().clear();
    assert_eq!(
        plugin
            .authorize(&identity, "topic", AclAccess::Subscribe)
            .await,
        Authorization {
            verdict: Verdict::Allow,
            reuse_for: Duration::ZERO
        }
    );
    assert_eq!(
        plugin
            .authorize(&identity, "", AclAccess::Subscribe)
            .await
            .verdict,
        Verdict::Defer
    );
    assert!(calls.lock().unwrap().is_empty());

    for decisions in [
        [[Allow, Error, Allow], [Defer, Deny, Allow]],
        [[Allow, Error, Deny], [Defer, Defer, Allow]],
    ] {
        let (plugin, _) = fake_chain(&decisions, None);
        assert_eq!(
            plugin
                .authorize(&identity, "topic", AclAccess::Read)
                .await
                .verdict,
            Verdict::Error
        );
    }
}
