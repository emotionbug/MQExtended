//! go-auth's files backend and the ACL checker reused by JWT files mode.

use std::{
    borrow::Cow,
    collections::HashMap,
    fs::File,
    io::{self, BufRead, BufReader},
    sync::{Arc, RwLock},
};

use mqx_auth::external::BoxFuture;

use crate::backend::LoadError;

use super::super::{
    backend::{Backend, BackendError, Hasher, Init, Log},
    topics,
};

const READ: i32 = 1;
const WRITE: i32 = 2;
const READWRITE: i32 = 3;
const SUBSCRIBE: i32 = 4;
const DENY: i32 = 0x11;

pub(crate) async fn create(init: Init<'_>) -> Result<Box<dyn Backend>, LoadError> {
    // backends/files.go: NewFiles tests the original `files_register`
    // string for the substring `user`; omitted registration is different.
    let path = |key| init.options.get(key).cloned().unwrap_or_default();
    let passwords = path("files_password_path");
    if passwords.is_empty()
        && init
            .options
            .get("files_register")
            .is_some_and(|reg| reg.contains("user"))
    {
        return Err(LoadError::new("missing passwords file path"));
    }
    let acl = path("files_acl_path");
    let allow_without_acl = !path("backends").contains(',');
    let checker = tokio::task::spawn_blocking(move || {
        Checker::load(passwords, acl, allow_without_acl, init.log)
    })
    .await
    .map_err(|err| LoadError::new(err.to_string()))??;
    Ok(Box::new(Files {
        checker,
        hasher: init.hasher,
    }))
}

struct Files {
    checker: Checker,
    hasher: Arc<dyn Hasher>,
}

impl Backend for Files {
    fn name(&self) -> String {
        "Files".to_owned()
    }

    fn get_user<'a>(
        &'a self,
        username: &'a str,
        password: &'a [u8],
        _client_id: &'a str,
    ) -> BoxFuture<'a, Result<bool, BackendError>> {
        Box::pin(async move {
            // backends/files/files.go: GetUser.
            let Some(saved) = self
                .checker
                .state
                .read()
                .unwrap_or_else(|err| err.into_inner())
                .users
                .get(username)
                .and_then(|user| user.password.clone())
            else {
                return Ok(false);
            };
            let hasher = self.hasher.clone();
            let password = password.to_vec();
            let matched =
                tokio::task::spawn_blocking(move || hasher.compare_bytes(&password, &saved))
                    .await
                    .map_err(|err| BackendError::new(err.to_string()))?;
            if !matched {
                self.checker
                    .log
                    .warn(format_args!("wrong password for user {username}"));
            }
            Ok(matched)
        })
    }

    fn get_superuser<'a>(
        &'a self,
        _username: &'a str,
    ) -> BoxFuture<'a, Result<bool, BackendError>> {
        // backends/files.go: GetSuperuser.
        Box::pin(std::future::ready(Ok(false)))
    }

    fn check_acl<'a>(
        &'a self,
        username: &'a str,
        topic: &'a str,
        client_id: &'a str,
        acc: i32,
    ) -> BoxFuture<'a, Result<bool, BackendError>> {
        Box::pin(async move { Ok(self.checker.check_acl(username, topic, client_id, acc)) })
    }
}

pub(crate) struct Checker {
    state: Arc<RwLock<State>>,
    acl_enabled: bool,
    allow_without_acl: bool,
    log: Log,
    #[cfg(unix)]
    watcher: Option<tokio::task::JoinHandle<()>>,
}

#[derive(Default)]
struct State {
    users: HashMap<String, User>,
    common: Vec<Rule>,
}

#[derive(Default)]
struct User {
    password: Option<Arc<[u8]>>,
    rules: Vec<Rule>,
}

struct Rule {
    pattern: String,
    access: i32,
}

impl Checker {
    // backends/jwt_files.go: NewFilesJWTChecker.
    pub(crate) fn from_acl(path: &str, log: Log) -> Result<Self, LoadError> {
        if path.is_empty() {
            return Err(LoadError::new("missing acl file path"));
        }
        Self::load(String::new(), path.to_owned(), false, log)
    }

    // backends/files/files.go: NewChecker, loadStaticFiles.
    fn load(
        passwords: String,
        acl: String,
        allow_without_acl: bool,
        log: Log,
    ) -> Result<Self, LoadError> {
        if passwords.is_empty() {
            log.info(format_args!("[StaticFiles] passwords won't be checked"));
        }
        if acl.is_empty() {
            log.info(format_args!("[StaticFiles] acls won't be checked"));
        }
        let mut state = State::default();
        state.read(&passwords, &acl, &log)?;
        let acl_enabled = !acl.is_empty();
        let state = Arc::new(RwLock::new(state));
        #[cfg(unix)]
        let watcher = if passwords.is_empty() && !acl_enabled {
            None
        } else {
            Self::watch(&state, passwords, acl, log.clone())?
        };
        Ok(Self {
            state,
            acl_enabled,
            allow_without_acl,
            log,
            #[cfg(unix)]
            watcher,
        })
    }

    // backends/files/files.go: watchSignals and mosquitto.c: main race to
    // install the SIGHUP handler: the reference can reload either its broker
    // config (auth-plugin.c's security reload callbacks are no-ops) or the
    // Go files, not both. Tokio delivers SIGHUP to both subscribers.
    #[cfg(unix)]
    fn watch(
        state: &Arc<RwLock<State>>,
        passwords: String,
        acl: String,
        log: Log,
    ) -> Result<Option<tokio::task::JoinHandle<()>>, LoadError> {
        use tokio::signal::unix::{SignalKind, signal};

        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return Ok(None);
        };
        let mut hup =
            signal(SignalKind::hangup()).map_err(|err| LoadError::new(err.to_string()))?;
        let state = Arc::downgrade(state);
        let args = Arc::new((passwords, acl, log));
        Ok(Some(runtime.spawn(async move {
            while hup.recv().await.is_some() {
                let Some(state) = state.upgrade() else { break };
                args.2.debug(format_args!(
                    "[StaticFiles] got SIGHUP, reloading static files"
                ));
                let args = args.clone();
                let _ = tokio::task::spawn_blocking(move || {
                    let (passwords, acl, log) = &*args;
                    // loadStaticFiles mutates existing state: removed users
                    // and rules persist, including changes before a parse error.
                    state
                        .write()
                        .unwrap_or_else(|err| err.into_inner())
                        .read(passwords, acl, log)
                })
                .await;
            }
        })))
    }

    // backends/files/files.go: CheckAcl. A deny on either list overrides
    // every grant. Match each rule at most once, and retain the first grant.
    pub(crate) fn check_acl(
        &self,
        username: &str,
        topic: &str,
        client_id: &str,
        access: i32,
    ) -> bool {
        if !self.acl_enabled {
            return self.allow_without_acl;
        }
        let state = self.state.read().unwrap_or_else(|err| err.into_inner());
        let personal = state
            .users
            .get(username)
            .map_or(&[][..], |user| user.rules.as_slice());
        let mut granted = false;
        for (rule, common) in personal
            .iter()
            .map(|rule| (rule, false))
            .chain(state.common.iter().map(|rule| (rule, true)))
        {
            if rule.access != DENY
                && (granted
                    || !(rule.access == READWRITE
                        || access == rule.access
                        || access == SUBSCRIBE && topic != "#" && rule.access == READ))
            {
                continue;
            }
            let pattern = if common {
                substitute(
                    substitute(Cow::Borrowed(&rule.pattern), "%c", client_id),
                    "%u",
                    username,
                )
            } else {
                Cow::Borrowed(rule.pattern.as_str())
            };
            if topics::matches(&pattern, topic) {
                if rule.access == DENY {
                    return false;
                }
                granted = true;
            }
        }
        granted
    }
}

#[cfg(unix)]
impl Drop for Checker {
    fn drop(&mut self) {
        if let Some(task) = &self.watcher {
            task.abort();
        }
    }
}

fn substitute<'a>(pattern: Cow<'a, str>, token: &str, value: &str) -> Cow<'a, str> {
    if pattern.contains(token) {
        Cow::Owned(pattern.replace(token, value))
    } else {
        pattern
    }
}

impl State {
    fn read(&mut self, passwords: &str, acl: &str, log: &Log) -> Result<(), LoadError> {
        if !passwords.is_empty() {
            let count = self
                .read_passwords(passwords, log)
                .map_err(|err| LoadError::new(format!("read passwords: {err}")))?;
            log.debug(format_args!("got {count} users from passwords file"));
        }
        if !acl.is_empty() {
            let count = self
                .read_acl(acl, !passwords.is_empty(), log)
                .map_err(|err| LoadError::new(format!("read acls: {err}")))?;
            log.debug(format_args!("got {count} lines from acl file"));
        }
        Ok(())
    }

    // backends/files/files.go: readPasswords, checkCommentOrEmpty.
    fn read_passwords(&mut self, path: &str, log: &Log) -> Result<usize, LoadError> {
        let mut scanner = open(path).map_err(|err| {
            LoadError::new(format!(
                "[StaticFiles] error: couldn't open passwords file: {err}"
            ))
        })?;
        let mut count = 0;
        let mut index = 0;
        let mut line = Vec::new();
        while scan_line(&mut scanner, &mut line) {
            index += 1;
            if comment_or_empty(&line) {
                continue;
            }
            let mut split = line.split(|&byte| byte == b':');
            let (Some(username), Some(hash), None) = (split.next(), split.next(), split.next())
            else {
                log.error(format_args!(
                    "Read passwords error: line {index} is not well formatted"
                ));
                continue;
            };
            // MQTT usernames must be UTF-8 even though the file's salt may not be.
            let Ok(username) = std::str::from_utf8(username) else {
                continue;
            };
            if let Some(user) = self.users.get_mut(username) {
                user.password = Some(hash.into());
            } else {
                self.users.insert(
                    username.to_owned(),
                    User {
                        password: Some(hash.into()),
                        rules: Vec::new(),
                    },
                );
                count += 1;
            }
        }
        Ok(count)
    }

    // backends/files/files.go: readAcls, removeAndTrim.
    fn read_acl(&mut self, path: &str, check_users: bool, log: &Log) -> Result<usize, LoadError> {
        let mut scanner = open(path).map_err(|err| {
            LoadError::new(format!(
                "StaticFiles backend error: couldn't open acl file: {err}"
            ))
        })?;
        let mut count = 0;
        let mut index = 0;
        let mut current = CurrentUser::None;
        let mut line = Vec::new();
        while scan_line(&mut scanner, &mut line) {
            index += 1;
            if comment_or_empty(&line) {
                continue;
            }
            let format_error = || {
                LoadError::new(format!(
                    "StaticFiles backend error: wrong acl format at line {index}"
                ))
            };
            let line = std::str::from_utf8(&line)
                .map_err(|_| format_error())?
                .trim();
            let mut fields = line.split_whitespace();
            let prefix = fields.next().ok_or_else(format_error)?;
            let rest = line[prefix.len()..].trim();
            match prefix {
                "user" if !rest.is_empty() => {
                    if !self.users.contains_key(rest) {
                        if check_users {
                            log.warn(format_args!("user {rest} doesn't exist, skipping acls"));
                            current = CurrentUser::Unknown;
                            continue;
                        }
                        self.users.insert(rest.to_owned(), User::default());
                    }
                    current = CurrentUser::Known(rest.to_owned());
                }
                "topic" | "pattern" => {
                    let word = fields.next().ok_or_else(format_error)?;
                    let rule = if fields.next().is_none() {
                        Rule {
                            access: READWRITE,
                            pattern: word.to_owned(),
                        }
                    } else {
                        // Go uses ASCII space to split explicit permissions.
                        let (permission, pattern) =
                            rest.split_once(' ').ok_or_else(format_error)?;
                        let access = match permission {
                            "read" => READ,
                            "write" => WRITE,
                            "readwrite" => READWRITE,
                            "subscribe" => SUBSCRIBE,
                            "deny" => DENY,
                            _ => return Err(format_error()),
                        };
                        Rule {
                            access,
                            pattern: pattern.trim().to_owned(),
                        }
                    };
                    match (&current, prefix) {
                        (_, "pattern") | (CurrentUser::None, _) => self.common.push(rule),
                        (CurrentUser::Known(user), _) => self
                            .users
                            .get_mut(user)
                            .expect("registered user")
                            .rules
                            .push(rule),
                        (CurrentUser::Unknown, _) => continue,
                    }
                    count += 1;
                }
                _ => return Err(format_error()),
            }
        }
        Ok(count)
    }
}

enum CurrentUser {
    None,
    Unknown,
    Known(String),
}

fn open(path: &str) -> Result<BufReader<File>, String> {
    File::open(path)
        .map(BufReader::new)
        .map_err(|err| format!("open {path}: {}", super::super::os_error(&err)))
}

fn comment_or_empty(line: &[u8]) -> bool {
    line.first() == Some(&b'#') || line.iter().all(|&byte| byte == b' ')
}

// The reference's bufio.Scanner stops at a 64 KiB token or an I/O error;
// the caller ignores scanner.Err() and keeps the previous lines.
fn scan_line(scanner: &mut BufReader<File>, line: &mut Vec<u8>) -> bool {
    use io::Read as _;
    line.clear();
    let Ok(read) = scanner.take(64 * 1024).read_until(b'\n', line) else {
        return false;
    };
    if read == 0 || (read == 64 * 1024 && !line.ends_with(b"\n")) {
        return false;
    }
    if line.ends_with(b"\n") {
        line.pop();
    }
    if line.ends_with(b"\r") {
        line.pop();
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::goauth::{backend::Level, hashing};

    // test-files/acls and associated cases in backends/files/files_test.go.
    const ACLS: &str = "\
topic read test/general
topic deny test/general_denied

user test1
topic write test/topic/1
topic read test/topic/2
topic readwrite readwrite/topic

user test2
topic read test/topic/+

user test3
topic read test/#
topic deny test/denied

user  test with space
topic  test/space
topic read test/multiple spaces in/topic
  topic   read   test/lots   of   spaces   in/topic and borders

user not_present
topic read test/not_present

pattern read test/%u
pattern read test/%c
";

    fn tempdir() -> tempfile::TempDir {
        tempfile::tempdir_in(std::env::var_os("TMPDIR").expect("set TMPDIR for test fixtures"))
            .unwrap()
    }

    fn fixture(dir: &tempfile::TempDir, name: &str, text: &str) -> String {
        let path = dir.path().join(name);
        std::fs::write(&path, text).unwrap();
        path.into_os_string().into_string().unwrap()
    }

    fn log() -> Log {
        Log::new(Level::Panic, Box::new(io::sink()))
    }

    #[tokio::test]
    async fn reference_acl_cases_and_missing_acl() {
        let dir = tempdir();
        let pw = fixture(
            &dir,
            "passwords",
            "test1:PBKDF2$sha512$100000$2WQHK5rjNN+oOT+TZAsWAw==$TDf4Y6J+9BdnjucFQ0ZUWlTwzncTjOOeE00W4Qm8lfPQyPCZACCjgfdK353jdGFwJjAf6vPAYaba9+z4GWK7Gg==\ntest2:unused\ntest3:unused\ntest with space:unused\n",
        );
        let acl = fixture(&dir, "acls", ACLS);
        let checker = Checker::load(pw, acl.clone(), true, log()).unwrap();
        let backend = Files {
            checker,
            hasher: hashing::new(&HashMap::new(), "files", &log()),
        };
        assert_eq!(
            backend.get_user("test1", b"test1", "test_client").await,
            Ok(true)
        );
        assert_eq!(
            backend.get_user("test1", b"test2", "test_client").await,
            Ok(false)
        );
        assert_eq!(backend.get_superuser("test1").await, Ok(false));
        for (user, topic, access, allowed) in [
            ("test1", "test/general", READ, true),
            ("test1", "test/general", WRITE, false),
            ("test1", "test/general", SUBSCRIBE, true),
            ("test3", "test/general_denied", READ, false),
            ("test1", "test/topic/1", WRITE, true),
            ("test1", "test/topic/1", SUBSCRIBE, false),
            ("test1", "test/topic/2", SUBSCRIBE, true),
            ("test1", "readwrite/topic", SUBSCRIBE, true),
            ("test2", "test/topic/2", READ, true),
            ("test2", "test/other/2", READ, false),
            ("test3", "test", READ, true),
            ("test3", "test/denied", READ, false),
            ("test with space", "test/space", WRITE, true),
            (
                "test with space",
                "test/multiple spaces in/topic",
                READ,
                true,
            ),
            (
                "test with space",
                "test/lots   of   spaces   in/topic and borders",
                WRITE,
                false,
            ),
            (
                "test with space",
                "test/lots   of   spaces   in/topic and borders",
                READ,
                true,
            ),
            ("test1", "test/test1", READ, true),
            ("test1", "test/test_client", READ, true),
            ("not_present", "test/not_present", WRITE, false),
        ] {
            assert_eq!(
                backend
                    .checker
                    .check_acl(user, topic, "test_client", access),
                allowed,
                "{user}: {topic} {access}"
            );
        }
        assert!(
            !backend
                .checker
                .state
                .read()
                .unwrap()
                .users
                .contains_key("not_present")
        );
        let from_acl = Checker::from_acl(&acl, log()).unwrap();
        assert!(
            from_acl
                .state
                .read()
                .unwrap()
                .users
                .contains_key("not_present")
        );
        let from_acl = Checker::from_acl(
            &fixture(&dir, "acls-only", "user some-user\ntopic #\n"),
            log(),
        )
        .unwrap();
        assert!(from_acl.check_acl("some-user", "#", "cid", SUBSCRIBE));
        let from_acl = Checker::from_acl(
            &fixture(&dir, "acls-read-only", "user some-user\ntopic read #\n"),
            log(),
        )
        .unwrap();
        assert!(!from_acl.check_acl("some-user", "#", "cid", SUBSCRIBE));
        assert!(from_acl.check_acl("some-user", "anything", "cid", SUBSCRIBE));
        for allow in [true, false] {
            assert_eq!(
                Checker::load(String::new(), String::new(), allow, log())
                    .unwrap()
                    .check_acl("unknown", "any", "id", WRITE),
                allow
            );
        }
    }

    #[test]
    fn reload_accumulates_old_users_and_rules() {
        let dir = tempdir();
        let pw = fixture(&dir, "p", "test1:first\n");
        let acl = fixture(&dir, "acl", "user test1\ntopic read test/#\n");
        let mut state = State::default();
        state.read(&pw, &acl, &log()).unwrap();
        std::fs::write(&pw, "test2:second\n").unwrap();
        std::fs::write(
            &acl,
            "user test1\ntopic deny test/denied\nuser test2\ntopic write test/#\n",
        )
        .unwrap();
        state.read(&pw, &acl, &log()).unwrap();
        assert_eq!(
            state.users["test1"].password.as_deref(),
            Some(b"first".as_slice())
        );
        assert_eq!(state.users["test1"].rules.len(), 2);
        assert_eq!(state.users["test1"].rules[0].access, READ);
        assert_eq!(state.users["test1"].rules[1].access, DENY);
        assert_eq!(state.users["test2"].rules[0].access, WRITE);
    }
}
