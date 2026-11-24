use std::collections::HashMap;
use std::path::Path;

use mqx_auth::external::BoxFuture;

use crate::authplug::c_string;
use crate::backend::{Backend, BackendResult, GetUser, LoadError, Options};

#[derive(Default)]
struct User {
    password: Option<String>,
    rules: Vec<Rule>,
}

struct Rule {
    access: i32,
    filter: Vec<u8>,
}

#[derive(Default)]
struct Files {
    users: HashMap<Vec<u8>, User>,
    global_rules: Vec<Rule>,
    acl_checks: bool,
}

pub(crate) async fn create(options: &Options) -> Result<Box<dyn Backend>, LoadError> {
    let passwords = options
        .get("password_file")
        .map(|path| Box::from(Path::new(path)));
    let acl = options
        .get("acl_file")
        .map(|path| Box::from(Path::new(path)));
    let files = tokio::task::spawn_blocking(move || Files::open(passwords, acl))
        .await
        .map_err(|_| LoadError::new("files init returns NULL"))??;
    Ok(Box::new(files))
}

impl Files {
    // be-files.c: be_files_init, read_passwords, read_acl.
    fn open(passwords: Option<Box<Path>>, acl: Option<Box<Path>>) -> Result<Self, LoadError> {
        let mut files = Self {
            acl_checks: acl.is_some(),
            ..Self::default()
        };
        if let Some(path) = passwords {
            files.read_passwords(&read(&path, "password")?);
        }
        if let Some(path) = acl {
            files.read_acl(&read(&path, "ACL")?);
        }
        Ok(files)
    }

    fn read_passwords(&mut self, bytes: &[u8]) {
        for line in fgets(bytes) {
            if matches!(line.first(), Some(b'#' | b'\r' | b'\n')) {
                continue;
            }
            if let Some(colon) = line.iter().position(|&b| b == b':') {
                // find_pwd scans in file order, so the first record wins.
                self.users
                    .entry(line[..colon].to_vec())
                    .or_insert_with(|| User {
                        password: std::str::from_utf8(chomp(&line[colon + 1..]))
                            .ok()
                            .map(str::to_owned),
                        rules: Vec::new(),
                    });
            }
        }
    }

    fn read_acl(&mut self, bytes: &[u8]) {
        let mut selected_user = None;
        for line in fgets(bytes) {
            if line.first() == Some(&b'#') {
                continue;
            }
            let trimmed = skip_blanks(line);
            if matches!(trimmed.first(), Some(b'\r' | b'\n')) {
                continue;
            }
            // C uses prefix comparison without requiring a delimiter.
            if let Some(rest) = trimmed.strip_prefix(b"user") {
                let name = chomp(skip_blanks(rest));
                self.users.entry(name.to_vec()).or_default();
                selected_user = Some(name);
            } else if let Some(rest) = trimmed.strip_prefix(b"topic") {
                let rule = Rule::parse(skip_blanks(rest));
                if let Some(user) = selected_user.and_then(|name| self.users.get_mut(name)) {
                    user.rules.push(rule);
                } else {
                    self.global_rules.push(rule);
                }
            } else if let Some(rest) = trimmed.strip_prefix(b"pattern") {
                self.global_rules.push(Rule::parse(skip_blanks(rest)));
            } else {
                tracing::warn!("failed to parse line: {}", String::from_utf8_lossy(line));
            }
        }
    }
}

fn read(path: &Path, kind: &str) -> Result<Vec<u8>, LoadError> {
    std::fs::read(path).map_err(|_| {
        tracing::error!("failed to open {kind} file: {}", path.display());
        LoadError::new("files init returns NULL")
    })
}

fn fgets(bytes: &[u8]) -> impl Iterator<Item = &[u8]> {
    bytes
        .split_inclusive(|&b| b == b'\n')
        .flat_map(|line| line.chunks(511))
        .map(c_string)
}

fn chomp(bytes: &[u8]) -> &[u8] {
    &bytes[..bytes
        .iter()
        .position(|&b| matches!(b, b'\r' | b'\n'))
        .unwrap_or(bytes.len())]
}

fn skip_blanks(bytes: &[u8]) -> &[u8] {
    &bytes[bytes
        .iter()
        .position(|&b| !matches!(b, b' ' | b'\t'))
        .unwrap_or(bytes.len())..]
}

impl Rule {
    // be-files.c: read_acl_line. Access uses a bitmask, not a minimum level.
    fn parse(line: &[u8]) -> Self {
        let (access, rest) = match line {
            [b'r', b'e', b'a', b'd', b' ' | b'\t', rest @ ..] => (1, skip_blanks(rest)),
            [b'w', b'r', b'i', b't', b'e', b' ' | b'\t', rest @ ..] => (2, skip_blanks(rest)),
            _ => (3, line),
        };
        let end = rest
            .iter()
            .position(|b| matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
            .unwrap_or(rest.len());
        Self {
            access,
            filter: rest[..end].to_vec(),
        }
    }

    // be-files.c: do_aclcheck expands all %c/%u substrings. Unknown %x
    // appends x without advancing, so the next iteration appends x again.
    fn expand<'a>(&'a self, buffer: &'a mut Vec<u8>, client_id: &str, username: &str) -> &'a [u8] {
        let Some(first) = self.filter.iter().position(|&b| b == b'%') else {
            return &self.filter;
        };
        buffer.clear();
        buffer.extend_from_slice(&self.filter[..first]);
        let mut input = &self.filter[first..];
        while let Some((&byte, rest)) = input.split_first() {
            input = rest;
            if byte == b'%' {
                match input {
                    [b'c', tail @ ..] => {
                        buffer.extend_from_slice(client_id.as_bytes());
                        input = tail;
                    }
                    [b'u', tail @ ..] => {
                        buffer.extend_from_slice(username.as_bytes());
                        input = tail;
                    }
                    [next, ..] => buffer.push(*next),
                    [] => break,
                }
            } else {
                buffer.push(byte);
            }
        }
        buffer
    }
}

impl Backend for Files {
    fn name(&self) -> &'static str {
        "files"
    }

    fn getuser<'a>(&'a self, username: &'a str, _: &'a [u8], _: &'a str) -> BoxFuture<'a, GetUser> {
        Box::pin(async move {
            // be-files.c: be_files_getuser returns the first matching hash.
            self.users
                .get(username.as_bytes())
                .and_then(|u| u.password.clone())
                .map_or_else(|| GetUser::result(BackendResult::Defer), GetUser::hash)
        })
    }

    fn superuser<'a>(&'a self, _: &'a str) -> BoxFuture<'a, BackendResult> {
        Box::pin(async { BackendResult::Defer })
    }

    fn aclcheck<'a>(
        &'a self,
        client_id: &'a str,
        username: &'a str,
        topic: &'a str,
        access: i32,
    ) -> BoxFuture<'a, BackendResult> {
        Box::pin(async move {
            // be-files.c: be_files_aclcheck checks user rules before global
            // rules; without an ACL file it allows every access.
            if !self.acl_checks {
                return BackendResult::Allow;
            }
            let user_rules = self
                .users
                .get(username.as_bytes())
                .into_iter()
                .flat_map(|u| &u.rules);
            let mut buffer = Vec::new();
            for rule in user_rules.chain(&self.global_rules) {
                let filter = rule.expand(&mut buffer, client_id, username);
                let Ok(filter) = std::str::from_utf8(filter) else {
                    continue;
                };
                match mqx_topic::matches(filter, topic) {
                    Ok(true) if access & rule.access != 0 => return BackendResult::Allow,
                    Ok(_) => (),
                    Err(_) => tracing::error!("invalid topic '{filter}'"),
                }
            }
            BackendResult::Defer
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn password_duplicates_and_file_acl_quirks() {
        let mut files = Files {
            acl_checks: true,
            ..Files::default()
        };
        files.read_passwords(b"#comment:bad\r\nuser:first\r\nuser:second\n");
        files.read_acl(
            b"topic global/#\nuseruser\n topic write room/%u-%c/%x\npattern read pattern/%u/%\n",
        );
        assert_eq!(
            files.getuser("user", b"", "id").await,
            GetUser::hash("first".into())
        );
        assert_eq!(
            files.aclcheck("id", "user", "room/user-id/xx", 2).await,
            BackendResult::Allow
        );
        assert_eq!(
            files.aclcheck("id", "user", "room/user-id/xx", 1).await,
            BackendResult::Defer
        );
        assert_eq!(
            files.aclcheck("id", "user", "pattern/user/", 1).await,
            BackendResult::Allow
        );
        assert_eq!(
            files.aclcheck("id", "any", "global/other", 4).await,
            BackendResult::Defer
        );
        assert_eq!(
            files.aclcheck("id", "any", "global/other", 1).await,
            BackendResult::Allow
        );
    }
}
