//! Native implementation of Mosquitto 2.1.4's `plugins/dynamic-security`.

mod acl;
mod control;
mod init;

use std::collections::BTreeMap;
use std::fmt;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Value, json};
use sha2::Sha512;

use crate::PasswordHash;
pub use control::{DynsecRequest, DynsecResult};

pub const DYNSEC_CONTROL_TOPIC: &str = "$CONTROL/dynamic-security/v1";
pub const DYNSEC_RESPONSE_TOPIC: &str = "$CONTROL/dynamic-security/v1/response";

const PRIORITY_MAX: i32 = 100_000;
const DEFAULT_ACL_TYPES: [&str; 4] = [
    "publishClientSend",
    "publishClientReceive",
    "subscribe",
    "unsubscribe",
];

/// Plugin state. The Raft encoding retains the resolved model; `to_json` writes
/// the Mosquitto file format, including the group-to-client membership lists.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct DynamicSecurity {
    clients: BTreeMap<String, Client>,
    groups: BTreeMap<String, Group>,
    roles: BTreeMap<String, Role>,
    anonymous_group: Option<String>,
    defaults: [bool; 4],
    change_index: i64,
}

impl fmt::Debug for DynamicSecurity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DynamicSecurity")
            .field("clients", &self.clients.len())
            .field("groups", &self.groups.len())
            .field("roles", &self.roles.len())
            .field("change_index", &self.change_index)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Default, Serialize, Deserialize)]
struct Client {
    text: Text,
    client_id: Option<String>,
    disabled: bool,
    password: Option<EncodedPassword>,
    roles: Vec<Membership>,
    groups: Vec<Membership>,
}

#[derive(Clone, Default, Serialize, Deserialize)]
struct Group {
    text: Text,
    roles: Vec<Membership>,
}

#[derive(Clone, Serialize, Deserialize)]
struct Role {
    text: Text,
    allow_wildcards: bool,
    acls: Vec<Acl>,
}

#[derive(Clone, Default, Serialize, Deserialize)]
struct Text {
    name: Option<String>,
    description: Option<String>,
}

impl Text {
    fn load(value: &Value) -> Self {
        Self {
            name: string(value, "textname").map(str::to_owned),
            description: string(value, "textdescription").map(str::to_owned),
        }
    }

    fn update(&mut self, value: &Value) {
        if let Some(name) = string(value, "textname") {
            self.name = Some(name.to_owned());
        }
        if let Some(description) = string(value, "textdescription") {
            self.description = Some(description.to_owned());
        }
    }

    fn write(&self, value: &mut Value) {
        if let Some(name) = &self.name {
            value["textname"] = json!(name);
        }
        if let Some(description) = &self.description {
            value["textdescription"] = json!(description);
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct Membership {
    name: String,
    priority: i32,
}

impl Membership {
    fn json(&self, key: &str) -> Value {
        let mut value = json!({ key: self.name });
        if self.priority != -1 {
            value["priority"] = json!(self.priority);
        }
        value
    }
}

fn insert_membership(memberships: &mut Vec<Membership>, name: &str, priority: i32) -> bool {
    if has_membership(memberships, name) {
        return false;
    }
    // rolelist.c: rolelist_cmp; grouplist.c: dynsec_grouplist__cmp.
    let index = memberships.partition_point(|m| {
        m.priority > priority || (m.priority == priority && m.name.as_str() < name)
    });
    memberships.insert(
        index,
        Membership {
            name: name.into(),
            priority,
        },
    );
    true
}

fn has_membership(memberships: &[Membership], name: &str) -> bool {
    memberships.iter().any(|m| m.name == name)
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
enum AclType {
    Send,
    Receive,
    SubLiteral,
    SubPattern,
    UnsubLiteral,
    UnsubPattern,
}

impl AclType {
    const ALL: [Self; 6] = [
        Self::Send,
        Self::Receive,
        Self::SubLiteral,
        Self::SubPattern,
        Self::UnsubLiteral,
        Self::UnsubPattern,
    ];

    fn name(self) -> &'static str {
        match self {
            Self::Send => "publishClientSend",
            Self::Receive => "publishClientReceive",
            Self::SubLiteral => "subscribeLiteral",
            Self::SubPattern => "subscribePattern",
            Self::UnsubLiteral => "unsubscribeLiteral",
            Self::UnsubPattern => "unsubscribePattern",
        }
    }

    fn parse(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|kind| kind.name().eq_ignore_ascii_case(name))
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct Acl {
    kind: AclType,
    topic: String,
    priority: i32,
    allow: bool,
}

impl Role {
    // roles.c: dynsec_roles__acl_load, insert_acl_cmp.
    fn load_acls(value: &Value) -> Option<Vec<Acl>> {
        let mut role = Self {
            text: Text::default(),
            allow_wildcards: true,
            acls: Vec::new(),
        };
        for acl in item(value, "acls")?.as_array()? {
            if let Some(topic) = string(acl, "topic").filter(|s| !s.is_empty())
                && let Some(kind) = string(acl, "acltype").and_then(AclType::parse)
            {
                role.insert_acl(kind, topic, acl);
            }
        }
        Some(role.acls)
    }

    fn insert_acl(&mut self, kind: AclType, topic: &str, value: &Value) -> bool {
        if self
            .acls
            .iter()
            .any(|entry| entry.kind == kind && entry.topic == topic)
        {
            return false;
        }
        let priority = integer(value, "priority", 0).clamp(-PRIORITY_MAX, PRIORITY_MAX);
        let index = self
            .acls
            .partition_point(|a| a.kind < kind || (a.kind == kind && a.priority >= priority));
        self.acls.insert(
            index,
            Acl {
                kind,
                topic: topic.to_owned(),
                priority,
                allow: item(value, "allow")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
            },
        );
        true
    }

    fn json(&self, name: &str) -> Value {
        let mut value = json!({ "rolename": name });
        self.text.write(&mut value);
        value["allowwildcardsubs"] = json!(self.allow_wildcards);
        value["acls"] = Value::Array(self.acls.iter().map(|acl| {
            json!({"acltype": acl.kind.name(), "topic": acl.topic, "priority": acl.priority, "allow": acl.allow})
        }).collect());
        value
    }
}

#[derive(Clone)]
struct EncodedPassword {
    encoded: String,
    decoded: PasswordHash,
}

impl Serialize for EncodedPassword {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.encoded)
    }
}

impl<'de> Deserialize<'de> for EncodedPassword {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let encoded = String::deserialize(deserializer)?;
        let decoded = encoded.parse().map_err(serde::de::Error::custom)?;
        Ok(Self { encoded, decoded })
    }
}

impl EncodedPassword {
    fn load(client: &Value) -> Option<Self> {
        let encoded = match string(client, "encoded_password") {
            Some(encoded) => encoded.to_owned(),
            None => {
                let iterations = integer(client, "iterations", 0);
                if iterations <= 0 {
                    return None;
                }
                let salt = string(client, "salt")?;
                let hash = string(client, "password")?;
                format!("$7${iterations}${salt}${hash}")
            }
        };
        let decoded = encoded.parse().ok()?;
        Some(Self { encoded, decoded })
    }

    // libcommon/password_common.c: pw__create_sha512_pbkdf2.
    fn hash(password: &[u8]) -> Result<Self, getrandom::Error> {
        const ITERATIONS: u32 = 20_000;
        let mut salt = vec![0u8; 64];
        let mut hash = [0u8; 64];
        getrandom::fill(&mut salt)?;
        let password = password.split(|&byte| byte == 0).next().unwrap_or_default();
        pbkdf2::pbkdf2_hmac::<Sha512>(password, &salt, ITERATIONS, &mut hash);
        let encoded = format!(
            "$7${ITERATIONS}${}${}",
            BASE64.encode(&salt),
            BASE64.encode(hash)
        );
        Ok(Self {
            encoded,
            decoded: PasswordHash::Sha512Pbkdf2 {
                iterations: ITERATIONS,
                salt,
                hash,
            },
        })
    }
}

// common/json_help.c: cJSON_GetObjectItem looks up ASCII keys case-insensitively.
fn item<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    value
        .as_object()?
        .iter()
        .find_map(|(name, value)| name.eq_ignore_ascii_case(key).then_some(value))
}

fn c_string(text: &str) -> &str {
    text.split_once('\0').map_or(text, |(prefix, _)| prefix)
}

fn string<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    item(value, key)?.as_str().map(c_string)
}

fn integer(value: &Value, key: &str, default: i32) -> i32 {
    item(value, key)
        .and_then(Value::as_f64)
        .map_or(default, |n| n as i32)
}

fn array<'a>(value: &'a Value, key: &str) -> Option<&'a [Value]> {
    item(value, key)?.as_array().map(Vec::as_slice)
}

fn parse_json(bytes: &[u8]) -> Result<Value, serde_json::Error> {
    // cJSON_Parse(WithLength) accepts one value followed by extra bytes.
    let mut decoder =
        serde_json::Deserializer::from_slice(bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(bytes));
    Value::deserialize(&mut decoder)
}

fn memberships_json(memberships: &[Membership], key: &str) -> Value {
    Value::Array(memberships.iter().map(|member| member.json(key)).collect())
}

impl DynamicSecurity {
    /// `config.c: dynsec__config_from_json` loads roles first, then clients,
    /// then groups. Unknown references and invalid individual entries are ignored.
    pub fn parse(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        if bytes.is_empty() {
            return Ok(Self::default());
        }
        let value = parse_json(bytes)?;
        let mut state = Self {
            change_index: item(&value, "changeIndex")
                .and_then(Value::as_f64)
                .unwrap_or(0.0) as i64,
            ..Self::default()
        };
        if let Some(defaults) = item(&value, "defaultACLAccess") {
            for (key, allow) in DEFAULT_ACL_TYPES.into_iter().zip(&mut state.defaults) {
                *allow = item(defaults, key)
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
            }
        }
        if let Some(roles) = item(&value, "roles") {
            let Some(roles) = roles.as_array() else {
                return Ok(state);
            };
            for role in roles {
                if let Some(name) = string(role, "rolename").filter(|s| !s.is_empty()) {
                    state.roles.entry(name.to_owned()).or_insert_with(|| Role {
                        text: Text::load(role),
                        allow_wildcards: item(role, "allowwildcardsubs")
                            .and_then(Value::as_bool)
                            .unwrap_or(true),
                        acls: Role::load_acls(role).unwrap_or_default(),
                    });
                }
            }
        }
        if let Some(clients) = item(&value, "clients") {
            let Some(clients) = clients.as_array() else {
                return Ok(state);
            };
            for client in clients {
                if let Some(name) = string(client, "username").filter(|s| !s.is_empty()) {
                    state
                        .clients
                        .entry(name.to_owned())
                        .or_insert_with(|| Client {
                            text: Text::load(client),
                            client_id: string(client, "clientid").map(str::to_owned),
                            disabled: item(client, "disabled")
                                .and_then(Value::as_bool)
                                .unwrap_or(false),
                            password: EncodedPassword::load(client),
                            roles: Self::config_roles(&state.roles, client),
                            groups: Vec::new(),
                        });
                }
            }
        }
        if let Some(groups) = item(&value, "groups") {
            let Some(groups) = groups.as_array() else {
                return Ok(state);
            };
            for group in groups {
                let Some(name) = string(group, "groupname").filter(|s| !s.is_empty()) else {
                    continue;
                };
                if state.groups.contains_key(name) {
                    continue;
                }
                state.groups.insert(
                    name.into(),
                    Group {
                        text: Text::load(group),
                        roles: Self::config_roles(&state.roles, group),
                    },
                );
                for member in array(group, "clients").unwrap_or_default() {
                    if let Some(client) =
                        string(member, "username").and_then(|name| state.clients.get_mut(name))
                    {
                        insert_membership(
                            &mut client.groups,
                            name,
                            integer(member, "priority", -1).clamp(-PRIORITY_MAX, PRIORITY_MAX),
                        );
                    }
                }
            }
        }
        state.anonymous_group = string(&value, "anonymousGroup")
            .filter(|name| state.groups.contains_key(*name))
            .map(str::to_owned);
        Ok(state)
    }

    fn config_roles(roles: &BTreeMap<String, Role>, owner: &Value) -> Vec<Membership> {
        let mut memberships = Vec::new();
        for member in array(owner, "roles").unwrap_or_default() {
            if let Some(name) = string(member, "rolename").filter(|name| roles.contains_key(*name))
            {
                insert_membership(
                    &mut memberships,
                    name,
                    integer(member, "priority", -1).clamp(-PRIORITY_MAX, PRIORITY_MAX),
                );
            }
        }
        memberships
    }

    /// `config.c: dynsec__config_to_json`. Passwords are saved as the 2.1
    /// `encoded_password` even if they were imported from 2.0 split fields.
    pub fn to_json(&self) -> Result<Vec<u8>, serde_json::Error> {
        let mut value = json!({
            "changeIndex": self.change_index,
            "defaultACLAccess": DEFAULT_ACL_TYPES.into_iter().zip(self.defaults).map(|(key, allow)| (key.to_owned(), json!(allow))).collect::<serde_json::Map<_, _>>(),
            "clients": self.clients.iter().map(|(name, client)| {
                let mut value = client.json(name);
                if let Some(password) = &client.password {
                    value["encoded_password"] = json!(password.encoded);
                }
                value
            }).collect::<Vec<_>>(),
            "groups": self.groups.iter().map(|(name, group)| self.group_json(name, group, true)).collect::<Vec<_>>(),
        });
        if let Some(group) = &self.anonymous_group {
            value["anonymousGroup"] = json!(group);
        }
        value["roles"] = Value::Array(
            self.roles
                .iter()
                .map(|(name, role)| role.json(name))
                .collect(),
        );
        serde_json::to_vec_pretty(&value)
    }

    fn group_json(&self, name: &str, group: &Group, file: bool) -> Value {
        let mut value = json!({ "groupname": name });
        group.text.write(&mut value);
        value["clients"] = Value::Array(
            self.clients
                .iter()
                .filter_map(|(username, client)| {
                    let member = client.groups.iter().find(|member| member.name == name)?;
                    let mut value = json!({ "username": username });
                    if file && member.priority != -1 {
                        value["priority"] = json!(member.priority);
                    }
                    Some(value)
                })
                .collect(),
        );
        value["roles"] = memberships_json(&group.roles, "rolename");
        value
    }

    /// `auth.c: dynsec_auth__basic_auth_callback`; `None` defers to the next plugin.
    pub fn authenticate(
        &self,
        client_id: &str,
        username: Option<&str>,
        password: Option<&[u8]>,
    ) -> Option<bool> {
        let password = password?;
        let client = self.clients.get(username?)?;
        Some(
            !client.disabled
                && client
                    .client_id
                    .as_deref()
                    .is_none_or(|expected| expected == client_id)
                && client
                    .password
                    .as_ref()
                    .is_some_and(|hash| hash.decoded.verify(password)),
        )
    }
}

impl Client {
    fn json(&self, name: &str) -> Value {
        let mut value = json!({ "username": name });
        if let Some(client_id) = &self.client_id {
            value["clientid"] = json!(client_id);
        }
        self.text.write(&mut value);
        if self.disabled {
            value["disabled"] = json!(true);
        }
        value["roles"] = memberships_json(&self.roles, "rolename");
        value
    }
}
