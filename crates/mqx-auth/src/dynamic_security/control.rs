use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::{
    AclType, Client, DEFAULT_ACL_TYPES, DynamicSecurity, EncodedPassword, Group, Membership,
    PRIORITY_MAX, Role, Text, array, c_string, has_membership, insert_membership, integer, item,
    memberships_json, parse_json, string,
};

const UNKNOWN: &str = "Unknown command";
const ROLES_INVALID: &str = "'roles' not an array or missing/invalid rolename";
const INTERNAL_ERROR: &str = "Internal error";

/// Prepared before log submission so replicas never generate salts or receive
/// plaintext credentials. Envelope errors still produce a control response.
#[derive(Clone, Serialize, Deserialize)]
pub struct DynsecRequest {
    commands: Vec<PreparedCommand>,
    connections: Vec<(String, String, Option<String>)>,
}

impl fmt::Debug for DynsecRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DynsecRequest")
            .field("commands", &self.commands.len())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct PreparedCommand {
    name: String,
    correlation: Option<String>,
    body: Result<Value, String>,
    password: PreparedPassword,
}

#[derive(Clone, Default, Serialize, Deserialize)]
enum PreparedPassword {
    #[default]
    Missing,
    Invalid,
    Empty,
    Hashed(EncodedPassword),
}

/// A single QoS 0 response, a dirty flag for the JSON projection and the
/// usernames to disconnect. `None` in the kick set means anonymous clients.
pub struct DynsecResult {
    pub response: Vec<u8>,
    pub changed: bool,
    pub kicks: BTreeSet<Option<String>>,
}

impl DynsecRequest {
    /// `src/control_common.c: mosquitto_control_generic_callback` and
    /// `control__generic_handle_commands` stop on envelope errors, but not on
    /// command-specific errors. cJSON's `correlationData` is a string.
    pub fn prepare(payload: &[u8]) -> Result<Self, getrandom::Error> {
        let mut commands = Vec::new();
        let failure = |name: &str, correlation: Option<String>, error: &str| PreparedCommand {
            name: name.into(),
            correlation,
            body: Err(error.into()),
            password: PreparedPassword::Missing,
        };
        match parse_json(payload) {
            Err(_) => commands.push(failure(UNKNOWN, None, "Payload not valid JSON")),
            Ok(mut json) => {
                let list = json.as_object_mut().and_then(|object| {
                    let (_, value) = object
                        .iter_mut()
                        .find(|(key, _)| key.eq_ignore_ascii_case("commands"))?;
                    value.as_array_mut()
                });
                if let Some(list) = list {
                    let mut last_correlation = None;
                    for value in list.drain(..) {
                        if !value.is_object() {
                            commands.push(failure(
                                UNKNOWN,
                                last_correlation,
                                "Command not an object",
                            ));
                            break;
                        }
                        let Some(name) = string(&value, "command").map(str::to_owned) else {
                            commands.push(failure(UNKNOWN, last_correlation, "Missing command"));
                            break;
                        };
                        let correlation = match item(&value, "correlationData") {
                            None => None,
                            Some(Value::String(data)) => Some(c_string(data).to_owned()),
                            Some(_) => {
                                commands.push(failure(
                                    &name,
                                    None,
                                    "Invalid correlationData data type.",
                                ));
                                break;
                            }
                        };
                        last_correlation.clone_from(&correlation);
                        let uses_password = ["createClient", "modifyClient", "setClientPassword"]
                            .into_iter()
                            .any(|command| name.eq_ignore_ascii_case(command));
                        let password = if uses_password {
                            match item(&value, "password") {
                                None => PreparedPassword::Missing,
                                Some(Value::String(password)) if c_string(password).is_empty() => {
                                    if name.eq_ignore_ascii_case("createClient") {
                                        PreparedPassword::Hashed(EncodedPassword::hash(b"")?)
                                    } else {
                                        PreparedPassword::Empty
                                    }
                                }
                                Some(Value::String(password)) => PreparedPassword::Hashed(
                                    EncodedPassword::hash(password.as_bytes())?,
                                ),
                                Some(_) => PreparedPassword::Invalid,
                            }
                        } else {
                            PreparedPassword::Missing
                        };
                        let Value::Object(mut body) = value else {
                            unreachable!("checked object")
                        };
                        body.retain(|key, _| !key.eq_ignore_ascii_case("password"));
                        commands.push(PreparedCommand {
                            name,
                            correlation,
                            body: Ok(Value::Object(body)),
                            password,
                        });
                    }
                } else {
                    commands.push(failure(UNKNOWN, None, "Invalid/missing commands"));
                }
            }
        }
        Ok(Self {
            commands,
            connections: Vec::new(),
        })
    }

    /// Only client-detail queries need a snapshot of the receiving node's
    /// live connections.
    pub fn needs_connections(&self) -> bool {
        self.commands.iter().any(|command| {
            command.body.as_ref().is_ok_and(|body| {
                command.name.eq_ignore_ascii_case("getClient")
                    || (command.name.eq_ignore_ascii_case("listClients")
                        && item(body, "verbose").and_then(Value::as_bool) == Some(true))
            })
        })
    }

    /// Live connection addresses belong to the receiving broker, not to the
    /// replicated configuration. Only read-only queries use this observation.
    pub fn with_connections(mut self, connections: Vec<(String, String, Option<String>)>) -> Self {
        self.connections = connections;
        self
    }
}

struct Change {
    changed: bool,
    kicks: BTreeSet<Option<String>>,
}

type Reply = Result<Option<(&'static str, Value)>, &'static str>;

impl DynamicSecurity {
    /// `control.c: dynsec__handle_command`; `config.c: dynsec__config_batch_save`.
    pub fn apply(&mut self, request: DynsecRequest) -> DynsecResult {
        let mut responses = Vec::with_capacity(request.commands.len());
        let mut kicks = BTreeSet::new();
        let mut changed = false;
        for command in request.commands {
            let mut change = Change {
                changed: false,
                kicks: BTreeSet::new(),
            };
            let mut response = match command.body {
                Ok(body) => match self.command(
                    &command.name,
                    &body,
                    command.password,
                    &request.connections,
                    &mut change,
                ) {
                    Ok(Some((name, data))) => json!({"command": name, "data": data}),
                    Ok(None) => json!({"command": command.name}),
                    Err(error) => json!({"command": command.name, "error": error}),
                },
                Err(error) => json!({"command": command.name, "error": error}),
            };
            if let Some(correlation) = command.correlation {
                response["correlationData"] = json!(correlation);
            }
            responses.push(response);
            if change.changed {
                self.change_index = self.change_index.wrapping_add(1);
                changed = true;
            }
            kicks.append(&mut change.kicks);
        }
        DynsecResult {
            response: serde_json::to_vec(&json!({"responses": responses}))
                .expect("JSON values serialize"),
            changed,
            kicks,
        }
    }

    fn command(
        &mut self,
        name: &str,
        body: &Value,
        password: PreparedPassword,
        connections: &[(String, String, Option<String>)],
        change: &mut Change,
    ) -> Reply {
        match name.to_ascii_lowercase().as_str() {
            // default_acl.c: dynsec__process_{get,set}_default_acl_access.
            "setdefaultaclaccess" => {
                let acls = array(body, "acls").ok_or("Missing/invalid actions array")?;
                for acl in acls {
                    if let Some(kind) = string(acl, "acltype")
                        && let Some(index) = DEFAULT_ACL_TYPES
                            .iter()
                            .position(|name| name.eq_ignore_ascii_case(kind))
                        && let Some(allow) = item(acl, "allow").and_then(Value::as_bool)
                    {
                        self.defaults[index] = allow;
                    }
                }
            }
            "getdefaultaclaccess" => {
                return Ok(Some((
                    "getDefaultACLAccess",
                    json!({
                        "acls": DEFAULT_ACL_TYPES.into_iter().zip(self.defaults).map(|(kind, allow)| json!({"acltype":kind,"allow":allow})).collect::<Vec<_>>()
                    }),
                )));
            }
            // details.c: dynsec_details__process_get.
            "getdetails" => {
                return Ok(Some((
                    "getDetails",
                    json!({
                        "clientCount": self.clients.len(), "groupCount": self.groups.len(),
                        "roleCount": self.roles.len(), "changeIndex": self.change_index,
                    }),
                )));
            }
            "createclient" => self.create_client(body, password)?,
            "modifyclient" => self.modify_client(body, password, change)?,
            "deleteclient" => {
                // clients.c: dynsec_clients__process_delete does not validate UTF-8.
                let name = string(body, "username").ok_or("Invalid/missing username")?;
                self.clients.remove(name).ok_or("Client not found")?;
                change.kick(name);
            }
            "getclient" => {
                let name = username(body)?;
                let client = self.clients.get(name).ok_or("Client not found")?;
                return Ok(Some((
                    "getClient",
                    json!({"client": client_response(name, client, connections)}),
                )));
            }
            "listclients" => {
                return Ok(Some((
                    "listClients",
                    list(&self.clients, "clients", body, |name, client| {
                        client_response(name, client, connections)
                    }),
                )));
            }
            "enableclient" | "disableclient" => {
                let username = username(body)?;
                let client = self.clients.get_mut(username).ok_or("Client not found")?;
                client.disabled = name.eq_ignore_ascii_case("disableclient");
                if client.disabled {
                    change.kick(username);
                }
            }
            "setclientid" => {
                let username = username(body)?;
                let id = optional_string(body, "clientid", "Invalid/missing client ID")?;
                validate_text(id.unwrap_or_default(), "Client ID not valid UTF-8")?;
                let client = self.clients.get_mut(username).ok_or("Client not found")?;
                client.client_id = id.filter(|id| !id.is_empty()).map(str::to_owned);
                change.kick(username);
            }
            "setclientpassword" => {
                let username = username(body)?;
                let password = match password {
                    PreparedPassword::Hashed(password) => password,
                    PreparedPassword::Empty => return Err("Empty password is not allowed"),
                    _ => return Err("Invalid/missing password"),
                };
                self.clients
                    .get_mut(username)
                    .ok_or("Client not found")?
                    .password = Some(password);
                change.kick(username);
            }
            "addclientrole" | "removeclientrole" => {
                let username = username(body)?;
                let role = role_name(body)?;
                let client = self.clients.get_mut(username).ok_or("Client not found")?;
                if !self.roles.contains_key(role) {
                    return Err("Role not found");
                }
                if name.eq_ignore_ascii_case("addclientrole") {
                    if !insert_membership(
                        &mut client.roles,
                        role,
                        integer(body, "priority", -1).min(PRIORITY_MAX),
                    ) {
                        return Err(INTERNAL_ERROR);
                    }
                } else {
                    client.roles.retain(|member| member.name != role);
                }
                change.kick(username);
            }
            "creategroup" => self.create_group(body)?,
            "modifygroup" => self.modify_group(body, change)?,
            "deletegroup" => {
                let group = group_name(body)?;
                if self.anonymous_group.as_deref() == Some(group) {
                    return Err("Deleting the anonymous group is forbidden");
                }
                self.groups.remove(group).ok_or("Group not found")?;
                self.kick_group(group, change);
                for client in self.clients.values_mut() {
                    client.groups.retain(|member| member.name != group);
                }
            }
            "getgroup" => {
                let name = group_name(body)?;
                let group = self.groups.get(name).ok_or("Group not found")?;
                return Ok(Some((
                    "getGroup",
                    json!({"group": self.group_json(name, group, false)}),
                )));
            }
            "listgroups" => {
                return Ok(Some((
                    "listGroups",
                    list(&self.groups, "groups", body, |name, group| {
                        self.group_json(name, group, false)
                    }),
                )));
            }
            "setanonymousgroup" => {
                let group = group_name(body)?;
                if !self.groups.contains_key(group) {
                    return Err("Group not found");
                }
                self.anonymous_group = Some(group.into());
                change.kicks.insert(None);
            }
            "getanonymousgroup" => {
                return Ok(Some((
                    "getAnonymousGroup",
                    json!({"group": {"groupname": self.anonymous_group.as_deref().unwrap_or_default()}}),
                )));
            }
            "addgroupclient" | "removegroupclient" => {
                let username = username(body)?;
                let group = group_name(body)?;
                // groups.c: both operations kick even if the membership edit fails.
                change.kick(username);
                let client = self.clients.get_mut(username).ok_or("Client not found")?;
                if !self.groups.contains_key(group) {
                    return Err("Group not found");
                }
                if name.eq_ignore_ascii_case("addgroupclient") {
                    if !insert_membership(&mut client.groups, group, priority(body)) {
                        return Err("Client is already in this group");
                    }
                } else {
                    client.groups.retain(|member| member.name != group);
                }
            }
            "addgrouprole" | "removegrouprole" => {
                let group = group_name(body)?;
                let role = role_name(body)?;
                let group_state = self.groups.get_mut(group).ok_or("Group not found")?;
                if !self.roles.contains_key(role) {
                    return Err("Role not found");
                }
                if name.eq_ignore_ascii_case("addgrouprole") {
                    if !insert_membership(&mut group_state.roles, role, priority(body)) {
                        return Err("Group is already in this role");
                    }
                } else {
                    group_state.roles.retain(|member| member.name != role);
                }
                self.kick_group(group, change);
            }
            "createrole" => self.create_role(body)?,
            "modifyrole" => self.modify_role(body, change)?,
            "deleterole" => {
                let role = role_name(body)?;
                self.roles.remove(role).ok_or("Role not found")?;
                self.kick_role(role, change);
                for client in self.clients.values_mut() {
                    client.roles.retain(|member| member.name != role);
                }
                for group in self.groups.values_mut() {
                    group.roles.retain(|member| member.name != role);
                }
            }
            "getrole" => {
                let name = role_name(body)?;
                let role = self.roles.get(name).ok_or("Role not found")?;
                return Ok(Some(("getRole", json!({"role": role.json(name)}))));
            }
            "listroles" => {
                return Ok(Some((
                    "listRoles",
                    list(&self.roles, "roles", body, |name, role| role.json(name)),
                )));
            }
            "addroleacl" | "removeroleacl" => {
                self.change_role_acl(body, name.eq_ignore_ascii_case("addroleacl"), change)?
            }
            _ => return Err(UNKNOWN),
        }
        change.changed = true;
        Ok(None)
    }

    // clients.c: dynsec_clients__process_create, dynsec_clients__process_modify.
    fn create_client(
        &mut self,
        body: &Value,
        password: PreparedPassword,
    ) -> Result<(), &'static str> {
        let name = checked_name(
            body,
            "username",
            "Invalid/missing username",
            "Username not valid UTF-8",
            Some("Empty username"),
        )?;
        let password = match password {
            PreparedPassword::Missing => None,
            PreparedPassword::Invalid | PreparedPassword::Empty => {
                return Err("Invalid/missing password");
            }
            PreparedPassword::Hashed(password) => Some(password),
        };
        let id = optional_string(body, "clientid", "Invalid/missing client id")?;
        validate_text(id.unwrap_or_default(), "Client ID not valid UTF-8")?;
        let text = create_text(body)?;
        if self.clients.contains_key(name) {
            return Err("Client already exists");
        }
        let roles = self.command_roles(body, ROLES_INVALID)?.unwrap_or_default();
        let mut groups = Vec::new();
        for group in array(body, "groups").unwrap_or_default() {
            if let Some(name) = string(group, "groupname") {
                if !self.groups.contains_key(name) {
                    return Err("Group not found");
                }
                if !insert_membership(
                    &mut groups,
                    name,
                    integer(group, "priority", -1).min(PRIORITY_MAX),
                ) {
                    return Err(INTERNAL_ERROR);
                }
            }
        }
        self.clients.insert(
            name.into(),
            Client {
                text,
                client_id: id.filter(|id| !id.is_empty()).map(str::to_owned),
                disabled: false,
                password,
                roles,
                groups,
            },
        );
        Ok(())
    }

    fn modify_client(
        &mut self,
        body: &Value,
        password: PreparedPassword,
        change: &mut Change,
    ) -> Result<(), &'static str> {
        let name = username(body)?;
        if !self.clients.contains_key(name) {
            return Err("Client not found");
        }
        let roles = self.command_roles(body, ROLES_INVALID)?;
        let groups = array(body, "groups")
            .map(|members| {
                let mut result = Vec::new();
                for member in members.iter().filter(|member| member.is_object()) {
                    let group = string(member, "groupname")
                        .ok_or("'groups' contains an object with an invalid 'groupname'")?;
                    if !self.groups.contains_key(group) {
                        return Err(
                            "'groups' contains an object with a 'groupname' that does not exist",
                        );
                    }
                    insert_membership(
                        &mut result,
                        group,
                        integer(member, "priority", -1).min(PRIORITY_MAX),
                    );
                }
                Ok(result)
            })
            .transpose()?;
        let client = self.clients.get_mut(name).expect("checked client");
        if let Some(id) = string(body, "clientid") {
            client.client_id = (!id.is_empty()).then(|| id.to_owned());
        }
        if let PreparedPassword::Hashed(password) = password {
            client.password = Some(password);
        }
        client.text.update(body);
        if let Some(roles) = roles {
            client.roles = roles;
        }
        if let Some(groups) = groups {
            client.groups = groups;
        }
        change.kick(name);
        Ok(())
    }

    // groups.c: dynsec_groups__process_create, dynsec_groups__process_modify.
    fn create_group(&mut self, body: &Value) -> Result<(), &'static str> {
        let name = checked_name(
            body,
            "groupname",
            "Invalid/missing groupname",
            "Group name not valid UTF-8",
            Some("Empty groupname"),
        )?;
        let text = create_text(body)?;
        if self.groups.contains_key(name) {
            return Err("Group already exists");
        }
        let roles = self
            .command_roles(body, INTERNAL_ERROR)?
            .unwrap_or_default();
        self.groups.insert(name.into(), Group { text, roles });
        Ok(())
    }

    fn modify_group(&mut self, body: &Value, change: &mut Change) -> Result<(), &'static str> {
        let name = group_name(body)?;
        if !self.groups.contains_key(name) {
            return Err("Group not found");
        }
        let roles = self.command_roles(body, ROLES_INVALID)?;
        if let Some(clients) = array(body, "clients") {
            let mut members = Vec::new();
            for member in clients.iter().filter(|member| member.is_object()) {
                let username = string(member, "username")
                    .ok_or("'clients' contains an object with an invalid 'username'")?;
                if !self.clients.contains_key(username) {
                    return Err(
                        "'clients' contains an object with a 'username' that does not exist",
                    );
                }
                members.push((username, priority(member)));
            }
            self.kick_group(name, change);
            for client in self.clients.values_mut() {
                client.groups.retain(|member| member.name != name);
            }
            for (username, priority) in members {
                let client = self.clients.get_mut(username).expect("checked client");
                insert_membership(&mut client.groups, name, priority);
            }
        }
        let group = self.groups.get_mut(name).expect("checked group");
        group.text.update(body);
        if let Some(roles) = roles {
            group.roles = roles;
        }
        self.kick_group(name, change);
        Ok(())
    }

    // roles.c: dynsec_roles__process_create, dynsec_roles__process_modify.
    fn create_role(&mut self, body: &Value) -> Result<(), &'static str> {
        let name = checked_name(
            body,
            "rolename",
            "Invalid/missing rolename",
            "Role name not valid UTF-8",
            Some("Empty rolename"),
        )?;
        let text = create_text(body)?;
        let allow_wildcards = match item(body, "allowwildcardsubs") {
            None => true,
            Some(value) => value.as_bool().ok_or("Invalid allowwildcardsubs")?,
        };
        if self.roles.contains_key(name) {
            return Err("Role already exists");
        }
        self.roles.insert(
            name.into(),
            Role {
                text,
                allow_wildcards,
                acls: Role::load_acls(body).unwrap_or_default(),
            },
        );
        Ok(())
    }

    fn modify_role(&mut self, body: &Value, change: &mut Change) -> Result<(), &'static str> {
        let name = role_name(body)?;
        let role = self.roles.get_mut(name).ok_or("Role does not exist")?;
        role.text.update(body);
        let mut kick = false;
        if let Some(wildcards) = item(body, "allowwildcardsubs").and_then(Value::as_bool) {
            kick = role.allow_wildcards != wildcards;
            role.allow_wildcards = wildcards;
        }
        if let Some(acls) = Role::load_acls(body) {
            role.acls = acls;
            kick = true;
        }
        if kick {
            self.kick_role(name, change);
        }
        Ok(())
    }

    // roles.c: dynsec_roles__process_add_acl, dynsec_roles__process_remove_acl.
    fn change_role_acl(
        &mut self,
        body: &Value,
        add: bool,
        change: &mut Change,
    ) -> Result<(), &'static str> {
        let name = role_name(body)?;
        let role = self.roles.get_mut(name).ok_or("Role not found")?;
        let kind = AclType::parse(string(body, "acltype").ok_or("Invalid/missing acltype")?)
            .ok_or("Unknown acltype")?;
        let topic = string(body, "topic").ok_or("Invalid/missing topic")?;
        validate_text(topic, "Topic not valid UTF-8")?;
        if mqx_topic::validate_topic_filter(topic).is_err() {
            return Err("Invalid ACL topic");
        }
        if add {
            if !role.insert_acl(kind, topic, body) {
                return Err("ACL with this topic already exists");
            }
        } else {
            let index = role
                .acls
                .iter()
                .position(|acl| acl.kind == kind && acl.topic == topic)
                .ok_or("ACL not found")?;
            role.acls.remove(index);
        }
        self.kick_role(name, change);
        Ok(())
    }

    // rolelist.c: dynsec_rolelist__load_from_json; unlike config load, errors
    // abort the command. Equal priorities break ties by role/group name.
    fn command_roles(
        &self,
        body: &Value,
        invalid: &'static str,
    ) -> Result<Option<Vec<Membership>>, &'static str> {
        let Some(roles) = item(body, "roles") else {
            return Ok(None);
        };
        let mut memberships = Vec::new();
        for member in roles.as_array().ok_or(invalid)? {
            let role = string(member, "rolename").ok_or(invalid)?;
            if !self.roles.contains_key(role) {
                return Err("Role not found");
            }
            insert_membership(
                &mut memberships,
                role,
                integer(member, "priority", -1).min(PRIORITY_MAX),
            );
        }
        Ok(Some(memberships))
    }

    // groups.c: group__kick_all kicks anonymous *instead of* named clients
    // for the anonymous group. roles.c: role__kick_all kicks both.
    fn kick_group(&self, group: &str, change: &mut Change) {
        if self.anonymous_group.as_deref() == Some(group) {
            change.kicks.insert(None);
        } else {
            for (username, client) in &self.clients {
                if has_membership(&client.groups, group) {
                    change.kick(username);
                }
            }
        }
    }

    fn kick_role(&self, role: &str, change: &mut Change) {
        let group_has_role = |name| {
            self.groups
                .get(name)
                .is_some_and(|group| has_membership(&group.roles, role))
        };
        if self.anonymous_group.as_deref().is_some_and(group_has_role) {
            change.kicks.insert(None);
        }
        for (username, client) in &self.clients {
            if has_membership(&client.roles, role)
                || client
                    .groups
                    .iter()
                    .any(|member| group_has_role(&member.name))
            {
                change.kick(username);
            }
        }
    }
}

impl Change {
    fn kick(&mut self, username: &str) {
        self.kicks
            .insert((!username.is_empty()).then(|| username.to_owned()));
    }
}

fn create_text(body: &Value) -> Result<Text, &'static str> {
    Ok(Text {
        name: optional_string(body, "textname", "Invalid/missing textname")?.map(str::to_owned),
        description: optional_string(body, "textdescription", "Invalid/missing textdescription")?
            .map(str::to_owned),
    })
}

fn optional_string<'a>(
    body: &'a Value,
    key: &str,
    error: &'static str,
) -> Result<Option<&'a str>, &'static str> {
    item(body, key)
        .map(|value| value.as_str().map(c_string).ok_or(error))
        .transpose()
}

fn validate_text(value: &str, error: &'static str) -> Result<(), &'static str> {
    mqx_codec::validate_utf8(value.as_bytes())
        .map(|_| ())
        .map_err(|_| error)
}

fn checked_name<'a>(
    body: &'a Value,
    key: &str,
    missing: &'static str,
    invalid: &'static str,
    empty: Option<&'static str>,
) -> Result<&'a str, &'static str> {
    let name = string(body, key).ok_or(missing)?;
    if name.is_empty()
        && let Some(error) = empty
    {
        return Err(error);
    }
    validate_text(name, invalid)?;
    Ok(name)
}

fn username(body: &Value) -> Result<&str, &'static str> {
    checked_name(
        body,
        "username",
        "Invalid/missing username",
        "Username not valid UTF-8",
        None,
    )
}

fn group_name(body: &Value) -> Result<&str, &'static str> {
    checked_name(
        body,
        "groupname",
        "Invalid/missing groupname",
        "Group name not valid UTF-8",
        None,
    )
}

fn role_name(body: &Value) -> Result<&str, &'static str> {
    checked_name(
        body,
        "rolename",
        "Invalid/missing rolename",
        "Role name not valid UTF-8",
        None,
    )
}

fn priority(body: &Value) -> i32 {
    integer(body, "priority", -1).clamp(-PRIORITY_MAX, PRIORITY_MAX)
}

// clients.c: add_client_to_json, dynsec_connections__all_to_json.
fn client_response(
    username: &str,
    client: &Client,
    connections: &[(String, String, Option<String>)],
) -> Value {
    let mut value = client.json(username);
    value["groups"] = memberships_json(&client.groups, "groupname");
    value["connections"] = Value::Array(
        connections
            .iter()
            .filter_map(|(user, id, address)| {
                if user != username
                    || client
                        .client_id
                        .as_ref()
                        .is_some_and(|expected| expected != id)
                {
                    return None;
                }
                Some(if let Some(address) = address {
                    json!({"address": address})
                } else {
                    json!({})
                })
            })
            .collect(),
    );
    value
}

// clients.c/groups.c/roles.c: dynsec_*__process_list. count=0 still emits the
// first item at offset because Mosquitto counts down after appending it.
fn list<T>(
    entries: &BTreeMap<String, T>,
    key: &str,
    body: &Value,
    render: impl Fn(&str, &T) -> Value,
) -> Value {
    let verbose = item(body, "verbose")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let offset = integer(body, "offset", 0).max(0) as usize;
    let count = integer(body, "count", -1);
    let limit = if count < 0 {
        usize::MAX
    } else {
        count.max(1) as usize
    };
    json!({ "totalCount": entries.len(), key: entries.iter().skip(offset).take(limit).map(|(name, value)| {
        if verbose { render(name, value) } else { json!(name) }
    }).collect::<Vec<_>>() })
}
