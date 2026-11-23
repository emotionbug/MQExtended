use mqx_auth::{Access, DYNSEC_CONTROL_TOPIC, DynamicSecurity, DynsecRequest};
use serde_json::{Value, json};

// Mosquitto test/broker/dynamic-security-init.json's pre-2.1 password fields.
#[test]
fn imported_legacy_password_survives_native_save_and_reload() {
    let source = br#"{"clients":[{"username":"admin","clientid":"cli",
        "password":"Rko31yHY12ryMoyZTBNIUsCPb5SDa4WmUP3Xe2+V6P+QOSW3Gj6IDmpl6zQsAjutb476zEYdBeTw9tU7WZ1new==",
        "salt":"Ezuo4G1TqYtTQDL/","iterations":101}]}"#;
    let state = DynamicSecurity::parse(source).unwrap();
    let saved = state.to_json().unwrap();
    let json: Value = serde_json::from_slice(&saved).unwrap();
    assert!(
        json["clients"][0]["encoded_password"]
            .as_str()
            .unwrap()
            .starts_with("$7$101$")
    );
    assert!(json["clients"][0].get("password").is_none());
    for loaded in [state, DynamicSecurity::parse(&saved).unwrap()] {
        assert_eq!(
            loaded.authenticate("cli", Some("admin"), Some(b"admin")),
            Some(true)
        );
        assert_eq!(
            loaded.authenticate("elsewhere", Some("admin"), Some(b"admin")),
            Some(false)
        );
        assert_eq!(
            loaded.authenticate("cli", Some("admin"), Some(b"bad")),
            Some(false)
        );
        assert_eq!(loaded.authenticate("cli", Some("admin"), None), None);
    }
}

// plugins/dynamic-security/acl.c: acl_check, acl_check_subscribe;
// libcommon/topic_common.c: sub_matches_acl.
#[test]
fn direct_roles_precede_groups_and_literal_subscription_precedes_patterns() {
    let state = DynamicSecurity::parse(br#"{
        "clients":[{"username":"name","roles":[{"rolename":"direct","priority":0}]}],
        "groups":[{"groupname":"ops","clients":[{"username":"name","priority":20}],"roles":[{"rolename":"ops","priority":20}]}],
        "roles":[
          {"rolename":"direct","acls":[
            {"acltype":"subscribeLiteral","topic":"name/+/#","allow":true},
            {"acltype":"subscribePattern","topic":"%u/#","priority":20,"allow":false},
            {"acltype":"subscribePattern","topic":"zone/+","priority":10,"allow":true}
          ]},
          {"rolename":"ops","acls":[{"acltype":"subscribePattern","topic":"name/#","allow":true}]}
        ],
        "defaultACLAccess":{"publishClientSend":true}
    }"#).unwrap();
    let authorize = |topic, access| state.authorize("client", Some("name"), topic, access);
    assert_eq!(authorize("name/+/#", Access::Subscribe), Some(true));
    assert_eq!(authorize("name/#", Access::Subscribe), Some(false));
    assert_eq!(authorize("zone/+", Access::Subscribe), Some(true));
    assert_eq!(authorize("zone/#", Access::Subscribe), None);
    assert_eq!(authorize("other", Access::Write), Some(true));
    assert_eq!(authorize(DYNSEC_CONTROL_TOPIC, Access::Write), None);
    assert_eq!(
        state.authorize("client", Some("unknown"), "other", Access::Write),
        None
    );
}

// src/control_common.c: control__generic_handle_commands; config.c:
// dynsec__config_batch_save. A malformed command stops the batch, not the
// changes that preceded it, and doesn't reset the prior correlationData.
#[test]
fn malformed_command_preserves_previous_changes_and_breaks_batch() {
    let mut state = DynamicSecurity::default();
    let request = DynsecRequest::prepare(
        br#"{"commands":[
        {"command":"createGroup","groupname":"ops","correlationData":"one"},
        {"command":"getDetails"},
        {"command":"getRole","rolename":"missing","correlationData":"three"},
        [],
        {"command":"deleteGroup","groupname":"ops"}
    ]}"#,
    )
    .unwrap();
    let result = state.apply(request);
    assert!(result.changed);
    assert!(result.kicks.is_empty());
    let response: Value = serde_json::from_slice(&result.response).unwrap();
    assert_eq!(
        response,
        json!({"responses":[
            {"command":"createGroup","correlationData":"one"},
            {"command":"getDetails","data":{"clientCount":0,"groupCount":1,"roleCount":0,"changeIndex":1}},
            {"command":"getRole","error":"Role not found","correlationData":"three"},
            {"command":"Unknown command","error":"Command not an object","correlationData":"three"}
        ]})
    );
}

#[test]
fn prepared_password_is_hashed_before_replication() {
    let request = DynsecRequest::prepare(
        br#"{"commands":[
        {"command":"createClient","username":"new","PASSWORD":"not-in-the-log"},
        {"command":"setClientPassword","username":"new","password":""}
    ]}"#,
    )
    .unwrap();
    let encoded = serde_json::to_vec(&request).unwrap();
    assert!(
        !encoded
            .windows(b"not-in-the-log".len())
            .any(|window| window == b"not-in-the-log")
    );
    let mut state = DynamicSecurity::default();
    let result = state.apply(serde_json::from_slice(&encoded).unwrap());
    let response: Value = serde_json::from_slice(&result.response).unwrap();
    assert_eq!(
        response["responses"][1]["error"],
        "Empty password is not allowed"
    );
    assert_eq!(
        state.authenticate("id", Some("new"), Some(b"not-in-the-log")),
        Some(true)
    );
}

// cJSON_GetObjectItem returns the first member whose name matches
// case-insensitively; later duplicates are never read. Expected values were
// observed from Mosquitto 2.1.4 with the same control payloads.
#[test]
fn duplicate_json_keys_use_the_first_occurrence() {
    let mut state = DynamicSecurity::default();
    let request = DynsecRequest::prepare(
        br#"{"commands":[
        {"command":"createClient","username":"a","username":"b"},
        {"command":"createClient","Username":"c","username":"d"},
        {"command":"createClient","username":"e","Username":"f","password":"first","PASSWORD":"second"},
        {"command":"createRole","rolename":"r"},
        {"command":"addRoleACL","rolename":"r","acltype":"publishClientSend","topic":"x","allow":true,"allow":false},
        {"command":"addClientRole","username":"a","rolename":"r"}
    ]}"#,
    )
    .unwrap();
    state.apply(request);
    let list = state
        .apply(DynsecRequest::prepare(br#"{"commands":[{"command":"listClients"}]}"#).unwrap());
    let response: Value = serde_json::from_slice(&list.response).unwrap();
    assert_eq!(
        response["responses"][0]["data"]["clients"],
        json!(["a", "c", "e"])
    );
    assert_eq!(
        state.authorize("id", Some("a"), "x", Access::Write),
        Some(true)
    );
    assert_eq!(
        state.authenticate("id", Some("e"), Some(b"first")),
        Some(true)
    );

    let loaded = DynamicSecurity::parse(
        br#"{"clients":[{"username":"u","roles":[{"rolename":"r"}]}],
        "roles":[{"rolename":"r","acls":[
            {"acltype":"publishClientReceive","topic":"t","allow":true,"Allow":false}
        ]}]}"#,
    )
    .unwrap();
    assert_eq!(
        loaded.authorize("id", Some("u"), "t", Access::Read),
        Some(true)
    );
}
