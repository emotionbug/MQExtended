use bytes::Bytes;
use mqx_auth::DYNSEC_CONTROL_TOPIC;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub(crate) const PREFIX: &str = "$CONTROL/";
pub(crate) const TOPIC: &str = "$CONTROL/broker/v1";
pub(crate) const RESPONSE_TOPIC: &str = "$CONTROL/broker/v1/response";
pub(crate) const UNAVAILABLE: Bytes =
    Bytes::from_static(b"{\"error\": \"endpoint not available\"}");

/// Public metadata from a bound listener. Never include certificate paths,
/// security configuration or plugin options in control replies.
#[derive(Serialize)]
pub struct ControlListener {
    pub port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<&'static str>,
    #[serde(rename = "bind-address", skip_serializing_if = "Option::is_none")]
    pub bind_address: Option<String>,
    #[serde(rename = "socket-path", skip_serializing_if = "Option::is_none")]
    pub socket_path: Option<String>,
    pub tls: bool,
}

/// Inventory is taken on the node that receives the request, not the Raft leader.
pub struct ControlInventory {
    listeners: Vec<ControlListener>,
    plugins: Vec<Plugin>,
}

#[derive(Serialize)]
struct Plugin {
    name: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<&'static str>,
    #[serde(rename = "control-endpoints")]
    control_endpoints: &'static [&'static str],
}

#[derive(Serialize)]
#[serde(rename_all = "lowercase")]
enum Data<'a> {
    Listeners(&'a [ControlListener]),
    Plugins(&'a [Plugin]),
}

#[derive(Serialize)]
struct Response<'a> {
    command: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<Data<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<&'static str>,
    #[serde(rename = "correlationData", skip_serializing_if = "Option::is_none")]
    correlation: Option<&'a str>,
}

#[derive(Serialize)]
struct Envelope<'a> {
    responses: Vec<Response<'a>>,
}

impl ControlInventory {
    pub fn new(listeners: Vec<ControlListener>, registrations: &[&'static str]) -> Self {
        let plugins = registrations
            .iter()
            .map(|&name| Plugin {
                name,
                version: (name == "sparkplug-aware").then_some("1.0"),
                control_endpoints: if name == "dynamic-security" {
                    &[DYNSEC_CONTROL_TOPIC]
                } else {
                    &[]
                },
            })
            .collect();
        Self { listeners, plugins }
    }

    pub(crate) fn respond(&self, payload: &[u8], client_id: &str, username: Option<&str>) -> Bytes {
        // control_common.c: mosquitto_control_generic_callback accepts a JSON
        // prefix and produces an envelope even if the payload cannot be parsed.
        let payload = payload.strip_prefix(b"\xef\xbb\xbf").unwrap_or(payload);
        let mut json = serde_json::Deserializer::from_slice(payload);
        let tree = Value::deserialize(&mut json);
        let responses = match &tree {
            Err(_) => vec![error("Unknown command", "Payload not valid JSON", None)],
            Ok(tree) => match item(tree, "commands").and_then(Value::as_array) {
                Some(commands) => self.responses(commands, client_id, username),
                None => vec![error("Unknown command", "Invalid/missing commands", None)],
            },
        };
        let response =
            serde_json::to_vec(&Envelope { responses }).expect("control response serializes");
        Bytes::from(response)
    }

    fn responses<'a>(
        &'a self,
        commands: &'a [Value],
        client_id: &str,
        username: Option<&str>,
    ) -> Vec<Response<'a>> {
        // control_common.c: control__generic_handle_commands stops on envelope
        // errors, but not on an unknown command. Invalid command objects keep
        // the previous correlation until a new command name is read.
        let mut responses = Vec::new();
        let mut correlation = None;
        for value in commands {
            if !value.is_object() {
                responses.push(error(
                    "Unknown command",
                    "Command not an object",
                    correlation,
                ));
                break;
            }
            let Some(command) = item(value, "command").and_then(Value::as_str).map(c_str) else {
                responses.push(error("Unknown command", "Missing command", correlation));
                break;
            };
            correlation = match item(value, "correlationData") {
                None => None,
                Some(Value::String(value)) => Some(c_str(value)),
                Some(_) => {
                    responses.push(error(command, "Invalid correlationData data type.", None));
                    break;
                }
            };
            let (command, data) = if command.eq_ignore_ascii_case("listListeners") {
                ("listListeners", Data::Listeners(&self.listeners))
            } else if command.eq_ignore_ascii_case("listPlugins") {
                ("listPlugins", Data::Plugins(&self.plugins))
            } else {
                responses.push(error(command, "Unknown command", correlation));
                continue;
            };
            let username = username.unwrap_or("(null)");
            tracing::info!("Broker: {client_id}/{username} | {command}");
            responses.push(Response {
                command,
                data: Some(data),
                error: None,
                correlation,
            });
        }
        responses
    }
}

fn error<'a>(command: &'a str, error: &'static str, correlation: Option<&'a str>) -> Response<'a> {
    Response {
        command,
        data: None,
        error: Some(error),
        correlation,
    }
}

fn item<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    value
        .as_object()?
        .iter()
        .find_map(|(name, value)| c_str(name).eq_ignore_ascii_case(key).then_some(value))
}

fn c_str(value: &str) -> &str {
    value.split_once('\0').map_or(value, |(prefix, _)| prefix)
}
