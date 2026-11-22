use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

use mqx_difftest::{BrokerConfig, BrokerKind, ClusterConfig, Harness};

#[test]
#[ignore = "requires Mosquitto 2.1.4, mqextended and paho-mqtt 2.1.0"]
fn paho_tcp() {
    run("python3", "paho_interop.py", None);
}

#[test]
#[ignore = "requires Mosquitto 2.1.4, mqextended and MQTT.js"]
fn mqttjs_tcp() {
    run("node", "mqttjs_interop.cjs", Some("tcp"));
}

#[test]
#[ignore = "requires WebSocket-enabled Mosquitto 2.1.4, mqextended and MQTT.js"]
fn mqttjs_websockets() {
    run("node", "mqttjs_interop.cjs", Some("ws"));
}

fn run(runtime: &str, script: &str, transport: Option<&str>) {
    let ws = transport == Some("ws");
    let script = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/clients")
        .join(script);
    for (kind, cluster) in [
        (BrokerKind::Mosquitto, false),
        (BrokerKind::MqExtended, false),
        (BrokerKind::MqExtended, true),
    ] {
        let config = BrokerConfig {
            conf: if ws {
                "protocol websockets\nallow_anonymous true"
            } else {
                "allow_anonymous true"
            },
            ..BrokerConfig::default()
        };
        let harness = match (kind, cluster) {
            (_, true) => Harness::start_cluster(config, ClusterConfig::default()),
            (BrokerKind::Mosquitto, false) if ws => {
                let dir =
                    env::var_os("MOSQUITTO_WS_BUILD_DIR").expect("set MOSQUITTO_WS_BUILD_DIR");
                Harness::start_with_binary(kind, &PathBuf::from(dir).join("src/mosquitto"), config)
            }
            (_, false) => Harness::start(kind, config),
        }
        .unwrap_or_else(|e| panic!("{kind:?} cluster={cluster}: {e}"));
        let publisher = harness.node_addr(1).unwrap();
        let subscriber = harness.node_addr(if cluster { 2 } else { 1 }).unwrap();
        let output = Command::new(runtime)
            .arg(&script)
            .arg(publisher.ip().to_string())
            .arg(publisher.port().to_string())
            .arg(subscriber.port().to_string())
            .args(transport)
            .output()
            .unwrap_or_else(|e| panic!("{} {}: {e}", runtime, script.display()));
        assert!(
            output.status.success(),
            "{kind:?} ({publisher} -> {subscriber}): {}\n{}\n{}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
            (1..=if cluster { 3 } else { 1 })
                .filter_map(|index| harness.node_log(index).ok())
                .collect::<Vec<_>>()
                .join("\n")
        );
    }
}
