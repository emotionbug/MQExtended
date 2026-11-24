# Testing

Test the behaviour a client or operator observes. For MQExtended that almost always means "what Mosquitto 2.1.4 does", so the strongest evidence comes from Mosquitto itself.

## Layers

| Layer | Proves | Example |
| --- | --- | --- |
| Parity tables | Our port returns what Mosquitto's own unit tests expect | `crates/mqx-topic/tests/mosquitto_topic_test.rs`, extracted from `test/unit/libcommon/topic_test.c` |
| Tool vectors | We read what Mosquitto tools write | `mosquitto_passwd` hashes in `mqx-auth` tests |
| Unit tests | One parity rule or edge case at its owner | ACL check order, `strtok` quirks |
| Property tests | Invariants over generated input: round trips, no panics, agreement with a reference model | codec encode→decode, topic matcher vs. level-based model |
| Differential tests | The real Mosquitto binary and MQExtended agree on a live scenario | `mosquitto_pub` against the codec; `mqx-difftest` broker scenarios |
| Cluster fault tests | MQTT guarantees hold when nodes die, restart or lose leadership | `mqx-difftest` failover tests, `mqx-cluster` integration tests |

Every test names the failure a client would see if it regressed. Do not assert defaults, echoes or wording.

## Parity tables

Extract cases from Mosquitto's test suite instead of retyping them, and say which file they came from at the top of the test. Regenerate from the source file when the reference version changes; never edit a case by hand to make it pass.

## Differential tests

Differential tests need the Mosquitto reference binaries and are `#[ignore]` by default.

| Variable | Points at |
| --- | --- |
| `MOSQUITTO_BUILD_DIR` | Mosquitto 2.1.4 build directory (`src/mosquitto`, `client/mosquitto_{pub,sub}`, `apps/mosquitto_passwd/`) |
| `MOSQUITTO_WS_BUILD_DIR` | A second Mosquitto build with `WITH_WEBSOCKETS=ON`, for `mqx-ws` |
| `MOSQUITTO_HTTP_BUILD_DIR` | A third build with `WITH_HTTP_API=ON`, for `$SYS` and HTTP API scenarios |
| `MOSQUITTO_PLUGIN_BUILD_DIR` | A fourth build with `WITH_PLUGINS=ON`, for dynamic-security scenarios driven by `mosquitto_ctrl` |
| `MQEXTENDED_BIN` | The `mqextended` binary under test; defaults to `target/debug/mqextended` |

```sh
MOSQUITTO_BUILD_DIR=$HOME/mqx-reference/mosquitto/build cargo test -p <crate> -- --ignored
```

A differential test fails when a binary it needs is missing; it must never silently pass. Build the references as described in [development](development.md#mosquitto-reference-build).

Broker behaviour is compared with `mqx-difftest`: each scenario is a script for a raw MQTT client (built on `mqx-codec`, v3 and v5) and has three tests:

| Test suffix | Runs the scenario against | Must hold |
| --- | --- | --- |
| `mosquitto_self` | Mosquitto, twice | identical transcripts: the scenario is deterministic |
| `cross_broker` | Mosquitto and standalone `mqextended` | identical transcripts, packet ids, flags and properties included |
| `cross_cluster` | Mosquitto and a three-node `mqextended` cluster, clients placed round-robin | identical transcripts |

Only generated client ids and clock-dependent expiry values are normalized, after checking their format. A scenario that needs a cross-client ordering waits for an acknowledgement instead of relying on timing. Mine new scenarios from Mosquitto's `test/broker/*.py` and cite the file.

Failover tests have no Mosquitto counterpart; they assert MQTT's guarantees directly while killing (SIGKILL) and restarting nodes: persistent queues and DUP resends survive, a lost node's wills are published once, retained messages and subscriptions survive, takeover works across nodes, publishing resumes after leader loss.

The `auth_plug` and `go_auth` scenarios run Mosquitto with the real `auth-plug.so` or `go-auth.so` against MQExtended's [ports](auth-plugins.md), backed by real back-end servers. Besides the transcripts, they compare every HTTP and JWT request the back-ends receive, duplicates included, and the PostgreSQL, MariaDB and Redis operation counts: with caching off the plugin asks once per check, so the number of requests is part of the contract. The comparison reads the requests as soon as the script ends. End a scenario on an observable result of every check it starts, such as a delivery, not on silence. The `mqx-extauth` reference tests compare individual back-ends, gRPC included, below the broker. Build the references first ([development](development.md#legacy-mosquitto-auth-plug)).

### Client SDK interoperability

`client_sdks` runs unmodified client libraries against Mosquitto 2.1.4, standalone MQExtended and a three-node MQExtended cluster. In cluster runs the publisher and subscriber connect to different nodes.

| Client | Transport | Scenarios |
| --- | --- | --- |
| [Eclipse Paho Python 2.2.0](https://pypi.org/project/paho-mqtt/2.2.0/) | TCP | MQTT 3.1 retained QoS 2; MQTT 3.1.1 offline delivery after session resume; MQTT 5 request/reply with binary Correlation Data |
| MQTT.js 5.16.1 | TCP and WebSocket | MQTT 3.1.1 QoS 2; MQTT 5 batched subscriptions, No Local, Retain As Published, repeated User Properties and request/reply |

With Python 3.9 or newer and Node.js 24 on `PATH`, run from the repository root:

```sh
python3 -m venv "$HOME/mqx-reference/venv"
. "$HOME/mqx-reference/venv/bin/activate"
python3 -m pip install --require-hashes --only-binary=:all: -r crates/mqx-difftest/tests/clients/requirements.txt
npm ci --prefix crates/mqx-difftest/tests/clients --ignore-scripts --no-audit --no-fund
cargo build --locked -p mqx-server
MOSQUITTO_BUILD_DIR=$HOME/mqx-reference/mosquitto/build MOSQUITTO_WS_BUILD_DIR=$HOME/mqx-reference/mosquitto/build-ws \
  cargo test --locked -p mqx-difftest --test client_sdks -- --ignored
```

These tests cover the listed client paths, not full protocol conformance. The [standards and release scope](mosquitto-compatibility.md#standards-and-release-scope-2026-11-22) distinguishes published MQTT specifications from drafts and application profiles.

#### Additional compatibility checks, 2026-11-22

The following were one-time tests on **both Mosquitto 2.1.4 and standalone MQExtended**. They are not additional cluster CI jobs.

| Released client | Exchange verified |
| --- | --- |
| [Mosquitto CLI 2.1.4 and 2.0.23](https://mosquitto.org/blog/2026/11/version-2-1-3-released/) | MQTT 3.1, 3.1.1 and 5.0: retained binary payload replayed with QoS 2 and RETAIN set. |
| [Eclipse Paho C 1.3.16](https://github.com/eclipse-paho/paho.mqtt.c/releases/tag/v1.3.16) | MQTT 3.1, 3.1.1 and 5.0: Paho's publisher sent a retained binary file to `mosquitto_sub`; Paho's subscriber received the return publication from `mosquitto_pub`. |
| [Eclipse Paho C++ 1.6.0](https://github.com/eclipse-paho/paho.mqtt.cpp/releases/tag/v1.6.0), linked with Paho C 1.3.16 | MQTT 3.1.1 and 5.0: negotiated the requested version and received the exact binary payload at QoS 2. |
| Paho Python 2.2.0 | MQTT 5 over TCP/TLS and WSS, forcing TLS 1.2 and 1.3 in turn with certificate and hostname verification. The client applied Server Keep Alive (60 requested, 8 granted) and completed a binary QoS 1 round trip. |
| [MQTT.js 5.16.1](https://www.npmjs.com/package/mqtt/v/5.16.1) in Chrome 158.0.8127.36 | Native browser WebSocket: MQTT 5 wildcard subscription, QoS 1 grant, publish acknowledgement and binary delivery. |
| [MQTTnet 5.2.0.1603](https://www.nuget.org/packages/MQTTnet/5.2.0.1603) | .NET 10: MQTT 3.1, 3.1.1 and 5.0 accepted; QoS 2 grant, publish completion and exact binary delivery on each. |
| [Eclipse Paho Java v3](https://repo.maven.apache.org/maven2/org/eclipse/paho/org.eclipse.paho.client.mqttv3/maven-metadata.xml) and [v5](https://repo.maven.apache.org/maven2/org/eclipse/paho/org.eclipse.paho.mqttv5.client/maven-metadata.xml), both 1.2.5; [HiveMQ MQTT Client 1.4.2](https://repo.maven.apache.org/maven2/com/hivemq/hivemq-mqtt-client/maven-metadata.xml) | OpenJDK 21, separate publisher and subscriber. QoS 1 and 2 grants in order and binary delivery on both topics. Paho: MQTT 3.1, 3.1.1 and 5.0; HiveMQ: 3.1.1 and 5.0. |
| [Paho Go 1.5.1](https://pkg.go.dev/github.com/eclipse/paho.mqtt.golang@v1.5.1) and [Paho Go 0.23.0](https://pkg.go.dev/github.com/eclipse/paho.golang@v0.23.0) | These are separate modules: MQTT 3.1.1 on the first and 5.0 on the second. Both completed a binary QoS 1 round trip. |
| [Bytebeam rumqttc 0.25.1](https://github.com/bytebeamio/rumqtt/releases/tag/rumqttc-0.25.1) | MQTT 3.1.1 and 5.0: QoS 1 SUBACK, publisher PUBACK and exact binary delivery to a second client. The `rumqttc-*-next` crates are a separate fork. |

Embedded releases checked upstream, **not run on hardware**: [FreeRTOS coreMQTT 5.0.2](https://github.com/FreeRTOS/coreMQTT/releases/tag/v5.0.2), [ESP-MQTT 1.1.0](https://github.com/espressif/esp-mqtt/releases/tag/v1.1.0), [Arduino PubSubClient 2.8](https://github.com/knolleary/pubsubclient/releases/tag/v2.8) and [Paho Embedded C 1.1.0](https://github.com/eclipse-paho/paho.mqtt.embedded-c/releases/tag/v1.1.0). Library version numbers do not identify the MQTT wire protocol.

## Root process smoke

The Linux `root-process` job runs on a dedicated GitHub-hosted VM after a push to `main`, not on pull requests. It builds as the runner user, then runs only the selected process test and the repository-built `mqextended` as root. It does not run a Mosquitto reference binary as root.

The smoke checks the broker's actual UID and GID, numeric environment overrides, and file permissions before and after the privilege drop. It verifies that unreadable credentials prevent readiness and that the detached daemon redirects its descriptors, serves a Unix socket, and cleans up on shutdown. Files and sockets live in a temporary directory. The private PID namespace contains any detached child even if startup fails before it writes a pid file.

To reproduce on a disposable Linux VM, first build as an unprivileged user. Save the `Executable` path printed by Cargo:

```sh
cargo test --locked -p mqx-server --test process --no-run
```

From a root shell **in that VM**, set `test_bin` to that absolute path and run:

```sh
env -i MQX_ROOT_PROCESS_SMOKE=1 \
  /usr/bin/timeout --kill-after=5s 90s \
  /usr/bin/unshare --fork --pid --mount-proc --kill-child -- \
  "$test_bin" --exact root_only_identity_mapping_and_privilege_drop_order
```

Confirm the harness runs one test. Without `MQX_ROOT_PROCESS_SMOKE`, the root checks do not run. The smoke requires a non-root `nobody` account, UID/GID changes and supplementary groups, and access to the dropped process's `/proc` descriptors. A rootless namespace that maps only UID/GID 0 cannot exercise this. Do not change host policies or accounts to enable it; use the disposable runner instead.

## Commands

```sh
cargo test -p <crate>                     # while working
cargo test --workspace                    # before a milestone commit
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
```

CI checks formatting, lint and tests against `Cargo.lock`. The differential job builds the Mosquitto references (cached); `linux-bundle` stages and validates a release without installing it. On trusted pushes to `main`, `root-process` runs the privilege/daemon smoke separately. `mqx-bench`'s ignored test needs release builds and runs locally.
