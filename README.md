# MQExtended

A clustered MQTT broker in Rust that replaces Mosquitto without changing clients.

- **Mosquitto 2.1.4 behaviour.** MQTT 3.1, 3.1.1 and 5 clients get the same CONNACK codes, accepted and rejected topics, packet ids, flags and properties as from Mosquitto. Existing `mosquitto.conf`, `password_file`, `acl_file`, dynamic-security JSON and `mosquitto.db` load unchanged. Proven by differential tests that run real Mosquitto builds side by side and compare byte for byte.
- **Active-active cluster.** Any client can connect to any node behind one load-balanced address. Sessions, subscriptions, retained messages and persistent queues are replicated with Raft; losing one node of three loses none of them, and the lost node's wills are published once. Nodes can be added, removed and replaced while the cluster serves traffic.
- **Mosquitto's feature set.** TCP, TLS, WebSocket, Unix socket and PROXY protocol listeners; bridges (one owner per bridge in a cluster); persistence; built-in dynamic security with `mosquitto_ctrl`; `$SYS` topics and the HTTP API; systemd readiness, privilege drop and signals as the `mosquitto` process.
- **Operations.** Mutual TLS between nodes, a cluster status endpoint and Prometheus metrics.

## Quick start

```sh
cargo build --release -p mqx-server
target/release/mqextended -c /etc/mosquitto/mosquitto.conf      # standalone
target/release/mqextended --test-config -c mosquitto.conf       # check a config
```

Add `cluster_*` directives to run a cluster; see [docs/cluster.md](docs/cluster.md). Moving an existing deployment: [docs/migration.md](docs/migration.md).

## Documentation

Start with [AGENTS.md](AGENTS.md); it indexes everything in [docs/](docs/).

## Build and test

```sh
cargo test --workspace
```

Differential and failover tests need Mosquitto reference builds and are `#[ignore]`d by default; see [docs/testing.md](docs/testing.md#differential-tests). CI runs both.
