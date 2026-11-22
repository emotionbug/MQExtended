# Product

MQExtended is an MQTT broker for operators who run Mosquitto today, cannot touch their clients, and need the broker to stop being a single point of failure.

## Who it's for

You run devices or services built on libmosquitto. Their settings are unknown or frozen: protocol version (libmosquitto 1.x defaults to MQTT 3.1), keepalive, clean-session flag, reconnect behaviour, topics. Your network already spreads one public address across several machines. You want every machine to accept any client and the cluster to keep working when one machine dies.

## What it promises

- **Drop-in for clients.** A client that works against Mosquitto 2.1.4 works against MQExtended with the same results: same CONNACK codes, same accepted and rejected topics, same authentication and ACL decisions. See [Mosquitto compatibility](mosquitto-compatibility.md).
- **Drop-in for operators.** The existing `mosquitto.conf`, `password_file`, `acl_file`, dynamic-security JSON, persistence file and service unit work unchanged; what MQExtended cannot honour makes it refuse to start instead of running without it. See [migration](migration.md).
- **Active-active cluster.** Any client can connect to any node. Messages reach subscribers on every node. Reconnecting to another node resumes the session. Losing one node of three loses no session, subscription, retained message or queued message. See [architecture](architecture.md).

## Non-goals

- Changing client behaviour to make the cluster easier (redirects, MQTT 5-only features as a requirement, forced reconnect settings).
- Load balancing. The network in front of the cluster decides which node a connection reaches.
- Loading Mosquitto's C plugins. The dynamic security plugin is built in; others are refused.

## Direction

Each milestone ends with passing tests — unit, parity tables and differential runs against Mosquitto — and a commit.

| Milestone | Scope | Done when |
| --- | --- | --- |
| M1 Foundation | `mqx-topic`, `mqx-codec`, `mqx-auth` | Mosquitto's topic unit tests, `mosquitto_passwd` vectors and a real `mosquitto_pub` session all pass against our crates |
| M2 Single-node broker | Sessions, QoS 0/1/2, retained, will, keepalive, takeover; `mqx-server` reading the relevant `mosquitto.conf` subset; TCP and TLS | Real `mosquitto_pub`/`mosquitto_sub` scenarios give the same results against MQExtended and Mosquitto |
| M3 Cluster | Raft-replicated broker state, delivery from each node's own apply, cross-node takeover, node leases and wills on node loss, replicated persistent inboxes | The 37 differential scenarios stay byte-identical to Mosquitto with clients spread over three nodes; killing a node keeps subscriptions, retained and queued messages |
| M4 BifroMQ parity | WebSocket, PROXY protocol and Unix socket listeners, MQTT 5, mutual TLS between nodes, publish fast path, dynamic membership, `$SYS` tree and Mosquitto's HTTP API, metrics and cluster status, bridges, persistence and `mosquitto.db` import, built-in dynamic security, process behaviour (systemd, privileges, signals) | Differential scenarios match Mosquitto for each feature; operators get Mosquitto's monitoring surface plus cluster health; a running Mosquitto deployment moves over with its state |
