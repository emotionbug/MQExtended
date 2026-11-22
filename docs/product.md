# Product

MQExtended is an MQTT broker for operators who run Mosquitto today, cannot touch their clients, and need the broker to stop being a single point of failure.

## Who it's for

You run devices or services built on libmosquitto. Their settings are unknown or frozen: protocol version (libmosquitto 1.x defaults to MQTT 3.1), keepalive, clean-session flag, reconnect behaviour, topics. Your network already spreads one public address across several machines. You want every machine to accept any client and the cluster to keep working when one machine dies.

## What it promises

- **Drop-in for clients.** A client that works against Mosquitto 2.1.4 works against MQExtended with the same results: same CONNACK codes, same accepted and rejected topics, same authentication and ACL decisions. See [Mosquitto compatibility](mosquitto-compatibility.md).
- **Drop-in for operators.** Existing `password_file` and `acl_file` load unchanged.
- **Active-active cluster.** Any client can connect to any node. Messages reach subscribers on every node. Reconnecting to another node resumes the session. Losing one node of three loses no session, subscription, retained message or queued message. See [architecture](architecture.md).

## Non-goals

- Changing client behaviour to make the cluster easier (redirects, MQTT 5-only features as a requirement, forced reconnect settings).
- Load balancing. The network in front of the cluster decides which node a connection reaches.
- Mosquitto plugins, bridges and `$SYS` topics, unless a client is shown to depend on them.

## Direction

Each milestone ends with passing tests — unit, parity tables and differential runs against Mosquitto — and a commit.

| Milestone | Scope | Done when |
| --- | --- | --- |
| M1 Foundation | `mqx-topic`, `mqx-codec`, `mqx-auth` | Mosquitto's topic unit tests, `mosquitto_passwd` vectors and a real `mosquitto_pub` session all pass against our crates |
| M2 Single-node broker | Sessions, QoS 0/1/2, retained, will, keepalive, takeover; `mqx-server` reading the relevant `mosquitto.conf` subset; TCP and TLS | Real `mosquitto_pub`/`mosquitto_sub` scenarios give the same results against MQExtended and Mosquitto |
| M3 Cluster | Replicated metadata, node mesh forwarding, cross-node takeover, node leases and wills on node loss | Any-node pub/sub and takeover pass; killing one of three nodes keeps subscriptions and retained messages |
| M4 BifroMQ parity | Replicated inbox, WebSocket, PROXY protocol, admin API, metrics, MQTT 5 | Queued messages of persistent sessions survive node loss; operational surface matches BifroMQ's |
