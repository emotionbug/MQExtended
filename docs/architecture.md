# Architecture

MQExtended is a set of Rust crates layered from wire format to cluster. The broker logic never knows whether it runs alone or in a cluster: it reads and writes state through a replicated-log interface whose single-node implementation is local.

```text
clients ── L4 address (owned by the network) ──┬── node A ─┐
                                               ├── node B ─┼── node mesh (forwarding, takeover)
                                               └── node C ─┘
each node:
  mqx-server   mosquitto.conf, listeners: TCP / TLS / WebSocket (mqx-ws), PROXY protocol (mqx-proxy)
    └ mqx-broker   sessions, QoS flows, retained, will, keepalive
        ├ mqx-auth    password_file / acl_file decisions
        ├ mqx-codec   MQTT 3.1 / 3.1.1 / 5 wire format
        ├ mqx-topic   validation, matching, subscription index
        └ mqx-cluster replicated state machine (Raft) + mesh RPC
```

## Ownership

| Crate | Responsibility |
| --- | --- |
| `mqx-topic` | Topic validation and matching identical to Mosquitto; the subscription index used for routing |
| `mqx-codec` | Encode/decode MQTT 3.1 / 3.1.1 packets (and MQTT 5 in `v5`); Mosquitto's per-protocol wire validation; no I/O |
| `mqx-auth` | Load `password_file` / `acl_file`; answer allow / deny / ignore exactly as Mosquitto's built-in plugins |
| `mqx-proxy` | Read PROXY protocol v1/v2 headers and their TLS TLVs as Mosquitto's `enable_proxy_protocol` does; no I/O in the parser |
| `mqx-ws` | Upgrade HTTP to WebSocket with Mosquitto's built-in handshake rules; expose the MQTT byte stream as `AsyncRead`/`AsyncWrite` |
| `mqx-broker` | Protocol engine per connection; session lifecycle; delivery; talks to state only through the replicated-log interface |
| `mqx-cluster` | Generic replicated state machine on openraft (durable log, snapshots, bootstrap); node leases; mesh RPC between nodes. Knows nothing about MQTT |
| `mqx-server` | The `mqextended` binary: `mosquitto.conf` parsing, listeners, TLS, signals, wiring of the crates above |
| `mqx-difftest` | Test-only: runs one scenario against Mosquitto and `mqextended` and compares client transcripts |

Lower crates never depend on higher ones. `mqx-codec`, `mqx-topic`, `mqx-auth` and the `mqx-proxy` parser stay sans-IO so their parity tests run without sockets. `mqx-cluster` is generic over the state machine so the broker can be tested without Raft and the cluster without MQTT.

## Request flows

- **CONNECT on node B.** Authenticate with `mqx-auth`, then commit a claim for the client id with a new connection epoch. Every node applies it; the node holding an older epoch closes that connection (session takeover). B answers CONNACK with `session_present` from the applied state.
- **PUBLISH on node X.** ACL `write` check; retained update if the retain flag is set; match the local subscription index; deliver to local transient subscribers; forward to the owning node of remote transient subscribers over the mesh; append to the inbox of persistent subscribers. ACL `read` is checked per subscriber before delivery.
- **Node loss.** Node leases are replicated state. When a lease expires, a surviving node commits the node's removal, publishes the wills of its clients and leaves their sessions unowned. Clients reconnect anywhere and resume from replicated state.

Transient (clean-session) delivery never touches the replicated log. Persistent sessions are always inbox-backed: a message for a persistent subscriber is committed first, pushed to the connection if online, and removed on acknowledgement. Which node held the session stops mattering after failover. The state itself is described in [data model](data-model.md).

## Why Raft first

The replicated-log interface is narrow on purpose. The first implementation uses `openraft`, a leader-based Raft with production users. QuePaxa (leaderless liveness, used by Cloudflare's Meerkat) removes leader-election stalls, which matters on wide-area links. In one site with three nodes, Raft's failover pause is shorter than the clients' own reconnect window, so Raft is the conservative default. A QuePaxa implementation can be evaluated behind the same interface without touching the broker.
