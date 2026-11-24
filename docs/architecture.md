# Architecture

MQExtended is a set of Rust crates layered from wire format to cluster. The broker logic never knows whether it runs alone or in a cluster: it reads and writes state through a replicated-log interface whose single-node implementation is local.

```text
clients ── L4 address (owned by the network) ──┬── node A ─┐
                                               ├── node B ─┼── replicated log (Raft): every node applies every command
                                               └── node C ─┘
each node:
  mqx-server   mosquitto.conf, listeners: TCP / TLS / WebSocket (mqx-ws), PROXY protocol (mqx-proxy)
    └ mqx-broker   sessions, QoS flows, retained, will, keepalive
        ├ mqx-auth    password_file / acl_file decisions; third-party plugin contract
        ├ mqx-extauth mosquitto-auth-plug port and its back-end clients (wired in by mqx-server)
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
| `mqx-extauth` | Rust ports of third-party auth plugins behind the `mqx-auth` plugin contract, with their back-end clients (HTTP, SQL, LDAP, Redis, memcached, MongoDB). The only crate that performs back-end I/O for authorization |
| `mqx-proxy` | Read PROXY protocol v1/v2 headers and their TLS TLVs as Mosquitto's `enable_proxy_protocol` does; no I/O in the parser |
| `mqx-ws` | Upgrade HTTP to WebSocket with Mosquitto's built-in handshake rules; expose the MQTT byte stream as `AsyncRead`/`AsyncWrite` |
| `mqx-broker` | Protocol engine per connection; session lifecycle; delivery; talks to state only through the replicated-log interface |
| `mqx-cluster` | Generic replicated state machine on openraft (durable log, snapshots, bootstrap); node leases; mesh RPC between nodes. Knows nothing about MQTT |
| `mqx-server` | The `mqextended` binary: `mosquitto.conf` parsing, listeners, TLS, signals, wiring of the crates above |
| `mqx-difftest` | Test-only: runs one scenario against Mosquitto and `mqextended` and compares client transcripts |

Lower crates never depend on higher ones. `mqx-codec`, `mqx-topic`, `mqx-auth` and the `mqx-proxy` parser stay sans-IO so their parity tests run without sockets. `mqx-cluster` is generic over the state machine so the broker can be tested without Raft and the cluster without MQTT.

## Request flows

- **CONNECT on node B.** Authenticate with `mqx-auth`, then commit a claim for the client id with a new connection epoch. Every node applies it; the node holding an older epoch closes that connection (session takeover). B answers CONNACK with `session_present` from the applied state, then pulls any pending inbox state itself instead of waiting for effects that its own apply may have dispatched before the connection registered.
- **PUBLISH on node X.** Two paths, chosen per message and subscriber:
  - *Fast path* — QoS 0/1 messages to clean-session subscribers. X matches its copy of the replicated subscription index and sends the message over the ordered mesh stream to each node that hosts a matching subscriber (itself included); that node checks ACL `read` and delivers. No consensus round: a clean session dies with its node anyway. Per-peer FIFO streams keep each publisher's messages in order for every subscriber.
  - *Replicated path* — everything whose state must outlive a node: retained updates, persistent subscribers' inboxes, shared subscriptions (so the round-robin choice is identical everywhere), QoS 2, session and will timers. X commits the command; every node applies it and acts for its own clients. The outbound cursor and acknowledgements of persistent sessions are commits too, batched per proposal.

  SUBSCRIBE, UNSUBSCRIBE and ACL changes are committed and then fenced: the reply waits until every live node has applied them, so the fast path never routes on a stale index. A peer that stops answering is waited out until its lease expires rather than failing the client.
- **Third-party plugin ACL.** `State::apply` never calls a plugin, because a back-end answer is not deterministic. The serving node asks the plugin before it proposes a PUBLISH or SUBSCRIBE and commits the verdicts with the operation. A delivery or will whose verdict is not known at apply waits in replicated state until a `ResolveVerdicts` command carries it. The session's node asks for that verdict, or the leader when that node is down. Reusable verdicts are a replicated cache ([auth plugins](auth-plugins.md#in-a-cluster)).
- **Node loss.** Node leases are replicated state. When a lease expires, the cluster commits the node's `Down` event; every node applies it at the same index, publishes the wills of the lost node's clients once, removes their transient sessions and keeps their persistent sessions for reconnection elsewhere.
- **Uncertain writes.** When a commit may or may not have happened (leader lost mid-request), the broker closes that client's connection instead of retrying. MQTT's own resend rules (DUP on reconnect) then decide, so a retry can never deliver a QoS 0 message twice.

Standalone mode (no `cluster_*` directives) applies the same state machine to an in-memory log, matching Mosquitto's default `persistence false`. Persistent sessions are always inbox-backed, so in a cluster which node held a session stops mattering after failover. The state itself is described in [data model](data-model.md). Measured latency and throughput are in [performance](performance.md).

## Why Raft first

The replicated-log interface is narrow on purpose. The first implementation uses `openraft`, a leader-based Raft with production users. QuePaxa (leaderless liveness, used by Cloudflare's Meerkat) removes leader-election stalls, which matters on wide-area links. In one site with three nodes, Raft's failover pause is shorter than the clients' own reconnect window, so Raft is the conservative default. A QuePaxa implementation can be evaluated behind the same interface without touching the broker.
