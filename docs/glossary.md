# Glossary

Use these terms in code, comments, docs and commit messages. No synonyms.

## Cluster

- **Node** — One MQExtended process. Nodes of a cluster are equals; any of them accepts any client.
- **Cluster** — The set of nodes sharing one replicated log.
- **Replicated log** — The ordered, majority-committed command log every node applies to the same state machine. Implemented with Raft; single-node mode is a one-member log.
- **Mesh** — Ordered (FIFO per peer), authenticated node-to-node messaging offered by `mqx-cluster`, not replicated. The publish fast path delivers clean-session traffic over it.
- **Fast path / replicated path** — The two ways a PUBLISH reaches subscribers; see [architecture](architecture.md#request-flows).
- **Node lease** — Replicated proof that a node is alive. Expiry triggers node removal, will publication and orphaning of its sessions.

## Sessions

- **Client id** — The MQTT client identifier. The unit of ownership and takeover.
- **Transient session** — A clean-session client. Lives in the memory of the node serving it.
- **Persistent session** — A client connected with clean session off. Its subscriptions and inbox are replicated.
- **Claim** — The replicated command that makes a connection the current owner of a client id.
- **Epoch** — Counter incremented by every claim. The connection holding the current epoch owns the session.
- **Takeover** — Closing an older connection after a newer claim for the same client id, on any node.
- **Inbox** — The replicated queue of messages and in-flight state for one persistent session.
- **Orphaned session** — A persistent session whose owning node was removed; the next CONNECT with its client id claims it.

## State

- **Tier 1 (metadata)** — Ownership, subscriptions, wills, retained messages, membership. See [data model](data-model.md).
- **Tier 2 (inbox)** — Per-message state of persistent sessions.

## Compatibility

- **Reference** — Mosquitto 2.1.4, the behaviour MQExtended reproduces.
- **Parity rule** — One client-observable Mosquitto behaviour ported with its source citation. See [Mosquitto compatibility](mosquitto-compatibility.md).
- **Differential test** — A test that runs the real Mosquitto binary or tool and compares its result with ours.
