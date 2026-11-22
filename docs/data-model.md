# Data model

State is split by write rate and by what must survive the loss of a node. Both tiers live in the replicated log; they differ in how often they are written and who reads them.

## Tiers

| Tier | Contents | Written on | Read by |
| --- | --- | --- | --- |
| 1. Metadata | client-id ownership and connection epoch; persistent-session subscriptions and settings; will messages; retained messages; node membership and leases | connect, disconnect, (un)subscribe, retained publish, node events | every node: subscription index, takeover, CONNACK `session_present`, retained delivery |
| 2. Inbox | queued messages and in-flight state of persistent sessions | every message to a persistent subscriber, every acknowledgement | the node currently serving that session |

Transient (clean-session) sessions exist only in the memory of the node serving them. Their subscriptions are still replicated so other nodes can route to them, and are removed when the connection ends.

## Rules

- **Ownership is an epoch, not a node name.** Every claim increments the epoch. A node acts on a session only while its connection carries the current epoch; anything older is closed.
- **Retained messages are global.** A retained publish is a tier-1 write so every node serves the same retained set to new subscriptions.
- **Wills are replicated at CONNECT.** A node that dies cannot publish its clients' wills; the node that removes it does.
- **Limits follow Mosquitto defaults.** Queue length 1000 (`max_queued_messages`), in-flight window 20 (`max_inflight_messages`), no session expiry, QoS 0 not queued for offline sessions (`queue_qos0_messages false`). See [Mosquitto compatibility](mosquitto-compatibility.md#defaults).

## On-disk layout

Defined in M3 with the Raft storage. Single-node mode uses the same state machine and storage with a one-member cluster.
