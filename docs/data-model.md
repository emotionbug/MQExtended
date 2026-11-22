# Data model

State is split by write rate and by what must survive the loss of a node. In a cluster both tiers live in the replicated log; standalone mode keeps the same state in memory.

## Tiers

| Tier | Contents | Written on | Read by |
| --- | --- | --- | --- |
| 1. Metadata | client-id ownership and connection epoch; persistent-session subscriptions and settings; will messages; retained messages; node membership and leases | connect, disconnect, (un)subscribe, retained publish, node events | every node: subscription index, takeover, CONNACK `session_present`, retained delivery |
| 2. Inbox | queued messages and in-flight state of persistent sessions | every message to a persistent subscriber, every acknowledgement | the node currently serving that session |

Transient (clean-session) sessions keep their outgoing queue in the memory of the node serving them. Their claim and subscriptions are replicated so every node can route to them, and are removed when the connection ends or the node is declared down.

## Rules

- **Ownership is an epoch, not a node name.** Every claim increments the epoch. A node acts on a session only while its connection carries the current epoch; anything older is closed.
- **Retained messages are global.** A retained publish is a tier-1 write so every node serves the same retained set to new subscriptions.
- **Wills are replicated at CONNECT.** A node that dies cannot publish its clients' wills; the node that removes it does.
- **Limits follow Mosquitto defaults.** Queue length 1000 (`max_queued_messages`), in-flight window 20 (`max_inflight_messages`), no session expiry, QoS 0 not queued for offline sessions (`queue_qos0_messages false`). See [Mosquitto compatibility](mosquitto-compatibility.md#defaults).

## Replication semantics

- **Apply runs on every node, in log order.** Side effects of an applied command (closing a taken-over connection, publishing a will) must check whether this node is the one that should act; the state itself is identical everywhere.
- **`submit` can be uncertain.** When a proposal may have committed but the reply was lost, `submit` returns `WriteUncertain`. Commands therefore carry the identity needed to be applied idempotently (client id + epoch, message id), so a retry cannot double-apply.
- **Node `Down` is liveness, not membership.** A lease expiry commits a `Down` event at one log index on every node; the node stays a Raft voter. A restarted node renews its lease and is marked `Alive`.
- **Peer traffic is unauthenticated.** The Raft/mesh port must live on a trusted private network.

## On-disk layout

Single-node mode uses the same layout with a one-member cluster.

```text
<data_dir>/
├── node.mpk        # node id and the static bootstrap peers (msgpack)
├── wal/            # Raft log entries, vote, commit frontier (raft-log chunk files)
└── snapshot.mpk    # Raft snapshot metadata, node leases, application state
```

Entries and votes are fsynced before they are acknowledged; the commit frontier is fsynced before entries are applied. A snapshot is written to a temporary file, fsynced, renamed and the directory fsynced before the log is compacted behind it. Restart restores the snapshot and replays the committed log tail.
