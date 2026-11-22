# Data model

State is split by write rate and by what must survive the loss of a node. In a cluster both tiers live in the replicated log; standalone mode keeps the same state in memory and, with `persistence true`, saves it to disk as Mosquitto does (on `autosave_interval`, SIGUSR1 and clean shutdown).

## Tiers

| Tier | Contents | Written on | Read by |
| --- | --- | --- | --- |
| 1. Metadata | client-id ownership and connection epoch; persistent-session subscriptions and settings; will messages; retained messages; node membership and leases | connect, disconnect, (un)subscribe, retained publish, node events | every node: subscription index, takeover, CONNACK `session_present`, retained delivery |
| 2. Inbox | queued messages and in-flight state of persistent sessions | every message to a persistent subscriber, every acknowledgement | the node currently serving that session |

Transient (clean-session) sessions keep their outgoing queue in the memory of the node serving them. Their claim and subscriptions are replicated so every node can route to them, and are removed when the connection ends or the node is declared down. Messages reach them over the mesh, not the log ([architecture](architecture.md#request-flows)).

A message to a persistent session is reserved for sending in the same commit that queues it (or that acknowledges the previous message, when the in-flight window was full). The serving node then sends it without another round. Because the reservation is committed before the packet can be written, a session that resumes on another node resends exactly the reserved messages with DUP set, as Mosquitto's `database.c` marks a message sent before writing it. A crash between commit and socket write can set DUP on a packet the client never received; the spec allows that, and clients treat DUP as a hint only.

## Rules

- **Ownership is an epoch, not a node name.** Every claim increments the epoch. A node acts on a session only while its connection carries the current epoch; anything older is closed.
- **Retained messages are global.** A retained publish is a tier-1 write so every node serves the same retained set to new subscriptions.
- **Wills are replicated at CONNECT.** A node that dies cannot publish its clients' wills; the node that removes it does.
- **Bridge ownership is a claim.** A bridge runs on the node holding the claim on its local client id. A node stops its bridges as soon as it can no longer prove a fresh lease renewal, so it always steps down before a peer can take the bridge over.
- **Security and `$SYS` state are replicated.** Dynamic-security changes and each `$SYS` sample are log commands, so every node enforces the same rules and serves the same retained `$SYS` tree.
- **Limits follow Mosquitto defaults.** Queue length 1000 (`max_queued_messages`), in-flight window 20 (`max_inflight_messages`), no session expiry, QoS 0 not queued for offline sessions (`queue_qos0_messages false`). See [Mosquitto compatibility](mosquitto-compatibility.md#defaults).

## Replication semantics

- **Apply runs on every node, in log order.** Side effects of an applied command (closing a taken-over connection, publishing a will) must check whether this node is the one that should act; the state itself is identical everywhere.
- **`submit` can be uncertain.** When a proposal may have committed but the reply was lost, `submit` returns `WriteUncertain`. Commands therefore carry the identity needed to be applied idempotently (client id + epoch, message id), so a retry cannot double-apply.
- **Node `Down` is liveness, not membership.** A lease expiry commits a `Down` event at one log index on every node; the node stays a Raft voter. A restarted node renews its lease and is marked `Alive`.
- **Peers authenticate with mutual TLS.** Node certificates carry Common Name `mqx-node-<id>`; a peer may only speak for the id in its certificate. Plaintext peer traffic is an explicit opt-in ([cluster](cluster.md#network)).

## On-disk layout

A Raft cluster, including one configured with a single voter, uses the layout below. A standalone broker has no Raft directory; with `persistence true` it stores a native `<persistence_file>.mqx` instead.

```text
<data_dir>/
├── node.mpk        # node id and the static bootstrap peers (msgpack)
├── wal/            # Raft log entries, vote, commit frontier (raft-log chunk files)
└── snapshot.mpk    # Raft snapshot metadata, node leases, application state
```

Entries and votes are fsynced before they are acknowledged. Commit frontiers are coalesced into the next required WAL sync, not synced separately before apply. Restart restores the snapshot and replays the locally recorded committed tail; Raft reestablishes any newer commit frontier. A snapshot is written to a temporary file, fsynced, renamed and the directory fsynced before the log is compacted behind it.
