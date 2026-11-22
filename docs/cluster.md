# Cluster

How to run MQExtended as an active-active cluster and what a client observes when a node fails. Replication internals are in [data model](data-model.md); the design rationale is in [architecture](architecture.md).

## Configuration

Cluster settings live in `mosquitto.conf`. The `cluster_*` directives are MQExtended extensions; Mosquitto refuses to start with them. Without them the broker runs standalone; state survives a restart only when standalone persistence is enabled.

| Directive | Meaning | Default |
| --- | --- | --- |
| `cluster_node_id <id>` | This node's id, a positive integer unique in the cluster | required |
| `cluster_bind <ip:port>` | Address this node listens on for Raft and mesh traffic | required |
| `cluster_peer <id> <ip:port>` | One line per node, this node included; identical on every node | required |
| `cluster_data_dir <path>` | Raft log, vote and snapshots; created with mode 0700 if missing | required |
| `cluster_cafile <path>` | CA that signed every node certificate | required unless plaintext |
| `cluster_certfile <path>` | This node's certificate; its Common Name must be `mqx-node-<id>` | required unless plaintext |
| `cluster_keyfile <path>` | Key for `cluster_certfile` | required unless plaintext |
| `cluster_insecure_plaintext true` | Run peer traffic without TLS; refused together with a wildcard `cluster_bind` | false |
| `cluster_max_snapshot_size <bytes>` | Largest snapshot this node can send or receive (at most 256 MiB) | 64 MiB |
| `cluster_heartbeat_interval <ms>` | Raft leader heartbeat | 100 |
| `cluster_election_timeout <min> <max>` | Raft election timeout range | 400 800 |
| `cluster_lease_interval <ms>` | How often a node renews its liveness lease | 1000 |
| `cluster_lease_timeout <ms>` | Lease age after which a node is declared down | 5000 |
| `cluster_request_timeout <ms>` | Deadline for a replicated write, including leader changes | 5000 |
| `cluster_join true` | Start an empty node as a new member of a running cluster instead of bootstrapping one | false |
| `cluster_membership_generation <n>` | Version of the `cluster_peer` list; raise it to request a membership change | 0 |
| `cluster_state_format <1\|2>` | On-disk and wire format this node writes; see [upgrades](#upgrades) | 2 |

Example for node 2 of three:

```text
listener 1883
password_file /etc/mqextended/passwd
acl_file /etc/mqextended/acl

cluster_node_id 2
cluster_bind 10.0.0.12:7000
cluster_peer 1 10.0.0.11:7000
cluster_peer 2 10.0.0.12:7000
cluster_peer 3 10.0.0.13:7000
cluster_data_dir /var/lib/mqextended
cluster_cafile /etc/mqextended/cluster-ca.pem
cluster_certfile /etc/mqextended/node2.pem
cluster_keyfile /etc/mqextended/node2.key
```

Give every node the same `password_file`, `acl_file` and broker limits. Send SIGHUP to every node after updating file credentials or ACLs. Roll the nodes to apply changed broker limits.

Issue node certificates from a CA used only for the cluster, one per node, with Common Name `mqx-node-<id>` matching `cluster_node_id`. Every peer connection is mutually authenticated: a node only accepts a peer whose certificate chains to `cluster_cafile` and whose Common Name matches the node id it claims, and it checks the same when it dials out. Addresses play no part in authentication.

## Network

- Keep `cluster_bind` on a private network even with TLS. With `cluster_insecure_plaintext true` peer traffic is neither authenticated nor encrypted, and anyone who can reach the port can rewrite broker state; use it only on an isolated network or for tests.
- The MQTT listeners sit behind your load balancer. Any node can serve any client, so the balancer needs no stickiness; least-connections spreads reconnect storms best.
- Probe `GET /api/v1/mqx/ready` on an HTTP API listener, with credentials and a read ACL for just that path. It checks the same gate as MQTT admission: security registration and an unexpired quorum-backed voter lease. A partition may remain ready until that lease expires. A TCP connect or a successful cluster-status query only proves the process is up.
- Run an odd number of nodes. Three nodes tolerate one failure; writes stop while a majority is unreachable.

## Bootstrap and restart

Start all nodes with identical `cluster_peer` lines and no `cluster_membership_generation`, in any order. The first start bootstraps the cluster exactly once; later starts rejoin from `cluster_data_dir`, and from then on the replicated membership, not the config file, decides who the members are. Never reuse a data directory under a different `cluster_node_id`, and never copy one node's data directory to another.

After a restart or loss of its lease, a follower only admits MQTT clients after renewing its lease and applying through a fresh quorum-confirmed read index. Keep it out of the load balancer until `/api/v1/mqx/ready` returns `200`; an open TCP port or an `Alive` membership entry alone is not sufficient.

### Cold backup and restore

1. Drain client traffic and stop **all** nodes. Confirm each process has exited successfully before taking the first copy. Independent copies of live WALs are not a cluster backup.
2. Back up every node's entire `cluster_data_dir`, indexed by its node ID. Keep its config, referenced credential files and matching peer certificate/key in protected storage as well. Preserve ownership and permissions. Record the binary version, membership generation and state format with the backup.
3. Restore the set to an isolated network, with the original cluster stopped or unreachable. Use the same binary version, IDs and configured peer addresses. Restore each directory only to its original ID; do not bootstrap an empty cluster or run a restored voter concurrently with its original.
4. With client traffic still drained, start the restored nodes. Check that `/api/v1/mqx/cluster` reports the expected voters and leader, and `/api/v1/mqx/ready` returns `200` on each serving node. Check a known retained payload and reconnect a test persistent client with clean start disabled: verify session-present and the expected queued messages before routing production traffic. Changes made after the backup are not recovered.

Keep each node's `snapshot.mpk` below the configured transfer limit with headroom. A larger local snapshot can be written, but a learner or lagging voter that needs it cannot catch up from it. Set an alert on the file size and qualify the expected application state against the limit before deploying.

## Changing membership

Membership changes run while the cluster serves traffic. The leader adds a new node as a learner, waits until it has caught up, checks that both the current and the proposed voter sets have a reachable majority, and only then switches voters; it refuses a change that would lose quorum and reports why.

To add a node:

1. Pick a node id that has never been used in this cluster and issue its `mqx-node-<id>` certificate.
2. Start it with an empty `cluster_data_dir`, `cluster_join true`, and `cluster_peer` lines for itself and the current voters.
3. On every current voter, put the full desired peer list in the config, set `cluster_membership_generation` to a number higher than the one in use, and send SIGHUP.
4. Wait until the new node shows as a voter in the cluster status before routing clients to it.

To remove a node, delete its `cluster_peer` line on every remaining voter, raise `cluster_membership_generation`, and send SIGHUP. The removed node disconnects its MQTT clients (they reconnect through the load balancer) but keeps answering the HTTP status endpoints; stop it once the cluster lists its id as retired.

To replace a node that died for good, do both in one change: a new id joins as above, and the desired peer list leaves out the dead id. A retired id stays retired across restarts; a node started with a retired id or with the data directory of a removed node is refused. If a majority is lost, bring the missing voters back. Re-bootstrapping a cluster that still has data discards it.

## Upgrades

Use a rolling upgrade only if every running binary can replay every command that traffic can produce. A node refuses log entries, snapshots and node identity files whose format version it does not know. For a compatible rolling upgrade:

1. Roll the new binary out to every node while it keeps writing the old format (`cluster_state_format 1` when coming from a release before format 2).
2. Once every node runs the new binary, roll the setting to the new format, again one node at a time.

Don't change membership in the middle of an upgrade.

When upgrading a build that predates the MQTT broker control API, use a cold upgrade if clients can publish to `$CONTROL/` topics. Requests to disabled or unknown endpoints also produce a replicated `BrokerControl` command that the old build cannot replay. Turning off `enable_control_api` is not a mixed-version compatibility switch. Drain clients, stop all voters, take the cold backup above and upgrade all voters before restoring traffic.

Also use a cold upgrade when crossing the introduction of `SubscribeDollarRoot` and `ReserveOutboundWithQos0Expiry`. A subscription such as `$app/#`, or a QoS 0 delivery past an expired in-flight message, can emit these commands even with `cluster_state_format 1`. Drain clients and bridge traffic, stop and back up the cluster, upgrade every voter and learner, then restore traffic. New binaries replay historical `Subscribe` and `ReserveOutbound` entries with their original semantics; old binaries cannot replay the new commands.

Do not enable `mosquitto_sparkplug_aware` until every node runs a build that supports it. The first matching birth publication can write `ReceiveBirth` or `ForwardBirth` to the log. Existing log entries are not reinterpreted when you enable the plugin.

## What clients observe when a node fails

- Clients connected to the failed node lose their connection and reconnect through the load balancer to a surviving node.
- After `cluster_lease_timeout`, the cluster publishes the wills of the failed node's clients, once.
- A persistent session (clean session off) resumes on any node with `session_present` set, its subscriptions, the messages queued while it was away, and unacknowledged messages resent with DUP.
- Retained messages and subscriptions of all clients are unaffected.
- A leader failure pauses writes for about one election timeout; clients see slower acknowledgements, not disconnects.
