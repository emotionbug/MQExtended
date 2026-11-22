# Cluster

How to run MQExtended as an active-active cluster and what a client observes when a node fails. Replication internals are in [data model](data-model.md); the design rationale is in [architecture](architecture.md).

## Configuration

Cluster settings live in the same `mosquitto.conf` as everything else. The `cluster_*` directives are MQExtended extensions; Mosquitto refuses to start with them. Without any `cluster_*` directive the broker runs standalone and in memory, like Mosquitto with `persistence false`.

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
| `cluster_max_snapshot_size <bytes>` | Largest snapshot a node accepts from a peer (at most 256 MiB) | 64 MiB |
| `cluster_heartbeat_interval <ms>` | Raft leader heartbeat | 100 |
| `cluster_election_timeout <min> <max>` | Raft election timeout range | 400 800 |
| `cluster_lease_interval <ms>` | How often a node renews its liveness lease | 1000 |
| `cluster_lease_timeout <ms>` | Lease age after which a node is declared down | 5000 |
| `cluster_request_timeout <ms>` | Deadline for a replicated write, including leader changes | 5000 |

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

Give every node the same `password_file`, `acl_file` and broker limits. Send SIGHUP to every node after changing them.

Issue node certificates from a CA used only for the cluster, one per node, with Common Name `mqx-node-<id>` matching `cluster_node_id`. Every peer connection is mutually authenticated: a node only accepts a peer whose certificate chains to `cluster_cafile` and whose Common Name matches the node id it claims, and it checks the same when it dials out. Addresses play no part in authentication.

## Network

- Keep `cluster_bind` on a private network even with TLS. With `cluster_insecure_plaintext true` peer traffic is neither authenticated nor encrypted, and anyone who can reach the port can rewrite broker state; use it only on an isolated network or for tests.
- The MQTT listeners sit behind your load balancer. Any node can serve any client, so the balancer needs no stickiness; least-connections spreads reconnect storms best.
- Run an odd number of nodes. Three nodes tolerate one failure; writes stop while a majority is unreachable.

## Bootstrap and restart

Start all nodes with identical `cluster_peer` lines, in any order. The first start bootstraps the cluster exactly once; later starts rejoin from `cluster_data_dir`. Never reuse a data directory under a different `cluster_node_id`, and never copy one node's data directory to another.

## What clients observe when a node fails

- Clients connected to the failed node lose their connection and reconnect through the load balancer to a surviving node.
- After `cluster_lease_timeout`, the cluster publishes the wills of the failed node's clients, once.
- A persistent session (clean session off) resumes on any node with `session_present` set, its subscriptions, the messages queued while it was away, and unacknowledged messages resent with DUP.
- Retained messages and subscriptions of all clients are unaffected.
- A leader failure pauses writes for about one election timeout; clients see slower acknowledgements, not disconnects.
