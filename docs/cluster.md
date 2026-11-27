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
| `cluster_max_snapshot_size <bytes>` | Largest snapshot this node can send or receive; see [storage](#storage-and-state-growth) | 4294967295 (2147483647 on 32-bit) |
| `cluster_storage_reserve <bytes>` | Space this node holds back on its data volume for low-space recovery, at most 1 GiB; `0` turns it off; see [storage](#storage-and-state-growth) | 5% of the volume, 64 MiB to 1 GiB |
| `cluster_heartbeat_interval <ms>` | Raft leader heartbeat | 100 |
| `cluster_election_timeout <min> <max>` | Raft election timeout range | 400 800 |
| `cluster_lease_interval <ms>` | How often a node renews its liveness lease | 1000 |
| `cluster_lease_timeout <ms>` | Lease age after which a node is declared down | 5000 |
| `cluster_request_timeout <ms>` | Deadline for a replicated write, including leader changes | 5000 |
| `cluster_join true` | Start an empty node as a new member of a running cluster instead of bootstrapping one | false |
| `cluster_membership_generation <n>` | Version of the `cluster_peer` list; raise it to request a membership change | 0 |
| `cluster_state_format <1\|2>` | On-disk and wire format this node writes; see [upgrades](#upgrades) | 2 |
| `cluster_qos1_replay_batch true` | Reserve a bounded window of ready MQTT 3.x QoS 1 messages in one commit when a persistent subscriber resumes; see [upgrades](#upgrades) | false |
| `auto_recover <true\|false>` | Recover from quorum loss, a lost peer or unusable local state without operator action, giving up consistency; see [automatic recovery](#automatic-recovery). Also applies to a standalone broker | true, or false with `cluster_state_format 1` or without a `cluster_peer` line for this node |
| `auto_recover_timeout <ms>` | How long a node waits without quorum before it continues alone; requires `auto_recover true` | `cluster_lease_timeout` |

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

Give every node the same `password_file`, `acl_file` and broker limits. Replace the credential and ACL files on every node; each broker [reloads the files automatically](mosquitto-compatibility.md#deliberate-deviations). A SIGHUP on any node commits that node's `message_size_limit`, `persistent_client_expiration`, `retain_max_age`, `queue_qos0_messages`, `upgrade_outgoing_qos`, `allow_duplicate_messages` and `clientid_prefixes` to the whole cluster, so every node applies them at the same point in the log. Committed values survive restarts and take precedence over a node's file until the next SIGHUP; a node whose file disagrees logs a warning when it starts. Roll the nodes to change the other broker limits.

Issue node certificates from a CA used only for the cluster, one per node, with Common Name `mqx-node-<id>` matching `cluster_node_id`. Every peer connection is mutually authenticated: a node only accepts a peer whose certificate chains to `cluster_cafile` and whose Common Name matches the node id it claims, and it checks the same when it dials out. Addresses play no part in authentication.

To renew a certificate, replace the files in place (write a new file and rename it over the old one, or let your secret store swap them). Both [MQTT listener certificates](mosquitto-compatibility.md#deliberate-deviations) and peer certificates reload without a signal. A node checks `cluster_cafile`, `cluster_certfile` and `cluster_keyfile` before each new peer connection, at most once per second, and uses them once the CA, chain, key and Common Name are consistent; until then it keeps the previous set and logs a warning. Established peer connections are not interrupted. Renew certificates well before they expire: a connection opened after expiry is refused.

## Network

- Keep `cluster_bind` on a private network even with TLS. With `cluster_insecure_plaintext true` peer traffic is neither authenticated nor encrypted, and anyone who can reach the port can rewrite broker state; use it only on an isolated network or for tests.
- The MQTT listeners sit behind your load balancer. Any node can serve any client, so the balancer needs no stickiness; least-connections spreads reconnect storms best.
- Probe `GET /api/v1/mqx/ready` on an HTTP API listener, with credentials and a read ACL for just that path. It checks the same gate as MQTT admission: security registration and an unexpired quorum-backed voter lease. A partition may remain ready until that lease expires. A TCP connect or a successful cluster-status query only proves the process is up.
- One voter can serve and persist data on its own, but has no failover. Two voters require both for a majority. Use three voters to keep serving through one failure, or enable [automatic recovery](#automatic-recovery) if you accept losing writes to keep serving. Without it, never turn an isolated member of a larger cluster into a new single-voter cluster.

## Quick start on EKS

The [Helm chart](../deploy/helm/mqextended) starts a new cluster without asking for node IDs, peer IPs or peer keys. Pick the topology **at first install**:

| Helm values | MQTT-serving Pods | Total voters | If one voter stops |
| --- | ---: | ---: | --- |
| Defaults (`replicaCount=1`) | 1 | 1 | No service until that Pod restarts with its PVC. |
| `replicaCount=2` | 2 | 2 | The remaining Pod continues alone after `cluster_lease_timeout` ([automatic recovery](#automatic-recovery)). With `autoRecover.enabled=false`, there is no quorum for writes and admission closes until the missing voter restarts with its PVC. |
| `replicaCount=2,additionalVoter.enabled=true` | 2 | 3 | The remaining majority serves MQTT. If one serving Pod fails, **one MQTT Pod plus the additional voter** can still commit writes. |
| `replicaCount=3` | 3 | 3 | The two survivors keep serving; any voter can receive MQTT traffic. |

[Automatic recovery](#automatic-recovery) is on in every topology. Set `autoRecover.enabled=false` to wait for quorum instead of giving up writes that only reached the lost side.

The additional voter is a full replica, not a lightweight witness. Give each voter its own schedulable worker and volume. Spread workers and voters across availability zones if you need to survive loss of a zone. An EBS volume can reattach only in its own zone; a singleton cannot fail over across zones.

### Install

Use an IPv4 EKS cluster with Helm 3, [cert-manager](https://cert-manager.io/docs/installation/helm/), and an [EBS CSI StorageClass](https://docs.aws.amazon.com/eks/latest/userguide/ebs-csi.html) with `WaitForFirstConsumer`. [EKS Auto Mode](https://docs.aws.amazon.com/eks/latest/userguide/create-storage-class.html) uses provisioner `ebs.csi.eks.amazonaws.com`; clusters with the standard EBS CSI driver use `ebs.csi.aws.com`. Use the actual StorageClass name, not the provisioner name. Allow worker access to the image registry. These steps assume your `kubectl` context points at the target cluster.

1. Build the image from this checkout and push it to an existing ECR repository. Choose the architecture of the worker nodes (`linux/arm64` for Graviton). Use a new tag for each build.

   ```sh
   region=us-east-1
   repo=$(aws ecr describe-repositories --region "$region" --repository-names mqextended \
     --query 'repositories[0].repositoryUri' --output text)
   tag=$(git rev-parse HEAD)
   aws ecr get-login-password --region "$region" | docker login --username AWS --password-stdin "${repo%%/*}"
   docker buildx build --platform linux/amd64 -t "$repo:$tag" --push .
   ```

2. Choose the client listeners your devices already use, then create their secrets. Each enabled listener uses the same password and ACL files, as with `per_listener_settings true` in Mosquitto.

   | Values | Listener |
   | --- | --- |
   | `listeners.mqtts` (default on, port 8883) | MQTT over TLS |
   | `listeners.mqtt` (port 1883) | Plain MQTT |
   | `listeners.ws` (port 8080), `listeners.wss` (port 8081) | MQTT over WebSocket, without and with TLS |
   | `auth.passwordFile`, `auth.aclFile` (default on) | Keys `password_file` and `acl_file` of `auth.existingSecret` |
   | `auth.allowAnonymous` (default off) | Mosquitto `allow_anonymous` |
   | `mqttTLS.existingSecret` | `kubernetes.io/tls` Secret for `mqtts` and `wss` |

   For an existing installation, import its password and ACL files and enable the listeners its clients connect to; for example `--set listeners.mqtt.enabled=true` keeps plain MQTT on 1883 working. Use a server certificate whose DNS SAN covers the name your MQTT clients use. For a first private test, `mosquitto_passwd -c password_file device` prompts for a password **and creates a new file**; an ACL containing `user device` and `topic readwrite devices/device/#` on separate lines restricts that account to its test topic tree.

   ```sh
   kubectl create namespace mqtt
   kubectl -n mqtt create secret generic mqtt-policy --from-file=password_file --from-file=acl_file
   kubectl -n mqtt create secret tls mqtt-listener --cert=server-chain.pem --key=server.key
   ```

3. Install from the repository root. This starts a **single durable voter**. For two client-facing brokers that must survive one broker failure, append `--set replicaCount=2,additionalVoter.enabled=true` on this first install.

   ```sh
   helm upgrade --install mqtt ./deploy/helm/mqextended -n mqtt \
     --set-string image.repository="$repo" --set-string image.tag="$tag" \
     --set-string auth.existingSecret=mqtt-policy --set-string mqttTLS.existingSecret=mqtt-listener \
     --set-string storage.storageClassName=gp3 --wait --timeout 10m
   kubectl -n mqtt get pods,pvc,certificates
   ```

The default MQTT endpoint is the private Service `mqtt.mqtt.svc`, with one port per enabled listener. To expose it through an **internal** NLB managed by EKS Auto Mode, include this values file with `-f` on install. Use `service.k8s.aws/nlb` instead of `eks.amazonaws.com/nlb` for the AWS Load Balancer Controller. Use private subnets tagged for internal load balancers and point your certificate's DNS name at the NLB. The NLB forwards TCP to the broker, which terminates TLS itself; port 7000 and the HTTP API are not exposed.

```yaml
service:
  type: LoadBalancer
  loadBalancerClass: eks.amazonaws.com/nlb
  annotations:
    service.beta.kubernetes.io/aws-load-balancer-scheme: internal
    service.beta.kubernetes.io/aws-load-balancer-nlb-target-type: ip
```

### Restart and upgrade

Each voter gets a numbered StatefulSet, a stable peer Service IP, a PVC and its own `mqx-node-<id>` certificate. cert-manager issues peer certificates from a release-specific CA; no Pod receives the CA signing key or another voter's private key. The peer Services publish addresses before readiness so the voters can form a quorum. Only Ready serving Pods enter the MQTT Service.

Keep the namespace, release name, peer Services, CA and PVCs. Restart a Pod, **not** its Service: a numeric peer IP is part of committed membership. `helm uninstall` removes Services; retained PVCs alone do not make a new install a safe restore. Use the [cold restore procedure](#cold-backup-and-restore) for a lost installation.

Do not use an HPA, `kubectl scale`, or a change to Helm replica counts to resize an existing cluster. The chart manages fixed topologies and rejects ordinary topology-changing upgrades. To move an existing installation, plan a [membership change](#changing-membership) separately.

StatefulSets use `OnDelete` so a chart upgrade cannot restart all voters together. Apply new chart values, then replace **one Pod at a time**, waiting for each new Pod to be Ready before touching another. A one-voter or two-voter cluster necessarily has a maintenance interruption. For incompatible broker versions follow [Upgrades](#upgrades), not a rolling restart.

Updating the contents of a mounted Secret needs no restart. After the kubelet projects the updated Secret into the Pod (typically within a minute), the broker [loads renewed certificates](#configuration) for new connections. If a configured `password_file` or `acl_file` changes in `auth.existingSecret`, the chart sends the broker SIGHUP within 10 seconds of projection. Kubernetes swaps the Secret files atomically, so the broker reads complete files.

The disruption budget protects a majority from voluntary evictions. A worker drain can therefore block for a one- or two-voter topology; schedule downtime rather than lowering the broker's quorum. A disruption budget does not prevent physical node failures.

## Bootstrap and restart

Start all nodes with identical `cluster_peer` lines and no `cluster_membership_generation`, in any order. The first start bootstraps the cluster exactly once; later starts rejoin from `cluster_data_dir`, and from then on the replicated membership, not the config file, decides who the members are. Never reuse a data directory under a different `cluster_node_id`, and never copy one node's data directory to another.

With automatic recovery off, the first voter waits for quorum even if its peers start later than `cluster_request_timeout`. That deadline limits individual requests, not the time allowed to form a cluster. The voter does not serve MQTT or declare startup ready while it waits.

After a restart or loss of its lease, a follower only admits MQTT clients after renewing its lease and applying through a fresh quorum-confirmed read index. Keep it out of the load balancer until `/api/v1/mqx/ready` returns `200`; an open TCP port or an `Alive` membership entry alone is not sufficient.

### Cold backup and restore

1. Drain client traffic and stop **all** nodes. Confirm each process has exited successfully before taking the first copy. Independent copies of live WALs are not a cluster backup.
2. Back up every node's entire `cluster_data_dir`, indexed by its node ID. Keep its config, referenced credential files and matching peer certificate/key in protected storage as well. Preserve ownership and permissions. Record the binary version, membership generation and state format with the backup.
3. Restore the set to an isolated network, with the original cluster stopped or unreachable. Use the same binary version, IDs and configured peer addresses. Restore each directory only to its original ID; do not bootstrap an empty cluster or run a restored voter concurrently with its original.
4. With client traffic still drained, start the restored nodes. Check that `/api/v1/mqx/cluster` reports the expected voters and leader, and `/api/v1/mqx/ready` returns `200` on each serving node. Check a known retained payload and reconnect a test persistent client with clean start disabled: verify session-present and the expected queued messages before routing production traffic. Changes made after the backup are not recovered.

## Storage and state growth

Each node compacts its own WAL. After 5,000 new log entries it writes a new `snapshot.mpk`, then deletes WAL chunks older than the 1,000 entries it keeps behind the snapshot. Lease renewals add entries even without client traffic, so compaction continues on an idle cluster. A snapshot replacement needs room for the old and the new file, plus up to two snapshots being received from a peer. Temporary files left by a crash are removed at the next start.

Each node also keeps `reserve.mqx` in `cluster_data_dir`, a preallocated file of 5% of the volume (at least 64 MiB, at most 1 GiB; `cluster_storage_reserve` sets it). When free space on the volume drops below the reserve size, the node logs a warning, deletes `discarded/`, releases the reserve and compacts at once: it writes a snapshot and deletes the WAL up to it, without the usual 1,000-entry tail, so a lagging replica may need that snapshot to catch up. It keeps serving. Once free space is above three times the reserve size again, it recreates the reserve. Unix only; `mqx_storage_available_bytes` and `mqx_storage_reserve_bytes` show both values ([monitoring](monitoring.md#prometheus-metrics)). Several nodes sharing one volume each keep their own reserve; set a smaller one, or `0` for test clusters.

On Unix, a node reports storage pressure when free space falls below its configured or automatic reserve size plus its current snapshot size, even if it has already released the reserve. While any member reports pressure, retained publishes still reach live subscribers but do not replace stored messages; empty retained publishes still clear them. The broker drops new offline deliveries as it does for a full queue and refuses new persistent sessions with Server unavailable (MQTT 3) or Quota exceeded (MQTT 5). Existing sessions can reconnect, clean sessions still connect, and online delivery continues. Normal admission resumes when every reporting member has at least twice that headroom again. Expiry and compaction can shrink the state; enlarge the volume if expiry does not free enough space. Reserve release and early compaction still apply.

A failed WAL or snapshot write (a full or read-only volume, an I/O error) stops the node in every mode: the process logs `Raft node failed: …` and exits with status 3, so systemd or Kubernetes restarts it. A node that starts with less free space than its reserve size releases the reserve before opening the WAL.

The snapshot holds the replicated broker state, so its size follows client behaviour. A node that is new, replaced, or too far behind catches up from the leader's snapshot. `cluster_max_snapshot_size` limits the snapshots this node sends and receives; the default is the largest size the wire format carries. Older releases default to 64 MiB and accept at most 256 MiB, so keep snapshots within every member's limit during a rolling upgrade; a lagging node cannot catch up from a larger one. A node warns when it builds or installs a snapshot above its own limit, and `mqx_raft_snapshot_size_bytes` reports the current size ([monitoring](monitoring.md#prometheus-metrics)). Budget memory for at least twice the snapshot size while a node builds one and three times while it installs one. A transfer must finish within the snapshot timeout (90 s on the sender, 120 s on the receiver), so a 4 GiB snapshot needs over 45 MiB/s between nodes.

The broker bounds that state by default, unlike Mosquitto ([defaults](mosquitto-compatibility.md#defaults)):

- A persistent session whose client stays away for 30 days is removed (`persistent_client_expiration`). Until then its offline queue holds at most 1,000 messages and 16 MiB (`max_queued_messages`, `max_queued_bytes`); later messages are dropped as for any full queue.
- With `queue_qos0_messages true`, queued QoS 0 messages count against the same limits.
- The retained sweep removes messages whose MQTT 5 expiry has passed (`retain_expiry_interval`) and applies the [age limit](mosquitto-compatibility.md#defaults) to messages without an expiry (`retain_max_age`). Their topic levels stay, as in Mosquitto.

Change these in `mosquitto.conf`, or with `brokerOptions` in the Helm chart.

With automatic recovery, `discarded/` keeps the most recently discarded state, including `discarded/interrupted-switch/`. A node deletes it 7 days after it was written, or immediately when space runs low; delete it sooner if you don't need it.

`log_dest file` rotates at 64 MiB: the broker renames the file to `<file>.<UTC time>` and keeps the 4 newest such files. The broker user needs write access to the log directory; if a rename fails, the broker keeps writing to the open file, warns and retries. `log_file_max_size <bytes>` changes the size and `0` leaves rotation to an external tool, as in Mosquitto. External rotation (rename and SIGHUP, or copy and truncate) still works and uses names the broker never deletes. The shipped systemd unit and the Helm chart log to the journal and stdout, which journald and the kubelet rotate.

## Changing membership

Membership changes run while the cluster serves traffic. The leader adds a new node as a learner, waits until it has caught up, checks that both the current and the proposed voter sets have a reachable majority, and only then switches voters; it refuses a change that would lose quorum and reports why.

To add a node:

1. Pick a node id that has never been used in this cluster and issue its `mqx-node-<id>` certificate.
2. Start it with an empty `cluster_data_dir`, `cluster_join true`, and `cluster_peer` lines for itself and the current voters.
3. On every current voter, put the full desired peer list in the config, set `cluster_membership_generation` to a number higher than the one in use, and send SIGHUP.
4. Wait until the new node shows as a voter in the cluster status before routing clients to it.

To remove a node, delete its `cluster_peer` line on every remaining voter, raise `cluster_membership_generation`, and send SIGHUP. The removed node disconnects its MQTT clients (they reconnect through the load balancer) but keeps answering the HTTP status endpoints; stop it once the cluster lists its id as retired.

To replace a node that died for good, do both in one change: a new id joins as above, and the desired peer list leaves out the dead id. A retired id stays retired across restarts; a node started with a retired id or with the data directory of a removed node is refused. If a majority is lost, bring the missing voters back, or let [automatic recovery](#automatic-recovery) continue without them. Re-bootstrapping a cluster that still has data discards it.

## Automatic recovery

With `auto_recover` on (the default) on every node, a survivor can resume service after losing quorum. Once peers can communicate again, they can rejoin without an operator. This requires working storage, a valid configuration and a shared cluster history. The price is consistency: writes that only reached a discarded branch are lost, even ones the client already saw acknowledged. Set `auto_recover false` on every node when keeping every acknowledged message matters more than staying available, and bring lost voters back by hand.

When every desired voter is live and the local quorum lease has been renewed recently, recovery checks reuse that renewal instead of opening a connection to every peer on every tick. Nodes still compare histories periodically (30 seconds between sweeps in a healthy cluster). A stale renewal, missing voter, learner or joint membership restores the normal probe cadence; the healthy sweep interval is not added to the quorum-loss timeout.

- **Losing quorum.** After `auto_recover_timeout` without a successful quorum-backed lease renewal here or at a reachable member, a node can restart as a single voter from its applied state. The timeout is not an end-to-end recovery deadline. Clients reconnect. Each serving branch expires leases independently: subscribers can see a will twice if both sides of a partition continue.
- **Coming back.** A node that returns asks its peers which branch continued. An ancestor that committed past the fork point beats its descendant. Between sibling branches the one with more voters wins, then the higher incarnation, then the lower founder id, then the lower digest. Nodes keep the first fork point and the latest 511; an intermediate ancestor older than that window competes as a sibling. If three or more branches disagree, nodes compare one representative per branch in digest order so that nodes with the same view choose the same winner.
- **Rejoining.** The losing node moves its data to `<cluster_data_dir>/discarded/` and rejoins as a learner. It catches up before voting or admitting clients. The survivor restores the latest committed desired membership, even if it was changed online after startup. Without a committed change it uses the configured `cluster_peer` list.
- **Unusable local state.** A node whose data directory cannot be loaded (a damaged WAL or snapshot, an identity for another node id, an unknown format version) moves it to `discarded/` and rejoins as an empty node. If no peer answers within six times `auto_recover_timeout`, it starts serving with empty state.
- **Storage paths.** Put the whole `cluster_data_dir` on the intended volume. A symlink in place of `wal/` or a non-UTF-8 WAL path is a configuration error, not corruption. Startup refuses it without replacing the WAL or the previous recovery archive. Once the original storage is available at a supported path, a normal restart uses the existing state.
- **Crashes during recovery.** A crash before the switch is published leaves the old state in place. The next start completes a published switch. If files needed to finish the journal are missing, automatic recovery starts an empty learner instead of mixing old and new state. `discarded/interrupted-switch/` keeps the damaged journal and remaining live files alongside the previous archive. Each archive slot is replaced, not appended to. Unwritable storage or conflicting journals still stop startup.
- **Process failures.** A runtime failure the broker cannot repair in place exits non-zero. The shipped systemd unit (`Restart=on-failure`, `RestartSec=5s`) and Kubernetes restart it. Configuration errors still stop the broker, because a restart can't fix them.

Give every node the same `auto_recover` settings; a node logs a warning when a peer's differ. A retired node id stays retired: removing a node is a deliberate operator decision. `/api/v1/mqx/cluster` reports `auto_recover`, the branch `incarnation` and `last_survivor_event`, and Prometheus exports `mqx_cluster_auto_recover`, `mqx_cluster_incarnation` and `mqx_cluster_last_recovery_timestamp_seconds{reason=…}`, where the reason is `peer_unreachable`, `peer_won` or `unusable_state`.

## Upgrades

Use a rolling upgrade only if every running binary can replay every command that traffic can produce. A node refuses log entries, snapshots and node identity files whose format version it does not know. For a compatible rolling upgrade:

1. Roll the new binary out to every node while it keeps writing the old format (`cluster_state_format 1` when coming from a release before format 2).
2. Once every node runs the new binary, roll the setting to the new format, again one node at a time.

Don't change membership in the middle of an upgrade.

Leave `cluster_qos1_replay_batch` off during a rolling upgrade. Enable it at startup (`qos1ReplayBatch.enabled=true` in Helm) only after every voter and learner can read replay-window commands, including binaries used to recover from a backup. Switching it off stops new commands; it does not rewrite the WAL for a downgrade. Take a cold backup before enabling it if you need to return to an older binary.

The replay window covers at most 16 eligible packets and 16 KiB. If the owner dies between committing a window and finishing its socket writes, the replacement retries unacknowledged packets with the same IDs and `DUP` set. `DUP` marks a possible earlier delivery; the client need not have seen that packet before the crash.

When upgrading a build that predates the MQTT broker control API, use a cold upgrade if clients can publish to `$CONTROL/` topics. Requests to disabled or unknown endpoints also produce a replicated `BrokerControl` command that the old build cannot replay. Turning off `enable_control_api` is not a mixed-version compatibility switch. Drain clients, stop all voters, take the cold backup above and upgrade all voters before restoring traffic.

Also use a cold upgrade when crossing the introduction of `SubscribeDollarRoot`, `ReserveOutboundWithQos0Expiry`, `BridgeConnack`, `ReceivedInFlight` and `ReloadLimits`. A subscription such as `$app/#`, a QoS 0 delivery past an expired in-flight message, a bridge CONNACK that changes the maximum QoS or Receive Maximum, a client PUBREC for a packet id that is not in flight, or a SIGHUP that changes one of the reloadable broker limits can emit these commands even with `cluster_state_format 1`. Drain clients and bridge traffic, stop and back up the cluster, upgrade every voter and learner, then restore traffic. New binaries replay historical `Subscribe`, `ReserveOutbound`, `BridgeOnline` and `Ack` entries with their original semantics; old binaries cannot replay the new commands.

Do not enable `mosquitto_sparkplug_aware` until every node runs a build that supports it. The first matching birth publication can write `ReceiveBirth` or `ForwardBirth` to the log. Existing log entries are not reinterpreted when you enable the plugin.

Enable `auth-plug` or `go-auth` only once every node runs a build that supports it. Their ACL checks write `Authorize` and `ResolveVerdicts` entries, and the sessions of their clients carry verdicts and waiting deliveries that an older build cannot replay. Every node applies those entries through its own copy of the plugin, so add, remove or reconfigure a plugin with the whole cluster stopped. A node without the plugin would decide differently from the others. Existing log entries are not reinterpreted when you enable one.

Releases before this one never expire persistent sessions, cap offline queues in bytes, or sweep retained messages by default; this release does ([defaults](mosquitto-compatibility.md#defaults)). Every node applies those limits to the same log entries, so nodes with different values keep different state. When upgrading from an earlier release:

1. As each node gets the new binary, add `persistent_client_expiration never`, `retain_max_age never`, `max_queued_bytes 0` and `auto_recover false` to its file, unless the file already sets them. The upgraded nodes then decide exactly as the old ones did.
2. Once every node runs the new binary, remove those lines. Send SIGHUP to one node to commit the new session expiry and retained age limits everywhere at the same log index, then restart the nodes one at a time for the queue limit and automatic recovery.

Only sessions that disconnect after the switch get the 30-day expiry; sessions already offline expire when they next disconnect. Expired retained messages leave a node's memory at different times while the defaults differ; clients see no difference. If `queue_qos0_messages` is on, upgrade with client traffic drained: queued QoS 0 messages now count against the queue limits, and no setting reproduces the earlier accounting.

Keep `auto_recover` off until every node runs a build that supports it (step 1 above). Its branch identity files use a format an older build refuses to start with. When upgrading from a build that stores unbounded recovery history, finish upgrading every node before the 513th fork of a branch. If already past that point, use a cold upgrade. Do not downgrade a node after its history has been compacted.

## What clients observe when a node fails

These guarantees assume the survivors retain quorum. If automatic recovery has to discard a branch, the [loss rules above](#automatic-recovery) apply instead.

- Clients connected to the failed node lose their connection and reconnect through the load balancer to a surviving node.
- After `cluster_lease_timeout`, the cluster publishes the wills of the failed node's clients, once.
- A persistent session (clean session off) resumes on any node with `session_present` set, its subscriptions, the messages queued while it was away, and unacknowledged messages resent with DUP.
- Retained messages and subscriptions of all clients are unaffected.
- A new subscription waits for the other serving voters to apply it. When a peer stops responding, SUBACK can wait for an election and committed lease expiry. Once the local node applies the peer's Down event, it stops waiting for that peer, even if its TCP connection is still open.
- A leader failure pauses writes for about one election timeout; clients see slower acknowledgements. A write not yet sent to the failed leader goes to the new one. A write the failed leader had already received has an unknown outcome, so the broker closes that client's connection and MQTT's resend rules decide on reconnect (see [architecture](architecture.md)).
- Every node admits new clients only while it can renew its own lease, and renewal needs a leader. Keep `cluster_lease_timeout` well above `cluster_lease_interval` plus the election timeout; the defaults leave several seconds to spare. With tighter values, a leader failure on a loaded host can close admission on the survivors until the new leader renews their leases. Each node logs `Cluster lease expired` and `Cluster lease renewed` around such a gap.
