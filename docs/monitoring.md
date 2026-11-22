# Monitoring

What MQExtended exposes for monitoring: Mosquitto's `$SYS` topics and HTTP API, unchanged, plus a cluster status endpoint and Prometheus metrics.

## `$SYS` topics

`$SYS/broker/...` carries the same topics, payload formats and retain flags as Mosquitto 2.1.4 (`src/sys_tree.c`), so existing dashboards keep working.

- `sys_interval <seconds>` sets the period (default 10, `0` turns the periodic tree off; the version and other startup topics are still published). SIGHUP applies a new value.
- `$SYS/broker/version` reports `mosquitto version 2.1.4`, the behaviour MQExtended reproduces. The MQExtended release is in the [cluster endpoint](#cluster-status).
- `$SYS/broker/heap/*` is not published. Mosquitto only has it in builds with memory tracking; MQExtended has no equivalent allocator counter.

In a cluster the tree describes the whole cluster, not the node a subscriber happens to be connected to. The Raft leader publishes each sample through the log: client, subscription and retained counts come from replicated state, message and byte counters are the sum of every node's counters collected over the mesh. A node that dies keeps its last reported totals, so counters never step backwards; current socket counts include only nodes that answered. The latest tree is part of the replicated state, so retained `$SYS` values survive a leader change instead of flapping between nodes.

## HTTP API

A `listener <port>` with `protocol http_api` serves Mosquitto's HTTP API (`src/http_api.c`):

| Path | Content |
| --- | --- |
| `/api/v1/version` | Version object, as Mosquitto 2.1.4 |
| `/api/v1/listeners` | The configured listeners, in config order |
| `/api/v1/systree` | The current `$SYS` tree as one JSON object |
| `/api/v1/mqx/cluster` | MQExtended: cluster status, below |
| `/metrics` | MQExtended: Prometheus text format, below |
| anything else | A file from the listener's `http_dir`, if set |

Access works as in Mosquitto: only `GET`; HTTP Basic credentials are checked against the listener's `password_file` (or `allow_anonymous` without credentials), and the `acl_file`, if any, must grant `read` on the request path for that user. `certfile` and `keyfile` turn on HTTPS. With no config file at all, Mosquitto's local-only mode also opens the API on `127.0.0.1:9883`, and so does MQExtended.

## Cluster status

`/api/v1/mqx/cluster` returns this node's view as JSON: the MQExtended version, the applied membership (generation, desired and current members with their role and liveness, retired ids, and the reason for a refused change) and Raft progress (term, leader, last log, committed and applied indexes). A standalone broker answers `{"mode":"standalone", ...}`. Use it to watch a [membership change](cluster.md#changing-membership) converge; a removed node keeps serving it.

## Prometheus metrics

`/metrics` needs the same credentials as the rest of the API. It reports this process's connections, packets, bytes and proposal latency, and gauges of the replicated state (sessions, subscriptions, retained messages, Raft indexes). Scrape every node and aggregate in Prometheus; unlike `$SYS`, these are per-node values.

On cluster nodes, `mqx_raft_wal_appended_entries_total` and `mqx_raft_wal_sync_batches_total` show how many entries share a WAL sync batch. `mqx_raft_wal_sync_seconds_total` records time spent syncing WAL files. Compare `mqx_raft_wal_sync_max_seconds`, `mqx_raft_wal_write_max_seconds` and `mqx_raft_wal_queue_wait_max_seconds` with proposal latency to separate long filesystem syncs from writes or time spent waiting for the WAL worker. The maxima are for completed work since node startup, not a scrape interval.
