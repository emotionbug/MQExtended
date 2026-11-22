# Performance

How to measure MQExtended against Mosquitto and what the current numbers are. The publish paths these numbers exercise are described in [architecture](architecture.md#request-flows).

## Measuring

`mqx-bench` generates MQTT load and can start the brokers itself, so Mosquitto, standalone MQExtended and a three-node cluster run the same workload:

```sh
cargo build --release -p mqx-server -p mqx-bench
MOSQUITTO_BUILD_DIR=/tmp/mosquitto/build target/release/mqx-bench compare \
    --seconds 30 --rate 100 --json results.json
```

Each payload carries a send timestamp, so latency is end to end (publisher to subscriber). The report counts lost and duplicated messages per workload; a QoS 0 "loss" counts messages not delivered by the drain deadline.

Always compare release builds on the same machine, and keep the cluster's `cluster_data_dir` on the disk you will run in production: WAL fsync latency dominates the replicated path.

## Current numbers

Three nodes on one 12-thread machine, loopback mTLS, NVMe/ext4 WAL, 256-byte payloads, clean sessions unless noted. p99 end-to-end latency; every row delivered every message with no duplicates.

| Workload | QoS | Mosquitto 2.1.4 | Standalone | 3-node cluster |
| --- | ---: | ---: | ---: | ---: |
| Fan-in 100 → 1, 100 msg/s | 0 / 1 | 0.23 / 0.38 ms | 0.59 / 0.28 ms | 3.8 / 2.9 ms |
| Fan-out 1 → 100, 100 msg/s (10 000 deliveries/s) | 0 / 1 | 2.0 / 2.1 ms | 2.8 / 3.1 ms | 1.6 / 1.8 ms |
| 200 pairs, 1 000 msg/s | 0 / 1 | — | — | 1.3 / 0.3 ms |
| 200 pairs, 100 msg/s, persistent sessions | 1 | — | — | 3 758 ms |

The cluster's Raft layer alone sustains about 14 000 commits/s at 6.9 ms p99 with 64 concurrent writers.

## Known gaps

- Persistent-session delivery in a cluster is the slow path: every message costs an inbox commit plus a committed outbound cursor so DUP flags stay exact after failover. At 100 msg/s it delivers everything but with seconds of p99 latency. This is the next optimisation target.
- QoS 0 one-to-one at low rates showed one 235 ms p99 sample in a short run; it did not reproduce at 1 000 msg/s.
