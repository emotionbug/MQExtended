# Performance

How to measure MQExtended against Mosquitto and what the current numbers are. The publish paths these numbers exercise are described in [architecture](architecture.md#request-flows).

## Measuring

`mqx-bench` generates MQTT load and can start the brokers itself, so Mosquitto, standalone MQExtended and a three-node cluster run the same workload:

```sh
cargo build --release -p mqx-server -p mqx-bench
MOSQUITTO_BUILD_DIR=/tmp/mosquitto/build target/release/mqx-bench compare \
    --seconds 30 --rate 100 --json results.json
# persistent sessions, one-to-one:
target/release/mqx-bench compare --pattern one-to-one --publishers 200 --subscribers 200 \
    --qos 1 --persistent --rate 1000 --seconds 10
```

Each payload carries a send timestamp, so latency is end to end (publisher to subscriber). The report counts lost and duplicated messages per workload; a QoS 0 "loss" counts messages not delivered by the drain deadline. `--state-dir` puts the cluster's WALs on a chosen filesystem; keep it on the disk type you will run in production.

## Current numbers

Release builds, three nodes on one 12-thread laptop, loopback mTLS, WALs on a consumer NVMe (ext4), 256-byte payloads, 10-second runs. The host was not idle (an emulator and unrelated builds were running), so treat tails as upper bounds. p99 end-to-end latency in milliseconds; every row delivered every message with no duplicates.

| Workload | QoS | Mosquitto 2.1.4 | Standalone | 3-node cluster |
| --- | ---: | ---: | ---: | ---: |
| Fan-in 100 → 1, 100 msg/s | 0 / 1 | 0.82 / 0.21 | 0.72 / 3.0 | 0.46 / 0.51 |
| Fan-out 1 → 100, 100 msg/s (10 000 deliveries/s) | 0 / 1 | 1.9 / 4.5 | 6.0 / 1.9 | 3.0 / 4.7 |
| 200 pairs, 100 msg/s | 0 / 1 | 2.9 / 3.1 | 2.2 / 3.1 | 3.8 / 3.8 |
| 200 persistent pairs, 100 msg/s | 1 | 3.3 | 3.5 | 2 080 (p50 75) |
| 200 persistent pairs, 1 000 msg/s | 1 | 2.5 | 3.0 | 2 819 (p50 24) |

Clean-session traffic in the cluster takes the mesh fast path and stays within a few milliseconds of Mosquitto. The Raft layer alone sustains about 10 000 commits/s at 18–20 ms median latency with 192 concurrent writers on the same disk.

## Persistent sessions in a cluster

Every message to a persistent session is committed to a majority of WALs before it is sent, so its latency is bounded below by `fdatasync` on two nodes. On the measurement laptop `fdatasync` has a 63 ms p99 and stalls of up to 1.5 s when other processes write to the disk; the multi-second tails above coincide with those stalls (traced per message). Mosquitto pays nothing comparable because it only writes its database every `autosave_interval` (30 minutes by default) and loses everything since the last save when it crashes.

For production, put `cluster_data_dir` on a dedicated SSD with power-loss protection, where `fdatasync` takes well under a millisecond. Persistent delivery should then cost a few milliseconds over the transient path; this has not been measured on such hardware yet.
