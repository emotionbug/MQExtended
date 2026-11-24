# Performance

How to measure MQExtended against Mosquitto and what the current numbers are. The publish paths these numbers exercise are described in [architecture](architecture.md#request-flows).

## Measuring

`mqx-bench` generates MQTT load and can start the brokers itself, so Mosquitto, standalone MQExtended and a three-node cluster run the same workload:

```sh
cargo build --release -p mqx-server -p mqx-bench
export MOSQUITTO_BUILD_DIR=$HOME/mqx-reference/mosquitto/build
target/release/mqx-bench compare \
    --seconds 30 --rate 100 --json results.json
# persistent sessions, one-to-one:
target/release/mqx-bench compare --pattern one-to-one --publishers 200 --subscribers 200 \
    --qos 1 --persistent --rate 1000 --seconds 30 --drain-seconds 10 \
    --require-p99-below-ms 50 --json persistent.json
```

Run the comparison as an unprivileged user. MQTT clients connect over loopback TCP. Cluster peers use mutual TLS with a fresh CA and distinct node keys per run. The JSON report records the peer transport; older reports without this field used plaintext. `--state-dir` puts the three WALs on a chosen filesystem; use the disk type you will run in production.

Each payload carries a send timestamp, so latency is end to end (publisher to subscriber). Loss counts expected deliveries still missing after drain; duplicates are counted separately.

Use `--require-p99-below-ms` with a target `--rate` for release qualification. `load` checks the specified endpoints; `compare` checks every row. Both write their report before returning failure if p99 reaches the limit, fewer than 99% of scheduled publishes were sent, any duplicates or losses were observed, or a QoS handshake was still outstanding after drain. Delivery alone does not prove that the publisher received its acknowledgement.

## Current numbers

### Clean sessions: cross-broker comparison

One Linux host, loopback TCP, QoS 1, 256-byte messages, 8 s of traffic and 3 s of drain. Both MQExtended builds used the unoptimized dev profile with two Tokio workers per process; the three voters used mutual TLS. Mosquitto 2.1.4 and Mochi MQTT 2.7.9 were optimized standalone builds (Mochi `GOMAXPROCS=2`). Use the before/after columns to compare MQExtended builds. The other brokers are reference points, **not** a release-to-release ranking.

| Workload | Mosquitto p99 | Mochi p99 | MQExtended standalone p99 | MQExtended 3-node p99, before → after |
| --- | ---: | ---: | ---: | ---: |
| 64 one-to-one pairs, 8,000 publishes/s offered | 0.72 ms | 4.72 ms | 2.10 ms | 260.05 → 4.46 ms |
| 1 publisher → 48 subscribers, 300 publishes/s (14,400 deliveries/s) | 1.02 ms | 5.24 ms | 2.88 ms | 3.41 → 3.41 ms |

At 8,000/s, three voters handled **5,328 → 7,999 publishes/s** versus revision `2ae7fe0`; all three standalone brokers reached the offered rate. The final cluster acknowledged and delivered all 63,992 publications once. For a single fan-out publisher the cluster p99 did not improve. To repeat the 64-pair test, run `compare --pattern one-to-one --publishers 64 --subscribers 64 --qos 1 --rate 8000 --seconds 8 --drain-seconds 3`. Use `load` with the same flags and `--endpoint` for an independently started broker.

With the rate limit removed (same 64 pairs), **in-window deliveries/s** rose from **12,616 to 19,300** standalone and **5,099 to 14,621** on three voters. Mosquitto delivered **92,281/s** and Mochi **18,150/s**. After drain, the final standalone run accounted for all 161,672 publications and the cluster for all 117,910, with no duplicates. An intermediate standalone build accepted 28,069 publishes/s but missed 93,972 deliveries after drain: a faster publisher alone is not higher broker throughput.

### Persistent sessions: shared-disk qualification

Persistent QoS 1, 200 one-to-one pairs, 256-byte payloads, 30 s of traffic and 10 s configured drain. Release brokers, mutual TLS between the three voters, all three WALs on the same consumer NVMe/ext4 device. These are local measurements under contention, **not a passing release qualification**. Reported latency is the publisher-to-subscriber histogram's p99.

| Offered publishes/s | Mosquitto p99 (ms) | Standalone p99 (ms) | 3-node p99 (ms) | Cluster sent / PUBACK / delivered | Duplicates |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 100 | 0.221 | 0.360 | 4 295 | 3 000 / 3 000 / 3 000 | 0 |
| 1 000 | 0.180 | 0.221 | 2 147 | 29 999 / 29 999 / 29 999 | 0 |

As a diagnostic, the same three-node workload on tmpfs (10 s per rate, 3 s drain) gave p99 **5.505 ms** and **44.040 ms** at 100 and 1 000 publishes/s respectively; both passed the traffic, latency and delivery gates. Tmpfs does not provide crash-durable writes. These shorter controls isolate the storage path; they do not qualify the service or justify disabling fsync.

A separate dev-build control used 32 persistent pairs at 250 publishes/s for 8 s. All 2,000 messages were acknowledged and delivered once, but the three-voter p99 was **168 ms before vs. 2,949 ms after** in the recorded runs. On five voters sharing the same ext4 device, the batcher wrote 13,100 WAL entries summed across voters (17,318 and 18,805 in the baseline runs). Delivery p99 was **2.95 s** vs. **2.82–3.20 s** before. One `fdatasync` took 1.22 s in the five-voter control. This is not a persistent latency improvement. A competing broker with in-memory sessions is not a crash-durability control.

For deployment qualification, use `load` against three separately provisioned staging voters (not `compare`, which launches all brokers locally). For example, with three authorized loopback staging endpoints:

```sh
for rate in 100 1000; do
    target/release/mqx-bench load \
        --endpoint 127.0.0.1:11883 --endpoint 127.0.0.1:21883 --endpoint 127.0.0.1:31883 \
        --pattern one-to-one --publishers 200 --subscribers 200 --qos 1 --persistent \
        --seconds 30 --drain-seconds 10 --rate "$rate" --require-p99-below-ms 50 \
        > "persistent-$rate.json" || exit 1
done
```

The client endpoints speak plain MQTT without credentials; use isolated test listeners or protected tunnels to staging, not an anonymous listener on the production network. Tunnels and the client host contribute to end-to-end latency. Load runs create persistent sessions; use disposable staging state.

### Cluster control traffic

Five voters on one Linux host, debug brokers, fresh WALs on the same disk. Compared with `3e464a7` using the same 50 ms heartbeat, 250 ms lease interval and 5 s recovery timeout. These measurements cover idle traffic and subscription setup, not maximum publish throughput.

With plaintext peers and no MQTT traffic for 32 s, the five brokers made **20 peer `connect()` calls instead of 2,560**. The window included one periodic full sweep. Peer socket read/write calls fell from **132,114 to 37,185** in the same trace. These are syscall entries, including would-block returns, not packet counts.

With mutual TLS and 4 ms of added delay in each direction between voters, the time from `SUBSCRIBE` to `SUBACK` fell from **64.9 to 35.1 ms at p50** and **93.7 to 50.6 ms at p95**. Each value is the median of three runs. One MQTT client subscribed to 120 distinct topics sequentially on the leader after 10 warm-up subscriptions. No syscall tracer ran during timing.

A two-voter plaintext control disabled automatic recovery to isolate peer framing from recovery scans. Over 8 idle seconds, peer read/write syscalls fell from 4,806 to 1,539. With tracing off, median subscription latency barely changed (15.2 vs. 15.0 ms); the three runs' p95 ranges overlapped (17–61 vs. 18–64 ms).

A plaintext QoS 1 control used 32 publisher/subscriber pairs at 250 publishes/s for 8 s. Both builds acknowledged and delivered all 2,000 messages once with clean sessions, and again with persistent sessions. Clean-session delivery p99 stayed at 2.49 ms. The persistent run still exceeded 50 ms p99 (201 ms after the change); use separate disks and the release qualification above before setting a deployment target.

### Historical plaintext baseline

Historical baseline: release builds, three nodes on one 12-thread laptop, **plaintext** loopback peer connections, WALs on a consumer NVMe (ext4), 256-byte payloads, 10-second runs. The host also ran an emulator and unrelated builds. These are observations under contention, not bounds on production latency. p99 end-to-end latency in milliseconds; every row delivered every message with no duplicates.

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

Put each voter's WAL on an independent device with power-loss protection. Qualify the deployment at both 100 and 1 000 publishes/s before adopting a 50 ms persistent p99 SLO. A shared laptop disk or a tmpfs control cannot establish that SLO on three production machines.
