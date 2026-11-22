# Performance

How to measure MQExtended against Mosquitto and what the current numbers are. The publish paths these numbers exercise are described in [architecture](architecture.md#request-flows).

## Measuring

`mqx-bench` generates MQTT load and can start the brokers itself, so Mosquitto, standalone MQExtended and a three-node cluster run the same workload:

```sh
cargo build --release -p mqx-server -p mqx-bench
export MOSQUITTO_BUILD_DIR=/tmp/mosquitto/build
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

Persistent QoS 1, 200 one-to-one pairs, 256-byte payloads, 30 s of traffic and 10 s configured drain. Release brokers, mutual TLS between the three voters, all three WALs on the same consumer NVMe/ext4 device. These are local measurements under contention, **not a passing release qualification**. Reported latency is the publisher-to-subscriber histogram's p99.

| Offered publishes/s | Mosquitto p99 (ms) | Standalone p99 (ms) | 3-node p99 (ms) | Cluster sent / PUBACK / delivered | Duplicates |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 100 | 0.221 | 0.360 | 4 295 | 3 000 / 3 000 / 3 000 | 0 |
| 1 000 | 0.180 | 0.221 | 2 147 | 29 999 / 29 999 / 29 999 | 0 |

As a diagnostic, the same three-node workload on tmpfs (10 s per rate, 3 s drain) gave p99 **5.505 ms** and **44.040 ms** at 100 and 1 000 publishes/s respectively; both passed the traffic, latency and delivery gates. Tmpfs does not provide crash-durable writes. These shorter controls isolate the storage path; they do not qualify the service or justify disabling fsync.

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
