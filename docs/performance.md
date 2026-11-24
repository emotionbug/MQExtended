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

To compare two revisions without rebuilding locally, use the `mqextended-linux-<full commit SHA>` artifacts from the `linux-bundle` CI job. Extract each bundle into a separate directory, verify it with `sha256sum --check --strict SHA256SUMS` there, and restore the executable bit on `bin/mqextended`. Set `MQEXTENDED_RELEASE_BIN` to that binary's absolute path for each run. Keep the load-generator binary, worker count, storage and Mosquitto binary fixed.

The same CI job publishes `mqx-bench-linux-<full commit SHA>` separately. Verify its `SHA256SUMS`, restore the executable bit on `mqx-bench`, and use that one binary for every row. Generators built before `31e8ab2` can time out while shutting down healthy subscribers if the drain is 10 seconds or longer; do not interpret a missing report as broker latency.

Each payload carries a send timestamp, so latency is end to end (publisher to subscriber). Loss counts expected deliveries still missing after drain; duplicates are counted separately.

Use `--require-p99-below-ms` with a target `--rate` for release qualification. `load` checks the specified endpoints; `compare` checks every row. Both write their report before returning failure if p99 reaches the limit, fewer than 99% of scheduled publishes were sent, any duplicates or losses were observed, or a QoS handshake was still outstanding after drain. Delivery alone does not prove that the publisher received its acknowledgement.

## Current numbers

### Clean sessions: optimized Mosquitto vs. optimized MQExtended

Linux, Ryzen 5 2600X (6 cores / 12 threads), loopback MQTT, 64 one-to-one QoS 1 pairs, 256-byte payloads, 20 outstanding handshakes per publisher. Mosquitto 2.1.4 ran as one process; MQExtended had two Tokio workers **per process**, three processes and mTLS between voters for the cluster. These are deployment throughput comparisons on one host, not equal-CPU efficiency measurements. Both MQExtended revisions were checksum-verified CI release builds. Broker processes and connections were fresh for each run.

| Broker | Saturated deliveries/s, before (`982e258`) | Saturated deliveries/s, after (`2331d24`) | After: saturated p99 | After: p99 at 60,000/s offered |
| --- | ---: | ---: | ---: | ---: |
| Mosquitto (reference in each run) | 85,538–93,026 | 93,713–94,471 | 24.12 ms | 5.24 ms |
| MQExtended standalone | 132,319–136,350 | 229,834–233,956 | 16.25–17.83 ms | 1.77–1.97 ms |
| MQExtended three voters | 55,868–86,329 | 192,476–193,302 | 31.46–35.65 ms | 3.93 ms |

Ranges are the two observed runs, not confidence intervals. Rates count **unique subscriber deliveries inside the 8-second load window**. After up to 3 seconds of drain, every publication in these runs had a PUBACK and exactly one delivery. At saturation the final three-voter deployment delivered about twice as many messages per second as Mosquitto, but its tail latency at that higher throughput was worse. At the same 60,000/s offered load all three passed the 50 ms p99, delivery and handshake gates.

A separate 30-second run offered 90,000/s (5 s drain, 50 ms p99 gate). Standalone delivered 89,989/s at 44.04 ms p99 and three voters 89,994/s at 17.83 ms; after drain all 2,699,964 and 2,699,930 publications respectively were acknowledged and received once. The comparison command exited nonzero: the Mosquitto row delivered 60,953/s at 226.49 ms p99 and missed the offered-rate gate. This is one longer run on a shared host, not a production latency bound.

An intermediate standalone build (`190b632`) accepted 237–241k publishes/s but lost 107,737 and 148,538 deliveries in the same saturation test. It is **not** counted as a throughput win. Bounding an ingress burst by the affected active subscriber's drain progress removed the observed overflow without raising queue limits. This is not a guarantee for arbitrarily slow or disconnected subscribers.

To reproduce, run `compare --pattern one-to-one --publishers 64 --subscribers 64 --qos 1 --seconds 8 --drain-seconds 3 --state-dir "$STATE" --json max.json`, then add `--rate 60000 --require-p99-below-ms 50` and use a different JSON path. For a 1 → 48 fan-out at 300 publishes/s, the final build and Mosquitto each delivered all **115,200** expected copies. P99 was 10.49 ms for Mosquitto, 9.44 ms standalone, and 14.68 ms for three voters.

### Historical dev-profile comparison

One Linux host, loopback TCP, QoS 1, 256-byte messages, 8 s of traffic and 3 s of drain. Both MQExtended builds used the unoptimized dev profile with two Tokio workers per process; the three voters used mutual TLS. Mosquitto 2.1.4 and Mochi MQTT 2.7.9 were optimized standalone builds (Mochi `GOMAXPROCS=2`). Use the before/after columns to compare MQExtended builds. The other brokers are reference points, **not** a release-to-release ranking.

| Workload | Mosquitto p99 | Mochi p99 | MQExtended standalone p99 | MQExtended 3-node p99, before → after |
| --- | ---: | ---: | ---: | ---: |
| 64 one-to-one pairs, 8,000 publishes/s offered | 0.72 ms | 4.72 ms | 2.10 ms | 260.05 → 4.46 ms |
| 1 publisher → 48 subscribers, 300 publishes/s (14,400 deliveries/s) | 1.02 ms | 5.24 ms | 2.88 ms | 3.41 → 3.41 ms |

At 8,000/s, three voters handled **5,328 → 7,999 publishes/s** versus revision `2ae7fe0`; all three standalone brokers reached the offered rate. The final cluster acknowledged and delivered all 63,992 publications once. For a single fan-out publisher the cluster p99 did not improve. To repeat the 64-pair test, run `compare --pattern one-to-one --publishers 64 --subscribers 64 --qos 1 --rate 8000 --seconds 8 --drain-seconds 3`. Use `load` with the same flags and `--endpoint` for an independently started broker.

With the rate limit removed (same 64 pairs), **in-window deliveries/s** rose from **12,616 to 19,300** standalone and **5,099 to 14,621** on three voters. Mosquitto delivered **92,281/s** and Mochi **18,150/s**. After drain, the final standalone run accounted for all 161,672 publications and the cluster for all 117,910, with no duplicates. An intermediate standalone build accepted 28,069 publishes/s but missed 93,972 deliveries after drain: a faster publisher alone is not higher broker throughput.

### Persistent sessions: shared-disk qualification

#### Draining an offline subscriber

The current release comparison (`8bd1490` → `8847eff`) used three mTLS voters on one NVMe/ext4 device. A subscriber disconnected on voter 1, a publisher on voter 2 filled its session with 480 numbered 256-byte QoS 1 messages, and the subscriber resumed on voter 3. Drain time is CONNACK to PINGRESP after the final PUBACK; sync counts sum all three WALs. All runs below received the 480 messages in order with no duplicates.

| Protocol / client ACK behavior | Comparison | Drain time | WAL sync batches |
| --- | --- | ---: | ---: |
| MQTT 5 / 16 compact PUBACKs per write | Old → new, default config | 6.20–6.70 s → 1.88–1.94 s | 1,514–1,522 → 159–165 |
| MQTT 3.1.1 / immediate PUBACK | New, replay window off → on | 6.59–8.25 s → 0.52–0.96 s | 1,470–1,474 → 159–161 |

Each range covers two runs. On the new binary, the first 16 packets reached the socket in **179–183 ms** with the window off and **10–12 ms** with it on, before the client sent its first ACK. The window is [opt-in for upgrade compatibility](cluster.md#upgrades). It is not faster in every run: with 16 PUBACKs per write and the window on, legacy drains ranged from 0.58 to 2.02 s.

If clients send PUBACKs in bursts, also try `set_tcp_nodelay true` (`setTcpNoDelay=true` in Helm). With 16 PUBACKs per write on loopback and standalone disk persistence enabled, MQExtended **and** Mosquitto 2.1.4 took 1.19 s at the default and 7.7 ms with Nagle disabled. The same change on three voters with the replay window on took 0.58 → 0.34 s in one paired run. It can send more small TCP packets; it did not improve live 250/s cluster p99 (168 ms either way).

**Earlier MQTT 3.1.1 comparison:**

Compared release `2331d24` with `8bd1490` on three voters sharing one NVMe/ext4 device. A persistent MQTT 3.1.1 subscriber disconnected on node 1; a publisher on node 2 received PUBACK for 480 numbered, 256-byte QoS 1 messages. The subscriber resumed on node 3 with its original client ID and a 20-message in-flight window. Time starts at CONNACK and ends at the PINGRESP following the last PUBACK. Ranges cover three baseline runs and two final runs with fresh state; WAL sync batches are summed across the three voters during resume.

| Subscriber sends PUBACK | Drain time before → after | WAL sync batches before → after |
| --- | ---: | ---: |
| After each PUBLISH | 8.25–17.50 s → 6.44–7.59 s | 1,469–1,487 → 1,381–1,454 |
| 16 PUBACKs in one write | 9.81–10.89 s → 0.76–1.06 s | 1,479–1,504 → 162 |

Every run delivered all 480 messages once and in order. The broker does not wait for a batch or require clients to change how they acknowledge. In a separate run, all three processes were killed after the publisher received its PUBACKs; the restarted cluster delivered all 480 from disk, in order, with `session_present` set. These are backlog drain times, not live-publish latency.

For a standalone reference, both brokers ran with `persistence true` and default autosave. With a PUBACK after each PUBLISH, Mosquitto 2.1.4 drained the same 480 messages in **9.4 ms** and MQExtended in **8.5 ms**. With 16 PUBACKs per write they took **1.24 s** and **1.23 s**, respectively (one run per case). Neither standalone broker syncs a quorum before it acknowledges a publish.

#### Live publishers and subscribers

On the same shared-disk setup, `8bd1490` → `8847eff` delivered **159 → 168 ms p99** at 250 publishes/s (32 pairs, 12 s). At 1,000/s (200 pairs, 16 s), the old build measured **2.68 s** and the new one **176 ms and 2.28 s**. One run per case except two final high-rate runs. The new build acknowledged and delivered every publication exactly once after drain; 11 of 3,000 and 94–588 of 16,000 deliveries arrived after the traffic window. The replay changes did **not** solve the 50 ms live target.

Using the checksum-verified `2f42bfa` load generator for all three brokers, the 32-pair run measured **0.180 ms** p99 for Mosquitto 2.1.4, **0.238 ms** for MQExtended standalone and **159 ms** for MQExtended with three voters. Both standalone brokers used `persistence true` with default autosave, not a synchronous WAL quorum. Each broker acknowledged and delivered all 3,000 messages exactly once; only the cluster needed drain time (12 deliveries).

`mqx-bench load`, one-to-one persistent QoS 1, 256-byte payloads, three fresh mTLS voters on the same NVMe/ext4 device and 10 s drain. `2331d24` and `8bd1490` ran sequentially on the same host:

| Pairs | Offered rate / traffic window | Delivery p99 before → after | Final PUBACKs / unique deliveries |
| ---: | ---: | ---: | ---: |
| 32 | 250/s for 12 s | 1.61–2.68 s → 151–159 ms | 3,000 / 3,000 in each run |
| 200 | 1,000/s for 16 s | 1.54 s → 176 ms | 16,000 / 16,000 |

The 32-pair ranges cover three baseline runs and two final runs. The 200-pair row has one completed run per build; an earlier baseline attempt closed an MQTT connection and produced no histogram. The final build delivered 164 of 16,000 during drain and none twice. The 50 ms p99 target is still unmet; these are same-host results, not a bound for separate production voters.

The `6ca8f2d` experiment also preallocated 256 KiB WAL extents on Linux without extending EOF. We dropped this change: on the **same binary** at 250 publishes/s, alternating runs that refused `fallocate` gave **159–193 ms** delivery p99, versus **2.15–3.22 s** with preallocation enabled. All four runs delivered all 3,000 messages. A short filesystem microbenchmark had favored preallocation; it did not predict the broker result.

With `2331d24`, 32 persistent pairs at 250 publishes/s for 8 s on one shared NVMe/ext4 device produced **2,000 PUBACKs and 2,000 unique deliveries** on every broker. The three-voter delivery p99 was **2.68 s** (2.78 s on `982e258`); 29 deliveries completed during drain. Standalone p99 was **0.22 ms**, Mosquitto **0.19 ms**. `compare` sets `persistence false` on both standalone processes; their sessions survive reconnect, not a crash. The cluster still waits for a durable quorum. These are different guarantees, and the cluster has **not** met the 50 ms persistent target on this disk.

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
