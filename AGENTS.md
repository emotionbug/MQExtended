# AGENTS.md

MQExtended is a clustered MQTT broker in Rust that replaces Mosquitto without changing a single client. Existing libmosquitto clients (MQTT 3.1 / 3.1.1) see Mosquitto 2.1.4 behaviour — including `password_file` and `acl_file` semantics — while the broker runs active-active on three or more nodes behind one load-balanced address and survives the loss of a node with sessions, subscriptions, retained and queued messages intact.

## Repository map

- `crates/mqx-topic` — Topic name/filter validation and matching, ported from Mosquitto's `libcommon/topic_common.c`; subscription index
- `crates/mqx-codec` — Sans-IO MQTT 3.1 / 3.1.1 codec with Mosquitto's wire validation; `v5` module for MQTT 5
- `crates/mqx-auth` — `password_file` (`$6$`, `$7$`) and `acl_file` parsing and checks
- `crates/mqx-proxy` — Sans-IO PROXY protocol v1/v2 reader (`enable_proxy_protocol`)
- `crates/mqx-ws` — MQTT-over-WebSocket transport with Mosquitto's built-in handshake rules
- `crates/mqx-broker` — Protocol engine: sessions, QoS flows, retained, will, keepalive, takeover; state through a command-based state machine
- `crates/mqx-cluster` — Generic replicated state machine on openraft: durable log, snapshots, node leases, mesh RPC
- `crates/mqx-server` — The `mqextended` binary: `mosquitto.conf` parsing, listeners, TLS, wiring
- `crates/mqx-difftest` — Differential test harness running the same scenarios against Mosquitto and `mqextended`
- `scripts/` — Generators for parity tables extracted from Mosquitto's test suite
- `docs/` — System and process knowledge (see below)

## Docs

`docs/` is the source of truth for system-level and process-level knowledge. **"The docs" always means this directory.** At the start of non-trivial work, list `docs/` and skim anything relevant.

| Doc | What's in it |
| --- | --- |
| [docs/product.md](docs/product.md) | What MQExtended is, who it's for, non-goals, milestone direction |
| [docs/architecture.md](docs/architecture.md) | Crate layering, request flows, cluster design, why Raft first |
| [docs/data-model.md](docs/data-model.md) | State tiers, replicated commands, on-disk layout |
| [docs/cluster.md](docs/cluster.md) | Running a cluster: `cluster_*` directives, network, bootstrap, what clients see on node failure |
| [docs/migration.md](docs/migration.md) | Moving a running Mosquitto deployment over: config check, version differences, client discovery from logs, cutover |
| [docs/performance.md](docs/performance.md) | Running `mqx-bench`, current latency/throughput numbers, known performance gaps |
| [docs/mosquitto-compatibility.md](docs/mosquitto-compatibility.md) | The parity contract: reference version, rule catalogue, deliberate deviations |
| [docs/glossary.md](docs/glossary.md) | Authoritative terminology |
| [docs/coding-standards.md](docs/coding-standards.md) | Rust conventions, parity comments, errors, module shape |
| [docs/testing.md](docs/testing.md) | Test layers, parity tables, differential tests against real Mosquitto |
| [docs/development.md](docs/development.md) | Toolchain, building the Mosquitto 2.1.4 reference, commands |

### Writing docs

- **Integrate, don't append.** Find the doc that owns the subject and rewrite the part that is now wrong.
- **Don't document logic.** Write what the code can't tell you: why it is shaped this way, the gotcha that cost an afternoon, constraints that span crates.
- **One fact, one doc.** Every other mention is a link.
- **One subject per doc.** If the subject doesn't fit in a sentence, split the doc.
- **New doc?** Add a row to the table above and link it from the docs that should send readers there.
- Code-level facts belong in comments next to the code.

### Doc voice

Plain and short. Second person. State the rule, then the reason when the reason isn't obvious. No setup-and-punchline sentences, no importance-asserting clauses, no "robust", "seamless", "simply", "just", no hedging when the answer is "do this".

## Quick start

```sh
cargo test -p <crate>                                   # tests for the crate you changed
cargo clippy -p <crate> --all-targets -- -D warnings
cargo fmt --all --check
MOSQUITTO_BUILD_DIR=/tmp/mosquitto/build cargo test -p <crate> -- --ignored   # differential tests
```

Build the Mosquitto reference first; see [docs/development.md](docs/development.md#mosquitto-reference-build).

## Critical rules

- **Mosquitto 2.1.4 behaviour is the contract, not the MQTT spec.** When they disagree, match Mosquitto and cite the source (`file.c` + function) in a comment. Read [docs/mosquitto-compatibility.md](docs/mosquitto-compatibility.md) before changing anything a client can observe.
- **Prove parity with Mosquitto's own artefacts.** Prefer test vectors extracted from Mosquitto's test suite, hashes from `mosquitto_passwd`, and differential runs against the real binaries over hand-written expectations.
- **Clients cannot be changed.** A fix that requires a client setting, reconnect logic or protocol version change is not a fix.
- **Run scoped checks.** Test the crate you changed; run the workspace suite before a milestone commit, not after every edit.
- **Commit per milestone step**, with the tests for that step passing.
