# Testing

Test the behaviour a client or operator observes. For MQExtended that almost always means "what Mosquitto 2.1.4 does", so the strongest evidence comes from Mosquitto itself.

## Layers

| Layer | Proves | Example |
| --- | --- | --- |
| Parity tables | Our port returns what Mosquitto's own unit tests expect | `crates/mqx-topic/tests/mosquitto_topic_test.rs`, extracted from `test/unit/libcommon/topic_test.c` |
| Tool vectors | We read what Mosquitto tools write | `mosquitto_passwd` hashes in `mqx-auth` tests |
| Unit tests | One parity rule or edge case at its owner | ACL check order, `strtok` quirks |
| Property tests | Invariants over generated input: round trips, no panics, agreement with a reference model | codec encode→decode, topic matcher vs. level-based model |
| Differential tests | The real Mosquitto binary and MQExtended agree on a live scenario | `mosquitto_pub` against the codec; `mqx-difftest` broker scenarios |
| Cluster fault tests | MQTT guarantees hold when nodes die, restart or lose leadership | `mqx-difftest` failover tests, `mqx-cluster` integration tests |

Every test names the failure a client would see if it regressed. Do not assert defaults, echoes or wording.

## Parity tables

Extract cases from Mosquitto's test suite instead of retyping them, and say which file they came from at the top of the test. Regenerate from the source file when the reference version changes; never edit a case by hand to make it pass.

## Differential tests

Differential tests need the Mosquitto reference binaries and are `#[ignore]` by default.

| Variable | Points at |
| --- | --- |
| `MOSQUITTO_BUILD_DIR` | Mosquitto 2.1.4 build directory (`src/mosquitto`, `client/mosquitto_{pub,sub}`, `apps/mosquitto_passwd/`) |
| `MOSQUITTO_WS_BUILD_DIR` | A second Mosquitto build with `WITH_WEBSOCKETS=ON`, for `mqx-ws` |
| `MOSQUITTO_HTTP_BUILD_DIR` | A third build with `WITH_HTTP_API=ON`, for `$SYS` and HTTP API scenarios |
| `MOSQUITTO_PLUGIN_BUILD_DIR` | A fourth build with `WITH_PLUGINS=ON`, for dynamic-security scenarios driven by `mosquitto_ctrl` |
| `MQEXTENDED_BIN` | The `mqextended` binary under test; defaults to `target/debug/mqextended` |

```sh
MOSQUITTO_BUILD_DIR=/tmp/mosquitto/build cargo test -p <crate> -- --ignored
```

A differential test fails when a binary it needs is missing; it must never silently pass. Build the references as described in [development](development.md#mosquitto-reference-build).

Broker behaviour is compared with `mqx-difftest`: each scenario is a script for a raw MQTT client (built on `mqx-codec`, v3 and v5) and has three tests:

| Test suffix | Runs the scenario against | Must hold |
| --- | --- | --- |
| `mosquitto_self` | Mosquitto, twice | identical transcripts: the scenario is deterministic |
| `cross_broker` | Mosquitto and standalone `mqextended` | identical transcripts, packet ids, flags and properties included |
| `cross_cluster` | Mosquitto and a three-node `mqextended` cluster, clients placed round-robin | identical transcripts |

Only generated client ids and clock-dependent expiry values are normalized, after checking their format. A scenario that needs a cross-client ordering waits for an acknowledgement instead of relying on timing. Mine new scenarios from Mosquitto's `test/broker/*.py` and cite the file.

Failover tests have no Mosquitto counterpart; they assert MQTT's guarantees directly while killing (SIGKILL) and restarting nodes: persistent queues and DUP resends survive, a lost node's wills are published once, retained messages and subscriptions survive, takeover works across nodes, publishing resumes after leader loss.

## Commands

```sh
cargo test -p <crate>                     # while working
cargo test --workspace                    # before a milestone commit
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
```

CI runs fmt, clippy and the workspace tests in one job, and in a second job builds the Mosquitto references (cached) and runs every differential and failover test. `mqx-bench`'s ignored test needs release builds and runs locally.
