# Testing

Test the behaviour a client or operator observes. For MQExtended that almost always means "what Mosquitto 2.1.4 does", so the strongest evidence comes from Mosquitto itself.

## Layers

| Layer | Proves | Example |
| --- | --- | --- |
| Parity tables | Our port returns what Mosquitto's own unit tests expect | `crates/mqx-topic/tests/mosquitto_topic_test.rs`, extracted from `test/unit/libcommon/topic_test.c` |
| Tool vectors | We read what Mosquitto tools write | `mosquitto_passwd` hashes in `mqx-auth` tests |
| Unit tests | One parity rule or edge case at its owner | ACL check order, `strtok` quirks |
| Property tests | Invariants over generated input: round trips, no panics, agreement with a reference model | codec encode→decode, topic matcher vs. level-based model |
| Differential tests | The real Mosquitto binary and MQExtended agree on a live scenario | `mosquitto_pub` against the codec; broker scenarios from M2 on |
| Cluster fault tests | Availability under node loss and partitions (M3) | kill one of three nodes mid-traffic |

Every test names the failure a client would see if it regressed. Do not assert defaults, echoes or wording.

## Parity tables

Extract cases from Mosquitto's test suite instead of retyping them, and say which file they came from at the top of the test. Regenerate from the source file when the reference version changes; never edit a case by hand to make it pass.

## Differential tests

Differential tests need the Mosquitto reference binaries and are `#[ignore]` by default.

| Variable | Points at |
| --- | --- |
| `MOSQUITTO_BUILD_DIR` | Mosquitto 2.1.4 build directory (`src/mosquitto`, `client/mosquitto_{pub,sub}`, `apps/mosquitto_passwd/`) |
| `MOSQUITTO_WS_BUILD_DIR` | A second Mosquitto build with `WITH_WEBSOCKETS=ON`, for `mqx-ws` |
| `MQEXTENDED_BIN` | The `mqextended` binary under test; defaults to `target/debug/mqextended` |

```sh
MOSQUITTO_BUILD_DIR=/tmp/mosquitto/build cargo test -p <crate> -- --ignored
```

A differential test fails when a binary it needs is missing; it must never silently pass. Build the references as described in [development](development.md#mosquitto-reference-build).

Broker behaviour is compared with `mqx-difftest`: each scenario is a script for a raw MQTT client (built on `mqx-codec`) that runs once against Mosquitto and once against `mqextended`, and the two transcripts of received packets must be identical, packet ids and flags included. Every scenario also runs twice against Mosquitto to prove the scenario itself is deterministic. Mine new scenarios from Mosquitto's `test/broker/*.py` and cite the file.

## Commands

```sh
cargo test -p <crate>                     # while working
cargo test --workspace                    # before a milestone commit
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
```

CI runs fmt, clippy and the workspace tests; it does not build Mosquitto, so differential tests run locally before a milestone commit.
