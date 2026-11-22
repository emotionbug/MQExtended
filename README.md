# MQExtended

A clustered MQTT broker in Rust that replaces Mosquitto without changing clients.

- Existing MQTT 3.1 / 3.1.1 clients see **Mosquitto 2.1.4** behaviour, including `password_file` and `acl_file` semantics.
- Runs **active-active** behind one load-balanced address: any client can connect to any node, and sessions, subscriptions, retained and queued messages survive the loss of a node.

Status: under development — see [docs/product.md](docs/product.md#direction).

## Documentation

Start with [AGENTS.md](AGENTS.md); it indexes everything in [docs/](docs/).

## Build and test

```sh
cargo test --workspace
```

Differential tests against the real Mosquitto are `#[ignore]`d by default; see [docs/testing.md](docs/testing.md#differential-tests).
