# MQExtended

A clustered MQTT broker in Rust that replaces Mosquitto without changing clients.

- **Mosquitto 2.1.4 compatibility.** Differential tests compare real MQTT 3.1, 3.1.1 and 5 client exchanges against Mosquitto. MQExtended reads Mosquitto password, ACL, dynamic-security and persistence files. Check [unsupported configuration directives](docs/mosquitto-compatibility.md#unsupported-directives) before migration; they are startup errors, not ignored settings.
- **Active-active cluster.** Any client can connect to any node behind one load-balanced address. Sessions, subscriptions, retained messages and persistent queues are replicated with Raft; losing one node of three loses none of them, and the lost node's wills are published once. Nodes can be added, removed and replaced while the cluster serves traffic.
- **Mosquitto's feature set.** TCP, TLS, WebSocket, Unix socket and PROXY protocol listeners; bridges (one owner per bridge in a cluster); persistence; built-in dynamic security with `mosquitto_ctrl`; a built-in [mosquitto-auth-plug](docs/auth-plugins.md) with its file, database, HTTP, JWT and LDAP back-ends; `$SYS` topics and the HTTP API; systemd readiness, privilege drop and signals as the `mosquitto` process.
- **Operations.** Mutual TLS between nodes, separate cluster status and MQTT readiness endpoints, Prometheus metrics, and a [cold restore procedure](docs/cluster.md#cold-backup-and-restore). Qualify persistent QoS latency on the target storage before production cutover; see [measured results and acceptance criteria](docs/performance.md).

## Quick start

**EKS:** [Install with Helm](docs/cluster.md#quick-start-on-eks). Start with one durable broker on one worker, or choose a multi-voter topology. The chart supplies node IDs, stable peer addresses, per-voter mTLS and PVCs.

Build a [Linux bundle](docs/development.md#linux-broker-build) into a fresh directory. This does not install or start a service.

```sh
work=$(mktemp -d)
bundle="$work/bundle"
./scripts/stage-linux.sh "$bundle"
(cd "$bundle" && sha256sum --check --strict SHA256SUMS)
"$bundle/bin/mqextended" --test-config -c "$bundle/etc/mqextended.conf"
```

The sample listens on `127.0.0.1:1883` only. Any local process can connect without credentials. See [staged checks](docs/development.md#check-a-staged-bundle) to run it as your own user on a spare port.

### Install a standalone Linux service

This is an opt-in **new** systemd installation, not a Mosquitto migration. Use [the migration guide](docs/migration.md) for an existing deployment and [the cluster guide](docs/cluster.md) for a cluster. Do not proceed if `mqextended.service`, the `mqextended` user or group, or any of `/opt/mqextended`, `/etc/mqextended`, `/var/lib/mqextended` and `/var/lib/private/mqextended` already exist (including symlinks). Ensure the sample port is free before starting the service.

Use systemd 245 or newer and a host with the [matching runtime libraries](docs/development.md#linux-broker-build). Check the hashes before installing; when receiving a bundle from someone else, confirm the digest of `SHA256SUMS` against a trusted copy. A manifest shipped with the bundle detects corruption but does not authenticate its origin.

From the staged bundle above, set `release` to a unique directory name with no slashes, such as the source commit hash. Run the following only as an administrator on the intended deployment host:

```sh
(
    set -eu
    cd "$bundle"
    sha256sum --check --strict SHA256SUMS
    sudo mkdir -m 0755 /opt/mqextended /etc/mqextended
    sudo mkdir -m 0755 /opt/mqextended/releases "/opt/mqextended/releases/$release"
    sudo install -D -m 0755 bin/mqextended "/opt/mqextended/releases/$release/bin/mqextended"
    sudo install -m 0644 etc/mqextended.conf /etc/mqextended/mqextended.conf
    sudo install -m 0644 lib/systemd/system/mqextended.service /etc/systemd/system/mqextended.service
    sudo ln -s "releases/$release" /opt/mqextended/current
)
```

Run `sudo systemctl daemon-reload`, then `sudo systemctl start mqextended.service`. Check `systemctl status mqextended.service` and connect a local MQTT client before opting in to boot startup with `sudo systemctl enable mqextended.service`.

Systemd supplies the unprivileged account and the private writable state directory; do not create an account or change the state directory's ownership yourself. The service reads the root-owned configuration in `/etc/mqextended` and stores `mqextended.db.mqx` under `/var/lib/mqextended`, the managed state path. Keep the anonymous listener on loopback. For other configurations, arrange service access to credentials and TLS keys without making secret files world-readable.

### Upgrade or roll back the standalone service

Verify the new bundle and set `release` to a new release name. Install only the binary:

```sh
sudo mkdir -m 0755 "/opt/mqextended/releases/$release" &&
sudo install -D -m 0755 "$bundle/bin/mqextended" "/opt/mqextended/releases/$release/bin/mqextended"
```

Leave the installed configuration and unit in place unless you have reviewed and are opting in to specific changes. Stop the service cleanly (`sudo systemctl stop mqextended.service`); check its journal for save errors before backing up `/etc/mqextended`, the unit and the contents of `/var/lib/mqextended`. Record the previous target of `/opt/mqextended/current` and keep that release.

With the service stopped, point `current` to the new release:

```sh
sudo ln -s "releases/$release" /opt/mqextended/.current-next &&
sudo mv -T /opt/mqextended/.current-next /opt/mqextended/current
```

Start the service and check readiness and client traffic as on first install. To roll back, stop it, keep a separate backup of the post-upgrade state, and switch `current` back using the previous release name. Restore the old configuration if it changed. If you cannot establish that the old binary can read the new state, restore the pre-upgrade state backup before starting it; that discards changes since the backup. Restore the old unit and run `sudo systemctl daemon-reload` if the unit changed.

## Documentation

Start with [AGENTS.md](AGENTS.md); it indexes everything in [docs/](docs/).

## Build and test

```sh
cargo test --workspace
```

Differential and failover tests need Mosquitto reference builds and are `#[ignore]`d by default; see [docs/testing.md](docs/testing.md#differential-tests). CI runs both.
