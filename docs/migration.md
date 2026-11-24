# Migrating from Mosquitto

How to move a running Mosquitto deployment to MQExtended without touching clients. Behaviour differences between MQExtended and Mosquitto 2.1.4 are listed in [Mosquitto compatibility](mosquitto-compatibility.md); this doc covers the procedure.

## 1. Check the configuration

Check your existing file without starting anything:

```sh
mqextended --test-config -c /etc/mosquitto/mosquitto.conf
```

It parses `mosquitto.conf` with Mosquitto's rules and fails on any directive it does not implement, naming the directive; the list is in [Mosquitto compatibility](mosquitto-compatibility.md#unsupported-directives). Like Mosquitto's `--test-config`, it does not open `password_file` or `acl_file`; start the broker once to load those. Both files load unchanged.

## 2. Find out what your Mosquitto version is

MQExtended reproduces 2.1.4. If you run an older Mosquitto, compare the defaults that changed for anything your clients rely on. The ones that bite most often:

- `max_packet_size` defaults to 2 000 000 bytes in 2.1.4. If any client sends larger packets, set it explicitly.
- `password_file` hashes from every 2.x version load (`$7$` with 12- or 64-byte salts); 1.x `$6$` hashes load too.
- The connection log line encodes the protocol differently. Up to 2.0 it is `p1` = MQTT 3.1, `p2` = 3.1.1; from 2.1 (and in MQExtended) `p3` = 3.1, `p4` = 3.1.1; `p5` = MQTT 5 in all versions. Adjust log parsers.

## 3. Learn what the clients do from the broker side

You cannot inspect the clients, but Mosquitto's log shows their settings. With `connection_messages true`:

```text
New client connected from 10.1.2.3:51234 as sensor-01 (p2, c0, k60, u'dev').
```

`c0` means a persistent session (clean session off), `k` is the keepalive, `u` the username. Summarise:

```sh
grep "New client connected" mosquitto.log \
  | sed -E 's/.* as (.+) \(p([0-9]), c([0-9]), k([0-9]+).*/p\2 c\3 k\4/' | sort | uniq -c | sort -rn
```

Then restart Mosquitto once in a quiet period and watch two things:

- Do all clients come back? Clients without automatic reconnect need a restart at cutover.
- Do `c0` clients send SUBSCRIBE again after reconnecting? If not, they rely on the broker keeping their sessions; carry the sessions over with step 5.

## 4. Run MQExtended in place of `mosquitto`

`mqextended` takes Mosquitto's command line (`-c`, `-d`, `-p`, `-v`, `--test-config`) and behaves as the `mosquitto` process does, so the distribution's service unit or container entrypoint only needs the binary path changed:

- It sends systemd `READY=1` when its listeners are open, so `Type=notify` units work. With `WatchdogSec` (Mosquitto's shipped unit sets 3 minutes) it sends `WATCHDOG=1` at Mosquitto's interval, half the timeout plus one second.
- Started as root, it drops to `user` (default `mosquitto`) right after reading the config, before opening certificates, credential files or listeners, honouring `PUID`/`PGID` as Mosquitto does. Ports below 1024 then need the same capability setup as for Mosquitto.
- `-d` daemonises, `pid_file` is written and removed as Mosquitto does, `UMASK_SET` applies.
- `--version` prints the MQExtended release without opening listeners; use this to identify the binary rather than the Mosquitto compatibility version in `$SYS`.
- SIGHUP rereads credential paths, ACLs and `allow_anonymous` for bound listeners. Each listener's options are reset to their defaults and reread, as Mosquitto's `listener__set_defaults` does, and apply to new connections: `mount_point`, `max_qos`, `accept_protocol_versions`, `use_username_as_clientid`, client id and topic alias limits, `require_certificate`, `use_identity_as_username` and `use_subject_as_username`. `certfile`, `keyfile` and `crlfile` are reloaded from the reread configuration; a path the new file leaves out keeps its old value. Existing MQTT clients are reauthenticated; HTTP requests use the refreshed policy too. Adding or removing a listener, changing `per_listener_settings`, `max_connections`, `websockets_origin` or `proxy_protocol_v2_require_tls` requires a restart. SIGUSR1 saves the persistence file; SIGRTMIN reopens log files.
- SIGHUP applies the broker-wide options Mosquitto 2.1.4 applies (`conf.c: config__copy`), at the same moments: `message_size_limit` to the next PUBLISH (a Will at the next CONNECT), `persistent_client_expiration` to sessions that disconnect afterwards, `queue_qos0_messages`, `upgrade_outgoing_qos` and `allow_duplicate_messages` to the next queued or delivered message, `clientid_prefixes` to the next CONNECT. Mosquitto rereads but ignores the other limits, and so does MQExtended: `global_max_clients`, `global_max_connections`, `max_inflight_messages`, `max_inflight_bytes`, `max_queued_messages`, `max_queued_bytes`, `max_keepalive`, `max_packet_size`, `check_retain_source`, `retain_expiry_interval`, `retain_available` and `set_tcp_nodelay` keep their startup values. A SIGHUP that changes one of these logs that it needs a restart.
- Any MQTT listener that cannot start (port in use, unloadable certificate, unresolvable host) exits with status 1. A failed `http_api` listener does not stop the broker, but a configuration whose only listeners are `http_api` does not start.

## 5. Carry state over

With `persistence true`, MQExtended reads Mosquitto's own `mosquitto.db` on its first start and imports retained messages, persistent sessions with their subscriptions, and queued and in-flight messages. It never writes that file: its own state goes to the same path with `.mqx` appended, and from then on that file wins.

- **Standalone:** stop Mosquitto (it saves the database on a clean stop), then start MQExtended with the same configuration.
- **Cluster:** give only the node with the lowest id `persistence true` and the Mosquitto `persistence_location`/`persistence_file` on its first start. It imports through the replicated log before it accepts clients, so every node gets the same state. On the other nodes, and after bootstrap, `persistence true` changes nothing; cluster state is always durable. The same node imports `dynamic-security.json` if you use [dynamic security](dynamic-security.md#in-a-cluster).

For standalone brokers, a failed by-changes autosave leaves the changes pending and retries after a one-second delay without waiting for more client traffic. A failed final save is logged and makes the process exit nonzero; do not treat that shutdown as a successful backup. A damaged persistence file stops the broker at startup unless you set `auto_recover true`, which starts with empty state instead ([deviations](mosquitto-compatibility.md#deliberate-deviations)).

For a standalone cold backup, stop the broker successfully, then back up its native `.mqx` file, config and referenced credentials together. Restore them with their original permissions on an isolated broker using the same release before reconnecting clients. Leaving out the `.mqx` file may reimport an older `mosquitto.db`. One exception: after automatic recovery, a `.mqx.discarded` file tells the broker not to repeat that import, even if it crashed before its first fresh save. For replicated state, follow the [cluster restore procedure](cluster.md#cold-backup-and-restore) instead.

Without a persistence file, copy retained messages instead, right before switching: subscribe to `#` on Mosquitto with a user that may read everything, collect every message delivered with the retain flag, and publish each one with retain to MQExtended. Copying after the switch would overwrite values that clients already updated. Persistent sessions then start empty.

## 6. Cut over

Mosquitto and MQExtended must never serve clients behind the same address at the same time: messages do not flow between them.

1. Test the MQExtended nodes with a real client whose destination you redirect (`/etc/hosts` or a DNAT rule on one test machine).
2. Stop Mosquitto, carry state over (step 5), and switch the load balancer's backends to the MQExtended nodes.
3. Keep Mosquitto installed until you are confident. Rolling back is starting Mosquitto on its untouched `mosquitto.db`; anything that happened on MQExtended since the switch is not carried back.
