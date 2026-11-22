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

- It sends systemd `READY=1` when its listeners are open, so `Type=notify` units work.
- Started as root, it drops to `user` (default `mosquitto`) right after reading the config, before opening certificates, credential files or listeners, honouring `PUID`/`PGID` as Mosquitto does. Ports below 1024 then need the same capability setup as for Mosquitto.
- `-d` daemonises, `pid_file` is written and removed as Mosquitto does, `UMASK_SET` applies.
- SIGHUP reloads, SIGUSR1 saves the persistence file, SIGRTMIN reopens log files.

## 5. Carry state over

With `persistence true`, MQExtended reads Mosquitto's own `mosquitto.db` on its first start and imports retained messages, persistent sessions with their subscriptions, and queued and in-flight messages. It never writes that file: its own state goes to the same path with `.mqx` appended, and from then on that file wins.

- **Standalone:** stop Mosquitto (it saves the database on a clean stop), then start MQExtended with the same configuration.
- **Cluster:** give only the node with the lowest id `persistence true` and the Mosquitto `persistence_location`/`persistence_file` on its first start. It imports through the replicated log before it accepts clients, so every node gets the same state. On the other nodes, and after bootstrap, `persistence true` changes nothing; cluster state is always durable. The same node imports `dynamic-security.json` if you use [dynamic security](dynamic-security.md#in-a-cluster).

Without a persistence file, copy retained messages instead, right before switching: subscribe to `#` on Mosquitto with a user that may read everything, collect every message delivered with the retain flag, and publish each one with retain to MQExtended. Copying after the switch would overwrite values that clients already updated. Persistent sessions then start empty.

## 6. Cut over

Mosquitto and MQExtended must never serve clients behind the same address at the same time: messages do not flow between them.

1. Test the MQExtended nodes with a real client whose destination you redirect (`/etc/hosts` or a DNAT rule on one test machine).
2. Stop Mosquitto, carry state over (step 5), and switch the load balancer's backends to the MQExtended nodes.
3. Keep Mosquitto installed until you are confident. Rolling back is starting Mosquitto on its untouched `mosquitto.db`; anything that happened on MQExtended since the switch is not carried back.
