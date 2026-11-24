# Third-party auth plugins

MQExtended has two widely deployed third-party Mosquitto auth plugins built in. A deployment that authenticates and authorizes clients through one of them keeps working unchanged:

- [mosquitto-auth-plug](https://github.com/jpmens/mosquitto-auth-plug) (`auth-plug.so`). The [emotionbug fork](https://github.com/emotionbug/mosquitto-auth-plug) is the same code as the upstream's last commit.
- [mosquitto-go-auth](https://github.com/iegomez/mosquitto-go-auth) (`go-auth.so`), at its final commit `20ee931`.

Both are Rust ports of the plugin as Mosquitto 2.1.4 runs it through its legacy-plugin wrapper (`plugin_v4.c`), not the libraries themselves: nothing is loaded from the configured path. Other servers' authentication systems, such as EMQX's authentication chains, VerneMQ's `vmq_diversity` or HiveMQ extensions, are not configured through `mosquitto.conf` and are out of scope.

## Enabling a plugin

Keep the plugin lines in your `mosquitto.conf`:

```text
auth_plugin /usr/lib/mosquitto/auth-plug.so
auth_opt_backends http
auth_opt_http_ip 127.0.0.1
auth_opt_http_getuser_uri /getuser
auth_opt_http_superuser_uri /superuser
auth_opt_http_aclcheck_uri /acl
```

- MQExtended recognizes each plugin by its file name (`auth-plug` or `go-auth`, with `.so`, `.dylib` or `.dll`) in `auth_plugin`, `plugin`, `global_plugin` or `plugin_load`. It doesn't open the file.
- `auth_opt_*` and `plugin_opt_*` take the plugin's own option names.
- `auth_plugin_deny_special_chars` works as in Mosquitto. While it is `true` (the default), a client whose username or client id contains `+`, `#` or `/` is denied every ACL check before the plugin is asked.
- A back-end that can't initialize stops the broker with exit status 1 and the plugin's own fatal log line, as the original plugin does.
- SIGHUP doesn't reread the plugin options, because Mosquitto skips plugin configuration on reload. Connected clients are authenticated again through the plugin, as Mosquitto does.

## Combining a plugin with other security

On one listener, a plugin can run alone or before the `password_file` and `acl_file` options. The plugin answers first, and the files decide whatever it leaves open.

MQExtended refuses these combinations at startup:

- a plugin together with Dynamic Security;
- a plugin together with the `mosquitto_password_file` or `mosquitto_acl_file` plugins (use the `password_file` and `acl_file` options instead);
- two auth plugins on one listener.

In each of these cases the outcome depends on callback order across plugin kinds, which MQExtended doesn't model.

## What both plugins share

- SUBSCRIBE is checked with access 4, delivery with 1 (read), PUBLISH and a will with 2 (write). UNSUBSCRIBE never reaches the plugin.
- When a back-end fails (an HTTP 5xx or a lost database connection, for example):
  - CONNECT: the connection closes without a CONNACK.
  - PUBLISH: the connection closes without an acknowledgement.
  - SUBSCRIBE: the filters before the failing one stay subscribed and the connection closes.
  - Retained replay: the replay stops and no SUBACK is sent, but the connection stays open.
  - Delivery or will: the message is dropped.
- Back-end calls don't block the broker. In Mosquitto every client waits while the plugin waits for its back-end. Here only the message being checked waits, so a delivery can arrive after the publisher's acknowledgement. Each subscriber still receives messages in order.
- A retained message the serving node couldn't foresee when the SUBSCRIBE arrived is checked after the SUBACK. A back-end error then drops only that message.
- The HTTP API asks the plugin directly from the node that serves the request, without the shared ACL cache.
- A standalone broker with `persistence true` doesn't save deliveries that are waiting for a verdict, or cached verdicts.
- The C plugin's memory errors and the Go plugin's panics are not reproduced. Input that would overflow or crash the original gets a defined result instead.

## mosquitto-auth-plug

- All back-ends are available: `files`, `cdb`, `sqlite`, `redis`, `memcached`, `postgres`, `mysql`, `ldap`, `http`, `jwt` and `mongo`. The `psk` back-end fails to load, as in the plugin's stock build, which leaves it out.
- Password hashes use the stock build's format, `PBKDF2$<digest>$<iterations>$<salt>$<key>`, as the plugin's `np` tool writes them. Hashes from builds compiled with `SUPPORT_DJANGO_HASHERS` or `RAW_SALT` don't verify.
- A back-end that can't initialize prints the plugin's `|-- … *** ABORT.` lines.

### Behaviour clients see

The port keeps what clients observe through Mosquitto's wrapper, including the quirks:

- **A denial only abstains.** Built against Mosquitto 1.4.9 or newer, the plugin reports both "deny" and "no answer" as deferral (`auth-plug.c`, `MOSQ_DENY_AUTH`). A configured `password_file` or `acl_file` then decides. Without one, the client gets what it gets when every check abstains: a refused CONNECT or a denied publish, subscription or delivery.
- **Anonymous clients get no plugin ACL.** The plugin only knows clients that logged in with a non-empty username and password, or that presented a client certificate. For any other client it abstains before applying `anonusername`. An anonymous client therefore gets only what `acl_file` grants.
- **`%c` is not the client id.** For a client that logged in with a password, the plugin substitutes the literal text `client id not available` for `%c` in ACL patterns and queries. Certificate clients get their real client id.
- **SUBSCRIBE needs another grant.** Back-ends that only know read (1) and write (2) never grant access 4: `files` rules, and Mongo `r` and `w` entries. A subscription then succeeds only if another check allows it; `acl_file` allows every SUBSCRIBE.
- **Retained messages and `check_retain_source`.** With `check_retain_source true`, Mosquitto's default, a retained message is checked again for its publisher before it is sent to a new subscriber. That check carries no credentials, so the plugin abstains. Unless `acl_file` grants the publisher write access, retained messages from plugin-authenticated publishers are not sent to new subscribers.
- **Superusers and back-end order** follow the plugin. Every back-end's superuser check runs before any ACL check, and any configured back-end can authorize a client, not only the one that authenticated it.

### Differences from the C plugin

- Options and `files` rules belong to one plugin instance. In the C plugin they are process-global, so two instances overwrite each other.
- The client identity comes from the connection, not from a table of C client pointers. The C plugin can hand a disconnected client's identity to a new client that reuses its memory.
- The broker, not the plugin, holds the ACL cache. Cache-hit and cleanup log lines differ, and an entry still expires at the end of the same second.
- Passwords, JWT tokens, cache digests and environment values are redacted in the plugin's log lines. HTTP response bodies are not printed.
- HTTP and JWT speak HTTP/1.1 over OpenSSL directly. libcurl's proxy environment variables and HTTP/2 are not used.
- Redis speaks RESP2 only. A `%` in a username or topic is literal, not a hiredis format directive.
- memcached rejects keys that are invalid in its text protocol, and gives up on an operation after 5 seconds.
- MySQL: a non-empty `ssl_cipher` with `ssl_enabled true` fails loading.
- PostgreSQL doesn't read `.pgpass` or service files and has no GSSAPI. `PGSSLROOTCERT=system` fails loading.
- LDAP: a failed search fails that one check instead of exiting the broker. Referrals are not followed.
- CDB is read once at startup, and a malformed file fails loading.
- SQLite uses the current statement API, so the retries on a locked database can differ.

## mosquitto-go-auth

- Back-ends: `files`, `http`, `jwt` (modes `remote`, `local` and `files`), `postgres`, `mysql`, `sqlite`, `redis` (standalone and cluster), `mongo`, `ldap` and `grpc`.
- The `js` back-end, `jwt_mode js` and the `plugin` back-end (custom Go shared objects) fail loading with a message saying MQExtended doesn't support them. They run JavaScript or Go code inside the plugin.
- Hashes: `pbkdf2` (both `PBKDF2$…` and `$pbkdf2-sha512$…`), `bcrypt` and `argon2id`, with global `hasher_*` options or `<backend>_hasher` per back-end, as the plugin's `pw` tool writes them.
- `backends`, `<backend>_register`, `disable_superuser`, `check_prefix`/`prefixes`/`strip_prefix`, `exhaust_backend_first`, `retry_count` and `use_clientid_as_username` work as in the plugin.
- The plugin logs in its own logrus format (`time="…" level=… msg=…`), honouring `log_level`, `log_dest` and `log_file`.

### Behaviour clients see

- **go-auth never abstains.** Its answer is final, so `password_file` and `acl_file` on the same listener never decide anything.
- **Anonymous clients are refused.** A CONNECT without a username or without a password is refused even with `allow_anonymous true`. The plugin's C shim rejects it before any back-end is asked, and prints `error: received null username or password for unpwd check` on standard output.
- **ACL checks use the real client id and username**, including the recheck of a retained message's publisher under `check_retain_source true`.
- **`files` rules:** deny rules win over grants, and `readwrite` also grants SUBSCRIBE, `#` included. Without an ACL file, `files` grants everything only when it is the only configured back-end.
- **SIGHUP reloads the `files` back-end** the way go-auth's own signal handler does: new users and rules are added, but deleted ones stay in force until a restart. MQExtended also reloads its own configuration. Under Mosquitto only one of the two happens, depending on which signal handler was installed last at startup. Restart to revoke a user or rule from those files.

### Caches

- Without `cache true`, every check asks the back-ends.
- With the memory cache, authentication results stay in the plugin on each node. ACL verdicts go into the broker's verdict cache for `acl_cache_seconds` ± `acl_jitter_seconds`, shared by all nodes of a cluster. `cache_refresh` does not extend ACL entries.
- With `cache_type redis`, both caches stay in the plugin and use go-auth's keys, refresh and `cache_reset` (which flushes the configured database). Those keys contain the username, password, topic and client id in recoverable form, as in go-auth. Protect the cache database accordingly.

### Differences from the Go plugin

- `mysql_allow_native_passwords false` is not enforced: the MySQL driver can't refuse the `mysql_native_password` method. A configuration that go-auth refuses at startup for this reason loads; configurations that work under go-auth behave the same.
- The Redis back-end and cache accept the cluster metadata of Redis 7 and later. go-auth's pinned Redis client retries forever on it.
- LDAP rejects passwords that are not UTF-8.
- When `prefixes` maps two back-ends to the same prefix, the first configured mapping wins. In go-auth the result depends on Go's map order.
- Some Argon2id parameter sizes that Go accepts are rejected, and oversized work parameters are bounded.
- HTTP back-ends don't use proxy environment variables.
- A Redis command follows one cluster redirection, and connection reuse and retry timing differ from go-redis.
- Error messages in the log come from different drivers.

## In a cluster

- Give every node the same plugin lines and options, and let every node reach the back-ends. Add, remove or reconfigure a plugin only with the whole cluster stopped, after every node runs a build that supports it ([upgrades](cluster.md#upgrades)). The node serving a client authenticates it.
- Each ACL check is made by one node. Its verdict goes through the replicated log, so every node applies the same decision at the same point. A delivery or will that is waiting for a verdict is replicated state. If the node asking the back-end fails, the leader asks again.
- A reusable verdict (auth-plug `acl_cacheseconds` above 0, go-auth's memory cache) is shared by all nodes until it expires. The plugins cache per process, so a cluster asks the back-end less often than separate brokers would. Authentication caches stay per node.
