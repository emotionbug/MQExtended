# Third-party auth plugins

MQExtended has [mosquitto-auth-plug](https://github.com/jpmens/mosquitto-auth-plug) built in. A deployment that authenticates and authorizes clients through it keeps working unchanged. This is a Rust port of the plugin as Mosquitto 2.1.4 runs it, not the C library: no library is loaded. The [emotionbug fork](https://github.com/emotionbug/mosquitto-auth-plug) is the same code as the upstream's last commit.

## Enabling it

Keep the plugin lines in your `mosquitto.conf`:

```text
auth_plugin /usr/lib/mosquitto/auth-plug.so
auth_opt_backends http
auth_opt_http_ip 127.0.0.1
auth_opt_http_getuser_uri /getuser
auth_opt_http_superuser_uri /superuser
auth_opt_http_aclcheck_uri /acl
```

- MQExtended recognizes the plugin by its file name (`auth-plug.so`, `.dylib` or `.dll`) in `auth_plugin`, `plugin`, `global_plugin` or `plugin_load`. It doesn't open the file.
- `auth_opt_*` and `plugin_opt_*` take the plugin's own option names. All back-ends are available: `files`, `cdb`, `sqlite`, `redis`, `memcached`, `postgres`, `mysql`, `ldap`, `http`, `jwt` and `mongo`.
- The `psk` back-end fails to load, as in the plugin's stock build, which leaves it out.
- Password hashes use the stock build's format, `PBKDF2$<digest>$<iterations>$<salt>$<key>`, as the plugin's `np` tool writes them. Hashes from builds compiled with `SUPPORT_DJANGO_HASHERS` or `RAW_SALT` don't verify.
- `auth_plugin_deny_special_chars` works as in Mosquitto. While it is `true` (the default), a client whose username or client id contains `+`, `#` or `/` is denied every ACL check before the plugin is asked.
- A back-end that can't initialize prints the plugin's `|-- … *** ABORT.` lines and the broker exits with status 1, as the C plugin's `_fatal` does.
- SIGHUP doesn't reread the plugin options, because Mosquitto skips plugin configuration on reload. Connected clients are authenticated again through the plugin, as Mosquitto does.

## Combining it with other security

On one listener, the plugin can run alone or before the `password_file` and `acl_file` options. The plugin answers first, and the files decide whatever it leaves open.

MQExtended refuses these combinations at startup:

- the plugin together with Dynamic Security;
- the plugin together with the `mosquitto_password_file` or `mosquitto_acl_file` plugins (use the `password_file` and `acl_file` options instead);
- two auth plugins on one listener.

In each of these cases the outcome depends on callback order across plugin kinds, which MQExtended doesn't model.

## Behaviour clients see

Mosquitto 2.1.4 runs auth-plug through its legacy-plugin wrapper. The port keeps what clients observe through that wrapper, including the quirks:

- **A denial only abstains.** Built against Mosquitto 1.4.9 or newer, the plugin reports both "deny" and "no answer" as deferral (`auth-plug.c`, `MOSQ_DENY_AUTH`). A configured `password_file` or `acl_file` then decides. Without one, the client gets what it gets when every check abstains: a refused CONNECT or a denied publish, subscription or delivery.
- **Anonymous clients get no plugin ACL.** The plugin only knows clients that logged in with a non-empty username and password, or that presented a client certificate. For any other client it abstains before applying `anonusername`. An anonymous client therefore gets only what `acl_file` grants.
- **`%c` is not the client id.** For a client that logged in with a password, the plugin substitutes the literal text `client id not available` for `%c` in ACL patterns and queries. Certificate clients get their real client id.
- **SUBSCRIBE is checked as access 4.** Back-ends that only know read (1) and write (2) never grant it: `files` rules, and Mongo `r` and `w` entries. A subscription then succeeds only if another check allows it; `acl_file` allows every SUBSCRIBE. UNSUBSCRIBE never reaches the plugin.
- **Retained messages and `check_retain_source`.** With `check_retain_source true`, Mosquitto's default, a retained message is checked again for its publisher before it is sent to a new subscriber. That check carries no credentials, so the plugin abstains. Unless `acl_file` grants the publisher write access, retained messages from plugin-authenticated publishers are not sent to new subscribers.
- **Back-end errors.** When a back-end fails (an HTTP 5xx or a lost database connection, for example):
  - CONNECT: the connection closes without a CONNACK.
  - PUBLISH: the connection closes without an acknowledgement.
  - SUBSCRIBE: the filters before the failing one stay subscribed and the connection closes.
  - Retained replay: the replay stops and no SUBACK is sent, but the connection stays open.
  - Delivery or will: the message is dropped.
- **Superusers and back-end order** follow the plugin. Every back-end's superuser check runs before any ACL check, and any configured back-end can authorize a client, not only the one that authenticated it.

## In a cluster

- Give every node the same plugin lines and options, and let every node reach the back-ends. Add, remove or reconfigure the plugin only with the whole cluster stopped, after every node runs a build that supports it ([upgrades](cluster.md#upgrades)). The node serving a client authenticates it.
- Each ACL check is made by one node. Its verdict goes through the replicated log, so every node applies the same decision at the same point. A delivery or will that is waiting for a verdict is replicated state. If the node asking the back-end fails, the leader asks again.
- With `acl_cacheseconds` above 0, a cached verdict is shared by all nodes until it expires. Mosquitto caches per process, so a cluster asks the back-end less often than separate brokers would. The `auth_cacheseconds` cache stays per node.

## Differences from the C plugin

- Options and `files` rules belong to one plugin instance. In the C plugin they are process-global, so two instances overwrite each other.
- The client identity comes from the connection, not from a table of C client pointers. The C plugin can hand a disconnected client's identity to a new client that reuses its memory.
- The broker, not the plugin, holds the ACL cache. Cache-hit and cleanup log lines differ, and an entry still expires at the end of the same second.
- Passwords, JWT tokens, cache digests and environment values are redacted in the plugin's log lines. HTTP response bodies are not printed.
- The C plugin's memory errors are not reproduced: buffer overflows in `files`, MySQL and LDAP filter expansion, the HTTP environment-parameter double free, and Mongo's dangling pointers. Input that would overflow or crash the C plugin gets a defined result instead.
- HTTP and JWT speak HTTP/1.1 over OpenSSL directly. libcurl's proxy environment variables and HTTP/2 are not used.
- Redis speaks RESP2 only. A `%` in a username or topic is literal, not a hiredis format directive.
- memcached rejects keys that are invalid in its text protocol, and gives up on an operation after 5 seconds.
- MySQL: a non-empty `ssl_cipher` with `ssl_enabled true` fails loading.
- PostgreSQL doesn't read `.pgpass` or service files and has no GSSAPI. `PGSSLROOTCERT=system` fails loading.
- LDAP: a failed search fails that one check instead of exiting the broker. Referrals are not followed.
- CDB is read once at startup, and a malformed file fails loading.
- SQLite uses the current statement API, so the retries on a locked database can differ.
- Back-end calls don't block the broker. In Mosquitto every client waits while the plugin waits for its back-end. Here only the message being checked waits, so a delivery can arrive after the publisher's acknowledgement. Each subscriber still receives messages in order.
- A retained message the serving node couldn't foresee when the SUBSCRIBE arrived is checked after the SUBACK. A back-end error then drops only that message.
- The HTTP API asks the plugin directly from the node that serves the request, without the shared ACL cache.
- A standalone broker with `persistence true` doesn't save deliveries that are waiting for a verdict, or cached verdicts.
