# Mosquitto compatibility

The reference is **Mosquitto 2.1.4** (tag `v2.1.4`). When Mosquitto and the MQTT specification disagree, MQExtended matches Mosquitto, because the clients it serves were tested against Mosquitto.

## Standards and release scope (2026-11-22)

The [Mosquitto download page](https://mosquitto.org/download/) lists 2.1.4. The [2.0.23 maintenance release](https://mosquitto.org/blog/2026/11/version-2-1-3-released/) is for the older line, not a newer broker baseline.

| Specification | Published status | What that means for MQExtended |
| --- | --- | --- |
| MQTT | The [OASIS publication index](https://docs.oasis-open.org/mqtt/mqtt/) lists [5.0](https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html) as the newest standard, not 5.1 or 6.0. | The broker accepts wire levels 3, 4 and 5. For 3.1.1 use [the text including Errata 01](https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/errata01/os/mqtt-v3.1.1-errata01-os-complete.html); [ISO/IEC 20922:2016](https://www.iso.org/standard/69466.html) covers 3.1.1, not 5.0. [3.1](https://mqtt.org/mqtt-specification/) is the historical protocol. |
| MQTT-SN | [1.2](https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=mqtt-sn) is the input specification. The [2.0 document dated 2026-11-17](https://groups.oasis-open.org/higherlogic/ws/public/document?document_id=73644) is a working draft, not an approved standard. | This is a separate wire protocol. Use an MQTT-SN gateway; there is no native MQTT-SN listener. |
| MQTT over WebSocket | MQTT §6 uses [RFC 6455](https://www.rfc-editor.org/info/rfc6455/). [RFC 8441](https://www.rfc-editor.org/info/rfc8441/) and [RFC 9220](https://www.rfc-editor.org/info/rfc9220/) specify bootstrapping over HTTP/2 and HTTP/3 respectively. | WS/WSS clients use HTTP/1.1 Upgrade. The broker does not implement HTTP/2 or HTTP/3 Extended CONNECT or a native QUIC listener. |
| TLS | [RFC 9846](https://www.rfc-editor.org/info/rfc9846/) supersedes RFC 8446; the negotiated version is still TLS 1.3. | Both TLS 1.2 and 1.3 were exercised on MQTT and WSS listeners. Successful negotiation is not an audit of every RFC requirement. |
| Sparkplug | [Eclipse Sparkplug 3.0](https://sparkplug.eclipse.org/specification/version/3.0/) is [ISO/IEC 20237:2023](https://www.iso.org/standard/86204.html). | The optional [Sparkplug-aware plugin](#plugins) publishes birth certificates. This is not Sparkplug certification; the TCK was not run. |

MQTT 5 support does not imply support for every authentication mechanism. A CONNECT with a nonempty Authentication Method receives CONNACK `0x8C` (Bad Authentication Method); there is no enhanced-authentication plugin. This does not prevent username/password or certificate authentication.

See [client interoperability](testing.md#client-sdk-interoperability) for the distinction between continuous tests, one-time probes and release lookups.

## How to add or change a rule

1. Find the Mosquitto code that decides the behaviour and read it, not the man page.
2. Port it. Keep quirks; a "fix" is a behaviour change a client may notice.
3. Put a comment next to the port naming the Mosquitto file and function.
4. Prove it with Mosquitto's own artefacts: cases extracted from Mosquitto's test suite, output of Mosquitto tools, or a differential run against the real binaries (see [testing](testing.md#differential-tests)).

## Rule catalogue

### Topics (`mqx-topic` ← `libcommon/topic_common.c`)

- Topic names: non-empty, at most 65 535 bytes, no `+`/`#`, at most 200 `/` separators (`TOPIC_HIERARCHY_LIMIT`).
- Matching is `topic_matches_sub`, including `foo/#` matching `foo`, `+` matching an empty level, and `$`-topics matched only by `$`-filters.
- ACL pattern substitution replaces whole `%c` / `%u` levels only; an absent or empty substitute never matches.

### Wire format (`mqx-codec` ← `lib/packet_*.c`, `src/handle_*.c`)

- Every MQTT string goes through `mosquitto_validate_utf8`: besides malformed UTF-8 it rejects NUL, control characters U+0001–U+001F and U+007F–U+009F, and non-characters.
- Zero-length strings and binary fields read as absent (`packet__read_binary`). An empty username is anonymous; an empty password is no password.
- Reserved fixed-header flags are checked for MQTT 3.1.1 only; MQTT 3.1 (`MQIsdp`) clients get Mosquitto's leniency, e.g. a username flag without a username is ignored.
- MQTT 5 (`mqx_codec::v5`) follows Mosquitto's separate rules for header and property variable-byte integers, property order and duplicates, and the per-packet allowed property sets (`property__read_all`, `mosquitto_property_check_all`). A property that runs past the declared property length does not end the list: Mosquitto keeps reading properties from the rest of the packet, so the first failure in the packet decides the response.
- A Remaining Length is rejected at its fifth byte; four continued bytes wait for more input (`packet__read_single`).

### Authentication (`mqx-auth` ← `plugins/password-file`, `libcommon/password_common.c`)

- Hashes: `$6$` (SHA-512 of password + salt) and `$7$` (PBKDF2-HMAC-SHA512). Salts of 12 bytes (Mosquitto 2.0) and 64 bytes (2.1) load; hashes must be 64 bytes.
- The password is compared up to its first NUL byte, as Mosquitto passes it with `strlen`.
- No username: the password file abstains and `allow_anonymous` decides. Unknown user, wrong or missing password: refused.
- File parsing keeps `strtok` and `mosquitto_fgets` behaviour: a leading `:` is skipped; a line without `:` or with a NUL byte is ignored, and so is a final line without a newline that exactly fills the read buffer; a duplicate user or undecodable hash rejects the whole file. Base64 in hashes is decoded as OpenSSL does: blanks are skipped and unused trailing bits are ignored.

### Authorization (`mqx-auth` ← `plugins/acl-file`)

- SUBSCRIBE and UNSUBSCRIBE are always allowed; `read` is checked per delivered message.
- Topic lines before the first `user` line apply to clients without a username only. A username without a `user` section gets patterns only.
- `deny` entries are checked before all others. The first matching entry that grants the requested access wins.
- With any `pattern` line present, a client id or username containing `+` or `#` is denied everything.
- Lines are split on spaces only; tabs are part of a token, and an indented `#` is not a comment. A line containing a NUL byte ends the file; later lines are ignored.

### Plugins

`plugin` and `auth_plugin` recognize the stock `.so` and `.dll` filenames; MQExtended runs the corresponding Rust implementation, not code from that path. `plugin_opt_` and `auth_opt_` are aliases. Use `global_plugin` for global scope, or `plugin_load` and `plugin_use` to attach a named plugin to a listener. Restart to change declarations or their options.

| Module | Behavior |
| --- | --- |
| `mosquitto_dynamic_security` | See [dynamic security](dynamic-security.md). |
| `mosquitto_password_file` | Set `plugin_opt_password_file` to the Mosquitto hash file. |
| `mosquitto_acl_file` | Set `plugin_opt_acl_file` to the Mosquitto ACL file. |
| `mosquitto_sparkplug_aware` | For an authorized `spBv1.0/+/NBIRTH/+` or `spBv1.0/+/DBIRTH/+/+` PUBLISH, publish a broker-origin copy at `$sparkplug/certificates/<original topic>` with the original QoS. Copies are retained if retention is enabled; an empty payload clears a stored certificate. A global plugin also sees inbound publications from outgoing bridges. |

Password and ACL plugins can be used together. SIGHUP rereads their **startup file paths**; an invalid policy file stops the broker. Validate replacement files before rotating them. MQExtended refuses different password files or different ACL files serving the same listener, and refuses an explicit file plugin and Dynamic Security on the same listener, rather than dropping a callback.

Use at most one Sparkplug-aware instance per listener. A certificate is not emitted if its prefixed topic cannot fit an MQTT topic name. In a cluster, [upgrade all nodes before enabling the plugin](cluster.md#upgrades).

### Broker (`mqx-broker` ← `src/handle_*.c`, `src/subs.c`, `src/database.c`)

- Taking over a client id sends the old connection's will when the old or the new session is clean; persistent-to-persistent takeover discards it (`connect__on_authorised`).
- On a slow link, a large PUBLISH may take longer than 1.5 times the Keep Alive interval. Progress receiving its body resets the timer while more than 1000 bytes remain (`lib/packet_mosq.c`: `packet__read_single`); a stalled transfer still times out.
- `mount_point` prefixes SUBSCRIBE filters, PUBLISH topics and Will topics, but not UNSUBSCRIBE filters (`handle__unsubscribe`): unsubscribe with the mounted filter. A Will topic is checked for `$CONTROL/` and topic syntax after the mount point is added (`will__read`); a refused Will closes the connection without CONNACK.
- A denied SUBSCRIBE filter returns 0x80 to MQTT 3.1.1 and 0x87 to MQTT 5, but the requested QoS to MQTT 3.1 clients, without installing the subscription (`handle__subscribe`).
- A PUBREC naming a packet id that is still queued gets its PUBREL and leaves the message queued (`handle__pubrec`, `db__message_update_outgoing`).
- SUBSCRIBE and UNSUBSCRIBE filters are applied one at a time: filters before the first invalid one stay subscribed or unsubscribed when the broker closes the connection, without a SUBACK or UNSUBACK (`handle__subscribe`, `handle__unsubscribe`).
- MQTT 3.1 has no 23-byte client id limit, and CONNACK `session_present` stays 0 for 3.1 clients.
- Outgoing packet ids are consumed even when a message is then dropped as a duplicate or for a full queue (`mosquitto__mid_generate`), so packet ids on the wire match Mosquitto's.
- `allow_duplicate_messages false` suppresses overlapping live copies only for pre-v5 recipients. MQTT 5 keeps separate deliveries from overlapping filters, each with its subscription's QoS and identifier if set (`src/database.c`: `db__message_insert_outgoing`).
- Connection log lines use 2.1's protocol numbers: `p3` for MQTT 3.1, `p4` for 3.1.1.
- MQTT 5 follows the same handlers' v5 branches: `max_topic_alias` and `max_topic_alias_broker`, `accept_protocol_versions` including `5`, and the listener's `disable_protocol_v5`. A CONNECT whose protocol name is `MQTT` followed by a NUL byte is accepted at levels 4 and 5, and `MQIsdp` at level 5 gets the legacy refusal `20 02 00 01` (`handle__connect`'s `strncmp` comparisons).
- With `enable_control_api true`, `$CONTROL/broker/v1` provides the read-only listener and plugin inventory (`src/broker_control.c`); see [monitoring](monitoring.md#mqtt-broker-control-api) for permissions and SIGHUP behavior.

### Transports (`mqx-proxy` ← `src/proxy_v1.c`, `src/proxy_v2.c`; `mqx-ws` ← `lib/net_ws.c`, `src/http_serv.c`)

- PROXY v2 `LOCAL` is a health check: the connection closes without MQTT. v1 `UNKNOWN` falls back to the socket's peer address. The CRC32C TLV is ignored, as Mosquitto does.
- Behind `enable_proxy_protocol 2`, the forwarded certificate CN becomes the username only when both `require_certificate` and `use_identity_as_username` are set; a missing CN is refused at CONNECT with bad credentials. A forwarded CN replaces the CONNECT credentials but still goes through password authentication; only a certificate the listener verified itself bypasses it (`proxy_v2.c`, `handle_connect.c`).
- The built-in WebSocket upgrade accepts any request path, does not require `Host`, and accepts a subprotocol that is a case-sensitive prefix of `mqtt` or `mqttv3.1`. A present `Origin` must be a prefix of a configured `websockets_origin`. Rejections close silently. `http_dir` is accepted but never served on a WebSocket listener.
- Incoming WebSocket close frames are ignored; the broker sends close 1000 when it ends the connection.
- On an mTLS listener, `disable_client_cert_date_checks true` tolerates expired and not-yet-valid certificates in the client chain. Trust, signatures, client usage and CRL checks still apply. Leave the option off unless your client deployment requires it; it does not affect bridge or cluster TLS.
- `listener 0 <path>` opens a Unix socket listener (`net__socket_listen_unix`).

### Bridges (`mqx-bridge` ← `src/bridge.c`, `src/bridge_topic.c`, `src/handle_connack.c`, `lib/send_publish.c`)

- Bridge configuration follows `config__read_file_core`; outgoing PSK and OCSP settings have the checks below.
- `topic` patterns, directions and prefixes are remapped as `bridge__add_topic` and `remap_topic_in` do; inbound remapping stops at the first matching topic line.
- The default remote client id is `<hostname>.<connection>` and the local one `local.<hostname>.<connection>`, as in `bridge__new`. In a cluster the ids are fixed when the bridge is first claimed, so a takeover by a node with another hostname keeps them.
- `try_private`, notifications, start types, `restart_timeout` backoff and `round_robin` behave as in `bridge__connect`, `bridge__on_connect` and `bridge_check`.
- A lazy bridge retries when a new offline enqueue reaches its threshold; an unchanged backlog does not repeatedly trigger dials. On broker shutdown the remote connection closes without `DISCONNECT`, allowing the remote broker to publish the bridge Will. Reconfiguring an active bridge still sends `DISCONNECT`.
- As in `lib/send_publish.c`, the outgoing bridge size check drops oversized PUBLISH packets without blocking subscription setup or QoS control packets. Keep control packets within the remote broker's advertised MQTT 5 Maximum Packet Size.
- In a cluster each bridge runs on exactly one node; see [data model](data-model.md#rules).
- Use `bridge_identity` and `bridge_psk` together for outgoing TLS 1.2 PSK. Supply the key in hexadecimal without `0x`. Do not combine PSK with certificate settings or OCSP on the same bridge.
- Bridge TLS uses OpenSSL with Mosquitto's settings (`net__init_ssl_ctx`, `tls__set_verify_hostname`): `bridge_ciphers` takes an OpenSSL cipher string and defaults to OpenSSL's default list, with `:!aNULL:!eNULL` appended; hostname checks use OpenSSL's defaults, so a certificate without DNS SANs is matched on its subject CN and partial wildcards are allowed. `bridge_tls_use_os_certs` loads OpenSSL's default trust locations.
- A bridge accepts messages as soon as its connection to the remote opens and sends them after CONNACK, as `db__message_insert_outgoing` does; `local_cleansession true` discards only messages published while the bridge has no connection.
- `bridge_require_ocsp true` requires certificate trust via `bridge_cafile`, `bridge_capath`, or `bridge_tls_use_os_certs`. The bridge accepts only an unambiguous `GOOD` status for the verified server leaf, signed by its issuer or a delegated responder, with a validity interval covering the current time. It never fetches OCSP responses. `bridge_insecure true` skips hostname verification only.

## Defaults

| Setting | Mosquitto default | MQExtended |
| --- | --- | --- |
| `max_queued_messages` | 1000 | 1000 |
| `max_inflight_messages` | 20 | 20 |
| `queue_qos0_messages` | false | false |
| `persistent_client_expiration` | never | never |
| `message_size_limit` | 0 (protocol maximum) | 0 |
| `allow_anonymous` | false when any listener is configured | same |

## Deliberate deviations

| Deviation | Why it is invisible to clients |
| --- | --- |
| `$argon2id$` hashes are rejected | Mosquitto 2.1.4 builds without `WITH_ARGON2` by default and rejects them too |
| Non-UTF-8 entries in `password_file` / `acl_file` are kept or dropped instead of matched byte-wise | MQTT usernames and topics are validated UTF-8, so such entries can never match |
| Base64 in a hash field longer than 1024 bytes that is also malformed can decode differently | OpenSSL's base64 BIO reads in 1024-byte chunks; the values Mosquitto writes are never this long |
| `$SYS/broker/heap/*` is not published | Mosquitto only publishes it in builds with memory tracking, so clients cannot rely on it |
| Persistence is written to `<persistence_file>.mqx`, not `mosquitto.db` | Clients see the same state after a restart; the Mosquitto file is read once for [migration](migration.md#5-carry-state-over) and left untouched for rollback |
| A persistence file that is unreadable, a symbolic link, not a regular file, or an empty `.mqx` stops the broker with exit status 1 | Mosquitto starts with an empty state and writes it over the file at its next save; refusing to start keeps the old data for recovery. A corrupt file exits 1 in both, and an empty `mosquitto.db` starts empty in both |
| A Unix listener refuses a non-socket path or a socket still accepting connections | A typo cannot replace an existing file or disconnect clients from a running listener. A stale socket is still reclaimed. Use a service-owned directory and serialize starts; pathname checks are not a lock against concurrent directory changes. |
| `log_timestamp_format` is rendered by Chrono, not libc `strftime` | Identical for the standard conversions; only libc-specific extensions differ |
| `log_dest dlt` logs nothing and `log_dest syslog` has no console fallback | Matches a stock Mosquitto build without DLT; syslog delivery goes to `/dev/log` as Mosquitto's does |
| An invalid dynamic-security config file stops the broker | Mosquitto would run with an empty policy; refusing to start is the safe reading of the same file ([dynamic security](dynamic-security.md#differences-from-the-c-plugin)) |
| Bridge reconnect delays follow `restart_timeout` without Mosquitto's event-loop jitter | The remote broker sees the same connect sequence; only the exact retry instants differ |
| Bridge TLS appends `:!aNULL:!eNULL` to `bridge_ciphers`, and PSK bridges default to `PSK:!aNULL:!eNULL` | Unauthenticated cipher suites are never negotiated; only a remote that offers nothing else is refused |
| A PROXY v1 header on a TLS listener is read before the TLS handshake | Mosquitto 2.1.4 accepts neither order with TLS 1.2 or 1.3, so no working Mosquitto setup depends on it |
| PROXY headers split across TCP reads are reassembled | Mosquitto closes such a connection; an intact header is handled the same way |
| Outgoing WebSocket frames are always binary | Mosquitto's send opcode can follow a half-read incoming frame; clients accept binary MQTT frames |

## Unsupported directives

These directives make `mqextended` refuse to start, naming the directive, rather than silently run without what they ask for:

| Directive | Why |
| --- | --- |
| `psk_file`, `psk_hint` | Incoming TLS-PSK needs to transmit the configured identity hint. The safe OpenSSL binding exposes the server callback but not the hint setter. Outgoing bridge PSK is supported. |
| `tls_engine`, `tls_engine_kpass_sha1`, `tls_keyform engine` | No provider for legacy OpenSSL ENGINE private keys or engine PIN controls. The broker does not substitute a PEM key. |
| `plugin`, `auth_plugin`, `plugin_load` for libraries outside the [supported set](#plugins) | Arbitrary Mosquitto C plugin ABIs are not loaded. |
| `memory_limit` above 0 | No fallible, process-wide equivalent of Mosquitto's tracked allocation limit. An address-space cap or systemd `MemoryMax` can kill the process rather than reject one operation. |
