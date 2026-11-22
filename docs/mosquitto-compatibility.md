# Mosquitto compatibility

The reference is **Mosquitto 2.1.4** (tag `v2.1.4`). When Mosquitto and the MQTT specification disagree, MQExtended matches Mosquitto, because the clients it serves were tested against Mosquitto.

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

### Authentication (`mqx-auth` ← `plugins/password-file`, `libcommon/password_common.c`)

- Hashes: `$6$` (SHA-512 of password + salt) and `$7$` (PBKDF2-HMAC-SHA512). Salts of 12 bytes (Mosquitto 2.0) and 64 bytes (2.1) load; hashes must be 64 bytes.
- The password is compared up to its first NUL byte, as Mosquitto passes it with `strlen`.
- No username: the password file abstains and `allow_anonymous` decides. Unknown user, wrong or missing password: refused.
- File parsing keeps `strtok` behaviour: a leading `:` is skipped, a line without `:` is ignored, a duplicate user or undecodable hash rejects the whole file.

### Authorization (`mqx-auth` ← `plugins/acl-file`)

- SUBSCRIBE and UNSUBSCRIBE are always allowed; `read` is checked per delivered message.
- Topic lines before the first `user` line apply to clients without a username only. A username without a `user` section gets patterns only.
- `deny` entries are checked before all others. The first matching entry that grants the requested access wins.
- With any `pattern` line present, a client id or username containing `+` or `#` is denied everything.
- Lines are split on spaces only; tabs are part of a token, and an indented `#` is not a comment.

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
| Base64 in hashes is decoded strictly | Every value Mosquitto writes is standard base64; malformed values fail Mosquitto's length checks as well |
