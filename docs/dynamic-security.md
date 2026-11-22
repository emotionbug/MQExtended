# Dynamic security

MQExtended has Mosquitto's dynamic security plugin built in, so a deployment that manages users, groups and roles with `mosquitto_ctrl dynsec` keeps working unchanged. It is a Rust port of `plugins/dynamic-security`, not the C plugin; no plugin is loaded.

## Enabling it

Keep the plugin lines of your `mosquitto.conf`. Any of Mosquitto's forms is recognised when the path names `mosquitto_dynamic_security`:

```text
plugin /usr/lib/x86_64-linux-gnu/mosquitto_dynamic_security.so
plugin_opt_config_file /var/lib/mosquitto/dynamic-security.json
```

- `plugin`, `auth_plugin`, `global_plugin`, and `plugin_load` with `plugin_use` work as in 2.1.4, including per-listener scoping under `per_listener_settings true`.
- `plugin_opt_config_file` is the JSON file with clients, groups, roles and ACLs, in Mosquitto's format. Existing files load as they are.
- Any other plugin path makes `mqextended` refuse to start, naming the plugin.

Authentication and ACL checks run in the plugin's order, after or alongside `password_file` and `acl_file` exactly as Mosquitto combines them. Control requests on `$CONTROL/dynamic-security/v1` get Mosquitto's JSON responses, so `mosquitto_ctrl` and other tools need no change.

## First start without a config file

When `plugin_opt_config_file` does not exist, MQExtended creates it as the plugin does, with an `admin` client whose password comes from, in order:

1. the first line of `plugin_opt_password_init_file`,
2. the `MOSQUITTO_DYNSEC_PASSWORD` environment variable,
3. a generated password, written to `<config file>.pw`.

An unreadable or invalid config file stops the broker. Mosquitto would continue with an empty policy; MQExtended refuses to start without its access rules.

## In a cluster

The policy is replicated state. Every `mosquitto_ctrl` change goes through the log, so all nodes enforce it at the same point, and each node writes its own copy of the JSON file. The response comes back once, from the node that received the request. Passwords are replicated as hashes, never in plaintext.

- Put the existing `dynamic-security.json` on the node with the lowest id for the first start of the cluster. That node imports it once; the other nodes receive it through the log.
- Give every node the plugin lines and a writable `plugin_opt_config_file` path.
- After bootstrap the replicated state is authoritative. Change the policy with `mosquitto_ctrl`; editing a node's JSON file has no effect.

## Differences from the C plugin

- JSON key order and whitespace in the saved file can differ; the content is the same.
- `getClient` reports the connections of the node that answers.
- The per-command audit log lines are not reproduced.
