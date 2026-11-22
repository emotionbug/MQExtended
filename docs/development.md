# Development

## Toolchain

Rust stable via rustup; `rust-toolchain.toml` pins the channel and adds clippy and rustfmt. Ubuntu's packaged `rustc` ships without Cargo, so install rustup even if `rustc` is present:

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path --profile minimal
export PATH="$HOME/.cargo/bin:$PATH"
```

## Linux broker build

Install a native Rust toolchain, a C compiler and linker, `pkg-config`, OpenSSL 3.x development headers and CA certificates. For Debian or Ubuntu the build packages are `build-essential`, `pkg-config`, `libssl-dev` and `ca-certificates`. The broker does not need CMake or a Mosquitto build.

```sh
cargo build --locked --release -p mqx-server --bin mqextended
target/release/mqextended --version
```

Use `./scripts/stage-linux.sh /path/to/new-bundle` to repeat the locked release build for your native Linux target and stage the executable, sample configuration, systemd unit and `SHA256SUMS`. The parent directory must exist; staging refuses an existing destination. The output can be moved as a directory. The unit inside it assumes the installation paths in the [README](../README.md#install-a-standalone-linux-service).

Build on the oldest Linux userspace you intend to support, or on the deployment distro. The executable is dynamically linked and needs a compatible C runtime and OpenSSL 3.x runtime (`libssl.so.3`, `libcrypto.so.3`). The lockfile pins the Cargo dependencies, not the native toolchain or libraries; record the source revision, `rustc -vV` and the build environment to reproduce a release.

### Check a staged bundle

From the repository root, stage into a temporary directory as a regular user:

```sh
work=$(mktemp -d)
bundle="$work/bundle"
./scripts/stage-linux.sh "$bundle"
(cd "$bundle" && sha256sum --check --strict SHA256SUMS)
"$bundle/bin/mqextended" --version
"$bundle/bin/mqextended" --test-config -c "$bundle/etc/mqextended.conf"
```

Verify the unit without installing it. Only the launch paths in this temporary copy point into the bundle:

```sh
sed "s|^ExecStart=.*|ExecStart=\"$bundle/bin/mqextended\" -c \"$bundle/etc/mqextended.conf\"|" \
    "$bundle/lib/systemd/system/mqextended.service" > "$work/mqextended-stage-check.service"
systemd-analyze verify "$work/mqextended-stage-check.service"
```

Pick a free unprivileged port (28883 below). Run the broker with a read-only config and separate private working directory, which takes the place of systemd's state directory:

```sh
mkdir -m 0700 "$work/state"
sed 's/^listener 1883 /listener 28883 /' "$bundle/etc/mqextended.conf" > "$work/smoke.conf"
chmod 0444 "$work/smoke.conf"
(
    cd "$work/state" || exit
    umask 077
    unset MOSQUITTO_PERSISTENCE_LOCATION UMASK_SET NOTIFY_SOCKET
    exec "$bundle/bin/mqextended" -c "$work/smoke.conf"
)
```

Connect a local MQTT client to `127.0.0.1:28883`, then stop the broker with Ctrl-C. Check that it exited cleanly and that `test -s "$work/state/mqextended.db.mqx"` succeeds. This checks the broker's file access as an unprivileged user; `systemd-analyze verify` checks the unit, not the running service's sandbox.

## Mosquitto reference build

Differential tests run the real Mosquitto 2.1.4. Its CMake build needs cJSON as a CMake package even when you only want the broker, and the plugin directory needs SQLite. The `password_file` and `acl_file` support you compare against is compiled into the broker from `plugins/password-file` and `plugins/acl-file` regardless of `WITH_PLUGINS`, so turning plugins off is safe.

```sh
git clone --depth 1 https://github.com/DaveGamble/cJSON.git /tmp/cJSON
cmake -S /tmp/cJSON -B /tmp/cJSON/build -DCMAKE_INSTALL_PREFIX=/tmp/cjson-install \
      -DENABLE_CJSON_TEST=OFF -DBUILD_SHARED_LIBS=OFF -DCMAKE_POSITION_INDEPENDENT_CODE=ON
cmake --build /tmp/cJSON/build && cmake --install /tmp/cJSON/build

git clone --depth 1 -b v2.1.4 https://github.com/eclipse-mosquitto/mosquitto.git /tmp/mosquitto
cmake -S /tmp/mosquitto -B /tmp/mosquitto/build -DCMAKE_PREFIX_PATH=/tmp/cjson-install \
      -DWITH_DOCS=OFF -DWITH_TESTS=OFF -DWITH_PLUGINS=OFF -DWITH_LIB_CPP=OFF \
      -DWITH_WEBSOCKETS=OFF -DWITH_CTRL_SHELL=OFF -DCMAKE_BUILD_TYPE=Release
cmake --build /tmp/mosquitto/build -j"$(nproc)"
```

The binaries land in `build/src/mosquitto`, `build/client/mosquitto_{pub,sub}` and `build/apps/mosquitto_passwd/mosquitto_passwd`. Point `MOSQUITTO_BUILD_DIR` at `build/`. The source tree is also the reference you port from; keep it next to the build.

The `mqx-ws` differential test needs a second build with Mosquitto's built-in WebSocket support; point `MOSQUITTO_WS_BUILD_DIR` at it:

```sh
cmake -S /tmp/mosquitto -B /tmp/mosquitto/build-ws -DCMAKE_PREFIX_PATH=/tmp/cjson-install \
      -DWITH_WEBSOCKETS=ON -DWITH_WEBSOCKETS_BUILTIN=ON -DWITH_DOCS=OFF -DWITH_TESTS=OFF \
      -DWITH_PLUGINS=OFF -DWITH_LIB_CPP=OFF -DWITH_CTRL_SHELL=OFF -DCMAKE_BUILD_TYPE=Release
cmake --build /tmp/mosquitto/build-ws -j"$(nproc)"
```

The `$SYS` and HTTP API differential tests need a third build with `WITH_HTTP_API=ON`, which links libmicrohttpd (`libmicrohttpd-dev`); point `MOSQUITTO_HTTP_BUILD_DIR` at it:

```sh
cmake -S /tmp/mosquitto -B /tmp/mosquitto/build-http -DCMAKE_PREFIX_PATH=/tmp/cjson-install \
      -DWITH_HTTP_API=ON -DHTTP_API_DIR=/tmp/mosquitto/www -DWITH_DOCS=OFF -DWITH_TESTS=OFF \
      -DWITH_PLUGIN_PERSIST_SQLITE=OFF -DWITH_LIB_CPP=OFF -DWITH_CTRL_SHELL=OFF -DCMAKE_BUILD_TYPE=Release
cmake --build /tmp/mosquitto/build-http -j"$(nproc)"
```

Without root, unpack the packages instead of installing them: `apt download libmicrohttpd-dev libmicrohttpd12t64`, `dpkg-deb -x` both into a directory, point `PKG_CONFIG_PATH` at its `usr/lib/x86_64-linux-gnu/pkgconfig` and add its library directory to `-DCMAKE_BUILD_RPATH`.

The dynamic-security differential tests need a fourth build with plugins and `mosquitto_ctrl`; point `MOSQUITTO_PLUGIN_BUILD_DIR` at it:

```sh
cmake -S /tmp/mosquitto -B /tmp/mosquitto/build-plugins -DCMAKE_PREFIX_PATH=/tmp/cjson-install \
      -DWITH_PLUGINS=ON -DWITH_PLUGIN_PERSIST_SQLITE=OFF -DWITH_WEBSOCKETS=OFF -DWITH_DOCS=OFF -DWITH_TESTS=OFF \
      -DWITH_LIB_CPP=OFF -DWITH_CTRL_SHELL=OFF -DCMAKE_BUILD_TYPE=Release
cmake --build /tmp/mosquitto/build-plugins -j"$(nproc)"
```

## Commands

See [testing](testing.md#commands) for checks. Workspace-wide lint settings live in the root `Cargo.toml`; crates opt in with `[lints] workspace = true`.
