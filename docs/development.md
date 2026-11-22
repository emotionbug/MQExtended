# Development

## Toolchain

Rust stable via rustup; `rust-toolchain.toml` pins the channel and adds clippy and rustfmt. Ubuntu's packaged `rustc` ships without Cargo, so install rustup even if `rustc` is present:

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path --profile minimal
export PATH="$HOME/.cargo/bin:$PATH"
```

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
