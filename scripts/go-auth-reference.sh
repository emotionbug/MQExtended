#!/usr/bin/env bash
# Build the pinned reference and its fixture tools without installing packages.
set -euo pipefail

if (( $# != 1 )); then
    echo "usage: $0 NEW_DIRECTORY > go-auth.env" >&2
    exit 2
fi
repo=$(cd -- "$(dirname -- "$0")/.." && pwd -P)
mosquitto_build=$(realpath -- "${MOSQUITTO_BUILD_DIR:?set MOSQUITTO_BUILD_DIR to the Mosquitto 2.1.4 build}")
mosquitto=$(realpath -- "${MOSQUITTO_SRC:-$mosquitto_build/..}")
cjson=$(realpath -- "${MOSQUITTO_CJSON_INCLUDE:?set MOSQUITTO_CJSON_INCLUDE to the cJSON include directory}")
if ! grep -Fxq 'set (VERSION 2.1.4)' "$mosquitto/CMakeLists.txt" ||
    [[ ! -f $mosquitto/include/mosquitto_plugin.h || ! -x $mosquitto_build/src/mosquitto ]]; then
    echo "MOSQUITTO_SRC and MOSQUITTO_BUILD_DIR must point to Mosquitto 2.1.4" >&2
    exit 2
fi
mkdir -- "$1"
prefix=$(realpath -- "$1")
if [[ $prefix$mosquitto$cjson == *[[:space:]]* ]]; then
    echo "The output and C include paths must not contain whitespace" >&2
    exit 2
fi

# Leave stdout for the environment fragment, including when fetching dependencies.
exec 3>&1 >&2
export GOTOOLCHAIN=local
version=$(go env GOVERSION 2>/dev/null || true)
if [[ ! $version =~ ^go([0-9]+)\.([0-9]+)(\.[0-9]+)?$ ]] ||
    (( BASH_REMATCH[1] < 1 || (BASH_REMATCH[1] == 1 && BASH_REMATCH[2] < 24) )); then
    case "$(uname -s)/$(uname -m)" in
        Linux/x86_64) go_arch=amd64; go_sha=bceca00afaac856bc48b4cc33db7cd9eb383c81811379faed3bdbc80edb0af65 ;;
        Linux/aarch64) go_arch=arm64; go_sha=beaf0f51cbe0bd71b8289b2b6fa96c0b11cd86aa58672691ef2f1de88eb621de ;;
        *) echo 'Install Go >= 1.24 to build the go-auth reference on this platform' >&2; exit 2 ;;
    esac
    go_archive=go1.24.11.linux-$go_arch.tar.gz
    curl --fail --silent --show-error --location "https://go.dev/dl/$go_archive" -o "$prefix/$go_archive"
    printf '%s  %s\n' "$go_sha" "$prefix/$go_archive" | sha256sum --check --strict
    tar -C "$prefix" -xzf "$prefix/$go_archive"
    rm -- "$prefix/$go_archive"
    export GOROOT="$prefix/go"
    export PATH="$prefix/go/bin:$PATH"
fi

revision=20ee9310fe3a05e5b6915ce6369bcd0837309894
plugin=$prefix/mosquitto-go-auth
git init -q "$plugin"
git -C "$plugin" fetch --depth 1 https://github.com/iegomez/mosquitto-go-auth.git "$revision"
git -C "$plugin" checkout -q --detach FETCH_HEAD
[[ $(git -C "$plugin" rev-parse HEAD) == "$revision" ]]
(
    cd "$plugin"
    # The upstream Makefile generates go-auth.h from go-auth.go before compiling auth-plugin.c.
    export CGO_ENABLED=1 CGO_CFLAGS="-I$mosquitto/include -I$cjson -fPIC"
    go build -mod=readonly -buildmode=c-archive -o go-auth.a go-auth.go
    CGO_LDFLAGS=-shared go build -mod=readonly -buildmode=c-shared -o go-auth.so .
    go build -mod=readonly -o pw pw-gen/pw.go
    go build -mod=readonly -o "$prefix/seed" "$repo/crates/mqx-difftest/tests/go_auth/seed.go"
)

# go-redis v8 cannot decode the Redis 7+ CLUSTER SLOTS node extension.
redis_release=redis-6.2.22
redis_sha=3ce191a727505b2d711bb45cfde8d9eeab1e061bdc0e5cb56a50201069a9729d
curl --fail --silent --show-error --location "https://download.redis.io/releases/$redis_release.tar.gz" -o "$prefix/$redis_release.tar.gz"
printf '%s  %s\n' "$redis_sha" "$prefix/$redis_release.tar.gz" | sha256sum --check --strict
tar -C "$prefix" -xzf "$prefix/$redis_release.tar.gz"
rm -- "$prefix/$redis_release.tar.gz"
make -C "$prefix/$redis_release" MALLOC=libc OPT=-O2 -j"${JOBS:-$(nproc)}" redis-server

if [[ -n ${MONGOD:-} ]]; then
    mongod=$(realpath -- "$MONGOD")
else
    # The shared Debian/Ubuntu fixtures do not supply MongoDB. Only unpack mongod.
    case "$(uname -s)/$(uname -m)" in
        Linux/x86_64) mongo_arch=x86_64; mongo_sha=3633d52d2aa6e423da1bdff238bef01165b6af01587200aac0864d93f39b608f ;;
        Linux/aarch64) mongo_arch=aarch64; mongo_sha=a15807ad72e36dced706b06bf10b428467f27ecfa10a8b780edf48fd07fd5f71 ;;
        *) echo 'Set MONGOD to an installed mongod' >&2; exit 2 ;;
    esac
    mongo_release=mongodb-linux-$mongo_arch-ubuntu2404-8.2.3
    curl --fail --silent --show-error --location "https://fastdl.mongodb.org/linux/$mongo_release.tgz" -o "$prefix/$mongo_release.tgz"
    printf '%s  %s\n' "$mongo_sha" "$prefix/$mongo_release.tgz" | sha256sum --check --strict
    tar -C "$prefix" -xzf "$prefix/$mongo_release.tgz" "$mongo_release/bin/mongod"
    rm -- "$prefix/$mongo_release.tgz"
    mongod=$prefix/$mongo_release/bin/mongod
fi
if [[ ! -x $mongod ]]; then
    echo "MONGOD is not executable: $mongod" >&2
    exit 2
fi

printf 'export %s=%q\n' \
    MOSQUITTO_GO_AUTH_SO "$plugin/go-auth.so" \
    MOSQUITTO_GO_AUTH_PW "$plugin/pw" \
    MOSQUITTO_GO_AUTH_BINARY "$mosquitto_build/src/mosquitto" \
    MOSQUITTO_GO_AUTH_SEED "$prefix/seed" \
    MOSQUITTO_GO_AUTH_REDIS_CLUSTER_SERVER "$prefix/$redis_release/src/redis-server" \
    MONGOD "$mongod" >&3
printf 'export LD_LIBRARY_PATH=%q${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}\n' \
    "$mosquitto_build/lib" >&3
