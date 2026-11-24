#!/usr/bin/env bash
# Build the reference and unpack backend servers without installing packages.
set -euo pipefail

if (( $# != 1 )); then
    echo "usage: $0 NEW_BUILD_DIRECTORY" >&2
    exit 2
fi
mkdir -- "$1"
prefix=$(realpath -- "$1")
# The upstream Makefile does not quote include and library paths.
if [[ $prefix == *[[:space:]]* ]]; then
    echo 'the build directory may not contain whitespace' >&2
    exit 2
fi

# Leave stdout for the environment fragment. Save it separately if invoking via eval.
exec 3>&1 >&2
mkdir "$prefix/debs" "$prefix/root" "$prefix/tools"
root=$prefix/root
multiarch=$(cc -print-multiarch)
libs=$root/usr/lib/$multiarch

development=(
    libcurl4-openssl-dev libhiredis-dev libldap-dev libmariadb-dev
    libmemcached-dev libpq-dev libsqlite3-dev
)
packages=(
    "${development[@]}"
    redis-server redis-tools memcached postgresql mariadb-server ldap-utils slapd sqlite3
)
# Download the requested packages even if installed: their data files and server
# binaries need to be together under this prefix. Let apt select missing runtime
# dependencies and the distribution's PostgreSQL major version.
plan=$(LC_ALL=C apt-get -s --no-install-recommends install "${packages[@]}")
mapfile -t planned < <(awk '/^Inst / { print $2 }' <<< "$plan")
# Development symlinks in the extracted tree need their shared library targets
# there too, even when apt's plan omits them because they are installed.
mapfile -t shared < <(apt-cache depends "${development[@]}" |
    awk '/Depends: lib[^ ]+[0-9]([a-z][0-9]+)?$/ { print $2 }' | sort -u)
postgres=$(apt-cache depends postgresql | awk '/Depends: postgresql-[0-9]+$/ { print $2; exit }')
[[ -n $postgres ]]
pg_major=${postgres#postgresql-}
(
    cd "$prefix/debs"
    apt-get download "${packages[@]}" "${planned[@]}" "${shared[@]}" "$postgres" "postgresql-client-$pg_major" \
        mariadb-server-core mariadb-client mariadb-client-core mariadb-common
    for deb in ./*.deb; do dpkg-deb -x "$deb" "$root"; done
)

# Use the extracted MariaDB client, regardless of what mysql_config is installed.
# MySQL's linker flags and headers vary by distribution; the plugin needs libmariadb.
cat > "$prefix/tools/mysql_config" <<'CONFIG'
#!/bin/sh
case "$1" in
    --cflags) printf '%s\n' '-I'"$AUTHREF_ROOT/usr/include/mariadb" ;;
    --libs) printf '%s\n' '-L'"$AUTHREF_LIBS"' -lmariadb' ;;
    *) exit 2 ;;
esac
CONFIG
cat > "$prefix/tools/pg_config" <<'CONFIG'
#!/bin/sh
case "$1" in
    --includedir) printf '%s\n' "$AUTHREF_ROOT/usr/include/postgresql" ;;
    --libdir) printf '%s\n' "$AUTHREF_LIBS" ;;
    *) exit 2 ;;
esac
CONFIG
chmod +x "$prefix/tools/"*_config

checkout() {
    git init -q "$3"
    git -C "$3" fetch -q --depth 1 "$1" "$2"
    git -C "$3" checkout -q --detach FETCH_HEAD
}
jobs=${JOBS:-$(nproc)}
cjson=$prefix/cjson-install
checkout https://github.com/DaveGamble/cJSON.git 6d9f2443ab071f86e5d9b43025a40929ec41c46c "$prefix/cJSON"
cmake -S "$prefix/cJSON" -B "$prefix/cJSON/build" -DCMAKE_INSTALL_PREFIX="$cjson" \
    -DENABLE_CJSON_TEST=OFF -DBUILD_SHARED_LIBS=OFF -DCMAKE_POSITION_INDEPENDENT_CODE=ON
cmake --build "$prefix/cJSON/build" -j "$jobs"
cmake --install "$prefix/cJSON/build"

mosquitto=$prefix/mosquitto
checkout https://github.com/eclipse-mosquitto/mosquitto.git v2.1.4 "$mosquitto"
cmake -S "$mosquitto" -B "$mosquitto/build" -DCMAKE_PREFIX_PATH="$cjson" \
    -DWITH_DOCS=OFF -DWITH_TESTS=OFF -DWITH_PLUGINS=OFF -DWITH_LIB_CPP=OFF \
    -DWITH_WEBSOCKETS=OFF -DWITH_CTRL_SHELL=OFF -DCMAKE_BUILD_TYPE=Release
cmake --build "$mosquitto/build" -j "$jobs"

plugin=$prefix/mosquitto-auth-plug
checkout https://github.com/jpmens/mosquitto-auth-plug.git 34c1ab00ce22f0e32faf3a2563019fb97e60e687 "$plugin"
# v4 changed these three callback signatures. Deprecated header and compiler
# warnings are expected; do not change the reference's authorization code.
patch -d "$plugin" -p1 <<'PATCH'
--- a/Makefile
+++ b/Makefile
@@ -130,7 +130,7 @@
 CFLAGS += -I$(MOSQUITTO_SRC)/src/
 CFLAGS += -I$(MOSQUITTO_SRC)/lib/
 ifneq ($(OS),Windows_NT)
-	CFLAGS += -fPIC -Wall -Werror
+	CFLAGS += -fPIC -Wall
 endif
 CFLAGS += $(BACKENDS) $(BE_CFLAGS) -I$(MOSQ)/src -DDEBUG=1 $(OSSLINC)
 
--- a/auth-plug.c
+++ b/auth-plug.c
@@ -502 +502 @@
-int mosquitto_auth_unpwd_check(void *userdata, const struct mosquitto *client, const char *username, const char *password)
+int mosquitto_auth_unpwd_check(void *userdata, struct mosquitto *client, const char *username, const char *password)
@@ -601 +601 @@
-int mosquitto_auth_acl_check(void *userdata, int access, const struct mosquitto *client, const struct mosquitto_acl_msg *msg)
+int mosquitto_auth_acl_check(void *userdata, int access, struct mosquitto *client, const struct mosquitto_acl_msg *msg)
@@ -752 +752 @@
-int mosquitto_auth_psk_key_get(void *userdata, const struct mosquitto *client, const char *hint, const char *identity, char *key, int max_key_len)
+int mosquitto_auth_psk_key_get(void *userdata, struct mosquitto *client, const char *hint, const char *identity, char *key, int max_key_len)
PATCH
cat > "$plugin/config.mk" <<CONFIG
BACKEND_CDB = yes
BACKEND_MYSQL = yes
BACKEND_SQLITE = yes
BACKEND_REDIS = yes
BACKEND_POSTGRES = yes
BACKEND_LDAP = yes
BACKEND_HTTP = yes
BACKEND_JWT = yes
BACKEND_MONGO = no
BACKEND_FILES = yes
BACKEND_MEMCACHED = yes
SUPPORT_DJANGO_HASHERS = no
MOSQUITTO_SRC = $mosquitto
OPENSSLDIR = /usr
CFG_CFLAGS = -I$cjson/include -I$mosquitto/include -I$root/usr/include -I$root/usr/include/$multiarch -I$root/usr/include/hiredis
CFG_LDFLAGS = -L$libs -L$mosquitto/build/lib
CONFIG
PATH="$prefix/tools:$PATH" AUTHREF_ROOT="$root" AUTHREF_LIBS="$libs" \
    make -C "$plugin" -j "$jobs" auth-plug.so
# Build the upstream CDB tool independently; the library target doesn't need it.
make -C "$plugin/contrib/tinycdb-0.78" cdb

printf 'export %s=%q\n' \
    MOSQUITTO_AUTH_PLUG_SO "$plugin/auth-plug.so" \
    MOSQUITTO_AUTH_PLUG_BINARY "$mosquitto/build/src/mosquitto" \
    MOSQUITTO_AUTH_PLUG_ROOT "$root" \
    MOSQUITTO_AUTH_PLUG_POSTGRES "$root/usr/lib/postgresql/$pg_major/bin" \
    MOSQUITTO_AUTH_PLUG_CDB "$plugin/contrib/tinycdb-0.78/cdb" \
    LD_LIBRARY_PATH "$libs:$mosquitto/build/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" >&3
