#!/bin/sh
set -eu

if [ "$#" -ne 1 ] || [ -z "$1" ]; then
    printf 'Usage: %s <new-bundle-directory>\n' "$0" >&2
    exit 2
fi

case $1 in
    /*) bundle=$1 ;;
    *)  bundle=$PWD/$1 ;;
esac
if [ -e "$bundle" ] || [ -L "$bundle" ]; then
    printf 'Bundle destination already exists: %s\n' "$bundle" >&2
    exit 1
fi

repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
cd "$repo"
host=$(rustc -vV | awk '$1 == "host:" { print $2 }')
case $host in
    *-linux-*) ;;
    *) printf 'A native Linux Rust toolchain is required.\n' >&2; exit 1 ;;
esac

target_dir=${CARGO_TARGET_DIR:-target}
cargo build --locked --release --target "$host" --target-dir "$target_dir" -p mqx-server --bin mqextended

umask 022
mkdir -- "$bundle"
install -Dm 0755 -- "$target_dir/$host/release/mqextended" "$bundle/bin/mqextended"
install -Dm 0644 -- packaging/linux/mqextended.conf "$bundle/etc/mqextended.conf"
install -Dm 0644 -- packaging/linux/mqextended.service "$bundle/lib/systemd/system/mqextended.service"
cd "$bundle"
sha256sum bin/mqextended etc/mqextended.conf lib/systemd/system/mqextended.service > SHA256SUMS
printf 'Staged %s in %s\n' "$host" "$bundle"
