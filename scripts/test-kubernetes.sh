#!/usr/bin/env bash
# Only for a disposable kind cluster named mqx-chart, with cert-manager and the image loaded.
set -euo pipefail
cd "$(dirname "$0")/.."
ns=mqx-chart-smoke
context=kind-mqx-chart
k=(kubectl --context "$context" -n "$ns")
h=(helm --kube-context "$context" -n "$ns")
chart=deploy/helm/mqextended
work=$(mktemp -d)
forward=
stop_forward() {
    if [[ -n $forward ]]; then kill "$forward" 2>/dev/null || :; wait "$forward" 2>/dev/null || :; forward=; fi
}
trap 'stop_forward; rm -rf "$work"' EXIT
umask 077
# Refuse to reuse an existing namespace: this test deliberately stops and restarts voters.
"${k[@]}" create namespace "$ns"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=mqx-test-ca \
    -keyout "$work/ca.key" -out "$work/ca.crt" 2>/dev/null
openssl req -new -newkey rsa:2048 -nodes -subj /CN=localhost \
    -keyout "$work/tls.key" -out "$work/tls.csr" 2>/dev/null
printf '%s\n' 'subjectAltName=DNS:localhost,IP:127.0.0.1' 'basicConstraints=critical,CA:FALSE' 'extendedKeyUsage=serverAuth' > "$work/extensions"
openssl x509 -req -in "$work/tls.csr" -CA "$work/ca.crt" -CAkey "$work/ca.key" \
    -CAcreateserial -days 2 -extfile "$work/extensions" -out "$work/tls.crt" 2>/dev/null
"${k[@]}" create secret tls client-listener --cert="$work/tls.crt" --key="$work/tls.key"
mosquitto_passwd -c -b "$work/password_file" device chart-test-password
printf 'user device\ntopic readwrite charts/#\n' > "$work/acl_file"
"${k[@]}" create secret generic policies --from-file="$work/password_file" --from-file="$work/acl_file"
values=(--set-string image.repository=mqextended --set-string image.tag=chart-test \
    --set-string auth.existingSecret=policies --set-string mqttTLS.existingSecret=client-listener --set storage.size=128Mi)
ready() {
    local pod="$1-node-$2-0"
    "${k[@]}" wait --for=create "pod/$pod" --timeout=90s
    "${k[@]}" wait --for=condition=Ready "pod/$pod" --timeout=180s
}
connect_to() {
    stop_forward
    "${k[@]}" port-forward --address 127.0.0.1 "$1" 29883:8883 >"$work/forward.log" 2>&1 & forward=$!
    local end=$((SECONDS+20))
    until grep -q 'Forwarding from' "$work/forward.log"; do
        if ! kill -0 "$forward" || (( SECONDS >= end )); then cat "$work/forward.log" >&2; return 1; fi
        sleep 0.2
    done
}
transport=(-h 127.0.0.1 -p 29883 --cafile "$work/ca.crt")
client=("${transport[@]}" -u device -P chart-test-password -q 1 -t charts/retained)
publish() { timeout 15 mosquitto_pub "${client[@]}" -r -m "$1"; }
read_retained() { [[ $(mosquitto_sub "${client[@]}" --retained-only -C 1 -W 12) == "$1" ]]; }
stop_first() {
    stop_forward
    "${k[@]}" scale "statefulset/$1-node-1" --replicas=0
    "${k[@]}" wait --for=delete "pod/$1-node-1-0" --timeout=90s
}
restore_first() { "${k[@]}" scale "statefulset/$1-node-1" --replicas=1; ready "$1" 1; }
install() {
    local release=$1 replicas=$2 extra=$3 count=$2
    [[ $extra == false ]] || count=$((count+1))
    "${h[@]}" install "$release" "$chart" "${values[@]}" --set "replicaCount=$replicas,additionalVoter.enabled=$extra" --wait --timeout 5m
    for ((i=1; i<=count; i++)); do ready "$release" "$i"; done
    connect_to "service/$release"
    publish "$release"; read_retained "$release"
    if timeout 10 mosquitto_pub "${transport[@]}" -t charts/retained -m anonymous; then echo 'anonymous MQTT accepted' >&2; return 1; fi
}
install single 1 false
stop_first single; restore_first single; connect_to service/single; read_retained single
# A Helm values change is not a Raft membership change.
if "${h[@]}" upgrade single "$chart" "${values[@]}" --set replicaCount=2 --dry-run=server >"$work/resize" 2>&1; then
    echo 'unsafe resize accepted' >&2; exit 1
fi
grep -Ei 'topology|membership|resize|voter.count' "$work/resize"
stop_forward; "${h[@]}" uninstall single
install pair 2 false
connect_to pod/pair-node-2-0; read_retained pair
stop_first pair
"${k[@]}" wait --for=condition=Ready=false pod/pair-node-2-0 --timeout=60s
restore_first pair; ready pair 2; connect_to service/pair; read_retained pair
stop_forward; "${h[@]}" uninstall pair
install ha 2 true
# When the first broker is down, the MQTT Service must contain only the second,
# not the additional voter. Pod #2 and voter #3 must still commit writes.
stop_first ha
"${k[@]}" wait --for=jsonpath='{.subsets[0].addresses[0].targetRef.name}'=ha-node-2-0 endpoints/ha --timeout=60s
[[ $("${k[@]}" get endpoints ha -o jsonpath='{range .subsets[*].addresses[*]}{.targetRef.name}{" "}{end}') == 'ha-node-2-0 ' ]]
connect_to service/ha; publish survivor; read_retained survivor
restore_first ha; connect_to pod/ha-node-1-0; read_retained survivor
