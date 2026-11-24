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
printf '%s\n' 'subjectAltName=DNS:localhost,IP:127.0.0.1' 'basicConstraints=critical,CA:FALSE' 'extendedKeyUsage=serverAuth' > "$work/extensions"
leaf() {
    openssl req -new -newkey rsa:2048 -nodes -subj /CN=localhost \
        -keyout "$work/$1.key" -out "$work/$1.csr" 2>/dev/null
    openssl x509 -req -in "$work/$1.csr" -CA "$work/ca.crt" -CAkey "$work/ca.key" \
        -CAcreateserial -days 2 -extfile "$work/extensions" -out "$work/$1.crt" 2>/dev/null
}
listener_secret() {
    "${k[@]}" create secret tls client-listener --cert="$work/$1.crt" --key="$work/$1.key" \
        --dry-run=client -o yaml | "${k[@]}" apply -f -
}
leaf first; leaf renewed
listener_secret first
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
# Client transport for the current release: TLS on 8883 or plain MQTT on 1883.
port=8883
transport=(-h 127.0.0.1 -p 29883 --cafile "$work/ca.crt")
use_tls() { port=8883; transport=(-h 127.0.0.1 -p 29883 --cafile "$work/ca.crt"); }
use_plain() { port=1883; transport=(-h 127.0.0.1 -p 29883); }
connect_to() {
    stop_forward
    # Truncate before starting: the background job's own redirection runs
    # later, and the previous forward's "Forwarding from" line would pass the wait.
    : >"$work/forward.log"
    "${k[@]}" port-forward --address 127.0.0.1 "$1" "29883:$port" >>"$work/forward.log" 2>&1 & forward=$!
    local end=$((SECONDS+20)) deadline=${2:-}
    if [[ -n $deadline ]] && (( deadline < end )); then end=$deadline; fi
    until grep -q 'Forwarding from' "$work/forward.log"; do
        if ! kill -0 "$forward" || (( SECONDS >= end )); then cat "$work/forward.log" >&2; return 1; fi
        sleep 0.2
    done
}
credentials=(-u device -P chart-test-password -q 1 -t charts/retained)
publish() { timeout 15 mosquitto_pub "${transport[@]}" "${credentials[@]}" -r -m "$1"; }
read_retained() {
    local payload budget=${2:-15}
    if (( budget > 15 )); then budget=15; fi
    payload=$(timeout --kill-after=2s "${budget}s" mosquitto_sub "${transport[@]}" "${credentials[@]}" \
        --retained-only -C 1 -W 12) || return
    if [[ $payload != "$1" ]]; then
        printf 'Expected retained payload %q, got %q\n' "$1" "$payload" >&2
        return 1
    fi
}
wait_retained() {
    local target=$1 expected=$2 end=$((SECONDS+$3)) remaining
    while (( SECONDS < end )); do
        # A recovery re-exec can interrupt port-forward. Reconnect for each read.
        if connect_to "$target" "$end"; then
            remaining=$((end-SECONDS))
            if (( remaining > 0 )) && read_retained "$expected" "$remaining"; then return 0; fi
        fi
        if (( SECONDS < end )); then sleep 1; fi
    done
    printf '%s did not serve retained payload %q within %ss\n' "$target" "$expected" "$3" >&2
    return 1
}
served_certificate() {
    openssl s_client -connect 127.0.0.1:29883 -servername localhost -CAfile "$work/ca.crt" </dev/null 2>/dev/null |
        openssl x509 -noout -fingerprint -sha256
}
stop_first() {
    stop_forward
    "${k[@]}" scale "statefulset/$1-node-1" --replicas=0
    "${k[@]}" wait --for=delete "pod/$1-node-1-0" --timeout=90s
}
restore_first() { "${k[@]}" scale "statefulset/$1-node-1" --replicas=1; ready "$1" 1; }
install() {
    local release=$1 replicas=$2 extra=$3 count=$2
    shift 3
    [[ $extra == false ]] || count=$((count+1))
    "${h[@]}" install "$release" "$chart" "${values[@]}" --set "replicaCount=$replicas,additionalVoter.enabled=$extra" "$@" --wait --timeout 5m
    for ((i=1; i<=count; i++)); do ready "$release" "$i"; done
    connect_to "service/$release"
    publish "$release"; read_retained "$release"
    if timeout 10 mosquitto_pub "${transport[@]}" -t charts/retained -m anonymous; then echo 'anonymous MQTT accepted' >&2; return 1; fi
}
install single 1 false
# A renewed listener certificate is served without restarting the broker.
pod_uid=$("${k[@]}" get pod single-node-1-0 -o jsonpath='{.metadata.uid}')
before=$(served_certificate)
[[ $before == $(openssl x509 -in "$work/first.crt" -noout -fingerprint -sha256) ]]
listener_secret renewed
renewed=$(openssl x509 -in "$work/renewed.crt" -noout -fingerprint -sha256)
end=$((SECONDS+240))
until [[ $(served_certificate) == "$renewed" ]]; do
    if (( SECONDS >= end )); then echo 'renewed listener certificate was not served' >&2; exit 1; fi
    sleep 5
done
[[ $("${k[@]}" get pod single-node-1-0 -o jsonpath='{.metadata.uid} {.status.containerStatuses[0].restartCount}') == "$pod_uid 0" ]]
read_retained single
stop_first single; restore_first single; connect_to service/single; read_retained single
# A Helm values change is not a Raft membership change.
if "${h[@]}" upgrade single "$chart" "${values[@]}" --set replicaCount=2 --dry-run=server >"$work/resize" 2>&1; then
    echo 'unsafe resize accepted' >&2; exit 1
fi
grep -Ei 'topology|membership|resize|voter.count' "$work/resize"
stop_forward; "${h[@]}" uninstall single
# Existing clients may use plain MQTT with the same password and ACL files.
use_plain
install pair 2 false --set listeners.mqtt.enabled=true,listeners.mqtts.enabled=false
connect_to pod/pair-node-2-0; read_retained pair
stop_first pair
"${k[@]}" wait --for=condition=Ready=false pod/pair-node-2-0 --timeout=60s
restore_first pair; ready pair 2; connect_to service/pair; read_retained pair
stop_forward; "${h[@]}" uninstall pair
use_tls
install recovery 2 false --set autoRecover.enabled=true
connect_to pod/recovery-node-1-0; read_retained recovery
stop_first recovery
# Ready can still reflect the old lease, but a fresh subscription needs a
# commit. Retry the read, then publish once and require a QoS 1 ACK.
wait_retained pod/recovery-node-2-0 recovery 120
publish recovered-while-alone; read_retained recovered-while-alone
# Restore the Pod on its original PVC. Read through that Pod directly so the
# survivor cannot satisfy the assertion.
restore_first recovery
wait_retained pod/recovery-node-1-0 recovered-while-alone 30
stop_forward; "${h[@]}" uninstall recovery
install ha 2 true
# When the first broker is down, the MQTT Service must contain only the second,
# not the additional voter. Pod #2 and voter #3 must still commit writes.
stop_first ha
"${k[@]}" wait --for=jsonpath='{.subsets[0].addresses[0].targetRef.name}'=ha-node-2-0 endpoints/ha --timeout=60s
[[ $("${k[@]}" get endpoints ha -o jsonpath='{range .subsets[*].addresses[*]}{.targetRef.name}{" "}{end}') == 'ha-node-2-0 ' ]]
connect_to service/ha; publish survivor; read_retained survivor
restore_first ha; connect_to pod/ha-node-1-0; read_retained survivor
