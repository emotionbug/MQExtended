{{- define "mqextended.selectorLabels" -}}
app.kubernetes.io/name: mqextended
app.kubernetes.io/instance: {{ .Release.Name | quote }}
{{- end -}}

{{- define "mqextended.voterName" -}}
{{- printf "%s-node-%d" (index . 0) (index . 1) -}}
{{- end -}}

{{- define "mqextended.voterCount" -}}
{{- $clients := int .Values.replicaCount -}}
{{- if .Values.additionalVoter.enabled -}}
{{- if ne $clients 2 -}}
{{- fail "additionalVoter.enabled requires replicaCount=2" -}}
{{- end -}}
{{- add1 $clients -}}
{{- else -}}
{{- $clients -}}
{{- end -}}
{{- end -}}

{{/*
Enabled client listeners as a JSON array of {name, port, protocol, tls}.
Also validates the client-facing security values they depend on.
*/}}
{{- define "mqextended.listeners" -}}
{{- $enabled := list -}}
{{- $ports := dict "7000" "the Raft peer port" "9883" "the readiness API" -}}
{{- range $name := list "mqtt" "mqtts" "ws" "wss" -}}
{{- $listener := index $.Values.listeners $name -}}
{{- if $listener.enabled -}}
{{- $port := int $listener.port -}}
{{- if hasKey $ports (toString $port) -}}
{{- fail (printf "listeners.%s.port %d is already used by %s" $name $port (get $ports (toString $port))) -}}
{{- end -}}
{{- $_ := set $ports (toString $port) (printf "listeners.%s" $name) -}}
{{- $enabled = append $enabled (dict "name" $name "port" $port "protocol" (ternary "mqtt" "websockets" (hasPrefix "mqtt" $name)) "tls" (has $name (list "mqtts" "wss"))) -}}
{{- end -}}
{{- end -}}
{{- if not $enabled -}}
{{- fail "enable at least one client listener under listeners" -}}
{{- end -}}
{{- $auth := .Values.auth -}}
{{- if and (not $auth.allowAnonymous) (not $auth.passwordFile) -}}
{{- fail "auth.passwordFile is required unless auth.allowAnonymous is true: no client could authenticate" -}}
{{- end -}}
{{- if and (or $auth.passwordFile $auth.aclFile) (not $auth.existingSecret) -}}
{{- fail "auth.existingSecret is required for auth.passwordFile or auth.aclFile" -}}
{{- end -}}
{{- if and (or .Values.listeners.mqtts.enabled .Values.listeners.wss.enabled) (not .Values.mqttTLS.existingSecret) -}}
{{- fail "mqttTLS.existingSecret is required by the mqtts and wss listeners" -}}
{{- end -}}
{{- toJson $enabled -}}
{{- end -}}

{{- define "mqextended.clientTLS" -}}
{{- if or .Values.listeners.mqtts.enabled .Values.listeners.wss.enabled -}}true{{- end -}}
{{- end -}}
