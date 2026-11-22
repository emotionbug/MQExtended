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
