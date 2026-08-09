{{- define "platform93.name" -}}platform93{{- end -}}
{{- define "platform93.fullname" -}}{{ include "platform93.name" . }}{{- end -}}
{{- define "platform93.labels" -}}
app.kubernetes.io/name: {{ include "platform93.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}
{{- define "platform93.image" -}}{{ .Values.image.repository }}:{{ default .Chart.AppVersion .Values.image.tag }}{{- end -}}
