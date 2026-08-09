package httpapi

import (
	"encoding/base64"
	"encoding/json"
	"html"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/supaapps/platform93/internal/kernel"
)

var notificationKeyPattern = regexp.MustCompile(`^[a-z][a-z0-9_.-]{2,100}$`)
var notificationVariablePattern = regexp.MustCompile(`{{\s*([A-Za-z][A-Za-z0-9_.-]{0,100})\s*}}`)

func (s *Server) createNotificationTemplate(w http.ResponseWriter, r *http.Request) {
	applicationID := chi.URLParam(r, "application_id")
	s.createNotificationTemplateForScope(w, r, &applicationID)
}

func (s *Server) createInstallationNotificationTemplate(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeProviderScope(w, r, installationProviderScope(), true) {
		return
	}
	s.createNotificationTemplateForScope(w, r, nil)
}

func (s *Server) createNotificationTemplateForScope(w http.ResponseWriter, r *http.Request, applicationID *string) {
	var request struct {
		Key            string         `json:"key"`
		Locale         string         `json:"locale,omitempty"`
		Category       string         `json:"category"`
		Subject        string         `json:"subject_template"`
		Text           string         `json:"text_template"`
		HTML           string         `json:"html_template,omitempty"`
		VariableSchema map[string]any `json:"variable_schema,omitempty"`
	}
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	if request.Locale == "" {
		request.Locale = "en"
	}
	normalizedLocale, err := normalizeNotificationLocale(request.Locale)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_notification_locale", err.Error())
		return
	}
	request.Locale = normalizedLocale
	if !validNotificationCategory(request.Category) || !notificationKeyPattern.MatchString(request.Key) || len(request.Locale) > 35 ||
		request.Subject == "" || len(request.Subject) > 500 || request.Text == "" || len(request.Text) > 100_000 || len(request.HTML) > 200_000 {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_notification_template", "Template key, locale, category, content, or HTML safety policy is invalid.")
		return
	}
	assetIDs, htmlErr := validateEmailHTML(request.HTML)
	if htmlErr != nil {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_notification_template_html", htmlErr.Error())
		return
	}
	if err := validateTemplatePlaceholders(request.Subject+request.Text+request.HTML, request.VariableSchema); err != nil {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_template_variables", err.Error())
		return
	}
	schema, _ := json.Marshal(request.VariableSchema)
	id := kernel.NewID()
	var version int
	tx, err := s.app.DB.Begin(r.Context())
	if err == nil {
		err = tx.QueryRow(r.Context(), `INSERT INTO notification_templates
(id,application_id,key,locale,category,version,subject_template,text_template,html_template,variable_schema)
SELECT $1,$2,$3,$4,$5,COALESCE(max(version),0)+1,$6,$7,NULLIF($8,''),$9 FROM notification_templates
WHERE application_id IS NOT DISTINCT FROM $2 AND key=$3 AND locale=$4 RETURNING version`, id, applicationID, request.Key,
			request.Locale, request.Category, request.Subject, request.Text, request.HTML, schema).Scan(&version)
	}
	if err == nil {
		err = syncNotificationTemplateAssets(r.Context(), tx, id.String(), assetIDs)
	}
	if err == nil {
		err = tx.Commit(r.Context())
	} else if tx != nil {
		_ = tx.Rollback(r.Context())
	}
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusConflict, "notification_template_creation_failed", "The template version could not be created.")
		return
	}
	kernel.WriteJSON(w, http.StatusCreated, map[string]any{"id": id, "key": request.Key, "locale": request.Locale, "category": request.Category, "version": version, "status": "draft"})
}

func (s *Server) listNotificationTemplates(w http.ResponseWriter, r *http.Request) {
	applicationID := chi.URLParam(r, "application_id")
	rows, err := s.app.DB.Query(r.Context(), `SELECT id,key,locale,category,version,subject_template,text_template,html_template,variable_schema,status,created_at,updated_at,
application_id,system_managed FROM notification_templates t WHERE application_id=$1 OR
(application_id IS NULL AND status='published' AND NOT EXISTS (
  SELECT 1 FROM notification_templates local WHERE local.application_id=$1 AND local.key=t.key AND local.locale=t.locale AND local.status='published'
)) ORDER BY key,locale,application_id NULLS FIRST,version DESC`, applicationID)
	s.writeNotificationTemplateList(w, r, rows, err, &applicationID)
}

func (s *Server) listInstallationNotificationTemplates(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeProviderScope(w, r, installationProviderScope(), false) {
		return
	}
	rows, err := s.app.DB.Query(r.Context(), `SELECT id,key,locale,category,version,subject_template,text_template,html_template,variable_schema,status,created_at,updated_at,
application_id,system_managed FROM notification_templates WHERE application_id IS NULL ORDER BY key,locale,version DESC`)
	s.writeNotificationTemplateList(w, r, rows, err, nil)
}

func (s *Server) writeNotificationTemplateList(w http.ResponseWriter, r *http.Request, rows pgx.Rows, err error, requestedApplicationID *string) {
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "Notification templates could not be loaded.")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, key, locale, category, subject, text, status string
		var htmlTemplate *string
		var applicationID *string
		var schema []byte
		var systemManaged bool
		var version int
		var createdAt, updatedAt time.Time
		if rows.Scan(&id, &key, &locale, &category, &version, &subject, &text, &htmlTemplate, &schema, &status, &createdAt, &updatedAt, &applicationID, &systemManaged) == nil {
			inherited := requestedApplicationID != nil && applicationID == nil
			scope := "installation"
			if applicationID != nil {
				scope = "application"
			}
			items = append(items, map[string]any{"id": id, "key": key, "locale": locale, "category": category, "version": version,
				"subject_template": subject, "text_template": text, "html_template": htmlTemplate, "variable_schema": decodeMap(schema), "status": status,
				"created_at": createdAt, "updated_at": updatedAt, "scope": scope, "inherited": inherited, "editable": true, "override_on_edit": inherited,
				"effective": status == "published", "system_managed": systemManaged})
		}
	}
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": nil})
}

func (s *Server) publishNotificationTemplate(w http.ResponseWriter, r *http.Request) {
	applicationID := chi.URLParam(r, "application_id")
	s.publishNotificationTemplateForScope(w, r, &applicationID)
}

func (s *Server) publishInstallationNotificationTemplate(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeProviderScope(w, r, installationProviderScope(), true) {
		return
	}
	s.publishNotificationTemplateForScope(w, r, nil)
}

func (s *Server) publishNotificationTemplateForScope(w http.ResponseWriter, r *http.Request, applicationID *string) {
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "The template could not be published.")
		return
	}
	defer tx.Rollback(r.Context())
	var key, locale string
	err = tx.QueryRow(r.Context(), `SELECT key,locale FROM notification_templates WHERE id=$1 AND application_id IS NOT DISTINCT FROM $2 AND status='draft' FOR UPDATE`,
		chi.URLParam(r, "template_id"), applicationID).Scan(&key, &locale)
	if err == nil {
		_, err = tx.Exec(r.Context(), `UPDATE notification_templates SET status='archived',updated_at=now()
WHERE application_id IS NOT DISTINCT FROM $1 AND key=$2 AND locale=$3 AND status='published'`, applicationID, key, locale)
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `UPDATE notification_templates SET status='published',updated_at=now() WHERE id=$1`, chi.URLParam(r, "template_id"))
	}
	if err == nil {
		err = tx.Commit(r.Context())
	}
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "notification_template_not_found", "A publishable template was not found.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) archiveNotificationTemplate(w http.ResponseWriter, r *http.Request) {
	applicationID := chi.URLParam(r, "application_id")
	s.archiveNotificationTemplateForScope(w, r, &applicationID)
}

func (s *Server) archiveInstallationNotificationTemplate(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeProviderScope(w, r, installationProviderScope(), true) {
		return
	}
	s.archiveNotificationTemplateForScope(w, r, nil)
}

func (s *Server) archiveNotificationTemplateForScope(w http.ResponseWriter, r *http.Request, applicationID *string) {
	result, err := s.app.DB.Exec(r.Context(), `UPDATE notification_templates SET status='archived',updated_at=now()
WHERE id=$1 AND application_id IS NOT DISTINCT FROM $2 AND status<>'archived'
AND NOT (application_id IS NULL AND system_managed AND status='published')`, chi.URLParam(r, "template_id"), applicationID)
	if err != nil || result.RowsAffected() != 1 {
		kernel.WriteProblem(w, r, http.StatusNotFound, "notification_template_not_found", "An active template was not found.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) queueNotification(w http.ResponseWriter, r *http.Request) {
	var request struct {
		TemplateKey string         `json:"template_key"`
		Locale      string         `json:"locale,omitempty"`
		Recipient   string         `json:"recipient,omitempty"`
		UserID      string         `json:"user_id,omitempty"`
		Variables   map[string]any `json:"variables,omitempty"`
		Attachments []struct {
			Filename    string `json:"filename"`
			ContentType string `json:"content_type"`
			Content     string `json:"content_base64"`
		} `json:"attachments,omitempty"`
	}
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	applicationID := chi.URLParam(r, "application_id")
	var err error
	var userLocale string
	request.Recipient, request.Variables, userLocale, err = s.resolveNotificationTemplateVariables(r.Context(), applicationID, request.UserID, request.Recipient, request.Variables, time.Now())
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "notification_recipient_unavailable", "The application or selected active user is unavailable.")
		return
	}
	if !strings.Contains(request.Recipient, "@") || strings.ContainsAny(request.Recipient, "\r\n") {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_notification_recipient", "A valid recipient is required.")
		return
	}
	preferredLocale := request.Locale
	if preferredLocale == "" {
		preferredLocale = userLocale
	} else {
		preferredLocale, err = normalizeNotificationLocale(preferredLocale)
		if err != nil {
			kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_notification_locale", err.Error())
			return
		}
	}
	resolution, err := s.resolvePublishedNotificationTemplate(r.Context(), &applicationID, request.TemplateKey, preferredLocale)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "notification_template_unavailable", "No published localization is available for this template.")
		return
	}
	template := resolution.Template
	request.Variables["message_locale"] = template.Locale
	if validateTemplateVariables(template.VariableSchema, request.Variables) != nil {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "notification_template_unavailable", "A published template and valid variables are required.")
		return
	}
	renderedSubject, err := renderNotificationTemplate(template.Subject, request.Variables, false)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_template_variables", err.Error())
		return
	}
	renderedText, _ := renderNotificationTemplate(template.Text, request.Variables, false)
	renderedHTML := ""
	if template.HTML != nil {
		renderedHTML, _ = renderNotificationTemplate(*template.HTML, request.Variables, true)
	}
	renderedSubject = strings.NewReplacer("\r", " ", "\n", " ").Replace(renderedSubject)
	id := kernel.NewID()
	payload, _ := json.Marshal(map[string]any{"subject": renderedSubject, "text": renderedText, "html": renderedHTML, "template_snapshot": map[string]any{
		"id": template.ID, "key": request.TemplateKey, "locale": template.Locale, "version": template.Version,
		"requested_locale": resolution.RequestedLocale, "fallback_used": resolution.FallbackUsed,
	}})
	ciphertext, err := s.app.Vault.Encrypt(payload, "notification:"+id.String())
	status := "queued"
	if request.UserID != "" && template.Category != "security" {
		var enabled bool
		_ = s.app.DB.QueryRow(r.Context(), `SELECT COALESCE((SELECT email_enabled FROM notification_preferences
WHERE application_id=$1 AND user_id=$2 AND category=$3),true)`, applicationID, request.UserID, template.Category).Scan(&enabled)
		if !enabled {
			status = "suppressed"
		}
	}
	tx, beginErr := s.app.DB.Begin(r.Context())
	if err == nil {
		err = beginErr
	}
	var userID any
	if request.UserID != "" {
		userID = request.UserID
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO notifications(id,application_id,template_id,user_id,recipient,category,locale,payload_ciphertext,status)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, id, applicationID, template.ID, userID, request.Recipient, template.Category, template.Locale, ciphertext, status)
	}
	totalSize := 0
	for _, attachment := range request.Attachments {
		if err != nil {
			break
		}
		content, decodeErr := base64.StdEncoding.DecodeString(attachment.Content)
		totalSize += len(content)
		if decodeErr != nil || attachment.Filename == "" || strings.ContainsAny(attachment.Filename, "\r\n/\\") || len(content) > 2<<20 || totalSize > 5<<20 {
			err = errInvalidAttachment
			break
		}
		_, err = tx.Exec(r.Context(), `INSERT INTO notification_attachments(id,notification_id,filename,content_type,content,size_bytes)
VALUES($1,$2,$3,$4,$5,$6)`, kernel.NewID(), id, attachment.Filename, safeContentType(attachment.ContentType), content, len(content))
	}
	if err == nil {
		err = tx.Commit(r.Context())
	} else if tx != nil {
		_ = tx.Rollback(r.Context())
	}
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "notification_queue_failed", "The notification or its attachments are invalid.")
		return
	}
	kernel.WriteJSON(w, http.StatusAccepted, map[string]any{
		"id": id, "status": status, "requested_locale": resolution.RequestedLocale,
		"resolved_locale": template.Locale, "fallback_used": resolution.FallbackUsed,
	})
}

func (s *Server) listMyNotificationPreferences(w http.ResponseWriter, r *http.Request) {
	rows, err := s.app.DB.Query(r.Context(), `SELECT category,email_enabled,updated_at FROM notification_preferences
WHERE application_id=$1 AND user_id=$2 ORDER BY category`, chi.URLParam(r, "application_id"), actor(r).ID)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "Notification preferences could not be loaded.")
		return
	}
	defer rows.Close()
	items := []map[string]any{{"category": "security", "email_enabled": true, "mutable": false}}
	for rows.Next() {
		var category string
		var enabled bool
		var updatedAt time.Time
		if rows.Scan(&category, &enabled, &updatedAt) == nil && category != "security" {
			items = append(items, map[string]any{"category": category, "email_enabled": enabled, "mutable": true, "updated_at": updatedAt})
		}
	}
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": nil})
}

func (s *Server) updateMyNotificationPreference(w http.ResponseWriter, r *http.Request) {
	category := chi.URLParam(r, "category")
	var request struct {
		EmailEnabled *bool `json:"email_enabled"`
	}
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	if category == "security" || !validNotificationCategory(category) || request.EmailEnabled == nil {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "immutable_security_notifications", "Security email delivery cannot be disabled.")
		return
	}
	_, err := s.app.DB.Exec(r.Context(), `INSERT INTO notification_preferences(application_id,user_id,category,email_enabled)
VALUES($1,$2,$3,$4) ON CONFLICT(application_id,user_id,category) DO UPDATE SET email_enabled=EXCLUDED.email_enabled,updated_at=now()`,
		chi.URLParam(r, "application_id"), actor(r).ID, category, *request.EmailEnabled)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "preference_update_failed", "The notification preference could not be updated.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func validNotificationCategory(value string) bool {
	return value == "security" || value == "transactional" || value == "billing" || value == "product" || value == "marketing"
}

func validateTemplatePlaceholders(template string, schema map[string]any) error {
	properties, _ := schema["properties"].(map[string]any)
	builtIns := builtInNotificationTemplateProperties()
	required, _ := schema["required"].([]any)
	for name, raw := range properties {
		if _, reserved := builtIns[name]; reserved {
			return &templateVariableError{name: name, reason: "is built in and must not be redeclared"}
		}
		definition, ok := raw.(map[string]any)
		variableType, _ := definition["type"].(string)
		if !ok || (variableType != "string" && variableType != "number" && variableType != "integer" && variableType != "boolean") {
			return &templateVariableError{name: name, reason: "has an unsupported type"}
		}
	}
	for _, raw := range required {
		name, ok := raw.(string)
		if !ok || (properties[name] == nil && builtIns[name] == nil) {
			return &templateVariableError{name: name, reason: "is required but undeclared"}
		}
	}
	effectiveProperties := effectiveNotificationTemplateProperties(schema)
	for _, match := range notificationVariablePattern.FindAllStringSubmatch(template, -1) {
		if _, exists := effectiveProperties[match[1]]; !exists {
			return &templateVariableError{name: match[1], reason: "is missing or undeclared"}
		}
	}
	return nil
}

func validateTemplateVariables(schema, variables map[string]any) error {
	properties := effectiveNotificationTemplateProperties(schema)
	required, _ := schema["required"].([]any)
	for _, raw := range required {
		name, _ := raw.(string)
		if _, exists := variables[name]; !exists {
			return &templateVariableError{name: name, reason: "is required"}
		}
	}
	for name, value := range variables {
		rawDefinition, exists := properties[name]
		if !exists {
			return &templateVariableError{name: name, reason: "is undeclared"}
		}
		definition, _ := rawDefinition.(map[string]any)
		variableType, _ := definition["type"].(string)
		if !validTemplateVariableType(variableType, value) {
			return &templateVariableError{name: name, reason: "has the wrong type"}
		}
	}
	return nil
}

func validTemplateVariableType(expected string, value any) bool {
	switch expected {
	case "string":
		_, ok := value.(string)
		return ok
	case "boolean":
		_, ok := value.(bool)
		return ok
	case "number":
		switch value.(type) {
		case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, float32, float64, json.Number:
			return true
		}
	case "integer":
		switch typed := value.(type) {
		case int, int8, int16, int32, int64, uint, uint8, uint16, uint32:
			return true
		case json.Number:
			_, err := typed.Int64()
			return err == nil
		case float64:
			return typed == float64(int64(typed))
		case float32:
			return typed == float32(int64(typed))
		}
	}
	return false
}

func renderNotificationTemplate(template string, variables map[string]any, escapeHTML bool) (string, error) {
	var renderErr error
	result := notificationVariablePattern.ReplaceAllStringFunc(template, func(token string) string {
		match := notificationVariablePattern.FindStringSubmatch(token)
		value, exists := variables[match[1]]
		if !exists {
			renderErr = &templateVariableError{name: match[1]}
			return ""
		}
		encoded := strings.TrimSpace(toString(value))
		if escapeHTML {
			encoded = html.EscapeString(encoded)
		}
		return encoded
	})
	return result, renderErr
}

type templateVariableError struct {
	name   string
	reason string
}

func (e *templateVariableError) Error() string {
	reason := e.reason
	if reason == "" {
		reason = "is invalid"
	}
	return "template variable " + e.name + " " + reason
}

var errInvalidAttachment = &templateVariableError{name: "attachment"}

func toString(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case json.Number:
		return typed.String()
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, float32, float64:
		encoded, _ := json.Marshal(typed)
		return string(encoded)
	case bool:
		if typed {
			return "true"
		}
		return "false"
	default:
		return ""
	}
}

func safeContentType(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "application/pdf" || value == "text/plain" || value == "text/csv" || value == "image/png" || value == "image/jpeg" {
		return value
	}
	return "application/octet-stream"
}
