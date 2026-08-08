package httpapi

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/smtp"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/supaapps/platform93/internal/kernel"
)

type storedSMTPConfig struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
	TLSMode  string `json:"tls_mode"`
}

func (s *Server) getNotificationProvider(w http.ResponseWriter, r *http.Request) {
	s.getNotificationProviderForScope(w, r, applicationProviderScope(chi.URLParam(r, "application_id")))
}

func (s *Server) getInstallationNotificationProvider(w http.ResponseWriter, r *http.Request) {
	s.getNotificationProviderForScope(w, r, installationProviderScope())
}

func (s *Server) getOrganizationNotificationProvider(w http.ResponseWriter, r *http.Request) {
	s.getNotificationProviderForScope(w, r, organizationProviderScope(chi.URLParam(r, "organization_id")))
}

func (s *Server) getNotificationProviderForScope(w http.ResponseWriter, r *http.Request, scope providerScope) {
	if !s.authorizeProviderScope(w, r, scope, false) {
		return
	}
	provider, ok := s.notificationProviderResponse(r, chi.URLParam(r, "provider_id"), scope)
	if !ok {
		kernel.WriteProblem(w, r, http.StatusNotFound, "notification_provider_not_found", "The notification provider was not found.")
		return
	}
	kernel.WriteJSON(w, http.StatusOK, provider)
}

func (s *Server) updateNotificationProvider(w http.ResponseWriter, r *http.Request) {
	s.updateNotificationProviderForScope(w, r, applicationProviderScope(chi.URLParam(r, "application_id")))
}

func (s *Server) updateInstallationNotificationProvider(w http.ResponseWriter, r *http.Request) {
	s.updateNotificationProviderForScope(w, r, installationProviderScope())
}

func (s *Server) updateOrganizationNotificationProvider(w http.ResponseWriter, r *http.Request) {
	s.updateNotificationProviderForScope(w, r, organizationProviderScope(chi.URLParam(r, "organization_id")))
}

func (s *Server) updateNotificationProviderForScope(w http.ResponseWriter, r *http.Request, scope providerScope) {
	if !s.authorizeProviderScope(w, r, scope, true) {
		return
	}
	var request struct {
		Name        *string `json:"name"`
		Host        *string `json:"host"`
		Port        *int    `json:"port"`
		Username    *string `json:"username"`
		Password    *string `json:"password"`
		TLSMode     *string `json:"tls_mode"`
		SenderEmail *string `json:"sender_email"`
		SenderName  *string `json:"sender_name"`
		Inheritable *bool   `json:"inheritable"`
	}
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	providerID := chi.URLParam(r, "provider_id")
	var name, senderEmail, senderName, ciphertext string
	err := s.app.DB.QueryRow(r.Context(), `SELECT name,sender_email,sender_name,config_ciphertext FROM notification_providers
WHERE id=$1 AND application_id IS NOT DISTINCT FROM $2::uuid AND organization_id IS NOT DISTINCT FROM $3::uuid AND disabled_at IS NULL`, providerID, scope.ApplicationID, scope.OrganizationID).Scan(&name, &senderEmail, &senderName, &ciphertext)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "notification_provider_not_found", "An active notification provider was not found.")
		return
	}
	plaintext, err := s.app.Vault.Decrypt(ciphertext, "notification-provider:"+providerID)
	var config storedSMTPConfig
	if err != nil || json.Unmarshal(plaintext, &config) != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "notification_provider_secret_unavailable", "The provider credentials could not be read.")
		return
	}
	applyString(request.Name, &name)
	applyString(request.Host, &config.Host)
	if request.Port != nil {
		config.Port = *request.Port
	}
	applyString(request.Username, &config.Username)
	applyString(request.Password, &config.Password)
	applyString(request.TLSMode, &config.TLSMode)
	applyString(request.SenderEmail, &senderEmail)
	applyString(request.SenderName, &senderName)
	config.Host = strings.TrimSpace(config.Host)
	senderEmail = kernel.NormalizeEmail(senderEmail)
	configurationChanged := request.Name != nil || request.Host != nil || request.Port != nil || request.Username != nil || request.Password != nil || request.TLSMode != nil || request.SenderEmail != nil || request.SenderName != nil
	if !validSMTPSettings(name, config.Host, config.Port, config.TLSMode, senderEmail) {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_smtp_provider", "Name, host, port, sender email, and TLS mode are invalid.")
		return
	}
	encoded, _ := json.Marshal(config)
	ciphertext, err = s.app.Vault.Encrypt(encoded, "notification-provider:"+providerID)
	if err == nil {
		_, err = s.app.DB.Exec(r.Context(), `UPDATE notification_providers SET name=$1,config_ciphertext=$2,sender_email=$3,sender_name=$4,
verified_at=CASE WHEN $5 THEN NULL ELSE verified_at END,inheritable=CASE WHEN $6::boolean IS NULL THEN inheritable ELSE $6 END
WHERE id=$7 AND application_id IS NOT DISTINCT FROM $8::uuid AND organization_id IS NOT DISTINCT FROM $9::uuid`, name, ciphertext, senderEmail, senderName, configurationChanged, request.Inheritable, providerID, scope.ApplicationID, scope.OrganizationID)
	}
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "notification_provider_update_failed", "The notification provider could not be updated.")
		return
	}
	provider, _ := s.notificationProviderResponse(r, providerID, scope)
	kernel.WriteJSON(w, http.StatusOK, provider)
}

func (s *Server) verifyNotificationProvider(w http.ResponseWriter, r *http.Request) {
	s.verifyNotificationProviderForScope(w, r, applicationProviderScope(chi.URLParam(r, "application_id")))
}

func (s *Server) verifyInstallationNotificationProvider(w http.ResponseWriter, r *http.Request) {
	s.verifyNotificationProviderForScope(w, r, installationProviderScope())
}

func (s *Server) verifyOrganizationNotificationProvider(w http.ResponseWriter, r *http.Request) {
	s.verifyNotificationProviderForScope(w, r, organizationProviderScope(chi.URLParam(r, "organization_id")))
}

func (s *Server) verifyNotificationProviderForScope(w http.ResponseWriter, r *http.Request, scope providerScope) {
	if !s.authorizeProviderScope(w, r, scope, true) {
		return
	}
	providerID := chi.URLParam(r, "provider_id")
	config, err := s.loadSMTPConfig(r.Context(), providerID, scope)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "notification_provider_not_found", "An active notification provider was not found.")
		return
	}
	if err = verifySMTP(r.Context(), config); err != nil {
		kernel.WriteProblem(w, r, http.StatusBadGateway, "notification_provider_verification_failed", "SMTP connectivity or authentication verification failed.")
		return
	}
	_, err = s.app.DB.Exec(r.Context(), `UPDATE notification_providers SET verified_at=now() WHERE id=$1 AND application_id IS NOT DISTINCT FROM $2::uuid AND organization_id IS NOT DISTINCT FROM $3::uuid`, providerID, scope.ApplicationID, scope.OrganizationID)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "notification_provider_update_failed", "Verification state could not be stored.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) testNotificationProvider(w http.ResponseWriter, r *http.Request) {
	s.testNotificationProviderForScope(w, r, applicationProviderScope(chi.URLParam(r, "application_id")))
}

func (s *Server) testInstallationNotificationProvider(w http.ResponseWriter, r *http.Request) {
	s.testNotificationProviderForScope(w, r, installationProviderScope())
}

func (s *Server) testOrganizationNotificationProvider(w http.ResponseWriter, r *http.Request) {
	s.testNotificationProviderForScope(w, r, organizationProviderScope(chi.URLParam(r, "organization_id")))
}

func (s *Server) testNotificationProviderForScope(w http.ResponseWriter, r *http.Request, scope providerScope) {
	if !s.authorizeProviderScope(w, r, scope, true) {
		return
	}
	var request struct {
		Recipient string `json:"recipient,omitempty"`
	}
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	providerID := chi.URLParam(r, "provider_id")
	if request.Recipient == "" {
		_ = s.app.DB.QueryRow(r.Context(), `SELECT sender_email FROM notification_providers WHERE id=$1 AND application_id IS NOT DISTINCT FROM $2::uuid AND organization_id IS NOT DISTINCT FROM $3::uuid AND disabled_at IS NULL`, providerID, scope.ApplicationID, scope.OrganizationID).Scan(&request.Recipient)
	}
	request.Recipient = kernel.NormalizeEmail(request.Recipient)
	if !strings.Contains(request.Recipient, "@") || strings.ContainsAny(request.Recipient, "\r\n") {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_notification_recipient", "A valid test recipient is required.")
		return
	}
	id := kernel.NewID()
	payload, _ := json.Marshal(map[string]any{"subject": "Platform93 SMTP test", "text": "This message verifies the configured Platform93 SMTP delivery path.", "html": ""})
	ciphertext, err := s.app.Vault.Encrypt(payload, "notification:"+id.String())
	if err == nil {
		result, insertErr := s.app.DB.Exec(r.Context(), `INSERT INTO notifications
(id,application_id,notification_provider_id,recipient,category,payload_ciphertext,status)
SELECT $1,$2,id,$3,'security',$4,'queued' FROM notification_providers
WHERE id=$5 AND application_id IS NOT DISTINCT FROM $6::uuid AND organization_id IS NOT DISTINCT FROM $7::uuid AND disabled_at IS NULL`,
			id, scope.ApplicationID, request.Recipient, ciphertext, providerID, scope.ApplicationID, scope.OrganizationID)
		err = insertErr
		if err == nil && result.RowsAffected() != 1 {
			err = fmt.Errorf("provider unavailable")
		}
	}
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "notification_provider_not_found", "An active notification provider was not found.")
		return
	}
	kernel.WriteJSON(w, http.StatusAccepted, map[string]any{"notification_id": id, "status": "queued"})
}

func (s *Server) notificationProviderResponse(r *http.Request, providerID string, scope providerScope) (map[string]any, bool) {
	var id, provider, name, senderEmail, senderName string
	var verifiedAt, disabledAt *time.Time
	var createdAt time.Time
	var inheritable bool
	err := s.app.DB.QueryRow(r.Context(), `SELECT id,provider,name,sender_email,sender_name,verified_at,disabled_at,created_at,inheritable
FROM notification_providers WHERE id=$1 AND application_id IS NOT DISTINCT FROM $2::uuid AND organization_id IS NOT DISTINCT FROM $3::uuid`, providerID, scope.ApplicationID, scope.OrganizationID).
		Scan(&id, &provider, &name, &senderEmail, &senderName, &verifiedAt, &disabledAt, &createdAt, &inheritable)
	if err != nil {
		return nil, false
	}
	return map[string]any{"id": id, "provider": provider, "name": name, "sender_email": senderEmail, "sender_name": senderName,
		"verified_at": verifiedAt, "disabled_at": disabledAt, "created_at": createdAt, "credentials_configured": true, "scope": scope.name(), "inheritable": inheritable}, true
}

func (s *Server) loadSMTPConfig(ctx context.Context, providerID string, scope providerScope) (storedSMTPConfig, error) {
	var ciphertext string
	err := s.app.DB.QueryRow(ctx, `SELECT config_ciphertext FROM notification_providers WHERE id=$1 AND application_id IS NOT DISTINCT FROM $2::uuid AND organization_id IS NOT DISTINCT FROM $3::uuid AND disabled_at IS NULL`, providerID, scope.ApplicationID, scope.OrganizationID).Scan(&ciphertext)
	if err != nil {
		return storedSMTPConfig{}, err
	}
	plaintext, err := s.app.Vault.Decrypt(ciphertext, "notification-provider:"+providerID)
	var config storedSMTPConfig
	if err == nil {
		err = json.Unmarshal(plaintext, &config)
	}
	return config, err
}
func verifySMTP(ctx context.Context, config storedSMTPConfig) error {
	address := net.JoinHostPort(config.Host, strconv.Itoa(config.Port))
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: config.Host}
	var connection net.Conn
	var err error
	if config.TLSMode == "implicit_tls" {
		connection, err = tls.DialWithDialer(dialer, "tcp", address, tlsConfig)
	} else {
		connection, err = dialer.DialContext(ctx, "tcp", address)
	}
	if err != nil {
		return err
	}
	defer connection.Close()
	client, err := smtp.NewClient(connection, config.Host)
	if err != nil {
		return err
	}
	defer client.Close()
	if config.TLSMode == "starttls" {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return fmt.Errorf("SMTP server does not support STARTTLS")
		}
		if err = client.StartTLS(tlsConfig); err != nil {
			return err
		}
	}
	if config.Username != "" {
		if err = client.Auth(smtp.PlainAuth("", config.Username, config.Password, config.Host)); err != nil {
			return err
		}
	}
	return client.Quit()
}

func applyString(source *string, target *string) {
	if source != nil {
		*target = *source
	}
}

func validSMTPSettings(name, host string, port int, tlsMode, senderEmail string) bool {
	return strings.TrimSpace(name) != "" && strings.TrimSpace(host) != "" && port > 0 && port <= 65535 &&
		(tlsMode == "starttls" || tlsMode == "implicit_tls") && strings.Contains(senderEmail, "@") && !strings.ContainsAny(senderEmail, "\r\n")
}

type notificationTemplateVersion struct {
	ID             string
	Key            string
	Locale         string
	Category       string
	Version        int
	Subject        string
	Text           string
	HTML           *string
	VariableSchema map[string]any
	Status         string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

func (s *Server) getNotificationTemplate(w http.ResponseWriter, r *http.Request) {
	applicationID := chi.URLParam(r, "application_id")
	s.getNotificationTemplateForScope(w, r, &applicationID)
}

func (s *Server) getInstallationNotificationTemplate(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeProviderScope(w, r, installationProviderScope(), false) {
		return
	}
	s.getNotificationTemplateForScope(w, r, nil)
}

func (s *Server) getNotificationTemplateForScope(w http.ResponseWriter, r *http.Request, applicationID *string) {
	current, ownerApplicationID, systemManaged, err := s.loadScopedNotificationTemplate(r.Context(), applicationID, chi.URLParam(r, "template_id"))
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "notification_template_not_found", "The notification template was not found.")
		return
	}
	rows, err := s.app.DB.Query(r.Context(), `SELECT id,key,locale,category,version,subject_template,text_template,html_template,variable_schema,status,created_at,updated_at
FROM notification_templates WHERE application_id IS NOT DISTINCT FROM $1 AND key=$2 AND locale=$3 ORDER BY version DESC`, ownerApplicationID, current.Key, current.Locale)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "Template versions could not be loaded.")
		return
	}
	defer rows.Close()
	versions := []map[string]any{}
	for rows.Next() {
		version, scanErr := scanNotificationTemplate(rows)
		if scanErr == nil {
			versions = append(versions, notificationTemplateResponse(version))
		}
	}
	result := notificationTemplateResponse(current)
	result["versions"] = versions
	result["scope"] = "installation"
	result["inherited"] = applicationID != nil && ownerApplicationID == nil
	result["editable"] = true
	result["override_on_edit"] = applicationID != nil && ownerApplicationID == nil
	result["system_managed"] = systemManaged
	if ownerApplicationID != nil {
		result["scope"] = "application"
	}
	localeRows, localeErr := s.app.DB.Query(r.Context(), `SELECT DISTINCT locale FROM notification_templates
WHERE key=$1 AND status<>'archived' AND (application_id IS NOT DISTINCT FROM $2 OR ($2::uuid IS NOT NULL AND application_id IS NULL))
ORDER BY locale`, current.Key, applicationID)
	if localeErr == nil {
		defer localeRows.Close()
		locales := []string{}
		for localeRows.Next() {
			var locale string
			if localeRows.Scan(&locale) == nil {
				locales = append(locales, locale)
			}
		}
		result["available_locales"] = locales
	}
	kernel.WriteJSON(w, http.StatusOK, result)
}

func (s *Server) updateNotificationTemplate(w http.ResponseWriter, r *http.Request) {
	applicationID := chi.URLParam(r, "application_id")
	s.updateNotificationTemplateForScope(w, r, &applicationID)
}

func (s *Server) updateInstallationNotificationTemplate(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeProviderScope(w, r, installationProviderScope(), true) {
		return
	}
	s.updateNotificationTemplateForScope(w, r, nil)
}

func (s *Server) updateNotificationTemplateForScope(w http.ResponseWriter, r *http.Request, applicationID *string) {
	var request struct {
		Category       *string         `json:"category"`
		Subject        *string         `json:"subject_template"`
		Text           *string         `json:"text_template"`
		HTML           *string         `json:"html_template"`
		VariableSchema *map[string]any `json:"variable_schema"`
	}
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	current, _, systemManaged, err := s.loadScopedNotificationTemplate(r.Context(), applicationID, chi.URLParam(r, "template_id"))
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "notification_template_not_found", "The notification template was not found.")
		return
	}
	applyString(request.Category, &current.Category)
	applyString(request.Subject, &current.Subject)
	applyString(request.Text, &current.Text)
	if request.HTML != nil {
		if *request.HTML == "" {
			current.HTML = nil
		} else {
			current.HTML = request.HTML
		}
	}
	if request.VariableSchema != nil {
		current.VariableSchema = *request.VariableSchema
	}
	htmlTemplate := ""
	if current.HTML != nil {
		htmlTemplate = *current.HTML
	}
	if !validNotificationCategory(current.Category) || current.Subject == "" || len(current.Subject) > 500 || current.Text == "" ||
		len(current.Text) > 100_000 || len(htmlTemplate) > 200_000 || unsafeEmailHTML(htmlTemplate) {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_notification_template", "Template category, content, or HTML safety policy is invalid.")
		return
	}
	if err = validateTemplatePlaceholders(current.Subject+current.Text+htmlTemplate, current.VariableSchema); err != nil {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_template_variables", err.Error())
		return
	}
	schema, _ := json.Marshal(current.VariableSchema)
	id := kernel.NewID()
	var version int
	err = s.app.DB.QueryRow(r.Context(), `INSERT INTO notification_templates
(id,application_id,key,locale,category,version,subject_template,text_template,html_template,variable_schema,system_managed)
SELECT $1,$2,$3,$4,$5,COALESCE(max(version),0)+1,$6,$7,NULLIF($8,''),$9,$10 FROM notification_templates
WHERE application_id IS NOT DISTINCT FROM $2 AND key=$3 AND locale=$4 RETURNING version`, id, applicationID, current.Key, current.Locale, current.Category,
		current.Subject, current.Text, htmlTemplate, schema, systemManaged).Scan(&version)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusConflict, "notification_template_update_failed", "A new immutable template version could not be created.")
		return
	}
	kernel.WriteJSON(w, http.StatusCreated, map[string]any{"id": id, "key": current.Key, "locale": current.Locale, "category": current.Category, "version": version, "status": "draft"})
}

func (s *Server) previewNotificationTemplate(w http.ResponseWriter, r *http.Request) {
	applicationID := chi.URLParam(r, "application_id")
	s.previewNotificationTemplateForScope(w, r, &applicationID)
}

func (s *Server) previewInstallationNotificationTemplate(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeProviderScope(w, r, installationProviderScope(), false) {
		return
	}
	s.previewNotificationTemplateForScope(w, r, nil)
}

func (s *Server) previewNotificationTemplateForScope(w http.ResponseWriter, r *http.Request, applicationID *string) {
	var request struct {
		Variables map[string]any `json:"variables"`
		UserID    string         `json:"user_id,omitempty"`
		Recipient string         `json:"recipient,omitempty"`
	}
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	template, _, _, err := s.loadScopedNotificationTemplate(r.Context(), applicationID, chi.URLParam(r, "template_id"))
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "notification_template_not_found", "The notification template was not found.")
		return
	}
	if applicationID != nil {
		request.Recipient, request.Variables, _, err = s.resolveNotificationTemplateVariables(r.Context(), *applicationID, request.UserID, request.Recipient, request.Variables, time.Now())
		if err != nil {
			kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "notification_preview_identity_unavailable", "The application or selected active user is unavailable.")
			return
		}
	} else {
		if request.Variables == nil {
			request.Variables = map[string]any{}
		}
		request.Variables["recipient_email"] = "operator@example.com"
		request.Variables["current_year"] = time.Now().UTC().Year()
	}
	request.Variables["message_locale"] = template.Locale
	if request.UserID == "" {
		request.Variables = sampleNotificationTemplateVariables(request.Variables)
	}
	if err = validateTemplateVariables(template.VariableSchema, request.Variables); err != nil {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_template_variables", err.Error())
		return
	}
	subject, err := renderNotificationTemplate(template.Subject, request.Variables, false)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_template_variables", err.Error())
		return
	}
	textBody, err := renderNotificationTemplate(template.Text, request.Variables, false)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_template_variables", err.Error())
		return
	}
	htmlBody := ""
	if template.HTML != nil {
		htmlBody, err = renderNotificationTemplate(*template.HTML, request.Variables, true)
	}
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_template_variables", err.Error())
		return
	}
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"template_id": template.ID, "version": template.Version, "subject": strings.NewReplacer("\r", " ", "\n", " ").Replace(subject), "text": textBody, "html": htmlBody})
}

type templateRow interface {
	Scan(dest ...any) error
}

func scanNotificationTemplate(row templateRow) (notificationTemplateVersion, error) {
	var value notificationTemplateVersion
	var schema []byte
	err := row.Scan(&value.ID, &value.Key, &value.Locale, &value.Category, &value.Version, &value.Subject, &value.Text, &value.HTML,
		&schema, &value.Status, &value.CreatedAt, &value.UpdatedAt)
	value.VariableSchema = decodeMap(schema)
	return value, err
}

func (s *Server) loadNotificationTemplate(ctx context.Context, applicationID, templateID string) (notificationTemplateVersion, error) {
	value, _, _, err := s.loadScopedNotificationTemplate(ctx, &applicationID, templateID)
	return value, err
}

func (s *Server) loadScopedNotificationTemplate(ctx context.Context, applicationID *string, templateID string) (notificationTemplateVersion, *string, bool, error) {
	var ownerApplicationID *string
	var systemManaged bool
	err := s.app.DB.QueryRow(ctx, `SELECT application_id,system_managed FROM notification_templates
WHERE id=$1 AND (application_id IS NOT DISTINCT FROM $2 OR ($2::uuid IS NOT NULL AND application_id IS NULL))`, templateID, applicationID).Scan(&ownerApplicationID, &systemManaged)
	if err != nil {
		return notificationTemplateVersion{}, nil, false, err
	}
	value, err := scanNotificationTemplate(s.app.DB.QueryRow(ctx, `SELECT id,key,locale,category,version,subject_template,text_template,html_template,variable_schema,status,created_at,updated_at
FROM notification_templates WHERE id=$1`, templateID))
	return value, ownerApplicationID, systemManaged, err
}

func notificationTemplateResponse(value notificationTemplateVersion) map[string]any {
	return map[string]any{"id": value.ID, "key": value.Key, "locale": value.Locale, "category": value.Category, "version": value.Version,
		"subject_template": value.Subject, "text_template": value.Text, "html_template": value.HTML, "variable_schema": value.VariableSchema,
		"status": value.Status, "created_at": value.CreatedAt, "updated_at": value.UpdatedAt}
}
