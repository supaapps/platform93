package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	operatorSignInTemplate      = "platform93.operator_sign_in"
	applicationSignInTemplate   = "platform93.application_sign_in"
	verifyEmailTemplate         = "platform93.verify_email"
	changeEmailTemplate         = "platform93.change_email"
	passwordResetTemplate       = "platform93.password_reset"
	organizationInviteTemplate  = "platform93.organization_invitation"
	workspaceInvitationTemplate = "platform93.workspace_invitation"
)

func accountChallengeTemplate(intent string) string {
	switch intent {
	case "verify_email":
		return verifyEmailTemplate
	case "change_email":
		return changeEmailTemplate
	case "password_reset":
		return passwordResetTemplate
	default:
		return applicationSignInTemplate
	}
}

func appendCredentialQuery(rawURL string, values map[string]string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return ""
	}
	query := parsed.Query()
	for key, value := range values {
		if value != "" {
			query.Set(key, value)
		}
	}
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func (s *Server) renderSystemNotification(ctx context.Context, applicationID *string, templateKey, recipient string, supplied map[string]any) (string, string, []byte, error) {
	variables := make(map[string]any, len(supplied)+8)
	for key, value := range supplied {
		variables[key] = value
	}
	recipient = strings.ToLower(strings.TrimSpace(recipient))
	variables["recipient_email"] = recipient
	variables["current_year"] = s.app.Now().UTC().Year()

	preferredLocale, _ := variables["user_locale"].(string)
	var err error
	if applicationID != nil {
		var applicationName, applicationSlug string
		if err = s.app.DB.QueryRow(ctx, `SELECT name,slug FROM applications WHERE id=$1 AND deleted_at IS NULL`, *applicationID).Scan(&applicationName, &applicationSlug); err == nil {
			variables["application_id"] = *applicationID
			variables["application_name"] = applicationName
			variables["application_slug"] = applicationSlug
			var recipientLocale string
			if s.app.DB.QueryRow(ctx, `SELECT locale FROM users WHERE application_id=$1 AND normalized_email=$2 AND status='active'`,
				*applicationID, recipient).Scan(&recipientLocale) == nil {
				preferredLocale = recipientLocale
				variables["user_locale"] = recipientLocale
			}
		}
	}
	if err != nil {
		return "", "", nil, fmt.Errorf("resolve system notification context %s: %w", templateKey, err)
	}
	resolution, err := s.resolvePublishedNotificationTemplate(ctx, applicationID, templateKey, preferredLocale)
	if err != nil {
		return "", "", nil, fmt.Errorf("resolve system notification template %s: %w", templateKey, err)
	}
	template := resolution.Template
	variables["message_locale"] = template.Locale
	if err = validateTemplateVariables(template.VariableSchema, variables); err != nil {
		return "", "", nil, err
	}
	subject, err := renderNotificationTemplate(template.Subject, variables, false)
	if err != nil {
		return "", "", nil, err
	}
	textBody, err := renderNotificationTemplate(template.Text, variables, false)
	if err != nil {
		return "", "", nil, err
	}
	htmlBody := ""
	if template.HTML != nil {
		htmlBody, err = renderNotificationTemplate(*template.HTML, variables, true)
		if err != nil {
			return "", "", nil, err
		}
	}
	payload, err := json.Marshal(map[string]any{
		"subject": strings.NewReplacer("\r", " ", "\n", " ").Replace(subject),
		"text":    textBody,
		"html":    htmlBody,
		"template_snapshot": map[string]any{
			"id": template.ID, "key": template.Key, "locale": template.Locale, "version": template.Version,
			"requested_locale": resolution.RequestedLocale, "fallback_used": resolution.FallbackUsed,
		},
	})
	return template.ID, template.Locale, payload, err
}

func templateTimestamp(value time.Time) string {
	return value.UTC().Format(time.RFC3339)
}
