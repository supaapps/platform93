package httpapi

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/supaapps/platform93/internal/kernel"
)

type notificationTemplateVariableDefinition struct {
	Key          string `json:"key"`
	Label        string `json:"label"`
	Description  string `json:"description"`
	Type         string `json:"type"`
	Availability string `json:"availability"`
	Sample       any    `json:"sample"`
}

func notificationTemplateVariableCatalog() []notificationTemplateVariableDefinition {
	return []notificationTemplateVariableDefinition{
		{Key: "application_id", Label: "Application ID", Description: "Immutable ID of the application sending the message.", Type: "string", Availability: "always", Sample: "01993f4e-7ae1-7000-8000-000000000001"},
		{Key: "application_name", Label: "Application name", Description: "Display name of the application sending the message.", Type: "string", Availability: "always", Sample: "Acme Cloud"},
		{Key: "application_slug", Label: "Application slug", Description: "Current human-readable application slug.", Type: "string", Availability: "always", Sample: "acme-cloud"},
		{Key: "support_name", Label: "Support name", Description: "Application support name from public configuration, falling back to the application name.", Type: "string", Availability: "always", Sample: "Acme Support"},
		{Key: "support_email", Label: "Support email", Description: "Application support email from public configuration, or an empty string when unset.", Type: "string", Availability: "always", Sample: "support@example.com"},
		{Key: "support_url", Label: "Support URL", Description: "Application support URL from public configuration, or an empty string when unset.", Type: "string", Availability: "always", Sample: "https://example.com/support"},
		{Key: "recipient_email", Label: "Recipient email", Description: "Normalized delivery address for this message.", Type: "string", Availability: "always", Sample: "ada@example.com"},
		{Key: "current_year", Label: "Current year", Description: "UTC year at the moment the notification is queued.", Type: "integer", Availability: "always", Sample: 2026},
		{Key: "message_locale", Label: "Message locale", Description: "BCP 47 locale of the template localization selected for this delivery.", Type: "string", Availability: "always", Sample: "de-CH"},
		{Key: "user_id", Label: "User ID", Description: "Application user ID. Available when the message is queued with user_id.", Type: "string", Availability: "user", Sample: "01993f4e-7ae1-7000-8000-000000000093"},
		{Key: "email", Label: "User email", Description: "Current normalized email of the selected active user.", Type: "string", Availability: "user", Sample: "ada@example.com"},
		{Key: "first_name", Label: "First name", Description: "Current first name of the selected active user.", Type: "string", Availability: "user", Sample: "Ada"},
		{Key: "last_name", Label: "Last name", Description: "Current last name of the selected active user.", Type: "string", Availability: "user", Sample: "Lovelace"},
		{Key: "full_name", Label: "Full name", Description: "Trimmed first and last name of the selected active user.", Type: "string", Availability: "user", Sample: "Ada Lovelace"},
		{Key: "username", Label: "Username", Description: "Username of the selected active user, or an empty string when unset.", Type: "string", Availability: "user", Sample: "ada"},
		{Key: "email_verified", Label: "Email verified", Description: "Whether the selected user's email is verified.", Type: "boolean", Availability: "user", Sample: true},
		{Key: "is_org_verified", Label: "Organization verified", Description: "Current organization-verification flag of the selected user.", Type: "boolean", Availability: "user", Sample: true},
		{Key: "user_locale", Label: "User locale", Description: "Preferred BCP 47 locale stored on the selected user, or an empty string when unset.", Type: "string", Availability: "user", Sample: "de-CH"},
	}
}

func builtInNotificationTemplateProperties() map[string]any {
	properties := make(map[string]any, len(notificationTemplateVariableCatalog()))
	for _, variable := range notificationTemplateVariableCatalog() {
		properties[variable.Key] = map[string]any{
			"type":         variable.Type,
			"title":        variable.Label,
			"description":  variable.Description,
			"availability": variable.Availability,
			"example":      variable.Sample,
		}
	}
	return properties
}

func effectiveNotificationTemplateProperties(schema map[string]any) map[string]any {
	properties := builtInNotificationTemplateProperties()
	custom, _ := schema["properties"].(map[string]any)
	for key, definition := range custom {
		if _, reserved := properties[key]; !reserved {
			properties[key] = definition
		}
	}
	return properties
}

func mergeNotificationTemplateVariables(supplied, resolved map[string]any) map[string]any {
	variables := make(map[string]any, len(supplied)+len(resolved))
	reserved := builtInNotificationTemplateProperties()
	for key, value := range supplied {
		if _, builtIn := reserved[key]; !builtIn {
			variables[key] = value
		}
	}
	// Only server-resolved identity values enter the final render context.
	for key, value := range resolved {
		variables[key] = value
	}
	return variables
}

func (s *Server) listNotificationTemplateVariables(w http.ResponseWriter, r *http.Request) {
	applicationID := chi.URLParam(r, "application_id")
	var exists bool
	if err := s.app.DB.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM applications WHERE id=$1 AND deleted_at IS NULL)`, applicationID).Scan(&exists); err != nil || !exists {
		kernel.WriteProblem(w, r, http.StatusNotFound, "application_not_found", "The application was not found.")
		return
	}
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"items": notificationTemplateVariableCatalog(), "next_cursor": nil})
}

func (s *Server) listInstallationNotificationTemplateVariables(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeProviderScope(w, r, installationProviderScope(), false) {
		return
	}
	items := []notificationTemplateVariableDefinition{}
	for _, variable := range notificationTemplateVariableCatalog() {
		if variable.Key == "recipient_email" || variable.Key == "current_year" {
			items = append(items, variable)
		}
	}
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": nil})
}

func (s *Server) resolveNotificationTemplateVariables(ctx context.Context, applicationID, userID, recipient string, supplied map[string]any, at time.Time) (string, map[string]any, string, error) {
	var applicationName, applicationSlug string
	var publicConfigRaw []byte
	if err := s.app.DB.QueryRow(ctx, `SELECT name,slug,public_config FROM applications WHERE id=$1 AND deleted_at IS NULL`, applicationID).Scan(&applicationName, &applicationSlug, &publicConfigRaw); err != nil {
		return "", nil, "", err
	}
	publicConfig := decodeMap(publicConfigRaw)
	resolved := map[string]any{
		"application_id":   applicationID,
		"application_name": applicationName,
		"application_slug": applicationSlug,
		"support_name":     stringWithFallback(toString(publicConfig["support_name"]), applicationName),
		"support_email":    strings.TrimSpace(toString(publicConfig["support_email"])),
		"support_url":      strings.TrimSpace(toString(publicConfig["support_url"])),
		"current_year":     at.UTC().Year(),
	}
	userLocale := ""
	if userID != "" {
		var email, firstName, lastName string
		var username *string
		var emailVerified, isOrgVerified bool
		if err := s.app.DB.QueryRow(ctx, `SELECT email,first_name,last_name,username,email_verified_at IS NOT NULL,is_org_verified,locale
FROM users WHERE id=$1 AND application_id=$2 AND status='active'`, userID, applicationID).
			Scan(&email, &firstName, &lastName, &username, &emailVerified, &isOrgVerified, &userLocale); err != nil {
			return "", nil, "", err
		}
		recipient = email
		resolved["user_id"] = userID
		resolved["email"] = kernel.NormalizeEmail(email)
		resolved["first_name"] = firstName
		resolved["last_name"] = lastName
		resolved["full_name"] = strings.TrimSpace(firstName + " " + lastName)
		resolved["username"] = ""
		if username != nil {
			resolved["username"] = *username
		}
		resolved["email_verified"] = emailVerified
		resolved["is_org_verified"] = isOrgVerified
		resolved["user_locale"] = userLocale
	}
	recipient = kernel.NormalizeEmail(recipient)
	resolved["recipient_email"] = recipient
	return recipient, mergeNotificationTemplateVariables(supplied, resolved), userLocale, nil
}

func stringWithFallback(value, fallback string) string {
	if value = strings.TrimSpace(value); value != "" {
		return value
	}
	return fallback
}

func sampleNotificationTemplateVariables(variables map[string]any) map[string]any {
	preview := make(map[string]any, len(variables)+len(notificationTemplateVariableCatalog()))
	for key, value := range variables {
		preview[key] = value
	}
	for _, variable := range notificationTemplateVariableCatalog() {
		if variable.Availability == "user" && preview[variable.Key] == nil {
			preview[variable.Key] = variable.Sample
		}
	}
	return preview
}
