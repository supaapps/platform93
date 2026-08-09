package httpapi

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"golang.org/x/text/language"
)

type notificationTemplateResolution struct {
	Template        notificationTemplateVersion
	RequestedLocale string
	FallbackUsed    bool
}

func normalizeNotificationLocale(value string) (string, error) {
	value = strings.TrimSpace(strings.ReplaceAll(value, "_", "-"))
	if value == "" {
		return "", nil
	}
	if len(value) > 35 {
		return "", fmt.Errorf("locale must not exceed 35 characters")
	}
	tag, err := language.Parse(value)
	if err != nil || tag == language.Und {
		return "", fmt.Errorf("locale must be a valid BCP 47 language tag such as en, de-CH, or pt-BR")
	}
	return tag.String(), nil
}

func notificationLocaleFallbacks(preferred string) []string {
	preferred, err := normalizeNotificationLocale(preferred)
	if err != nil {
		preferred = ""
	}
	values := []string{}
	seen := map[string]bool{}
	appendLocale := func(value string) {
		if value != "" && !seen[value] {
			seen[value] = true
			values = append(values, value)
		}
	}
	if preferred != "" {
		tag, _ := language.Parse(preferred)
		original := tag
		for tag != language.Und {
			appendLocale(tag.String())
			tag = tag.Parent()
		}
		base, _ := original.Base()
		appendLocale(base.String())
	}
	appendLocale("en")
	return values
}

func (s *Server) resolvePublishedNotificationTemplate(ctx context.Context, applicationID *string, key, preferredLocale string) (notificationTemplateResolution, error) {
	query := `SELECT id,key,locale,category,version,subject_template,text_template,html_template,variable_schema,status,created_at,updated_at
FROM notification_templates WHERE application_id IS NULL AND key=$1 AND status='published' ORDER BY locale`
	args := []any{key}
	if applicationID != nil {
		query = `SELECT id,key,locale,category,version,subject_template,text_template,html_template,variable_schema,status,created_at,updated_at
FROM notification_templates WHERE (application_id=$2 OR application_id IS NULL) AND key=$1 AND status='published'
ORDER BY application_id IS NOT NULL DESC,locale`
		args = append(args, *applicationID)
	}
	rows, err := s.app.DB.Query(ctx, query, args...)
	if err != nil {
		return notificationTemplateResolution{}, err
	}
	defer rows.Close()

	byLocale := map[string]notificationTemplateVersion{}
	for rows.Next() {
		template, scanErr := scanNotificationTemplate(rows)
		if scanErr != nil {
			return notificationTemplateResolution{}, scanErr
		}
		locale, normalizeErr := normalizeNotificationLocale(template.Locale)
		if normalizeErr != nil {
			locale = strings.TrimSpace(template.Locale)
		}
		if _, exists := byLocale[locale]; !exists {
			template.Locale = locale
			byLocale[locale] = template
		}
	}
	if err = rows.Err(); err != nil {
		return notificationTemplateResolution{}, err
	}
	requested, err := normalizeNotificationLocale(preferredLocale)
	if err != nil {
		return notificationTemplateResolution{}, err
	}
	for _, locale := range notificationLocaleFallbacks(requested) {
		if template, exists := byLocale[locale]; exists {
			return notificationTemplateResolution{Template: template, RequestedLocale: requested, FallbackUsed: requested != "" && locale != requested}, nil
		}
	}
	locales := make([]string, 0, len(byLocale))
	for locale := range byLocale {
		locales = append(locales, locale)
	}
	sort.Strings(locales)
	if len(locales) == 0 {
		return notificationTemplateResolution{}, fmt.Errorf("no published template for %s", key)
	}
	template := byLocale[locales[0]]
	return notificationTemplateResolution{Template: template, RequestedLocale: requested, FallbackUsed: requested != "" && template.Locale != requested}, nil
}
