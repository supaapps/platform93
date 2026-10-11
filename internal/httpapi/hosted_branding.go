package httpapi

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/supaapps/platform93/internal/kernel"
	"golang.org/x/text/language"
)

const installationBrandingID = "00000000-0000-0000-0000-000000000000"

func validateHostedInitiationURI(value string) error {
	if value == "" {
		return nil
	}
	u, err := url.Parse(value)
	if err != nil || len(value) > 2048 || u.Host == "" || u.User != nil || u.Fragment != "" || (u.Scheme != "https" && (u.Scheme != "http" || !loopbackHost(u.Hostname()))) {
		return errors.New("Application sign-in/start URL must use HTTPS or loopback HTTP, without credentials or a fragment.")
	}
	return nil
}

type hostedCopy struct {
	Heading string `json:"heading,omitempty"`
	Help    string `json:"help,omitempty"`
}
type hostedBranding struct {
	DisplayName     string                `json:"display_name,omitempty"`
	LogoURL         string                `json:"logo_url,omitempty"`
	FaviconURL      string                `json:"favicon_url,omitempty"`
	AccentColor     string                `json:"accent_color,omitempty"`
	BackgroundColor string                `json:"background_color,omitempty"`
	Layout          string                `json:"layout,omitempty"`
	PrivacyURL      string                `json:"privacy_url,omitempty"`
	TermsURL        string                `json:"terms_url,omitempty"`
	SupportURL      string                `json:"support_url,omitempty"`
	DefaultLocale   string                `json:"default_locale,omitempty"`
	Copy            map[string]hostedCopy `json:"copy,omitempty"`
}

func validateHostedClientPolicy(kind, ui string, grants []string, required bool) error {
	if ui != "headless" && ui != "hosted" {
		return errors.New("Authorization UI must be headless or hosted.")
	}
	if !required && kind != "confidential" {
		return errors.New("Only confidential web clients may opt out of required PKCE.")
	}
	if ui == "hosted" && (kind == "machine" || len(grants) > 0 && !stringSliceContains(grants, "authorization_code")) {
		return errors.New("Hosted authentication requires a public or confidential authorization-code client.")
	}
	return nil
}

func validateHostedBranding(b hostedBranding) error {
	for _, v := range []string{b.DisplayName} {
		if len(v) > 120 || strings.ContainsAny(v, "\x00\r\n") {
			return errors.New("Display name must be plain text of at most 120 characters.")
		}
	}
	for _, v := range []string{b.LogoURL, b.FaviconURL, b.PrivacyURL, b.TermsURL, b.SupportURL} {
		if v == "" {
			continue
		}
		u, e := url.Parse(v)
		if e != nil || len(v) > 2048 || u.Scheme != "https" || u.Host == "" || u.User != nil || strings.ContainsAny(v, "\r\n\\") {
			return errors.New("Branding URLs must be absolute HTTPS URLs without credentials.")
		}
	}
	for _, v := range []string{b.AccentColor, b.BackgroundColor} {
		if v != "" {
			if _, ok := hostedColor(v); !ok {
				return errors.New("Colors must use six-digit hexadecimal notation.")
			}
		}
	}
	if b.BackgroundColor != "" && hostedContrast(b.BackgroundColor, "#111827") < 4.5 {
		return errors.New("Background must provide readable contrast against the page text.")
	}
	if b.AccentColor != "" && hostedContrast(b.AccentColor, "#ffffff") < 4.5 {
		return errors.New("Accent color must provide at least 4.5:1 contrast against white button text.")
	}
	if b.Layout != "" && b.Layout != "centered" && b.Layout != "split" {
		return errors.New("Layout must be centered or split.")
	}
	if len(b.Copy) > 20 {
		return errors.New("At most twenty localized copies are supported.")
	}
	if b.DefaultLocale != "" {
		if _, e := language.Parse(b.DefaultLocale); e != nil {
			return errors.New("Default locale must be a valid language tag.")
		}
	}
	for tag, c := range b.Copy {
		if _, e := language.Parse(tag); e != nil || len(c.Heading) > 160 || len(c.Help) > 500 || strings.ContainsRune(c.Heading+c.Help, 0) {
			return errors.New("Localized copy must use valid language tags and bounded plain text.")
		}
	}
	return nil
}

func hostedColor(v string) ([]byte, bool) {
	if len(v) != 7 || v[0] != '#' {
		return nil, false
	}
	b, e := hex.DecodeString(v[1:])
	return b, e == nil
}
func hostedLuminance(v string) float64 {
	c, ok := hostedColor(v)
	if !ok {
		return 0
	}
	n := []float64{}
	for _, b := range c {
		x := float64(b) / 255
		if x <= 0.04045 {
			x /= 12.92
		} else {
			x = math.Pow((x+0.055)/1.055, 2.4)
		}
		n = append(n, x)
	}
	return n[0]*0.2126 + n[1]*0.7152 + n[2]*0.0722
}
func hostedContrast(a, b string) float64 {
	x, y := hostedLuminance(a), hostedLuminance(b)
	return (math.Max(x, y) + 0.05) / (math.Min(x, y) + 0.05)
}

func (s *Server) effectiveHostedBranding(ctx context.Context, appID string) (hostedBranding, error) {
	return s.effectiveHostedBrandingForScope(ctx, "application", appID)
}
func (s *Server) effectiveHostedBrandingForScope(ctx context.Context, scope, id string) (hostedBranding, error) {
	return s.resolveHostedBranding(ctx, scope, id, true)
}
func (s *Server) resolveHostedBranding(ctx context.Context, scope, id string, includeLocal bool) (hostedBranding, error) {
	b := hostedBranding{DisplayName: "Platform93", AccentColor: "#17261f", BackgroundColor: "#f6f8fa", Layout: "centered", DefaultLocale: "en", Copy: map[string]hostedCopy{"en": {Heading: "Sign in", Help: "Secure access to your application."}}}
	rows, e := s.app.DB.Query(ctx, `SELECT configuration FROM hosted_auth_branding WHERE ($4 OR NOT (scope_type=$3 AND scope_id=$2)) AND (
 (scope_type='installation' AND scope_id=$1) OR
 (scope_type='organization' AND (($3='organization' AND scope_id=$2) OR ($3='application' AND scope_id=(SELECT organization_id FROM applications WHERE id=$2)))) OR
 (scope_type='application' AND $3='application' AND scope_id=$2))
 ORDER BY CASE scope_type WHEN 'installation' THEN 0 WHEN 'organization' THEN 1 ELSE 2 END`, installationBrandingID, id, scope, includeLocal)
	if e != nil {
		return b, e
	}
	defer rows.Close()
	for rows.Next() {
		var raw []byte
		if e = rows.Scan(&raw); e != nil {
			return b, e
		}
		var merged map[string]json.RawMessage
		encoded, _ := json.Marshal(b)
		_ = json.Unmarshal(encoded, &merged)
		var override map[string]json.RawMessage
		if e = json.Unmarshal(raw, &override); e != nil {
			return b, e
		}
		for k, v := range override {
			if k == "copy" {
				var copies map[string]hostedCopy
				if err := json.Unmarshal(v, &copies); err != nil {
					return b, err
				}
				for locale, copy := range copies {
					inherited := b.Copy[locale]
					if copy.Heading != "" {
						inherited.Heading = copy.Heading
					}
					if copy.Help != "" {
						inherited.Help = copy.Help
					}
					b.Copy[locale] = inherited
				}
				v, _ = json.Marshal(b.Copy)
			}
			merged[k] = v
		}
		encoded, _ = json.Marshal(merged)
		if e = json.Unmarshal(encoded, &b); e != nil {
			return b, e
		}
	}
	return b, rows.Err()
}

func hostedBrandingScope(r *http.Request) (string, string) {
	if id := chi.URLParam(r, "application_id"); id != "" {
		return "application", id
	}
	if id := chi.URLParam(r, "organization_id"); id != "" {
		return "organization", id
	}
	return "installation", installationBrandingID
}
func (s *Server) getHostedBranding(w http.ResponseWriter, r *http.Request) {
	scope, id := hostedBrandingScope(r)
	if !s.authorizeHostedBranding(w, r, scope, id, false) {
		return
	}
	var raw []byte
	var version int64
	e := s.app.DB.QueryRow(r.Context(), `SELECT configuration,version FROM hosted_auth_branding WHERE scope_type=$1 AND scope_id=$2`, scope, id).Scan(&raw, &version)
	if errors.Is(e, pgx.ErrNoRows) {
		raw = []byte(`{}`)
		version = 0
	} else if e != nil {
		kernel.WriteProblem(w, r, 500, "branding_unavailable", "Branding settings could not be loaded.")
		return
	}
	w.Header().Set("ETag", kernel.ETag(version))
	result := map[string]any{"scope_type": scope, "configuration": json.RawMessage(raw), "version": version}
	b, err := s.effectiveHostedBrandingForScope(r.Context(), scope, id)
	if err != nil {
		kernel.WriteProblem(w, r, 500, "branding_unavailable", "Effective branding could not be loaded.")
		return
	}
	result["effective"] = b
	inherited, err := s.resolveHostedBranding(r.Context(), scope, id, false)
	if err != nil {
		kernel.WriteProblem(w, r, 500, "branding_unavailable", "Inherited branding could not be loaded.")
		return
	}
	result["inherited"] = inherited
	kernel.WriteJSON(w, 200, result)
}
func (s *Server) updateHostedBranding(w http.ResponseWriter, r *http.Request) {
	scope, id := hostedBrandingScope(r)
	if !s.authorizeHostedBranding(w, r, scope, id, true) {
		return
	}
	var b hostedBranding
	if !kernel.DecodeJSON(w, r, &b) {
		return
	}
	if e := validateHostedBranding(b); e != nil {
		kernel.WriteProblem(w, r, 422, "invalid_hosted_branding", e.Error())
		return
	}
	var version int64
	e := s.app.DB.QueryRow(r.Context(), `SELECT version FROM hosted_auth_branding WHERE scope_type=$1 AND scope_id=$2`, scope, id).Scan(&version)
	if e != nil && !errors.Is(e, pgx.ErrNoRows) {
		kernel.WriteProblem(w, r, 500, "branding_unavailable", "Branding settings could not be loaded.")
		return
	}
	if !kernel.CheckIfMatch(w, r, version) {
		return
	}
	raw, _ := json.Marshal(b)
	result, e := s.app.DB.Exec(r.Context(), `INSERT INTO hosted_auth_branding(scope_type,scope_id,configuration,version) VALUES($1,$2,$3,1)
 ON CONFLICT(scope_type,scope_id) DO UPDATE SET configuration=EXCLUDED.configuration,version=hosted_auth_branding.version+1,updated_at=now() WHERE hosted_auth_branding.version=$4`, scope, id, raw, version)
	if e != nil || result.RowsAffected() != 1 {
		kernel.WriteProblem(w, r, 409, "branding_version_conflict", "The branding settings changed. Reload before saving.")
		return
	}
	w.Header().Set("ETag", kernel.ETag(version+1))
	w.WriteHeader(204)
}

func (s *Server) authorizeHostedBranding(w http.ResponseWriter, r *http.Request, scope, id string, write bool) bool {
	provider := installationProviderScope()
	if scope == "organization" {
		provider = organizationProviderScope(id)
	} else if scope == "application" {
		provider = applicationProviderScope(id)
	}
	if !s.authorizeProviderScope(w, r, provider, false) {
		return false
	}
	if !write {
		return true
	}
	if scope == "installation" {
		role, ok := s.installationRole(r)
		if ok && (role == "owner" || role == "admin") {
			return true
		}
	} else {
		organization := id
		if scope == "application" {
			if err := s.app.DB.QueryRow(r.Context(), `SELECT organization_id FROM applications WHERE id=$1 AND deleted_at IS NULL`, id).Scan(&organization); err != nil {
				kernel.WriteProblem(w, r, 404, "application_not_found", "The application was not found.")
				return false
			}
		}
		if _, ok := s.organizationManagementRole(r, organization); ok {
			return true
		}
	}
	kernel.WriteProblem(w, r, 403, "branding_permission_required", "An owner or administrator of this scope is required to change branding.")
	return false
}
