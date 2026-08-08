package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
)

type applicationFlowConfig struct {
	OAuthClientID         string `json:"oauth_client_id"`
	SignInRedirectURI     string `json:"sign_in_redirect_uri"`
	InvitationRedirectURI string `json:"invitation_redirect_uri"`
}

func decodeApplicationFlowConfig(authConfig map[string]any) applicationFlowConfig {
	raw, ok := authConfig["flows"].(map[string]any)
	if !ok {
		return applicationFlowConfig{}
	}
	return applicationFlowConfig{
		OAuthClientID:         strings.TrimSpace(toString(raw["oauth_client_id"])),
		SignInRedirectURI:     strings.TrimSpace(toString(raw["sign_in_redirect_uri"])),
		InvitationRedirectURI: strings.TrimSpace(toString(raw["invitation_redirect_uri"])),
	}
}

func parseApplicationFlowConfig(raw json.RawMessage) (applicationFlowConfig, error) {
	var values map[string]json.RawMessage
	if json.Unmarshal(raw, &values) != nil {
		return applicationFlowConfig{}, errors.New("flows must be an object")
	}
	for key := range values {
		if key != "oauth_client_id" && key != "sign_in_redirect_uri" && key != "invitation_redirect_uri" {
			return applicationFlowConfig{}, errors.New("flows contains an unknown setting")
		}
	}
	var config applicationFlowConfig
	for key, target := range map[string]*string{
		"oauth_client_id": &config.OAuthClientID, "sign_in_redirect_uri": &config.SignInRedirectURI, "invitation_redirect_uri": &config.InvitationRedirectURI,
	} {
		if value, exists := values[key]; exists && json.Unmarshal(value, target) != nil {
			return applicationFlowConfig{}, errors.New("flow settings must be strings")
		}
		*target = strings.TrimSpace(*target)
	}
	if config == (applicationFlowConfig{}) {
		return config, nil
	}
	if config.OAuthClientID == "" || config.SignInRedirectURI == "" || config.InvitationRedirectURI == "" {
		return applicationFlowConfig{}, errors.New("oauth_client_id, sign_in_redirect_uri, and invitation_redirect_uri are required together")
	}
	return config, nil
}

func (s *Server) validateApplicationFlowConfig(ctx context.Context, applicationID string, config applicationFlowConfig) error {
	if config == (applicationFlowConfig{}) {
		return nil
	}
	var redirectURIs, grants []string
	var clientType string
	if err := s.app.DB.QueryRow(ctx, `SELECT client_type,redirect_uris,allowed_grants FROM clients
WHERE application_id=$1 AND client_id=$2 AND disabled_at IS NULL`, applicationID, config.OAuthClientID).Scan(&clientType, &redirectURIs, &grants); err != nil {
		return errors.New("the configured OAuth client does not exist or is disabled")
	}
	if clientType != "public" || !stringSliceContains(grants, "authorization_code") {
		return errors.New("the configured OAuth client must be public and allow authorization_code")
	}
	if !stringSliceContains(redirectURIs, config.SignInRedirectURI) {
		return errors.New("sign_in_redirect_uri must exactly match a registered OAuth client redirect URI")
	}
	signIn, signInErr := url.Parse(config.SignInRedirectURI)
	invitation, invitationErr := url.Parse(config.InvitationRedirectURI)
	if signInErr != nil || invitationErr != nil || !allowedApplicationRedirect(signIn) || !allowedApplicationRedirect(invitation) {
		return errors.New("flow redirects must be absolute HTTPS URLs; HTTP is allowed only for localhost development")
	}
	if !strings.EqualFold(signIn.Scheme, invitation.Scheme) || !strings.EqualFold(signIn.Host, invitation.Host) {
		return errors.New("invitation_redirect_uri must use the same origin as sign_in_redirect_uri")
	}
	return nil
}

func allowedApplicationRedirect(value *url.URL) bool {
	if value == nil || value.Host == "" || value.User != nil || value.Fragment != "" {
		return false
	}
	if value.Scheme == "https" {
		return true
	}
	host := strings.ToLower(value.Hostname())
	return value.Scheme == "http" && (host == "localhost" || host == "127.0.0.1" || host == "::1")
}

func (s *Server) loadApplicationFlowConfig(ctx context.Context, applicationID string) (applicationFlowConfig, error) {
	var raw []byte
	if err := s.app.DB.QueryRow(ctx, `SELECT auth_config FROM applications WHERE id=$1 AND deleted_at IS NULL`, applicationID).Scan(&raw); err != nil {
		return applicationFlowConfig{}, err
	}
	return decodeApplicationFlowConfig(decodeMap(raw)), nil
}

func stringSliceContains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
