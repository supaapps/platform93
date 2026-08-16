package httpapi

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/supaapps/platform93/internal/kernel"
	"github.com/supaapps/platform93/internal/secure"
)

func (s *Server) startAppleAuth(w http.ResponseWriter, r *http.Request) {
	s.startAppleAuthFlow(w, r, "", "")
}

func (s *Server) startAppleLink(w http.ResponseWriter, r *http.Request) {
	s.startAppleAuthFlow(w, r, "link", actor(r).ID)
}

func (s *Server) startAppleAuthFlow(w http.ResponseWriter, r *http.Request, forcedFlow, requestedBy string) {
	var request struct {
		Flow        string `json:"flow,omitempty"`
		RedirectURI string `json:"redirect_uri"`
	}
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	if forcedFlow != "" {
		request.Flow = forcedFlow
	}
	if request.Flow == "" {
		request.Flow = "automatic"
	}
	if request.Flow != "sign_in" && request.Flow != "sign_up" && request.Flow != "automatic" && request.Flow != "link" {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_apple_flow", "Apple flow must be sign_in, sign_up, automatic, or link.")
		return
	}
	if request.Flow == "link" && requestedBy == "" {
		kernel.WriteProblem(w, r, http.StatusUnauthorized, "authenticated_link_required", "Linking Apple requires a directly authenticated user session.")
		return
	}
	if err := validateRedirectURI(request.RedirectURI, true); err != nil {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "redirect_uri_not_allowed", "The redirect URI is invalid or unsafe.")
		return
	}
	applicationID := chi.URLParam(r, "application_id")
	var redirectAllowed bool
	_ = s.app.DB.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM clients WHERE application_id=$1 AND disabled_at IS NULL
AND $2=ANY(redirect_uris) AND (NOT $3 OR client_type='public'))`, applicationID, request.RedirectURI, isNativeRedirectURI(request.RedirectURI)).Scan(&redirectAllowed)
	if !redirectAllowed {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "redirect_uri_not_allowed", "The redirect URI must exactly match an enabled client redirect URI.")
		return
	}
	provider, err := s.loadEffectiveAuthProvider(r.Context(), applicationID, "apple")
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusServiceUnavailable, "apple_provider_unavailable", "Apple authentication is not configured.")
		return
	}
	state, _ := secure.RandomToken("p93_apple_state_", 32)
	nonce, _ := secure.RandomToken("", 32)
	challengeID := kernel.NewID()
	placeholder, err := s.app.Vault.Encrypt([]byte("apple"), "external-auth:"+challengeID.String())
	var requestedByUserID *string
	if requestedBy != "" {
		requestedByUserID = &requestedBy
	}
	if err == nil {
		_, err = s.app.DB.Exec(r.Context(), `INSERT INTO external_auth_challenges
(id,application_id,provider,flow,requested_by_user_id,app_redirect_uri,state_digest,nonce_digest,verifier_ciphertext,expires_at)
VALUES($1,$2,'apple',$3,$4,$5,$6,$7,$8,$9)`, challengeID, applicationID, request.Flow, requestedByUserID, request.RedirectURI,
			s.app.Vault.Digest(state), s.app.Vault.Digest(nonce), placeholder, s.app.Now().Add(10*time.Minute))
	}
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "apple_auth_start_failed", "The Apple authentication flow could not be started.")
		return
	}
	query := url.Values{
		"client_id":     {provider.ClientID},
		"redirect_uri":  {s.externalAuthCallbackURI("apple")},
		"response_type": {"code"},
		"response_mode": {"form_post"},
		"scope":         {"name email"},
		"state":         {state},
		"nonce":         {nonce},
	}
	kernel.WriteJSON(w, http.StatusCreated, map[string]any{"provider": "apple", "authorize_url": "https://appleid.apple.com/auth/authorize?" + query.Encode(), "expires_in": 600})
}

func (s *Server) appleCallback(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		kernel.WriteProblem(w, r, http.StatusBadRequest, "invalid_apple_response", "The Apple callback is invalid.")
		return
	}
	state := r.Form.Get("state")
	var challengeID, flow, appRedirect string
	var requestedBy *string
	var nonceDigest []byte
	err := s.app.DB.QueryRow(r.Context(), `UPDATE external_auth_challenges SET locked_until=now()+interval '2 minutes'
WHERE application_id=$1 AND provider='apple' AND state_digest=$2 AND consumed_at IS NULL AND expires_at>now()
AND (locked_until IS NULL OR locked_until<now()) RETURNING id,flow,requested_by_user_id,app_redirect_uri,nonce_digest`,
		chi.URLParam(r, "application_id"), s.app.Vault.Digest(state)).Scan(&challengeID, &flow, &requestedBy, &appRedirect, &nonceDigest)
	if err != nil || state == "" {
		kernel.WriteProblem(w, r, http.StatusUnauthorized, "invalid_apple_state", "The Apple authentication state is invalid or expired.")
		return
	}
	if r.Form.Get("error") != "" {
		s.releaseExternalAuthChallenge(r, challengeID)
		s.redirectExternalAuth(w, r, appRedirect, "", "provider_denied")
		return
	}
	provider, err := s.loadEffectiveAuthProvider(r.Context(), chi.URLParam(r, "application_id"), "apple")
	clientSecret, secretErr := createAppleClientSecret(provider, s.app.Now())
	if err != nil || secretErr != nil || r.Form.Get("code") == "" {
		s.releaseExternalAuthChallenge(r, challengeID)
		s.redirectExternalAuth(w, r, appRedirect, "", "provider_exchange_failed")
		return
	}
	form := url.Values{"client_id": {provider.ClientID}, "client_secret": {clientSecret}, "code": {r.Form.Get("code")}, "grant_type": {"authorization_code"}, "redirect_uri": {s.externalAuthCallbackURI("apple")}}
	request, _ := http.NewRequestWithContext(r.Context(), http.MethodPost, "https://appleid.apple.com/auth/token", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		s.releaseExternalAuthChallenge(r, challengeID)
		s.redirectExternalAuth(w, r, appRedirect, "", "provider_exchange_failed")
		return
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	var tokenResponse struct {
		IDToken string `json:"id_token"`
	}
	if response.StatusCode/100 != 2 || json.Unmarshal(body, &tokenResponse) != nil || tokenResponse.IDToken == "" {
		s.releaseExternalAuthChallenge(r, challengeID)
		s.redirectExternalAuth(w, r, appRedirect, "", "provider_exchange_failed")
		return
	}
	keySet := oidc.NewRemoteKeySet(r.Context(), "https://appleid.apple.com/auth/keys")
	verifier := oidc.NewVerifier("https://appleid.apple.com", keySet, &oidc.Config{ClientID: provider.ClientID})
	idToken, verifyErr := verifier.Verify(r.Context(), tokenResponse.IDToken)
	var claims struct {
		Subject       string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified any    `json:"email_verified"`
		Nonce         string `json:"nonce"`
	}
	if verifyErr == nil {
		verifyErr = idToken.Claims(&claims)
	}
	firstName, lastName := appleCallbackName(r.Form.Get("user"))
	if verifyErr != nil || claims.Subject == "" || !appleEmailVerified(claims.EmailVerified) || !strings.Contains(claims.Email, "@") || !equalBytes(nonceDigest, s.app.Vault.Digest(claims.Nonce)) {
		s.releaseExternalAuthChallenge(r, challengeID)
		s.redirectExternalAuth(w, r, appRedirect, "", "provider_identity_invalid")
		return
	}
	userID, completeErr := s.completeExternalIdentity(r, "apple", challengeID, flow, requestedBy, claims.Subject, claims.Email, firstName, lastName)
	if completeErr != nil {
		s.releaseExternalAuthChallenge(r, challengeID)
		s.redirectExternalAuth(w, r, appRedirect, "", completeErr.Error())
		return
	}
	s.completeExternalAuthCallback(w, r, challengeID, appRedirect, userID)
}

func (s *Server) completeExternalAuthCallback(w http.ResponseWriter, r *http.Request, challengeID, appRedirect, userID string) {
	exchangeCode, _ := secure.RandomToken("p93_external_", 32)
	exchangeID := kernel.NewID()
	tx, err := s.app.DB.Begin(r.Context())
	if err == nil {
		defer rollback(tx, r.Context())
		_, err = tx.Exec(r.Context(), `INSERT INTO external_auth_exchanges(id,application_id,user_id,credential_digest,expires_at) VALUES($1,$2,$3,$4,$5)`, exchangeID, chi.URLParam(r, "application_id"), userID, s.app.Vault.Digest(exchangeCode), s.app.Now().Add(2*time.Minute))
		if err == nil {
			_, err = tx.Exec(r.Context(), `UPDATE external_auth_challenges SET consumed_at=now(),locked_until=NULL WHERE id=$1`, challengeID)
		}
		if err == nil {
			err = tx.Commit(r.Context())
		}
	}
	if err != nil {
		s.releaseExternalAuthChallenge(r, challengeID)
		s.redirectExternalAuth(w, r, appRedirect, "", "exchange_creation_failed")
		return
	}
	s.redirectExternalAuth(w, r, appRedirect, exchangeID.String()+":"+exchangeCode, "")
}

func (s *Server) exchangeAppleAuth(w http.ResponseWriter, r *http.Request) {
	s.exchangeExternalAuth(w, r, "apple")
}

func (s *Server) exchangeExternalAuth(w http.ResponseWriter, r *http.Request, provider string) {
	var request struct {
		Exchange string `json:"exchange"`
	}
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	parts := strings.SplitN(request.Exchange, ":", 2)
	if len(parts) != 2 {
		kernel.WriteProblem(w, r, http.StatusUnauthorized, "invalid_external_exchange", "The external authentication exchange is invalid or expired.")
		return
	}
	var userID string
	err := s.app.DB.QueryRow(r.Context(), `UPDATE external_auth_exchanges SET consumed_at=now() WHERE id=$1 AND application_id=$2 AND credential_digest=$3 AND consumed_at IS NULL AND expires_at>now() RETURNING user_id`, parts[0], chi.URLParam(r, "application_id"), s.app.Vault.Digest(parts[1])).Scan(&userID)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusUnauthorized, "invalid_external_exchange", "The external authentication exchange is invalid or expired.")
		return
	}
	s.completePrimaryAuthentication(w, r, userID, []string{provider})
}

func createAppleClientSecret(config externalAuthProviderConfig, now time.Time) (string, error) {
	block, _ := pem.Decode([]byte(config.Credentials["private_key_pem"]))
	if block == nil {
		return "", fmt.Errorf("invalid apple private key")
	}
	var key *ecdsa.PrivateKey
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err == nil {
		key, _ = parsed.(*ecdsa.PrivateKey)
	} else {
		key, err = x509.ParseECPrivateKey(block.Bytes)
	}
	if err != nil || key == nil {
		return "", fmt.Errorf("invalid apple private key")
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{"iss": config.Credentials["team_id"], "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(), "aud": "https://appleid.apple.com", "sub": config.ClientID})
	token.Header["kid"] = config.Credentials["key_id"]
	return token.SignedString(key)
}

func appleEmailVerified(value any) bool {
	if verified, ok := value.(bool); ok {
		return verified
	}
	return strings.EqualFold(fmt.Sprint(value), "true")
}

func appleCallbackName(value string) (string, string) {
	var user struct {
		Name struct {
			FirstName string `json:"firstName"`
			LastName  string `json:"lastName"`
		} `json:"name"`
	}
	_ = json.Unmarshal([]byte(value), &user)
	return user.Name.FirstName, user.Name.LastName
}
