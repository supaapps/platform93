package httpapi

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	platformauthz "github.com/supaapps/platform93/internal/authorization"
	"github.com/supaapps/platform93/internal/identity"
	"github.com/supaapps/platform93/internal/kernel"
	"github.com/supaapps/platform93/internal/secure"
)

type userResponse struct {
	ID            string         `json:"id"`
	ApplicationID string         `json:"application_id"`
	Email         string         `json:"email"`
	FirstName     string         `json:"first_name"`
	LastName      string         `json:"last_name"`
	Username      *string        `json:"username"`
	Locale        string         `json:"locale"`
	EmailVerified bool           `json:"email_verified"`
	IsOrgVerified bool           `json:"is_org_verified"`
	Status        string         `json:"status"`
	Attributes    map[string]any `json:"custom_attributes"`
	Version       int64          `json:"version"`
	CreatedAt     time.Time      `json:"created_at"`
	UpdatedAt     time.Time      `json:"updated_at"`
}

type createUserRequest struct {
	Email            string         `json:"email"`
	Password         string         `json:"password,omitempty"`
	FirstName        string         `json:"first_name,omitempty"`
	LastName         string         `json:"last_name,omitempty"`
	Username         *string        `json:"username,omitempty"`
	Locale           string         `json:"locale,omitempty"`
	EmailVerified    bool           `json:"email_verified,omitempty"`
	IsOrgVerified    bool           `json:"is_org_verified,omitempty"`
	CustomAttributes map[string]any `json:"custom_attributes,omitempty"`
}

func (s *Server) adminCreateUser(w http.ResponseWriter, r *http.Request) {
	var request createUserRequest
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	created, err := s.createUser(r, request, true)
	if err != nil {
		var limit organizationLimitError
		if errors.As(err, &limit) {
			kernel.WriteProblem(w, r, http.StatusConflict, "organization_user_limit_reached", limit.Error())
			return
		}
		kernel.WriteProblem(w, r, http.StatusConflict, "user_creation_failed", err.Error())
		return
	}
	kernel.WriteJSON(w, http.StatusCreated, created)
}

func (s *Server) adminListUsers(w http.ResponseWriter, r *http.Request) {
	applicationID := chi.URLParam(r, "application_id")
	query := strings.TrimSpace(r.URL.Query().Get("query"))
	rows, err := s.app.DB.Query(r.Context(), `SELECT id,application_id,email,first_name,last_name,username,locale,
email_verified_at IS NOT NULL,is_org_verified,status,custom_attributes,version,created_at,updated_at
FROM users WHERE application_id=$1 AND ($2='' OR normalized_email LIKE '%'||lower($2)||'%' OR first_name ILIKE '%'||$2||'%' OR last_name ILIKE '%'||$2||'%')
ORDER BY created_at DESC,id LIMIT 101`, applicationID, query)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "Users could not be loaded.")
		return
	}
	defer rows.Close()
	items := []userResponse{}
	for rows.Next() {
		if user, ok := scanUser(rows); ok {
			items = append(items, user)
		}
	}
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": nil})
}

func (s *Server) adminGetUser(w http.ResponseWriter, r *http.Request) {
	user, err := s.loadUser(r, chi.URLParam(r, "user_id"))
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "user_not_found", "The user was not found.")
		return
	}
	w.Header().Set("ETag", kernel.ETag(user.Version))
	kernel.WriteJSON(w, http.StatusOK, user)
}

func (s *Server) adminUpdateUser(w http.ResponseWriter, r *http.Request) {
	var request struct {
		FirstName        *string         `json:"first_name"`
		LastName         *string         `json:"last_name"`
		Username         *string         `json:"username"`
		Locale           *string         `json:"locale"`
		Status           *string         `json:"status"`
		EmailVerified    *bool           `json:"email_verified"`
		IsOrgVerified    *bool           `json:"is_org_verified"`
		CustomAttributes *map[string]any `json:"custom_attributes"`
		Reason           string          `json:"reason"`
	}
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	if request.Status != nil && *request.Status != "active" && *request.Status != "suspended" && *request.Status != "pending_deletion" {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_user_status", "The requested user status is invalid.")
		return
	}
	if request.Locale != nil {
		normalized, localeErr := normalizeNotificationLocale(*request.Locale)
		if localeErr != nil {
			kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_user_locale", localeErr.Error())
			return
		}
		request.Locale = &normalized
	}
	var version int64
	if err := s.app.DB.QueryRow(r.Context(), `SELECT version FROM users WHERE id=$1 AND application_id=$2`, chi.URLParam(r, "user_id"), chi.URLParam(r, "application_id")).Scan(&version); err != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "user_not_found", "The user was not found.")
		return
	}
	if !kernel.CheckIfMatch(w, r, version) {
		return
	}
	if request.Status != nil && *request.Status != "active" {
		var ownsWorkspace bool
		err := s.app.DB.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM workspaces
WHERE application_id=$1 AND owner_user_id=$2 AND deleted_at IS NULL)`, chi.URLParam(r, "application_id"), chi.URLParam(r, "user_id")).Scan(&ownsWorkspace)
		if err != nil {
			kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "Workspace ownership could not be checked.")
			return
		}
		if ownsWorkspace {
			kernel.WriteProblem(w, r, http.StatusConflict, "workspace_ownership_requires_transfer", "Transfer or archive owned workspaces before deactivating this user.")
			return
		}
	}
	attributes, _ := json.Marshal(request.CustomAttributes)
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "The user could not be updated.")
		return
	}
	defer rollback(tx, r.Context())
	result, err := tx.Exec(r.Context(), `UPDATE users SET
first_name=COALESCE($1,first_name),last_name=COALESCE($2,last_name),username=COALESCE($3,username),
locale=COALESCE($4,locale),status=COALESCE($5,status),email_verified_at=CASE WHEN $6::boolean IS NULL THEN email_verified_at WHEN $6 THEN COALESCE(email_verified_at,now()) ELSE NULL END,
is_org_verified=COALESCE($7,is_org_verified),custom_attributes=CASE WHEN $8::jsonb IS NULL THEN custom_attributes ELSE $8 END,
version=version+1,updated_at=now() WHERE id=$9 AND application_id=$10 AND version=$11`, request.FirstName, request.LastName,
		request.Username, request.Locale, request.Status, request.EmailVerified, request.IsOrgVerified, nullableJSON(request.CustomAttributes, attributes),
		chi.URLParam(r, "user_id"), chi.URLParam(r, "application_id"), version)
	if err != nil || result.RowsAffected() != 1 {
		kernel.WriteProblem(w, r, http.StatusConflict, "user_version_conflict", "The user changed concurrently.")
		return
	}
	if request.Status != nil && *request.Status != "active" {
		_, err = tx.Exec(r.Context(), "UPDATE user_sessions SET revoked_at=now() WHERE user_id=$1 AND revoked_at IS NULL", chi.URLParam(r, "user_id"))
	}
	applicationID, parseErr := uuid.Parse(chi.URLParam(r, "application_id"))
	if err == nil && parseErr == nil {
		changed := []string{}
		if request.FirstName != nil {
			changed = append(changed, "first_name")
		}
		if request.LastName != nil {
			changed = append(changed, "last_name")
		}
		if request.Username != nil {
			changed = append(changed, "username")
		}
		if request.Locale != nil {
			changed = append(changed, "locale")
		}
		if request.Status != nil {
			changed = append(changed, "status")
		}
		if request.EmailVerified != nil {
			changed = append(changed, "email_verified")
		}
		if request.IsOrgVerified != nil {
			changed = append(changed, "is_org_verified")
		}
		if request.CustomAttributes != nil {
			changed = append(changed, "custom_attributes")
		}
		_, err = s.app.Emit(r.Context(), tx, &applicationID, "user.updated", "user/"+chi.URLParam(r, "user_id"), actor(r), map[string]any{"user_id": chi.URLParam(r, "user_id"), "changed_fields": changed})
	}
	if err != nil || parseErr != nil || tx.Commit(r.Context()) != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "user_update_failed", "The user update could not be committed.")
		return
	}
	w.Header().Set("ETag", kernel.ETag(version+1))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) passwordSignUp(w http.ResponseWriter, r *http.Request) {
	var request createUserRequest
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	if !s.allowAuthAttempt(w, r, "password_signup", kernel.NormalizeEmail(request.Email), 5, 10*time.Minute) {
		return
	}
	if !s.authFlag(r, "registration_enabled") || !s.authFlag(r, "password_enabled") {
		kernel.WriteProblem(w, r, http.StatusForbidden, "password_signup_disabled", "Password registration is disabled for this application.")
		return
	}
	created, err := s.createUser(r, request, false)
	if err != nil {
		var limit organizationLimitError
		if errors.As(err, &limit) {
			kernel.WriteProblem(w, r, http.StatusConflict, "organization_user_limit_reached", limit.Error())
			return
		}
		kernel.WriteProblem(w, r, http.StatusConflict, "account_unavailable", "An account cannot be created with these details.")
		return
	}
	s.issueSession(w, r, created.ID, []string{"pwd"})
}

func (s *Server) passwordSignIn(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	if !s.allowAuthAttempt(w, r, "password_signin", kernel.NormalizeEmail(request.Email), 10, 10*time.Minute) {
		return
	}
	if !s.authFlag(r, "password_enabled") {
		kernel.WriteProblem(w, r, http.StatusForbidden, "password_login_disabled", "Password login is disabled for this application.")
		return
	}
	var userID, hash, status string
	err := s.app.DB.QueryRow(r.Context(), `SELECT id,password_hash,status FROM users
WHERE application_id=$1 AND normalized_email=$2`, chi.URLParam(r, "application_id"), kernel.NormalizeEmail(request.Email)).Scan(&userID, &hash, &status)
	if err != nil || status != "active" || !identity.VerifyPassword(hash, request.Password) {
		time.Sleep(150 * time.Millisecond)
		kernel.WriteProblem(w, r, http.StatusUnauthorized, "invalid_credentials", "Email or password is incorrect.")
		return
	}
	s.completePrimaryAuthentication(w, r, userID, []string{"pwd"})
}

func (s *Server) createUser(r *http.Request, request createUserRequest, administrative bool) (userResponse, error) {
	applicationID, err := applicationID(r)
	if err != nil {
		return userResponse{}, fmt.Errorf("invalid application identifier")
	}
	normalized := kernel.NormalizeEmail(request.Email)
	if normalized == "" || !strings.Contains(normalized, "@") {
		return userResponse{}, fmt.Errorf("a valid email is required")
	}
	request.Locale, err = normalizeNotificationLocale(request.Locale)
	if err != nil {
		return userResponse{}, err
	}
	var passwordHash *string
	if request.Password != "" {
		hash, err := identity.HashPassword(request.Password)
		if err != nil {
			return userResponse{}, err
		}
		passwordHash = &hash
	}
	if !administrative {
		request.EmailVerified = false
		request.IsOrgVerified = false
	}
	attributes, _ := json.Marshal(request.CustomAttributes)
	id := kernel.NewID()
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		return userResponse{}, err
	}
	defer rollback(tx, r.Context())
	if err = enforceUserLimit(r.Context(), tx, applicationID.String()); err != nil {
		return userResponse{}, err
	}
	_, err = tx.Exec(r.Context(), `INSERT INTO users
(id,application_id,email,normalized_email,first_name,last_name,username,locale,password_hash,email_verified_at,is_org_verified,custom_attributes)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,CASE WHEN $10 THEN now() END,$11,$12)`, id, applicationID, request.Email,
		normalized, request.FirstName, request.LastName, request.Username, request.Locale, passwordHash, request.EmailVerified,
		request.IsOrgVerified, attributes)
	if err == nil {
		_, err = s.app.Emit(r.Context(), tx, &applicationID, "user.created", "user/"+id.String(), actor(r), map[string]any{"user_id": id, "email_verified": request.EmailVerified, "is_org_verified": request.IsOrgVerified})
	}
	if err != nil {
		return userResponse{}, fmt.Errorf("an account with this email already exists")
	}
	if err = tx.Commit(r.Context()); err != nil {
		return userResponse{}, err
	}
	return s.loadUser(r, id.String())
}

func (s *Server) emailStart(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Email       string `json:"email"`
		Intent      string `json:"intent"`
		Delivery    string `json:"delivery"`
		RedirectURI string `json:"redirect_uri,omitempty"`
	}
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	if !s.authFlag(r, "passwordless_enabled") {
		kernel.WriteProblem(w, r, http.StatusForbidden, "passwordless_disabled", "Passwordless login is disabled for this application.")
		return
	}
	if request.Intent != "sign_in" && request.Intent != "sign_up" && request.Intent != "automatic" {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_auth_intent", "Intent must be sign_in, sign_up, or automatic.")
		return
	}
	if request.Intent == "sign_up" && !s.registrationEnabled(r) {
		kernel.WriteProblem(w, r, http.StatusForbidden, "registration_invite_only", "Public registration is disabled. An administrator must create the account first.")
		return
	}
	if request.Delivery == "" {
		request.Delivery = "both"
	}
	if request.Delivery != "code" && request.Delivery != "link" && request.Delivery != "both" {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_delivery", "Delivery must be code, link, or both.")
		return
	}
	normalizedEmail := kernel.NormalizeEmail(request.Email)
	if !strings.Contains(normalizedEmail, "@") {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_email", "A valid email address is required.")
		return
	}
	if !s.allowAuthAttempt(w, r, "email_start", normalizedEmail, 5, 10*time.Minute) {
		return
	}
	if request.RedirectURI == "" {
		if flows, flowErr := s.loadApplicationFlowConfig(r.Context(), chi.URLParam(r, "application_id")); flowErr == nil {
			request.RedirectURI = flows.SignInRedirectURI
		}
	}
	if request.RedirectURI != "" {
		var redirectAllowed bool
		err := s.app.DB.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM clients
WHERE application_id=$1 AND disabled_at IS NULL AND $2=ANY(redirect_uris))`, chi.URLParam(r, "application_id"), request.RedirectURI).Scan(&redirectAllowed)
		if err != nil || !redirectAllowed {
			kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "redirect_uri_not_allowed", "The redirect URI is not registered for this application.")
			return
		}
	}
	code := randomCode(8)
	link, _ := secure.RandomToken("p93_link_", 32)
	id := kernel.NewID()
	applicationID, err := applicationID(r)
	if err != nil {
		return
	}
	var codeDigest, linkDigest []byte
	if request.Delivery != "link" {
		codeDigest = s.app.Vault.Digest(code)
	}
	if request.Delivery != "code" {
		linkDigest = s.app.Vault.Digest(link)
	}
	deliveredCode, magicLink := code, ""
	if request.Delivery == "link" {
		deliveredCode = ""
	}
	if request.Delivery != "code" && request.RedirectURI != "" {
		magicLink = appendCredentialQuery(request.RedirectURI, map[string]string{"challenge_id": id.String(), "link_token": link, "platform93_flow": "email"})
	}
	applicationIDString := applicationID.String()
	templateID, templateLocale, payload, renderErr := s.renderSystemNotification(r.Context(), &applicationIDString, applicationSignInTemplate, request.Email, map[string]any{
		"code": deliveredCode, "magic_link": magicLink, "expires_minutes": 10, "intent": request.Intent,
	})
	if renderErr != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "challenge_template_unavailable", "The application sign-in email template is unavailable or invalid.")
		return
	}
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "The login challenge could not be queued.")
		return
	}
	defer rollback(tx, r.Context())
	_, err = tx.Exec(r.Context(), `INSERT INTO login_challenges
(id,application_id,normalized_email,intent,code_digest,link_digest,redirect_uri,expires_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, id, applicationID, normalizedEmail, request.Intent,
		codeDigest, linkDigest, request.RedirectURI, s.app.Now().Add(10*time.Minute))
	if err == nil {
		ciphertext, encryptErr := s.app.Vault.Encrypt(payload, "notification:"+id.String())
		if encryptErr == nil {
			_, err = tx.Exec(r.Context(), `INSERT INTO notifications
(id,application_id,template_id,recipient,locale,payload_ciphertext,status) VALUES ($1,$2,$3,$4,$5,$6,'queued')`, id, applicationID, templateID, request.Email, templateLocale, ciphertext)
		} else {
			err = encryptErr
		}
	}
	if err != nil || tx.Commit(r.Context()) != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "challenge_delivery_failed", "The login challenge could not be queued.")
		return
	}
	kernel.WriteJSON(w, http.StatusAccepted, map[string]any{"challenge_id": id, "expires_in": 600})
}

func (s *Server) emailVerify(w http.ResponseWriter, r *http.Request) {
	if !s.authFlag(r, "passwordless_enabled") {
		kernel.WriteProblem(w, r, http.StatusForbidden, "passwordless_disabled", "Passwordless login is disabled for this application.")
		return
	}
	var request struct {
		ChallengeID string `json:"challenge_id"`
		Code        string `json:"code,omitempty"`
		LinkToken   string `json:"link_token,omitempty"`
	}
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	if !s.allowAuthAttempt(w, r, "email_verify", request.ChallengeID, 10, 10*time.Minute) {
		return
	}
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		kernel.WriteProblem(w, r, 500, "database_error", "The challenge could not be verified.")
		return
	}
	defer rollback(tx, r.Context())
	var normalized, intent string
	var codeDigest, linkDigest []byte
	var attempts int
	err = tx.QueryRow(r.Context(), `SELECT normalized_email,intent,code_digest,link_digest,attempts FROM login_challenges
WHERE id=$1 AND application_id=$2 AND consumed_at IS NULL AND expires_at>now() FOR UPDATE`, request.ChallengeID, chi.URLParam(r, "application_id")).Scan(&normalized, &intent, &codeDigest, &linkDigest, &attempts)
	valid := err == nil && attempts < 8 && ((request.Code != "" && equalBytes(codeDigest, s.app.Vault.Digest(strings.ToUpper(request.Code)))) || (request.LinkToken != "" && equalBytes(linkDigest, s.app.Vault.Digest(request.LinkToken))))
	if !valid {
		if err == nil {
			_, _ = tx.Exec(r.Context(), "UPDATE login_challenges SET attempts=attempts+1 WHERE id=$1", request.ChallengeID)
			_ = tx.Commit(r.Context())
		}
		kernel.WriteProblem(w, r, http.StatusUnauthorized, "invalid_challenge", "The login challenge is invalid or expired.")
		return
	}
	var userID string
	err = tx.QueryRow(r.Context(), "SELECT id FROM users WHERE application_id=$1 AND normalized_email=$2", chi.URLParam(r, "application_id"), normalized).Scan(&userID)
	if err != nil && (intent == "sign_up" || intent == "automatic") && s.registrationEnabled(r) {
		userID = kernel.NewID().String()
		_, err = tx.Exec(r.Context(), `INSERT INTO users (id,application_id,email,normalized_email,email_verified_at)
VALUES ($1,$2,$3,$3,now())`, userID, chi.URLParam(r, "application_id"), normalized)
	}
	if err != nil || intent == "sign_up" && userID == "" {
		kernel.WriteProblem(w, r, http.StatusUnauthorized, "account_unavailable", "The account is unavailable for this flow.")
		return
	}
	_, err = tx.Exec(r.Context(), "UPDATE login_challenges SET consumed_at=now() WHERE id=$1", request.ChallengeID)
	if err == nil {
		_, err = tx.Exec(r.Context(), "UPDATE users SET email_verified_at=COALESCE(email_verified_at,now()),updated_at=now() WHERE id=$1", userID)
	}
	if err != nil || tx.Commit(r.Context()) != nil {
		kernel.WriteProblem(w, r, 500, "challenge_completion_failed", "The challenge could not be completed.")
		return
	}
	s.completePrimaryAuthentication(w, r, userID, []string{"email"})
}

func (s *Server) issueSession(w http.ResponseWriter, r *http.Request, userID string, amr []string) {
	applicationID, err := applicationID(r)
	if err != nil {
		kernel.WriteProblem(w, r, 400, "invalid_application_id", "The application identifier is invalid.")
		return
	}
	var email, locale, status string
	var verified, orgVerified bool
	err = s.app.DB.QueryRow(r.Context(), `SELECT email,locale,email_verified_at IS NOT NULL,is_org_verified,status
FROM users WHERE id=$1 AND application_id=$2`, userID, applicationID).Scan(&email, &locale, &verified, &orgVerified, &status)
	if err != nil || status != "active" {
		kernel.WriteProblem(w, r, 401, "account_unavailable", "The account is unavailable.")
		return
	}
	access, err := s.userEffectiveAccess(r, applicationID, userID)
	if err != nil {
		kernel.WriteProblem(w, r, 500, "authorization_data_invalid", "The account authorization data is invalid and no access token was issued.")
		return
	}
	refresh, _ := secure.RandomToken("p93_refresh_", 32)
	sessionID := kernel.NewID()
	expires := s.app.Now().Add(30 * 24 * time.Hour)
	mfaAuthenticated := containsString(amr, "totp") || containsString(amr, "webauthn") || containsString(amr, "recovery_code")
	_, err = s.app.DB.Exec(r.Context(), `INSERT INTO user_sessions
(id,application_id,user_id,refresh_digest,user_agent,authenticated_at,mfa_authenticated_at,amr,expires_at)
VALUES ($1,$2,$3,$4,$5,now(),CASE WHEN $6 THEN now() END,$7,$8)`,
		sessionID, applicationID, userID, s.app.Vault.Digest(refresh), truncate(r.UserAgent(), 512), mfaAuthenticated, amr, expires)
	if err != nil {
		kernel.WriteProblem(w, r, 500, "session_creation_failed", "The session could not be created.")
		return
	}
	kid, privateKey, err := s.app.ActiveSigningKey(r.Context())
	if err != nil {
		kernel.WriteProblem(w, r, 500, "signing_key_unavailable", "No active signing key is available.")
		return
	}
	now := s.app.Now()
	customClaims, err := s.customClaimsForUser(r.Context(), applicationID.String(), userID)
	if err != nil {
		kernel.WriteProblem(w, r, 500, "custom_claims_unavailable", "The configured custom token claims could not be issued.")
		return
	}
	accessToken, err := identity.Sign(privateKey, kid, identity.Claims{Issuer: s.app.Issuer(), Subject: userID, Audience: []string{s.app.ApplicationAudience(applicationID)},
		ExpiresAt: now.Add(5 * time.Minute).Unix(), IssuedAt: now.Unix(), NotBefore: now.Add(-5 * time.Second).Unix(), JWTID: kernel.NewID().String(),
		SessionID: sessionID.String(), ApplicationID: applicationID.String(), TokenKind: "access", ActorType: "user", Scope: strings.Join(access.Scopes, " "), Roles: access.Roles, Email: email,
		Locale: locale, EmailVerified: verified, IsOrgVerified: orgVerified, CustomClaims: customClaims, AMR: amr})
	if err != nil {
		kernel.WriteProblem(w, r, 500, "token_creation_failed", "The access token could not be created.")
		return
	}
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"access_token": accessToken, "refresh_token": refresh, "token_type": "Bearer", "expires_in": 300, "refresh_expires_at": expires})
}

func (s *Server) refreshToken(w http.ResponseWriter, r *http.Request) {
	var request struct {
		RefreshToken string `json:"refresh_token"`
	}
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	applicationID, err := applicationID(r)
	if err != nil {
		return
	}
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		kernel.WriteProblem(w, r, 500, "database_error", "The session could not be refreshed.")
		return
	}
	defer rollback(tx, r.Context())
	var sessionID, userID string
	digest := s.app.Vault.Digest(request.RefreshToken)
	err = tx.QueryRow(r.Context(), `SELECT s.id,s.user_id FROM user_sessions s JOIN users u ON u.id=s.user_id
WHERE s.application_id=$1 AND s.refresh_digest=$2 AND s.revoked_at IS NULL AND s.expires_at>now()
AND u.status='active' FOR UPDATE OF s`, applicationID, digest).Scan(&sessionID, &userID)
	if err != nil {
		var replayedUserID string
		replayErr := tx.QueryRow(r.Context(), `SELECT user_id FROM user_sessions WHERE application_id=$1
AND previous_refresh_digest=$2 AND revoked_at IS NULL FOR UPDATE`, applicationID, digest).Scan(&replayedUserID)
		if replayErr == nil {
			_, _ = tx.Exec(r.Context(), "UPDATE user_sessions SET revoked_at=now() WHERE application_id=$1 AND user_id=$2 AND revoked_at IS NULL", applicationID, replayedUserID)
			_ = tx.Commit(r.Context())
			kernel.WriteProblem(w, r, 401, "refresh_token_reuse_detected", "Refresh token reuse was detected and all user sessions were revoked.")
			return
		}
		kernel.WriteProblem(w, r, 401, "invalid_refresh_token", "The refresh token is invalid or has been reused.")
		return
	}
	newRefresh, _ := secure.RandomToken("p93_refresh_", 32)
	_, err = tx.Exec(r.Context(), `UPDATE user_sessions SET previous_refresh_digest=refresh_digest,
previous_valid_until=now()+interval '30 seconds',refresh_digest=$1,last_used_at=now() WHERE id=$2`, s.app.Vault.Digest(newRefresh), sessionID)
	if err != nil || tx.Commit(r.Context()) != nil {
		kernel.WriteProblem(w, r, 500, "refresh_failed", "The session could not be refreshed.")
		return
	}
	s.issueAccessForExistingSession(w, r, applicationID, userID, sessionID, newRefresh)
}

func (s *Server) issueAccessForExistingSession(w http.ResponseWriter, r *http.Request, applicationID uuid.UUID, userID, sessionID, refresh string) {
	var email, locale string
	var verified, orgVerified bool
	var amr []string
	err := s.app.DB.QueryRow(r.Context(), `SELECT email,locale,email_verified_at IS NOT NULL,is_org_verified
FROM users WHERE id=$1 AND application_id=$2 AND status='active'`, userID, applicationID).Scan(&email, &locale, &verified, &orgVerified)
	if err != nil {
		kernel.WriteProblem(w, r, 401, "account_unavailable", "The account is unavailable.")
		return
	}
	_ = s.app.DB.QueryRow(r.Context(), `SELECT amr FROM user_sessions WHERE id=$1 AND user_id=$2`, sessionID, userID).Scan(&amr)
	kid, privateKey, err := s.app.ActiveSigningKey(r.Context())
	if err != nil {
		kernel.WriteProblem(w, r, 500, "signing_key_unavailable", "No active signing key is available.")
		return
	}
	now := s.app.Now()
	customClaims, err := s.customClaimsForUser(r.Context(), applicationID.String(), userID)
	if err != nil {
		kernel.WriteProblem(w, r, 500, "custom_claims_unavailable", "The configured custom token claims could not be issued.")
		return
	}
	tokenAMR := amr
	if refresh != "" {
		tokenAMR = append(append([]string{}, amr...), "refresh_token")
	}
	effective, err := s.userEffectiveAccess(r, applicationID, userID)
	if err != nil {
		kernel.WriteProblem(w, r, 500, "authorization_data_invalid", "The account authorization data is invalid and no access token was issued.")
		return
	}
	access, err := identity.Sign(privateKey, kid, identity.Claims{Issuer: s.app.Issuer(), Subject: userID, Audience: []string{s.app.ApplicationAudience(applicationID)}, ExpiresAt: now.Add(5 * time.Minute).Unix(), IssuedAt: now.Unix(), NotBefore: now.Add(-5 * time.Second).Unix(), JWTID: kernel.NewID().String(), SessionID: sessionID, ApplicationID: applicationID.String(), TokenKind: "access", ActorType: "user", Scope: strings.Join(effective.Scopes, " "), Roles: effective.Roles, Email: email, Locale: locale, EmailVerified: verified, IsOrgVerified: orgVerified, CustomClaims: customClaims, AMR: tokenAMR})
	if err != nil {
		kernel.WriteProblem(w, r, 500, "token_creation_failed", "The access token could not be created.")
		return
	}
	response := map[string]any{"access_token": access, "token_type": "Bearer", "expires_in": 300}
	if refresh != "" {
		response["refresh_token"] = refresh
	}
	kernel.WriteJSON(w, 200, response)
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	user, err := s.loadUser(r, actor(r).ID)
	if err != nil {
		kernel.WriteProblem(w, r, 404, "user_not_found", "The user was not found.")
		return
	}
	kernel.WriteJSON(w, 200, user)
}

func (s *Server) listMySessions(w http.ResponseWriter, r *http.Request) {
	rows, err := s.app.DB.Query(r.Context(), `SELECT id,user_agent,expires_at,last_used_at,revoked_at,created_at
FROM user_sessions WHERE application_id=$1 AND user_id=$2 ORDER BY created_at DESC`, chi.URLParam(r, "application_id"), actor(r).ID)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "Sessions could not be loaded.")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id string
		var expires, created time.Time
		var userAgent *string
		var lastUsed, revoked *time.Time
		if rows.Scan(&id, &userAgent, &expires, &lastUsed, &revoked, &created) == nil {
			items = append(items, map[string]any{"id": id, "user_agent": userAgent, "expires_at": expires, "last_used_at": lastUsed, "revoked_at": revoked, "created_at": created, "current": id == actor(r).SessionID})
		}
	}
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": nil})
}

func (s *Server) revokeMySession(w http.ResponseWriter, r *http.Request) {
	result, err := s.app.DB.Exec(r.Context(), `UPDATE user_sessions SET revoked_at=COALESCE(revoked_at,now())
WHERE id=$1 AND application_id=$2 AND user_id=$3`, chi.URLParam(r, "session_id"), chi.URLParam(r, "application_id"), actor(r).ID)
	if err != nil || result.RowsAffected() != 1 {
		kernel.WriteProblem(w, r, http.StatusNotFound, "session_not_found", "The session was not found.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) logoutAll(w http.ResponseWriter, r *http.Request) {
	_, err := s.app.DB.Exec(r.Context(), `UPDATE user_sessions SET revoked_at=COALESCE(revoked_at,now())
WHERE application_id=$1 AND user_id=$2`, chi.URLParam(r, "application_id"), actor(r).ID)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "session_revocation_failed", "Sessions could not be revoked.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) updateMe(w http.ResponseWriter, r *http.Request) {
	var request struct {
		FirstName *string `json:"first_name"`
		LastName  *string `json:"last_name"`
		Username  *string `json:"username"`
		Locale    *string `json:"locale"`
	}
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	if request.Locale != nil {
		normalized, err := normalizeNotificationLocale(*request.Locale)
		if err != nil {
			kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_user_locale", err.Error())
			return
		}
		request.Locale = &normalized
	}
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		kernel.WriteProblem(w, r, 500, "database_error", "The profile could not be updated.")
		return
	}
	defer rollback(tx, r.Context())
	_, err = tx.Exec(r.Context(), `UPDATE users SET first_name=COALESCE($1,first_name),last_name=COALESCE($2,last_name),username=COALESCE($3,username),locale=COALESCE($4,locale),version=version+1,updated_at=now()
WHERE id=$5 AND application_id=$6`, request.FirstName, request.LastName, request.Username, request.Locale, actor(r).ID, chi.URLParam(r, "application_id"))
	applicationID, parseErr := uuid.Parse(chi.URLParam(r, "application_id"))
	if err == nil && parseErr == nil {
		changed := []string{}
		if request.FirstName != nil {
			changed = append(changed, "first_name")
		}
		if request.LastName != nil {
			changed = append(changed, "last_name")
		}
		if request.Username != nil {
			changed = append(changed, "username")
		}
		if request.Locale != nil {
			changed = append(changed, "locale")
		}
		_, err = s.app.Emit(r.Context(), tx, &applicationID, "user.updated", "user/"+actor(r).ID, actor(r), map[string]any{"user_id": actor(r).ID, "changed_fields": changed})
	}
	if err != nil || parseErr != nil || tx.Commit(r.Context()) != nil {
		kernel.WriteProblem(w, r, 500, "profile_update_failed", "The profile could not be updated.")
		return
	}
	w.WriteHeader(204)
}

func (s *Server) listAPIKeys(w http.ResponseWriter, r *http.Request) {
	if !s.personalKeysEnabled(r) {
		kernel.WriteProblem(w, r, 403, "personal_api_keys_disabled", "Personal API keys are disabled for this application.")
		return
	}
	rows, err := s.app.DB.Query(r.Context(), `SELECT id,label,token_prefix,scopes,expires_at,last_used_at,revoked_at,created_at
FROM personal_api_keys WHERE application_id=$1 AND user_id=$2 ORDER BY created_at DESC`, chi.URLParam(r, "application_id"), actor(r).ID)
	if err != nil {
		kernel.WriteProblem(w, r, 500, "database_error", "API keys could not be loaded.")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, prefix string
		var expires, created time.Time
		var label *string
		var lastUsed, revoked *time.Time
		var scopes []string
		if rows.Scan(&id, &label, &prefix, &scopes, &expires, &lastUsed, &revoked, &created) == nil {
			items = append(items, map[string]any{"id": id, "label": label, "token_prefix": prefix, "scopes": scopes, "expires_at": expires, "last_used_at": lastUsed, "revoked_at": revoked, "created_at": created})
		}
	}
	kernel.WriteJSON(w, 200, map[string]any{"items": items, "next_cursor": nil})
}

func (s *Server) createAPIKey(w http.ResponseWriter, r *http.Request) {
	if !s.personalKeysEnabled(r) {
		kernel.WriteProblem(w, r, 403, "personal_api_keys_disabled", "Personal API keys are disabled for this application.")
		return
	}
	var request struct {
		Label         string   `json:"label"`
		ExpiresInDays int      `json:"expires_in_days"`
		Scopes        []string `json:"scopes"`
	}
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	if request.ExpiresInDays == 0 {
		request.ExpiresInDays = 365
	}
	if request.ExpiresInDays < 1 || request.ExpiresInDays > 366 {
		kernel.WriteProblem(w, r, 422, "invalid_api_key_expiry", "Expiry must be between 1 and 366 days.")
		return
	}
	request.Scopes = uniqueStrings(request.Scopes)
	applicationID, err := uuid.Parse(chi.URLParam(r, "application_id"))
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusBadRequest, "invalid_application_id", "The application identifier is invalid.")
		return
	}
	if len(request.Scopes) > 200 || platformauthz.ValidateScopeValues(request.Scopes, applicationID.String()) != nil {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_api_key_scopes", "API key scopes must be unique canonical permissions from this application and cannot contain whitespace or malformed paths.")
		return
	}
	liveScopes := s.permissions(r, applicationID, actor(r).ID)
	for _, requested := range request.Scopes {
		if !containsAllowedScope(liveScopes, requested) {
			kernel.WriteProblem(w, r, http.StatusForbidden, "api_key_scope_escalation", "API key scopes must reduce the user's current effective access.")
			return
		}
	}
	token, _ := secure.RandomToken("p93_pat_", 32)
	id := kernel.NewID()
	prefix := truncate(token, 16)
	expires := s.app.Now().Add(time.Duration(request.ExpiresInDays) * 24 * time.Hour)
	_, err = s.app.DB.Exec(r.Context(), `INSERT INTO personal_api_keys
(id,application_id,user_id,label,token_prefix,token_digest,scopes,expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, id, chi.URLParam(r, "application_id"), actor(r).ID, request.Label, prefix, s.app.Vault.Digest(token), request.Scopes, expires)
	if err != nil {
		kernel.WriteProblem(w, r, 500, "api_key_creation_failed", "The API key could not be created.")
		return
	}
	kernel.WriteJSON(w, 201, map[string]any{"token": token, "api_key": map[string]any{"id": id, "label": request.Label, "token_prefix": prefix, "scopes": request.Scopes, "expires_at": expires}})
}

func (s *Server) revokeAPIKey(w http.ResponseWriter, r *http.Request) {
	result, err := s.app.DB.Exec(r.Context(), `UPDATE personal_api_keys SET revoked_at=now() WHERE id=$1 AND user_id=$2 AND application_id=$3 AND revoked_at IS NULL`, chi.URLParam(r, "key_id"), actor(r).ID, chi.URLParam(r, "application_id"))
	if err != nil || result.RowsAffected() != 1 {
		kernel.WriteProblem(w, r, 404, "api_key_not_found", "The API key was not found.")
		return
	}
	w.WriteHeader(204)
}

func (s *Server) createAddress(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Name        string  `json:"name"`
		Line1       string  `json:"line1"`
		Line2       string  `json:"line2"`
		City        string  `json:"city"`
		Region      string  `json:"region"`
		PostalCode  string  `json:"postal_code"`
		CountryCode string  `json:"country_code"`
		TaxID       *string `json:"tax_id"`
		Active      bool    `json:"active"`
	}
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	if request.Line1 == "" || request.City == "" || request.PostalCode == "" || len(request.CountryCode) != 2 {
		kernel.WriteProblem(w, r, 422, "invalid_address", "Required address fields are missing.")
		return
	}
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		return
	}
	defer rollback(tx, r.Context())
	subjectType, subjectID, ok := s.addressSubject(w, r)
	if !ok {
		return
	}
	profileID, err := s.ensureBillingProfile(r.Context(), tx, chi.URLParam(r, "application_id"), subjectType, subjectID)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "billing_profile_not_found", "The billing profile was not found.")
		return
	}
	if request.Active {
		_, err = tx.Exec(r.Context(), "UPDATE addresses SET is_active=false,version=version+1,updated_at=now() WHERE billing_profile_id=$1", profileID)
	}
	id := kernel.NewID()
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO addresses
(id,application_id,billing_profile_id,name,line1,line2,city,region,postal_code,country_code,is_active)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,upper($10),$11)`, id, chi.URLParam(r, "application_id"), profileID, request.Name, request.Line1, request.Line2, request.City, request.Region, request.PostalCode, request.CountryCode, request.Active)
	}
	if err == nil && request.TaxID != nil {
		_, err = tx.Exec(r.Context(), `UPDATE billing_profiles SET tax_id=NULLIF(trim($1),''),version=version+1,updated_at=now() WHERE id=$2`, request.TaxID, profileID)
	}
	if err != nil || tx.Commit(r.Context()) != nil {
		kernel.WriteProblem(w, r, 500, "address_creation_failed", "The address could not be created.")
		return
	}
	kernel.WriteJSON(w, 201, map[string]any{"id": id, "active": request.Active})
}

func (s *Server) listAddresses(w http.ResponseWriter, r *http.Request) {
	subjectType, subjectID, ok := s.addressSubject(w, r)
	if !ok {
		return
	}
	profileID, err := s.ensureBillingProfile(r.Context(), s.app.DB, chi.URLParam(r, "application_id"), subjectType, subjectID)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "billing_profile_not_found", "The billing profile was not found.")
		return
	}
	rows, err := s.app.DB.Query(r.Context(), `SELECT a.id,a.name,a.line1,a.line2,a.city,a.region,a.postal_code,a.country_code,bp.tax_id,a.is_active,a.version,a.created_at,a.updated_at
FROM addresses a JOIN billing_profiles bp ON bp.id=a.billing_profile_id
WHERE a.application_id=$1 AND a.billing_profile_id=$2 ORDER BY a.is_active DESC,a.created_at DESC`, chi.URLParam(r, "application_id"), profileID)
	if err != nil {
		kernel.WriteProblem(w, r, 500, "database_error", "Addresses could not be loaded.")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, name, line1, line2, city, region, postal, country string
		var created, updated time.Time
		var taxID *string
		var active bool
		var version int64
		if rows.Scan(&id, &name, &line1, &line2, &city, &region, &postal, &country, &taxID, &active, &version, &created, &updated) == nil {
			items = append(items, map[string]any{"id": id, "name": name, "line1": line1, "line2": line2, "city": city, "region": region, "postal_code": postal, "country_code": country, "tax_id": taxID, "active": active, "version": version, "created_at": created, "updated_at": updated})
		}
	}
	kernel.WriteJSON(w, 200, map[string]any{"items": items, "next_cursor": nil})
}

func (s *Server) discovery(w http.ResponseWriter, r *http.Request) {
	issuer := s.app.Issuer()
	kernel.WriteJSON(w, 200, map[string]any{
		"issuer": issuer, "authorization_endpoint": issuer + "/authorize", "token_endpoint": issuer + "/token",
		"revocation_endpoint": issuer + "/revoke", "introspection_endpoint": issuer + "/introspect",
		"userinfo_endpoint": issuer + "/userinfo", "jwks_uri": issuer + "/jwks.json",
		"response_types_supported": []string{"code"}, "response_modes_supported": []string{"query"},
		"grant_types_supported":            []string{"authorization_code", "refresh_token", "client_credentials"},
		"code_challenge_methods_supported": []string{"S256"}, "id_token_signing_alg_values_supported": []string{"RS256"},
		"token_endpoint_auth_methods_supported": []string{"none", "client_secret_basic", "client_secret_post"},
		"scopes_supported":                      []string{"openid", "profile", "email", "offline_access"}, "subject_types_supported": []string{"public"},
		"claims_supported": []string{"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "actor_type", "application_id", "scope", "roles", "email", "email_verified", "given_name", "family_name", "locale", "is_org_verified", "custom_claims"},
	})
}

func (s *Server) jwks(w http.ResponseWriter, r *http.Request) {
	rows, err := s.app.DB.Query(r.Context(), `SELECT public_jwk FROM signing_keys
WHERE status='active' OR status='retiring' AND retires_at>now() ORDER BY created_at DESC`)
	if err != nil {
		kernel.WriteProblem(w, r, 404, "application_not_found", "Signing keys were not found.")
		return
	}
	defer rows.Close()
	keys := []any{}
	for rows.Next() {
		var raw []byte
		if rows.Scan(&raw) == nil {
			var key any
			if json.Unmarshal(raw, &key) == nil {
				keys = append(keys, key)
			}
		}
	}
	w.Header().Set("Cache-Control", "public, max-age=300")
	kernel.WriteJSON(w, 200, map[string]any{"keys": keys})
}

func (s *Server) loadUser(r *http.Request, userID string) (userResponse, error) {
	row := s.app.DB.QueryRow(r.Context(), `SELECT id,application_id,email,first_name,last_name,username,locale,email_verified_at IS NOT NULL,is_org_verified,status,custom_attributes,version,created_at,updated_at FROM users WHERE id=$1 AND application_id=$2`, userID, chi.URLParam(r, "application_id"))
	user, ok := scanUser(row)
	if !ok {
		return userResponse{}, pgx.ErrNoRows
	}
	return user, nil
}

type scanner interface{ Scan(...any) error }

func scanUser(row scanner) (userResponse, bool) {
	var u userResponse
	var raw []byte
	if row.Scan(&u.ID, &u.ApplicationID, &u.Email, &u.FirstName, &u.LastName, &u.Username, &u.Locale, &u.EmailVerified, &u.IsOrgVerified, &u.Status, &raw, &u.Version, &u.CreatedAt, &u.UpdatedAt) != nil {
		return userResponse{}, false
	}
	_ = json.Unmarshal(raw, &u.Attributes)
	if u.Attributes == nil {
		u.Attributes = map[string]any{}
	}
	return u, true
}

type effectiveAccess struct {
	Scopes     []string
	Roles      identity.RoleClaims
	Provenance []scopeProvenance
}

type scopeProvenance struct {
	Scope       string  `json:"scope"`
	Source      string  `json:"source"`
	RoleKey     string  `json:"role_key,omitempty"`
	GrantID     string  `json:"grant_id,omitempty"`
	WorkspaceID *string `json:"workspace_id,omitempty"`
	Permission  string  `json:"permission,omitempty"`
}

func emptyRoleClaims() identity.RoleClaims {
	return identity.RoleClaims{Application: []string{}, Workspaces: map[string][]string{}}
}

func (s *Server) permissions(r *http.Request, applicationID uuid.UUID, userID string) []string {
	access, err := s.userEffectiveAccess(r, applicationID, userID)
	if err != nil {
		return []string{}
	}
	return access.Scopes
}

func (s *Server) permissionsForWorkspace(r *http.Request, applicationID uuid.UUID, userID, workspaceID string) []string {
	access, err := s.userEffectiveAccess(r, applicationID, userID)
	if err != nil {
		return []string{}
	}
	values := access.Scopes
	if workspaceID == "" {
		return values
	}
	applicationPrefix := "/applications/" + applicationID.String() + "/"
	workspacePrefix := applicationPrefix + "workspaces/" + workspaceID + "/"
	filtered := make([]string, 0, len(values))
	for _, value := range values {
		if strings.HasPrefix(value, workspacePrefix) || !strings.HasPrefix(value, applicationPrefix+"workspaces/") {
			filtered = append(filtered, value)
		}
	}
	return filtered
}

func (s *Server) scopes(r *http.Request, applicationID uuid.UUID, userID string) []string {
	access, err := s.userEffectiveAccess(r, applicationID, userID)
	if err != nil {
		return []string{}
	}
	return access.Scopes
}

func (s *Server) userEffectiveAccess(r *http.Request, applicationID uuid.UUID, userID string) (effectiveAccess, error) {
	rows, err := s.app.DB.Query(r.Context(), `SELECT ro.key,ro.scope,ro.permissions,ra.workspace_id::text
FROM role_assignments ra JOIN roles ro ON ro.id=ra.role_id
WHERE ra.application_id=$1 AND ra.user_id=$2 ORDER BY ra.created_at,ra.id`, applicationID, userID)
	if err != nil {
		return effectiveAccess{}, err
	}
	defer rows.Close()
	set := map[string]struct{}{}
	provenance := []scopeProvenance{}
	roles := emptyRoleClaims()
	for rows.Next() {
		var roleKey, roleScope string
		var permissions []string
		var workspaceID *string
		if scanErr := rows.Scan(&roleKey, &roleScope, &permissions, &workspaceID); scanErr != nil {
			return effectiveAccess{}, scanErr
		}
		var roleWorkspaceID *string
		if roleScope == "workspace" {
			if workspaceID == nil {
				return effectiveAccess{}, fmt.Errorf("workspace role %q has no workspace", roleKey)
			}
			roleWorkspaceID = workspaceID
			roles.Workspaces[*workspaceID] = append(roles.Workspaces[*workspaceID], roleKey)
		} else {
			roles.Application = append(roles.Application, roleKey)
		}
		marker, markerErr := platformauthz.RoleMarker(applicationID.String(), roleWorkspaceID, roleKey)
		if markerErr != nil {
			return effectiveAccess{}, markerErr
		}
		set[marker] = struct{}{}
		provenance = append(provenance, scopeProvenance{Scope: marker, Source: "role_marker", RoleKey: roleKey, WorkspaceID: roleWorkspaceID})
		for _, permission := range permissions {
			expanded, expandErr := platformauthz.CanonicalScope(applicationID.String(), roleWorkspaceID, permission)
			if expandErr != nil {
				return effectiveAccess{}, expandErr
			}
			set[expanded] = struct{}{}
			provenance = append(provenance, scopeProvenance{Scope: expanded, Source: "role", RoleKey: roleKey, WorkspaceID: roleWorkspaceID, Permission: permission})
		}
	}
	if err = rows.Err(); err != nil {
		return effectiveAccess{}, err
	}
	if err = s.addDirectGrantScopes(r, applicationID, userID, "", set, &provenance); err != nil {
		return effectiveAccess{}, err
	}
	owned, err := s.app.DB.Query(r.Context(), `SELECT id::text FROM workspaces
WHERE application_id=$1 AND owner_user_id=$2 AND deleted_at IS NULL ORDER BY id`, applicationID, userID)
	if err == nil {
		defer owned.Close()
		for owned.Next() {
			var workspaceID string
			if scanErr := owned.Scan(&workspaceID); scanErr != nil {
				return effectiveAccess{}, scanErr
			}
			permission := "*"
			setScope, scopeErr := platformauthz.CanonicalScope(applicationID.String(), &workspaceID, permission)
			if scopeErr != nil {
				return effectiveAccess{}, scopeErr
			}
			set[setScope] = struct{}{}
			workspaceCopy := workspaceID
			provenance = append(provenance, scopeProvenance{Scope: setScope, Source: "workspace_owner", WorkspaceID: &workspaceCopy, Permission: "*"})
		}
	} else {
		return effectiveAccess{}, err
	}
	values := make([]string, 0, len(set))
	for value := range set {
		if value != "" {
			values = append(values, value)
		}
	}
	sort.Strings(values)
	sort.Strings(roles.Application)
	for workspaceID := range roles.Workspaces {
		sort.Strings(roles.Workspaces[workspaceID])
	}
	sort.Slice(provenance, func(i, j int) bool {
		if provenance[i].Scope == provenance[j].Scope {
			return provenance[i].Source < provenance[j].Source
		}
		return provenance[i].Scope < provenance[j].Scope
	})
	return effectiveAccess{Scopes: values, Roles: roles, Provenance: provenance}, nil
}

func (s *Server) clientScopes(r *http.Request, applicationID uuid.UUID, clientID string) []string {
	access, err := s.clientEffectiveAccess(r, applicationID, clientID)
	if err != nil {
		return []string{}
	}
	return access.Scopes
}

func (s *Server) clientEffectiveAccess(r *http.Request, applicationID uuid.UUID, clientID string) (effectiveAccess, error) {
	rows, err := s.app.DB.Query(r.Context(), `SELECT ro.key,ro.scope,ro.permissions,ra.workspace_id::text
FROM clients c JOIN role_assignments ra ON ra.client_id=c.id AND ra.application_id=c.application_id
JOIN roles ro ON ro.id=ra.role_id AND ro.application_id=ra.application_id
WHERE c.application_id=$1 AND c.client_id=$2 AND c.disabled_at IS NULL ORDER BY ra.created_at,ra.id`, applicationID, clientID)
	if err != nil {
		return effectiveAccess{}, err
	}
	defer rows.Close()
	set := map[string]struct{}{}
	provenance := []scopeProvenance{}
	roles := emptyRoleClaims()
	var clientDatabaseID string
	if err = s.app.DB.QueryRow(r.Context(), `SELECT id FROM clients WHERE application_id=$1 AND client_id=$2 AND disabled_at IS NULL`, applicationID, clientID).Scan(&clientDatabaseID); err != nil {
		return effectiveAccess{}, err
	}
	for rows.Next() {
		var roleKey, roleScope string
		var permissions []string
		var workspaceID *string
		if scanErr := rows.Scan(&roleKey, &roleScope, &permissions, &workspaceID); scanErr != nil {
			return effectiveAccess{}, scanErr
		}
		var roleWorkspaceID *string
		if roleScope == "workspace" {
			if workspaceID == nil {
				return effectiveAccess{}, fmt.Errorf("workspace role %q has no workspace", roleKey)
			}
			roleWorkspaceID = workspaceID
			roles.Workspaces[*workspaceID] = append(roles.Workspaces[*workspaceID], roleKey)
		} else {
			roles.Application = append(roles.Application, roleKey)
		}
		marker, markerErr := platformauthz.RoleMarker(applicationID.String(), roleWorkspaceID, roleKey)
		if markerErr != nil {
			return effectiveAccess{}, markerErr
		}
		set[marker] = struct{}{}
		provenance = append(provenance, scopeProvenance{Scope: marker, Source: "role_marker", RoleKey: roleKey, WorkspaceID: roleWorkspaceID})
		for _, permission := range permissions {
			expanded, expandErr := platformauthz.CanonicalScope(applicationID.String(), roleWorkspaceID, permission)
			if expandErr != nil {
				return effectiveAccess{}, expandErr
			}
			set[expanded] = struct{}{}
			provenance = append(provenance, scopeProvenance{Scope: expanded, Source: "role", RoleKey: roleKey, WorkspaceID: roleWorkspaceID, Permission: permission})
		}
	}
	if err = rows.Err(); err != nil {
		return effectiveAccess{}, err
	}
	if err = s.addDirectGrantScopes(r, applicationID, "", clientDatabaseID, set, &provenance); err != nil {
		return effectiveAccess{}, err
	}
	values := make([]string, 0, len(set))
	for value := range set {
		values = append(values, value)
	}
	sort.Strings(values)
	sort.Strings(roles.Application)
	for workspaceID := range roles.Workspaces {
		sort.Strings(roles.Workspaces[workspaceID])
	}
	sort.Slice(provenance, func(i, j int) bool {
		if provenance[i].Scope == provenance[j].Scope {
			return provenance[i].Source < provenance[j].Source
		}
		return provenance[i].Scope < provenance[j].Scope
	})
	return effectiveAccess{Scopes: values, Roles: roles, Provenance: provenance}, nil
}

func (s *Server) addDirectGrantScopes(r *http.Request, applicationID uuid.UUID, userID, clientID string, set map[string]struct{}, provenance *[]scopeProvenance) error {
	rows, err := s.app.DB.Query(r.Context(), `SELECT id::text,permission,canonical_scope,workspace_id::text FROM permission_grants
WHERE application_id=$1 AND user_id IS NOT DISTINCT FROM NULLIF($2,'')::uuid
AND client_id IS NOT DISTINCT FROM NULLIF($3,'')::uuid AND revoked_at IS NULL ORDER BY created_at,id`, applicationID, userID, clientID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var grantID, permission, canonical string
		var workspaceID *string
		if err = rows.Scan(&grantID, &permission, &canonical, &workspaceID); err != nil {
			return err
		}
		expected, canonicalErr := platformauthz.CanonicalScope(applicationID.String(), workspaceID, permission)
		if canonicalErr != nil || expected != canonical {
			return fmt.Errorf("permission grant contains invalid canonical data")
		}
		set[canonical] = struct{}{}
		*provenance = append(*provenance, scopeProvenance{Scope: canonical, Source: "direct", GrantID: grantID, WorkspaceID: workspaceID, Permission: permission})
	}
	return rows.Err()
}

func (s *Server) authFlag(r *http.Request, key string) bool {
	config, err := s.internalApplicationConfig(r)
	if err != nil {
		return false
	}
	switch key {
	case "registration_enabled":
		return config.RegistrationMode == "public" && s.organizationSettingEnabled(r.Context(), chi.URLParam(r, "application_id"), settingPublicRegistration)
	case "password_enabled":
		return config.PasswordEnabled && s.organizationSettingEnabled(r.Context(), chi.URLParam(r, "application_id"), settingPasswordAuthentication)
	case "passwordless_enabled":
		return config.PasswordlessEnabled && s.organizationSettingEnabled(r.Context(), chi.URLParam(r, "application_id"), settingPasswordlessAuthentication)
	default:
		return false
	}
}
func (s *Server) personalKeysEnabled(r *http.Request) bool {
	config, err := s.internalApplicationConfig(r)
	return err == nil && config.PersonalAPIKeysEnabled && s.organizationSettingEnabled(r.Context(), chi.URLParam(r, "application_id"), settingPersonalAPIKeys)
}
func randomCode(length int) string {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	value := make([]byte, length)
	random := make([]byte, length)
	_, _ = rand.Read(random)
	for i := range value {
		value[i] = alphabet[int(random[i])%len(alphabet)]
	}
	return string(value)
}
func equalBytes(left, right []byte) bool {
	if len(left) == 0 || len(left) != len(right) {
		return false
	}
	var result byte
	for i := range left {
		result |= left[i] ^ right[i]
	}
	return result == 0
}
func truncate(value string, max int) string {
	if len(value) <= max {
		return value
	}
	return value[:max]
}
func nullableJSON(value *map[string]any, encoded []byte) any {
	if value == nil {
		return nil
	}
	return encoded
}
