package httpapi

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/supaapps/platform93/internal/kernel"
	"github.com/supaapps/platform93/internal/secure"
)

func (s *Server) startExternalEmailEnrollment(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Enrollment   string `json:"enrollment"`
		Email        string `json:"email"`
		Delivery     string `json:"delivery,omitempty"`
		CodeVerifier string `json:"code_verifier"`
	}
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	parts := strings.SplitN(request.Enrollment, ":", 2)
	request.Email = kernel.NormalizeEmail(request.Email)
	if len(parts) != 2 || !strings.Contains(request.Email, "@") || !invitationPKCEVerifierPattern.MatchString(request.CodeVerifier) {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_external_email_enrollment", "A valid enrollment credential and email are required.")
		return
	}
	if request.Delivery == "" {
		request.Delivery = "both"
	}
	if request.Delivery != "code" && request.Delivery != "link" && request.Delivery != "both" {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_delivery", "Delivery must be code, link, or both.")
		return
	}
	if !s.registrationEnabled(r) {
		kernel.WriteProblem(w, r, http.StatusForbidden, "registration_disabled", "Public registration is disabled for this application.")
		return
	}
	if !s.allowAuthAttempt(w, r, "external_email_start", parts[0]+"|"+request.Email, 5, 10*time.Minute) {
		return
	}
	var provider, redirectURI, codeChallenge string
	var emailSentAt *time.Time
	err := s.app.DB.QueryRow(r.Context(), `SELECT provider,app_redirect_uri,code_challenge,email_sent_at FROM external_auth_email_enrollments
WHERE id=$1 AND application_id=$2 AND credential_digest=$3 AND consumed_at IS NULL AND expires_at>now()`, parts[0], chi.URLParam(r, "application_id"), s.app.Vault.Digest(parts[1])).Scan(&provider, &redirectURI, &codeChallenge, &emailSentAt)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusUnauthorized, "invalid_external_email_enrollment", "The external email enrollment is invalid or expired.")
		return
	}
	verifierDigest := sha256.Sum256([]byte(request.CodeVerifier))
	if !equalBytes([]byte(codeChallenge), []byte(base64.RawURLEncoding.EncodeToString(verifierDigest[:]))) {
		kernel.WriteProblem(w, r, http.StatusUnauthorized, "external_email_pkce_failed", "The external email enrollment is not bound to this browser session.")
		return
	}
	if emailSentAt != nil && emailSentAt.Add(time.Minute).After(s.app.Now()) {
		retry := int(time.Until(emailSentAt.Add(time.Minute)).Seconds()) + 1
		w.Header().Set("Retry-After", fmtInt(retry))
		kernel.WriteProblem(w, r, http.StatusTooManyRequests, "external_email_resend_cooldown", "The verification email can be resent after the cooldown.")
		return
	}
	code := randomCode(8)
	linkToken, _ := secure.RandomToken("p93_external_email_link_", 32)
	var codeDigest, linkDigest []byte
	if request.Delivery != "link" {
		codeDigest = s.app.Vault.Digest(code)
	}
	if request.Delivery != "code" {
		linkDigest = s.app.Vault.Digest(linkToken)
	}
	deliveredCode, magicLink := code, ""
	if request.Delivery == "link" {
		deliveredCode = ""
	}
	if request.Delivery != "code" {
		magicLink = appendCredentialQuery(redirectURI, map[string]string{
			"external_auth_provider": provider, "external_auth_email_enrollment": request.Enrollment, "external_auth_email_link": linkToken,
		})
	}
	applicationID := chi.URLParam(r, "application_id")
	templateID, locale, payload, renderErr := s.renderSystemNotification(r.Context(), &applicationID, verifyEmailTemplate, request.Email, map[string]any{
		"code": deliveredCode, "magic_link": magicLink, "expires_minutes": 10, "intent": "external_auth",
	})
	if renderErr != nil {
		kernel.WriteProblem(w, r, http.StatusServiceUnavailable, "external_email_delivery_unavailable", "Email verification is unavailable for this application.")
		return
	}
	notificationID := kernel.NewID()
	tx, err := s.app.DB.Begin(r.Context())
	if err == nil {
		defer rollback(tx, r.Context())
		result, updateErr := tx.Exec(r.Context(), `UPDATE external_auth_email_enrollments SET normalized_email=$1,code_digest=$2,link_digest=$3,attempts=0,email_sent_at=now(),pkce_verified_at=COALESCE(pkce_verified_at,now())
WHERE id=$4 AND application_id=$5 AND credential_digest=$6 AND consumed_at IS NULL AND expires_at>now()`, request.Email, codeDigest, linkDigest, parts[0], applicationID, s.app.Vault.Digest(parts[1]))
		err = updateErr
		if err == nil && result.RowsAffected() != 1 {
			err = pgx.ErrNoRows
		}
		if err == nil {
			ciphertext, encryptErr := s.app.Vault.Encrypt(payload, "notification:"+notificationID.String())
			if encryptErr != nil {
				err = encryptErr
			} else {
				_, err = tx.Exec(r.Context(), `INSERT INTO notifications(id,application_id,template_id,recipient,locale,payload_ciphertext,status)
VALUES($1,$2,$3,$4,$5,$6,'queued')`, notificationID, applicationID, templateID, request.Email, locale, ciphertext)
			}
		}
		if err == nil {
			err = tx.Commit(r.Context())
		}
	}
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusConflict, "external_email_delivery_failed", "The verification email could not be queued.")
		return
	}
	kernel.WriteJSON(w, http.StatusAccepted, map[string]any{"challenge_id": parts[0], "provider": provider, "expires_in": 600})
}

func (s *Server) verifyExternalEmailEnrollment(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Enrollment string `json:"enrollment"`
		Code       string `json:"code,omitempty"`
		LinkToken  string `json:"link_token,omitempty"`
	}
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	parts := strings.SplitN(request.Enrollment, ":", 2)
	if len(parts) != 2 || !hasExactlyOneExternalEmailCredential(request.Code, request.LinkToken) {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_external_email_verification", "An enrollment credential and exactly one email verification credential are required.")
		return
	}
	if !s.allowAuthAttempt(w, r, "external_email_verify", parts[0], 10, 10*time.Minute) {
		return
	}
	applicationID := chi.URLParam(r, "application_id")
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "The external identity could not be completed.")
		return
	}
	defer rollback(tx, r.Context())
	var providerConfigID, provider, subject, firstName, lastName, email string
	var codeDigest, linkDigest []byte
	var attempts int
	err = tx.QueryRow(r.Context(), `SELECT auth_provider_config_id,provider,provider_subject,first_name,last_name,normalized_email,code_digest,link_digest,attempts
FROM external_auth_email_enrollments WHERE id=$1 AND application_id=$2 AND credential_digest=$3 AND pkce_verified_at IS NOT NULL AND consumed_at IS NULL AND expires_at>now() FOR UPDATE`,
		parts[0], applicationID, s.app.Vault.Digest(parts[1])).Scan(&providerConfigID, &provider, &subject, &firstName, &lastName, &email, &codeDigest, &linkDigest, &attempts)
	valid := err == nil && attempts < 8 && ((request.Code != "" && equalBytes(codeDigest, s.app.Vault.Digest(strings.ToUpper(strings.TrimSpace(request.Code))))) ||
		(request.LinkToken != "" && equalBytes(linkDigest, s.app.Vault.Digest(request.LinkToken))))
	if !valid {
		if err == nil {
			_, _ = tx.Exec(r.Context(), `UPDATE external_auth_email_enrollments SET attempts=attempts+1 WHERE id=$1`, parts[0])
			_ = tx.Commit(r.Context())
		}
		kernel.WriteProblem(w, r, http.StatusUnauthorized, "invalid_external_email_verification", "The email verification credential is invalid or expired.")
		return
	}
	config, configErr := s.loadEffectiveAuthProvider(r.Context(), applicationID, provider)
	if configErr != nil || config.ID != providerConfigID {
		kernel.WriteProblem(w, r, http.StatusServiceUnavailable, "auth_provider_unavailable", "The authentication provider is no longer available.")
		return
	}
	var existingUser string
	if existingErr := tx.QueryRow(r.Context(), `SELECT id FROM users WHERE application_id=$1 AND normalized_email=$2`, applicationID, email).Scan(&existingUser); existingErr == nil {
		kernel.WriteProblem(w, r, http.StatusConflict, "account_link_required", "An account already uses this email. Sign in to that account and link the provider.")
		return
	}
	if limitErr := enforceUserLimit(r.Context(), tx, applicationID); limitErr != nil {
		kernel.WriteProblem(w, r, http.StatusConflict, "user_limit_reached", "The application user limit has been reached.")
		return
	}
	userID := kernel.NewID().String()
	_, err = tx.Exec(r.Context(), `INSERT INTO users(id,application_id,email,normalized_email,first_name,last_name,email_verified_at)
VALUES($1,$2,$3,$3,$4,$5,now())`, userID, applicationID, email, firstName, lastName)
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO user_identities(id,application_id,user_id,provider,provider_subject,metadata)
VALUES($1,$2,$3,$4,$5,jsonb_build_object('email',$6))`, kernel.NewID(), applicationID, userID, provider, subject, email)
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `UPDATE external_auth_email_enrollments SET consumed_at=now() WHERE id=$1`, parts[0])
	}
	parsedApplicationID, parseErr := uuid.Parse(applicationID)
	if err == nil && parseErr == nil {
		_, err = s.app.Emit(r.Context(), tx, &parsedApplicationID, "user.created", "user/"+userID, map[string]any{"type": "provider", "provider": provider},
			map[string]any{"user_id": userID, "email_verified": true, "is_org_verified": false})
	}
	if err != nil || parseErr != nil || tx.Commit(r.Context()) != nil {
		kernel.WriteProblem(w, r, http.StatusConflict, "external_identity_creation_failed", "The external identity could not be created.")
		return
	}
	s.completePrimaryAuthentication(w, r, userID, []string{provider, "email"})
}

func hasExactlyOneExternalEmailCredential(code, linkToken string) bool {
	return (code != "") != (linkToken != "")
}
