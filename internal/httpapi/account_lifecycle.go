package httpapi

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/supaapps/platform93/internal/identity"
	"github.com/supaapps/platform93/internal/kernel"
	"github.com/supaapps/platform93/internal/secure"
)

type accountChallengeRequest struct {
	ChallengeID string `json:"challenge_id"`
	Code        string `json:"code,omitempty"`
	LinkToken   string `json:"link_token,omitempty"`
}

func (s *Server) emailVerificationStart(w http.ResponseWriter, r *http.Request) {
	var email string
	err := s.app.DB.QueryRow(r.Context(), `SELECT email FROM users WHERE id=$1 AND application_id=$2 AND status='active'`,
		actor(r).ID, chi.URLParam(r, "application_id")).Scan(&email)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusUnauthorized, "account_unavailable", "The account is unavailable.")
		return
	}
	if !s.queueAccountChallenge(w, r, email, "verify_email", actor(r).ID) {
		return
	}
}

func (s *Server) emailVerificationVerify(w http.ResponseWriter, r *http.Request) {
	var request accountChallengeRequest
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	tx, normalized, ok := s.consumeAccountChallenge(w, r, request, "verify_email", actor(r).ID)
	if !ok {
		return
	}
	defer rollback(tx, r.Context())
	result, err := tx.Exec(r.Context(), `UPDATE users SET email_verified_at=COALESCE(email_verified_at,now()),version=version+1,updated_at=now()
WHERE id=$1 AND application_id=$2 AND normalized_email=$3 AND status='active'`, actor(r).ID, chi.URLParam(r, "application_id"), normalized)
	if err != nil || result.RowsAffected() != 1 {
		kernel.WriteProblem(w, r, http.StatusConflict, "email_verification_failed", "The email address could not be verified.")
		return
	}
	applicationID := uuid.MustParse(chi.URLParam(r, "application_id"))
	_, err = s.app.Emit(r.Context(), tx, &applicationID, "user.email_verified", "user/"+actor(r).ID, actor(r), map[string]any{"user_id": actor(r).ID, "verified": true, "reason": "self_service"})
	if err != nil || tx.Commit(r.Context()) != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "email_verification_failed", "The email verification could not be committed.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) emailChangeStart(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Email string `json:"email"`
	}
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	normalized := kernel.NormalizeEmail(request.Email)
	if !strings.Contains(normalized, "@") {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_email", "A valid new email address is required.")
		return
	}
	var exists bool
	_ = s.app.DB.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM users WHERE application_id=$1 AND normalized_email=$2)`,
		chi.URLParam(r, "application_id"), normalized).Scan(&exists)
	if exists {
		kernel.WriteProblem(w, r, http.StatusConflict, "email_unavailable", "The email address is unavailable.")
		return
	}
	s.queueAccountChallenge(w, r, request.Email, "change_email", actor(r).ID)
}

func (s *Server) emailChangeVerify(w http.ResponseWriter, r *http.Request) {
	var request accountChallengeRequest
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	tx, normalized, ok := s.consumeAccountChallenge(w, r, request, "change_email", actor(r).ID)
	if !ok {
		return
	}
	defer rollback(tx, r.Context())
	result, err := tx.Exec(r.Context(), `UPDATE users SET email=$1,normalized_email=$1,email_verified_at=now(),version=version+1,updated_at=now()
WHERE id=$2 AND application_id=$3 AND status='active'`, normalized, actor(r).ID, chi.URLParam(r, "application_id"))
	if err != nil || result.RowsAffected() != 1 {
		kernel.WriteProblem(w, r, http.StatusConflict, "email_change_failed", "The email address could not be changed.")
		return
	}
	_, _ = tx.Exec(r.Context(), `UPDATE user_sessions SET revoked_at=now() WHERE user_id=$1 AND id<>$2 AND revoked_at IS NULL`, actor(r).ID, actor(r).SessionID)
	applicationID := uuid.MustParse(chi.URLParam(r, "application_id"))
	_, err = s.app.Emit(r.Context(), tx, &applicationID, "user.email_changed", "user/"+actor(r).ID, actor(r), map[string]any{"user_id": actor(r).ID})
	if err != nil || tx.Commit(r.Context()) != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "email_change_failed", "The email change could not be committed.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) passwordResetStart(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Email string `json:"email"`
	}
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	if !s.allowAuthAttempt(w, r, "password_reset_start", kernel.NormalizeEmail(request.Email), 5, 10*time.Minute) {
		return
	}
	if !s.authFlag(r, "password_enabled") {
		kernel.WriteProblem(w, r, http.StatusForbidden, "password_login_disabled", "Password authentication is disabled for this application.")
		return
	}
	responseID := kernel.NewID()
	var userID string
	err := s.app.DB.QueryRow(r.Context(), `SELECT id FROM users WHERE application_id=$1 AND normalized_email=$2 AND status='active'`,
		chi.URLParam(r, "application_id"), kernel.NormalizeEmail(request.Email)).Scan(&userID)
	if err == nil {
		if !s.queueAccountChallengeWithID(w, r, request.Email, "password_reset", userID, responseID) {
			return
		}
		return
	}
	kernel.WriteJSON(w, http.StatusAccepted, map[string]any{"challenge_id": responseID, "expires_in": 600})
}

func (s *Server) passwordResetVerify(w http.ResponseWriter, r *http.Request) {
	var request struct {
		ChallengeID string `json:"challenge_id"`
		Code        string `json:"code,omitempty"`
		LinkToken   string `json:"link_token,omitempty"`
		Password    string `json:"password"`
	}
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	if !s.allowAuthAttempt(w, r, "password_reset_verify", request.ChallengeID, 10, 10*time.Minute) {
		return
	}
	hash, err := identity.HashPassword(request.Password)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_password", err.Error())
		return
	}
	tx, normalized, ok := s.consumeAccountChallenge(w, r, accountChallengeRequest{ChallengeID: request.ChallengeID, Code: request.Code, LinkToken: request.LinkToken}, "password_reset", "")
	if !ok {
		return
	}
	defer rollback(tx, r.Context())
	var userID string
	err = tx.QueryRow(r.Context(), `UPDATE users SET password_hash=$1,version=version+1,updated_at=now()
WHERE application_id=$2 AND normalized_email=$3 AND status='active' RETURNING id`, hash, chi.URLParam(r, "application_id"), normalized).Scan(&userID)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusUnauthorized, "invalid_challenge", "The reset challenge is invalid or expired.")
		return
	}
	_, _ = tx.Exec(r.Context(), `UPDATE user_sessions SET revoked_at=now() WHERE user_id=$1 AND revoked_at IS NULL`, userID)
	applicationID := uuid.MustParse(chi.URLParam(r, "application_id"))
	_, err = s.app.Emit(r.Context(), tx, &applicationID, "user.password_reset", "user/"+userID, map[string]any{"type": "user"}, map[string]any{"user_id": userID})
	if err != nil || tx.Commit(r.Context()) != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "password_reset_failed", "The password reset could not be committed.")
		return
	}
	s.completePrimaryAuthentication(w, r, userID, []string{"password_reset"})
}

func (s *Server) passwordChange(w http.ResponseWriter, r *http.Request) {
	var request struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	var currentHash string
	err := s.app.DB.QueryRow(r.Context(), `SELECT password_hash FROM users WHERE id=$1 AND application_id=$2 AND status='active'`,
		actor(r).ID, chi.URLParam(r, "application_id")).Scan(&currentHash)
	if err != nil || !identity.VerifyPassword(currentHash, request.CurrentPassword) {
		kernel.WriteProblem(w, r, http.StatusUnauthorized, "invalid_current_password", "The current password is incorrect.")
		return
	}
	newHash, err := identity.HashPassword(request.NewPassword)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_password", err.Error())
		return
	}
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "The password could not be changed.")
		return
	}
	defer rollback(tx, r.Context())
	_, err = tx.Exec(r.Context(), `UPDATE users SET password_hash=$1,version=version+1,updated_at=now() WHERE id=$2`, newHash, actor(r).ID)
	if err == nil {
		_, err = tx.Exec(r.Context(), `UPDATE user_sessions SET revoked_at=now() WHERE user_id=$1 AND id<>$2 AND revoked_at IS NULL`, actor(r).ID, actor(r).SessionID)
	}
	if err != nil || tx.Commit(r.Context()) != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "password_change_failed", "The password change could not be committed.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) exportMyAccount(w http.ResponseWriter, r *http.Request) {
	user, err := s.loadUser(r, actor(r).ID)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "user_not_found", "The user was not found.")
		return
	}
	addresses := []map[string]any{}
	rows, err := s.app.DB.Query(r.Context(), `SELECT a.id,a.name,a.line1,a.line2,a.city,a.region,a.postal_code,a.country_code,bp.tax_id,a.is_active,a.created_at
FROM addresses a JOIN billing_profiles bp ON bp.id=a.billing_profile_id
WHERE a.application_id=$1 AND bp.subject_type='user' AND bp.subject_id=$2 ORDER BY a.created_at`, chi.URLParam(r, "application_id"), actor(r).ID)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var id, name, line1, line2, city, region, postalCode, countryCode string
			var taxID *string
			var active bool
			var createdAt time.Time
			if rows.Scan(&id, &name, &line1, &line2, &city, &region, &postalCode, &countryCode, &taxID, &active, &createdAt) == nil {
				addresses = append(addresses, map[string]any{"id": id, "name": name, "line1": line1, "line2": line2, "city": city, "region": region, "postal_code": postalCode, "country_code": countryCode, "tax_id": taxID, "active": active, "created_at": createdAt})
			}
		}
	}
	w.Header().Set("Content-Disposition", `attachment; filename="platform93-account-export.json"`)
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"exported_at": s.app.Now().UTC(), "user": user, "addresses": addresses})
}

func (s *Server) anonymizeMyAccount(w http.ResponseWriter, r *http.Request) {
	s.anonymizeAccount(w, r, "anonymized")
}

func (s *Server) deleteMyAccount(w http.ResponseWriter, r *http.Request) {
	s.anonymizeAccount(w, r, "deleted")
}

func (s *Server) anonymizeAccount(w http.ResponseWriter, r *http.Request, status string) {
	var owned int
	if err := s.app.DB.QueryRow(r.Context(), `SELECT count(*) FROM workspaces WHERE application_id=$1 AND owner_user_id=$2 AND deleted_at IS NULL`, chi.URLParam(r, "application_id"), actor(r).ID).Scan(&owned); err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "Workspace ownership could not be checked.")
		return
	}
	if owned > 0 {
		kernel.WriteProblem(w, r, http.StatusConflict, "workspace_ownership_requires_transfer", "Transfer or archive owned workspaces before anonymizing or deleting this account.")
		return
	}
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "The account could not be updated.")
		return
	}
	defer rollback(tx, r.Context())
	anonymousEmail := fmt.Sprintf("anonymized+%s@invalid.platform93", actor(r).ID)
	_, err = tx.Exec(r.Context(), `UPDATE users SET email=$1,normalized_email=$1,first_name='',last_name='',username=NULL,locale='',password_hash=NULL,
email_verified_at=NULL,is_org_verified=false,status=$2,custom_attributes='{}',deleted_at=now(),version=version+1,updated_at=now() WHERE id=$3 AND application_id=$4`,
		anonymousEmail, status, actor(r).ID, chi.URLParam(r, "application_id"))
	if err == nil {
		_, err = tx.Exec(r.Context(), `UPDATE user_sessions SET revoked_at=now() WHERE user_id=$1 AND revoked_at IS NULL`, actor(r).ID)
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `UPDATE personal_api_keys SET revoked_at=now() WHERE user_id=$1 AND revoked_at IS NULL`, actor(r).ID)
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `DELETE FROM user_identities WHERE user_id=$1`, actor(r).ID)
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `DELETE FROM addresses WHERE billing_profile_id IN
(SELECT id FROM billing_profiles WHERE application_id=$1 AND subject_type='user' AND subject_id=$2)`, chi.URLParam(r, "application_id"), actor(r).ID)
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `DELETE FROM billing_profiles WHERE application_id=$1 AND subject_type='user' AND subject_id=$2`, chi.URLParam(r, "application_id"), actor(r).ID)
	}
	applicationID := uuid.MustParse(chi.URLParam(r, "application_id"))
	if err == nil {
		_, err = s.app.Emit(r.Context(), tx, &applicationID, "user."+status, "user/"+actor(r).ID, actor(r), map[string]any{"user_id": actor(r).ID})
	}
	if err != nil || tx.Commit(r.Context()) != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "account_update_failed", "The account update could not be committed.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) queueAccountChallenge(w http.ResponseWriter, r *http.Request, email, intent, userID string) bool {
	return s.queueAccountChallengeWithID(w, r, email, intent, userID, kernel.NewID())
}

func (s *Server) queueAccountChallengeWithID(w http.ResponseWriter, r *http.Request, email, intent, userID string, challengeID uuid.UUID) bool {
	code := randomCode(8)
	link, _ := secure.RandomToken("p93_link_", 32)
	notificationID := kernel.NewID()
	applicationID := chi.URLParam(r, "application_id")
	flows, _ := s.loadApplicationFlowConfig(r.Context(), applicationID)
	magicLink := ""
	if flows.SignInRedirectURI != "" {
		magicLink = appendCredentialQuery(flows.SignInRedirectURI, map[string]string{
			"challenge_id": challengeID.String(), "link_token": link, "platform93_flow": intent,
		})
	}
	var userLocale string
	_ = s.app.DB.QueryRow(r.Context(), `SELECT locale FROM users WHERE id=$1 AND application_id=$2 AND status='active'`, userID, applicationID).Scan(&userLocale)
	templateID, templateLocale, payload, renderErr := s.renderSystemNotification(r.Context(), &applicationID, accountChallengeTemplate(intent), email, map[string]any{
		"code": code, "magic_link": magicLink, "expires_minutes": 10, "user_locale": userLocale,
	})
	if renderErr != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "challenge_template_unavailable", "The account email template is unavailable or invalid.")
		return false
	}
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "The challenge could not be queued.")
		return false
	}
	defer rollback(tx, r.Context())
	_, err = tx.Exec(r.Context(), `INSERT INTO login_challenges
(id,application_id,normalized_email,requested_by_user_id,intent,code_digest,link_digest,expires_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, challengeID, chi.URLParam(r, "application_id"), kernel.NormalizeEmail(email),
		userID, intent, s.app.Vault.Digest(code), s.app.Vault.Digest(link), s.app.Now().Add(10*time.Minute))
	if err == nil {
		var ciphertext string
		ciphertext, err = s.app.Vault.Encrypt(payload, "notification:"+notificationID.String())
		if err == nil {
			_, err = tx.Exec(r.Context(), `INSERT INTO notifications
(id,application_id,template_id,recipient,locale,payload_ciphertext,status) VALUES ($1,$2,$3,$4,$5,$6,'queued')`, notificationID, applicationID, templateID, email, templateLocale, ciphertext)
		}
	}
	if err != nil || tx.Commit(r.Context()) != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "challenge_delivery_failed", "The challenge could not be queued.")
		return false
	}
	kernel.WriteJSON(w, http.StatusAccepted, map[string]any{"challenge_id": challengeID, "expires_in": 600})
	return true
}

func (s *Server) consumeAccountChallenge(w http.ResponseWriter, r *http.Request, request accountChallengeRequest, intent, userID string) (pgx.Tx, string, bool) {
	if !s.allowAuthAttempt(w, r, "account_challenge_"+intent, request.ChallengeID, 10, 10*time.Minute) {
		return nil, "", false
	}
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "The challenge could not be verified.")
		return nil, "", false
	}
	var normalized string
	var requestedBy *string
	var codeDigest, linkDigest []byte
	var attempts int
	err = tx.QueryRow(r.Context(), `SELECT normalized_email,requested_by_user_id,code_digest,link_digest,attempts FROM login_challenges
WHERE id=$1 AND application_id=$2 AND intent=$3 AND consumed_at IS NULL AND expires_at>now() FOR UPDATE`,
		request.ChallengeID, chi.URLParam(r, "application_id"), intent).Scan(&normalized, &requestedBy, &codeDigest, &linkDigest, &attempts)
	validActor := userID == "" || requestedBy != nil && *requestedBy == userID
	validCredential := request.Code != "" && equalBytes(codeDigest, s.app.Vault.Digest(strings.ToUpper(request.Code))) ||
		request.LinkToken != "" && equalBytes(linkDigest, s.app.Vault.Digest(request.LinkToken))
	if err != nil || attempts >= 8 || !validActor || !validCredential {
		if err == nil {
			_, _ = tx.Exec(r.Context(), `UPDATE login_challenges SET attempts=attempts+1 WHERE id=$1`, request.ChallengeID)
			_ = tx.Commit(r.Context())
		} else {
			_ = tx.Rollback(r.Context())
		}
		kernel.WriteProblem(w, r, http.StatusUnauthorized, "invalid_challenge", "The challenge is invalid or expired.")
		return nil, "", false
	}
	_, err = tx.Exec(r.Context(), `UPDATE login_challenges SET consumed_at=now() WHERE id=$1`, request.ChallengeID)
	if err != nil {
		_ = tx.Rollback(r.Context())
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "challenge_completion_failed", "The challenge could not be consumed.")
		return nil, "", false
	}
	return tx, normalized, true
}
