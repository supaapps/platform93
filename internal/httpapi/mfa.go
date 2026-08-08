package httpapi

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/supaapps/platform93/internal/identity"
	"github.com/supaapps/platform93/internal/kernel"
	"github.com/supaapps/platform93/internal/secure"
)

func (s *Server) completePrimaryAuthentication(w http.ResponseWriter, r *http.Request, userID string, amr []string) {
	var methods []string
	err := s.app.DB.QueryRow(r.Context(), `SELECT COALESCE(array_agg(DISTINCT method_type) FILTER (WHERE method_type IS NOT NULL),'{}')
FROM user_authentication_methods WHERE application_id=$1 AND user_id=$2 AND status='active'`,
		chi.URLParam(r, "application_id"), userID).Scan(&methods)
	if err != nil || len(methods) == 0 {
		s.issueSession(w, r, userID, amr)
		return
	}
	challengeID := kernel.NewID()
	_, err = s.app.DB.Exec(r.Context(), `INSERT INTO mfa_login_challenges
(id,application_id,user_id,primary_amr,expires_at) VALUES ($1,$2,$3,$4,$5)`, challengeID,
		chi.URLParam(r, "application_id"), userID, amr, s.app.Now().Add(5*time.Minute))
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "mfa_challenge_failed", "The MFA challenge could not be created.")
		return
	}
	kernel.WriteJSON(w, http.StatusAccepted, map[string]any{"mfa_required": true, "challenge_id": challengeID, "methods": methods, "expires_in": 300})
}

func (s *Server) verifyMFA(w http.ResponseWriter, r *http.Request) {
	var request struct {
		ChallengeID  string `json:"challenge_id"`
		Code         string `json:"code,omitempty"`
		RecoveryCode string `json:"recovery_code,omitempty"`
	}
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	if !s.allowAuthAttempt(w, r, "mfa_verify", request.ChallengeID, 10, 10*time.Minute) {
		return
	}
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "The MFA challenge could not be verified.")
		return
	}
	defer rollback(tx, r.Context())
	var userID string
	var primaryAMR []string
	var attempts int
	err = tx.QueryRow(r.Context(), `SELECT user_id,primary_amr,attempts FROM mfa_login_challenges
WHERE id=$1 AND application_id=$2 AND consumed_at IS NULL AND expires_at>now() FOR UPDATE`,
		request.ChallengeID, chi.URLParam(r, "application_id")).Scan(&userID, &primaryAMR, &attempts)
	if err != nil || attempts >= 8 {
		kernel.WriteProblem(w, r, http.StatusUnauthorized, "invalid_mfa_challenge", "The MFA challenge is invalid or expired.")
		return
	}
	verified := false
	method := ""
	if request.Code != "" {
		rows, queryErr := tx.Query(r.Context(), `SELECT id,secret_ciphertext FROM user_authentication_methods
WHERE application_id=$1 AND user_id=$2 AND method_type='totp' AND status='active'`, chi.URLParam(r, "application_id"), userID)
		if queryErr == nil {
			type encryptedMethod struct{ id, ciphertext string }
			methods := []encryptedMethod{}
			for rows.Next() {
				var methodID, ciphertext string
				if rows.Scan(&methodID, &ciphertext) == nil {
					methods = append(methods, encryptedMethod{id: methodID, ciphertext: ciphertext})
				}
			}
			rows.Close()
			for _, candidate := range methods {
				secret, decryptErr := s.app.Vault.Decrypt(candidate.ciphertext, "totp:"+chi.URLParam(r, "application_id")+":"+userID+":"+candidate.id)
				if decryptErr == nil && identity.VerifyTOTP(string(secret), request.Code, s.app.Now()) {
					verified, method = true, "totp"
					_, _ = tx.Exec(r.Context(), `UPDATE user_authentication_methods SET last_used_at=now() WHERE id=$1`, candidate.id)
					break
				}
			}
		}
	}
	if !verified && request.RecoveryCode != "" {
		result, updateErr := tx.Exec(r.Context(), `UPDATE user_recovery_codes SET used_at=now()
WHERE application_id=$1 AND user_id=$2 AND code_digest=$3 AND used_at IS NULL`, chi.URLParam(r, "application_id"), userID,
			s.app.Vault.Digest(strings.ToUpper(strings.TrimSpace(request.RecoveryCode))))
		verified = updateErr == nil && result.RowsAffected() == 1
		if verified {
			method = "recovery_code"
		}
	}
	if !verified {
		_, _ = tx.Exec(r.Context(), `UPDATE mfa_login_challenges SET attempts=attempts+1 WHERE id=$1`, request.ChallengeID)
		_ = tx.Commit(r.Context())
		kernel.WriteProblem(w, r, http.StatusUnauthorized, "invalid_mfa_credential", "The MFA credential is invalid.")
		return
	}
	_, err = tx.Exec(r.Context(), `UPDATE mfa_login_challenges SET consumed_at=now() WHERE id=$1`, request.ChallengeID)
	if err != nil || tx.Commit(r.Context()) != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "mfa_completion_failed", "The MFA challenge could not be completed.")
		return
	}
	s.issueSession(w, r, userID, append(primaryAMR, method))
}

func (s *Server) listMFAMethods(w http.ResponseWriter, r *http.Request) {
	rows, err := s.app.DB.Query(r.Context(), `SELECT id,method_type,label,status,created_at,activated_at,last_used_at
FROM user_authentication_methods WHERE application_id=$1 AND user_id=$2 AND status<>'disabled' ORDER BY created_at`,
		chi.URLParam(r, "application_id"), actor(r).ID)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "Authentication methods could not be loaded.")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, methodType, label, status string
		var createdAt time.Time
		var activatedAt, lastUsedAt *time.Time
		if rows.Scan(&id, &methodType, &label, &status, &createdAt, &activatedAt, &lastUsedAt) == nil {
			items = append(items, map[string]any{"id": id, "method_type": methodType, "label": label, "status": status, "created_at": createdAt, "activated_at": activatedAt, "last_used_at": lastUsedAt})
		}
	}
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": nil})
}

func (s *Server) startTOTPEnrollment(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Label string `json:"label"`
	}
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	secret, err := identity.GenerateTOTPSecret()
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "totp_generation_failed", "A TOTP secret could not be generated.")
		return
	}
	methodID := kernel.NewID()
	context := "totp:" + chi.URLParam(r, "application_id") + ":" + actor(r).ID + ":" + methodID.String()
	ciphertext, err := s.app.Vault.Encrypt([]byte(secret), context)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "totp_encryption_failed", "The TOTP secret could not be encrypted.")
		return
	}
	_, err = s.app.DB.Exec(r.Context(), `INSERT INTO user_authentication_methods
(id,application_id,user_id,method_type,label,secret_ciphertext) VALUES ($1,$2,$3,'totp',$4,$5)`,
		methodID, chi.URLParam(r, "application_id"), actor(r).ID, request.Label, ciphertext)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "totp_enrollment_failed", "The TOTP enrollment could not be started.")
		return
	}
	var email string
	_ = s.app.DB.QueryRow(r.Context(), `SELECT email FROM users WHERE id=$1`, actor(r).ID).Scan(&email)
	query := url.Values{"secret": {secret}, "issuer": {"Platform93"}, "algorithm": {"SHA1"}, "digits": {"6"}, "period": {"30"}}
	uri := "otpauth://totp/" + url.PathEscape("Platform93:"+email) + "?" + query.Encode()
	kernel.WriteJSON(w, http.StatusCreated, map[string]any{"method_id": methodID, "secret": secret, "otpauth_uri": uri})
}

func (s *Server) activateTOTPEnrollment(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Code string `json:"code"`
	}
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	methodID := chi.URLParam(r, "method_id")
	var ciphertext string
	err := s.app.DB.QueryRow(r.Context(), `SELECT secret_ciphertext FROM user_authentication_methods
WHERE id=$1 AND application_id=$2 AND user_id=$3 AND method_type='totp' AND status='pending'`, methodID,
		chi.URLParam(r, "application_id"), actor(r).ID).Scan(&ciphertext)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "mfa_method_not_found", "The pending TOTP method was not found.")
		return
	}
	secret, err := s.app.Vault.Decrypt(ciphertext, "totp:"+chi.URLParam(r, "application_id")+":"+actor(r).ID+":"+methodID)
	if err != nil || !identity.VerifyTOTP(string(secret), request.Code, s.app.Now()) {
		kernel.WriteProblem(w, r, http.StatusUnauthorized, "invalid_totp", "The TOTP code is invalid.")
		return
	}
	codes := make([]string, 10)
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "The TOTP method could not be activated.")
		return
	}
	defer rollback(tx, r.Context())
	result, err := tx.Exec(r.Context(), `UPDATE user_authentication_methods SET status='active',activated_at=now()
WHERE id=$1 AND status='pending'`, methodID)
	if err == nil && result.RowsAffected() != 1 {
		kernel.WriteProblem(w, r, http.StatusConflict, "totp_activation_failed", "The TOTP method is no longer pending.")
		return
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `DELETE FROM user_recovery_codes WHERE application_id=$1 AND user_id=$2`, chi.URLParam(r, "application_id"), actor(r).ID)
	}
	for index := range codes {
		if err != nil {
			break
		}
		value, tokenErr := secure.RandomToken("", 9)
		if tokenErr != nil {
			err = tokenErr
			break
		}
		codes[index] = strings.ToUpper(value)
		_, err = tx.Exec(r.Context(), `INSERT INTO user_recovery_codes
(id,application_id,user_id,code_digest) VALUES ($1,$2,$3,$4)`, kernel.NewID(), chi.URLParam(r, "application_id"),
			actor(r).ID, s.app.Vault.Digest(codes[index]))
	}
	if err != nil || tx.Commit(r.Context()) != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "totp_activation_failed", "The TOTP activation could not be committed.")
		return
	}
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"method_id": methodID, "recovery_codes": codes})
}

func (s *Server) disableMFAMethod(w http.ResponseWriter, r *http.Request) {
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "The authentication method could not be disabled.")
		return
	}
	defer rollback(tx, r.Context())
	result, err := tx.Exec(r.Context(), `UPDATE user_authentication_methods SET status='disabled',disabled_at=now()
WHERE id=$1 AND application_id=$2 AND user_id=$3 AND status<>'disabled'`, chi.URLParam(r, "method_id"),
		chi.URLParam(r, "application_id"), actor(r).ID)
	if err != nil || result.RowsAffected() != 1 {
		kernel.WriteProblem(w, r, http.StatusNotFound, "mfa_method_not_found", "The authentication method was not found.")
		return
	}
	var active bool
	err = tx.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM user_authentication_methods
WHERE application_id=$1 AND user_id=$2 AND status='active')`, chi.URLParam(r, "application_id"), actor(r).ID).Scan(&active)
	if err == nil && !active {
		_, err = tx.Exec(r.Context(), `DELETE FROM user_recovery_codes WHERE application_id=$1 AND user_id=$2`,
			chi.URLParam(r, "application_id"), actor(r).ID)
	}
	if err != nil || tx.Commit(r.Context()) != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "mfa_disable_failed", "The authentication method could not be disabled.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) regenerateRecoveryCodes(w http.ResponseWriter, r *http.Request) {
	codes := make([]string, 10)
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "Recovery codes could not be regenerated.")
		return
	}
	defer rollback(tx, r.Context())
	var active bool
	err = tx.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM user_authentication_methods
WHERE application_id=$1 AND user_id=$2 AND status='active')`, chi.URLParam(r, "application_id"), actor(r).ID).Scan(&active)
	if err != nil || !active {
		kernel.WriteProblem(w, r, http.StatusConflict, "mfa_not_enabled", "Recovery codes require an active MFA method.")
		return
	}
	_, err = tx.Exec(r.Context(), `DELETE FROM user_recovery_codes WHERE application_id=$1 AND user_id=$2`, chi.URLParam(r, "application_id"), actor(r).ID)
	for index := range codes {
		if err != nil {
			break
		}
		value, tokenErr := secure.RandomToken("", 9)
		if tokenErr != nil {
			err = tokenErr
			break
		}
		codes[index] = strings.ToUpper(value)
		_, err = tx.Exec(r.Context(), `INSERT INTO user_recovery_codes(id,application_id,user_id,code_digest)
VALUES ($1,$2,$3,$4)`, kernel.NewID(), chi.URLParam(r, "application_id"), actor(r).ID, s.app.Vault.Digest(codes[index]))
	}
	if err != nil || tx.Commit(r.Context()) != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "recovery_code_generation_failed", "Recovery codes could not be regenerated.")
		return
	}
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"recovery_codes": codes})
}

func (s *Server) requireRecentAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		current := actor(r)
		if current.DelegatedBy != "" {
			kernel.WriteProblem(w, r, http.StatusForbidden, "direct_authentication_required", "Delegated sessions cannot perform sensitive account actions.")
			return
		}
		var recent bool
		err := s.app.DB.QueryRow(r.Context(), `SELECT authenticated_at>now()-interval '10 minutes'
FROM user_sessions WHERE id=$1 AND user_id=$2 AND revoked_at IS NULL`, current.SessionID, current.ID).Scan(&recent)
		if err != nil || !recent {
			kernel.WriteProblem(w, r, http.StatusForbidden, "recent_authentication_required", "Authentication within the last ten minutes is required.")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
