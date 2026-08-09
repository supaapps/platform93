package httpapi

import (
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/supaapps/platform93/internal/kernel"
)

func (s *Server) adminSuspendUser(w http.ResponseWriter, r *http.Request) {
	s.adminTransitionUser(w, r, "suspended", "user.suspended")
}

func (s *Server) adminRestoreUser(w http.ResponseWriter, r *http.Request) {
	s.adminTransitionUser(w, r, "active", "user.restored")
}

func (s *Server) adminTransitionUser(w http.ResponseWriter, r *http.Request, status, eventType string) {
	reason, ok := adminReason(w, r)
	if !ok {
		return
	}
	applicationID, err := uuid.Parse(chi.URLParam(r, "application_id"))
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusBadRequest, "invalid_application_id", "The application identifier is invalid.")
		return
	}
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "The user state could not be changed.")
		return
	}
	defer rollback(tx, r.Context())
	expectedStatus := "active"
	if status == "active" {
		expectedStatus = "suspended"
	}
	result, err := tx.Exec(r.Context(), `UPDATE users SET status=$1,version=version+1,updated_at=now()
WHERE id=$2 AND application_id=$3 AND status=$4`, status, chi.URLParam(r, "user_id"), applicationID, expectedStatus)
	if err != nil && status == "suspended" && strings.Contains(err.Error(), "workspace ownership") {
		kernel.WriteProblem(w, r, http.StatusConflict, "workspace_ownership_requires_transfer", "Transfer or archive owned workspaces before suspending this user.")
		return
	}
	if err == nil && result.RowsAffected() != 1 {
		kernel.WriteProblem(w, r, http.StatusConflict, "user_state_conflict", "The user was not found or is already in the requested state.")
		return
	}
	if err == nil && status == "suspended" {
		_, err = tx.Exec(r.Context(), `UPDATE user_sessions SET revoked_at=COALESCE(revoked_at,now())
WHERE application_id=$1 AND user_id=$2 AND revoked_at IS NULL`, applicationID, chi.URLParam(r, "user_id"))
	}
	if err == nil && status == "suspended" {
		_, err = tx.Exec(r.Context(), `UPDATE oauth_sessions SET active=false,updated_at=now()
WHERE application_id=$1 AND request_payload->'session'->>'subject'=$2`, applicationID, chi.URLParam(r, "user_id"))
	}
	if err == nil {
		_, err = s.app.Emit(r.Context(), tx, &applicationID, eventType, "user/"+chi.URLParam(r, "user_id"), actor(r),
			map[string]any{"user_id": chi.URLParam(r, "user_id"), "reason": reason})
	}
	if err != nil || tx.Commit(r.Context()) != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "user_state_change_failed", "The user state change could not be committed.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) adminVerifyUserEmail(w http.ResponseWriter, r *http.Request) {
	s.adminSetUserVerification(w, r, "email", true)
}

func (s *Server) adminUnverifyUserEmail(w http.ResponseWriter, r *http.Request) {
	s.adminSetUserVerification(w, r, "email", false)
}

func (s *Server) adminVerifyUserOrganization(w http.ResponseWriter, r *http.Request) {
	s.adminSetUserVerification(w, r, "organization", true)
}

func (s *Server) adminUnverifyUserOrganization(w http.ResponseWriter, r *http.Request) {
	s.adminSetUserVerification(w, r, "organization", false)
}

func (s *Server) adminSetUserVerification(w http.ResponseWriter, r *http.Request, kind string, verified bool) {
	reason, ok := adminReason(w, r)
	if !ok {
		return
	}
	applicationID, err := uuid.Parse(chi.URLParam(r, "application_id"))
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusBadRequest, "invalid_application_id", "The application identifier is invalid.")
		return
	}
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "Verification state could not be changed.")
		return
	}
	defer rollback(tx, r.Context())
	var resultAffected int64
	if kind == "email" {
		result, updateErr := tx.Exec(r.Context(), `UPDATE users SET email_verified_at=CASE WHEN $1 THEN now() ELSE NULL END,
version=version+1,updated_at=now() WHERE id=$2 AND application_id=$3`, verified, chi.URLParam(r, "user_id"), applicationID)
		err = updateErr
		resultAffected = result.RowsAffected()
	} else {
		result, updateErr := tx.Exec(r.Context(), `UPDATE users SET is_org_verified=$1,version=version+1,updated_at=now()
WHERE id=$2 AND application_id=$3`, verified, chi.URLParam(r, "user_id"), applicationID)
		err = updateErr
		resultAffected = result.RowsAffected()
	}
	if err != nil || resultAffected != 1 {
		kernel.WriteProblem(w, r, http.StatusNotFound, "user_not_found", "The user was not found.")
		return
	}
	eventType := "user." + kind + "_unverified"
	if verified {
		eventType = "user." + kind + "_verified"
	}
	_, err = s.app.Emit(r.Context(), tx, &applicationID, eventType, "user/"+chi.URLParam(r, "user_id"), actor(r),
		map[string]any{"user_id": chi.URLParam(r, "user_id"), "verified": verified, "reason": reason})
	if err != nil || tx.Commit(r.Context()) != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "verification_change_failed", "The verification change could not be committed.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func adminReason(w http.ResponseWriter, r *http.Request) (string, bool) {
	var request struct {
		Reason string `json:"reason"`
	}
	if !kernel.DecodeJSON(w, r, &request) {
		return "", false
	}
	request.Reason = strings.TrimSpace(request.Reason)
	if request.Reason == "" || len(request.Reason) > 500 {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "audit_reason_required", "A concise audit reason is required.")
		return "", false
	}
	return request.Reason, true
}

func (s *Server) listMyIdentities(w http.ResponseWriter, r *http.Request) {
	rows, err := s.app.DB.Query(r.Context(), `SELECT id,provider,metadata,created_at FROM user_identities
WHERE application_id=$1 AND user_id=$2 ORDER BY created_at,id`, chi.URLParam(r, "application_id"), actor(r).ID)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "Linked identities could not be loaded.")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, provider string
		var metadata []byte
		var createdAt time.Time
		if rows.Scan(&id, &provider, &metadata, &createdAt) == nil {
			items = append(items, map[string]any{"id": id, "provider": provider, "metadata": decodeMap(metadata), "created_at": createdAt})
		}
	}
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": nil})
}

func (s *Server) unlinkMyIdentity(w http.ResponseWriter, r *http.Request) {
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "The linked identity could not be removed.")
		return
	}
	defer rollback(tx, r.Context())
	var passwordAvailable bool
	var identityCount int
	err = tx.QueryRow(r.Context(), `SELECT password_hash IS NOT NULL,
(SELECT count(*) FROM user_identities WHERE application_id=$1 AND user_id=$2)
FROM users WHERE id=$2 AND application_id=$1 AND status='active' FOR UPDATE`, chi.URLParam(r, "application_id"), actor(r).ID).
		Scan(&passwordAvailable, &identityCount)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "account_unavailable", "The account is unavailable.")
		return
	}
	if !passwordAvailable && identityCount <= 1 && !s.authFlag(r, "passwordless_enabled") {
		kernel.WriteProblem(w, r, http.StatusConflict, "last_login_method", "The last usable login method cannot be removed.")
		return
	}
	result, err := tx.Exec(r.Context(), `DELETE FROM user_identities WHERE id=$1 AND application_id=$2 AND user_id=$3`,
		chi.URLParam(r, "identity_id"), chi.URLParam(r, "application_id"), actor(r).ID)
	if err != nil || result.RowsAffected() != 1 {
		kernel.WriteProblem(w, r, http.StatusNotFound, "identity_not_found", "The linked identity was not found.")
		return
	}
	if tx.Commit(r.Context()) != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "identity_unlink_failed", "The linked identity could not be removed.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
