package httpapi

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/supaapps/platform93/internal/kernel"
	"github.com/supaapps/platform93/internal/secure"
)

func (s *Server) refreshOperatorSession(w http.ResponseWriter, r *http.Request) {
	var request struct {
		RefreshToken string `json:"refresh_token"`
	}
	if cookie, cookieErr := r.Cookie("p93_operator_refresh"); cookieErr == nil {
		request.RefreshToken = cookie.Value
	}
	if r.Body != nil && r.ContentLength != 0 {
		_ = json.NewDecoder(r.Body).Decode(&request)
	}
	if request.RefreshToken == "" {
		kernel.WriteProblem(w, r, http.StatusUnauthorized, "operator_refresh_required", "An operator refresh credential is required.")
		return
	}
	token, err := secure.RandomToken("p93_ops_refresh_", 32)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "credential_generation_failed", "The operator session could not be rotated.")
		return
	}
	expiresAt := s.app.Now().Add(12 * time.Hour)
	var sessionID, operatorID string
	err = s.app.DB.QueryRow(r.Context(), `UPDATE operator_sessions SET refresh_digest=$1,expires_at=$2,last_used_at=now(),ip_address=$3,user_agent=$4
WHERE refresh_digest=$5 AND kind='operator' AND revoked_at IS NULL AND expires_at>now()
RETURNING id,operator_id`, s.app.Vault.Digest(token), expiresAt, requestIPAddress(r), truncate(r.UserAgent(), 500), s.app.Vault.Digest(request.RefreshToken)).Scan(&sessionID, &operatorID)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusUnauthorized, "invalid_operator_session", "The operator session could not be refreshed.")
		return
	}
	access, err := s.issueOperatorAccess(r.Context(), operatorID, sessionID, "operator")
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "operator_token_failed", "The operator access token could not be issued.")
		return
	}
	s.setOperatorCookies(w, access, token, 12*time.Hour)
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"access_token": access, "refresh_token": token, "token_type": "Bearer", "expires_in": 300, "refresh_expires_at": expiresAt})
}

func (s *Server) listOperatorSessions(w http.ResponseWriter, r *http.Request) {
	rows, err := s.app.DB.Query(r.Context(), `SELECT id,ip_address::text,user_agent,last_used_at,expires_at,revoked_at,created_at
FROM operator_sessions WHERE operator_id=$1 AND kind='operator' ORDER BY created_at DESC,id DESC LIMIT 101`, actor(r).ID)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "Operator sessions could not be loaded.")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, userAgent string
		var ipAddress *string
		var lastUsedAt, expiresAt, createdAt time.Time
		var revokedAt *time.Time
		if rows.Scan(&id, &ipAddress, &userAgent, &lastUsedAt, &expiresAt, &revokedAt, &createdAt) == nil {
			items = append(items, map[string]any{"id": id, "ip_address": ipAddress, "user_agent": userAgent, "last_used_at": lastUsedAt,
				"expires_at": expiresAt, "revoked_at": revokedAt, "created_at": createdAt, "current": id == actor(r).SessionID})
		}
	}
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": nil})
}

func (s *Server) revokeOperatorSession(w http.ResponseWriter, r *http.Request) {
	sessionID := chi.URLParam(r, "session_id")
	result, err := s.app.DB.Exec(r.Context(), `UPDATE operator_sessions SET revoked_at=COALESCE(revoked_at,now())
WHERE id=$1 AND operator_id=$2 AND kind='operator'`, sessionID, actor(r).ID)
	if err != nil || result.RowsAffected() != 1 {
		kernel.WriteProblem(w, r, http.StatusNotFound, "operator_session_not_found", "The operator session was not found.")
		return
	}
	if sessionID == actor(r).SessionID {
		s.clearOperatorCookies(w)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) logoutAllOperatorSessions(w http.ResponseWriter, r *http.Request) {
	_, err := s.app.DB.Exec(r.Context(), `UPDATE operator_sessions SET revoked_at=COALESCE(revoked_at,now())
WHERE operator_id=$1 AND kind='operator'`, actor(r).ID)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "operator_logout_failed", "Operator sessions could not be revoked.")
		return
	}
	s.clearOperatorCookies(w)
	w.WriteHeader(http.StatusNoContent)
}

func requestIPAddress(r *http.Request) any {
	value := strings.TrimSpace(r.RemoteAddr)
	if host, _, err := net.SplitHostPort(value); err == nil {
		value = host
	}
	if net.ParseIP(value) == nil {
		return nil
	}
	return value
}
