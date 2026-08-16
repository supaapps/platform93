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

func (s *Server) refreshControlUserSession(w http.ResponseWriter, r *http.Request) {
	var request struct {
		RefreshToken string `json:"refresh_token"`
	}
	if cookie, cookieErr := r.Cookie("p93_control_refresh"); cookieErr == nil {
		request.RefreshToken = cookie.Value
	}
	if r.Body != nil && r.ContentLength != 0 {
		_ = json.NewDecoder(r.Body).Decode(&request)
	}
	if request.RefreshToken == "" {
		kernel.WriteProblem(w, r, http.StatusUnauthorized, "control_user_refresh_required", "A Platform user refresh credential is required.")
		return
	}
	token, err := secure.RandomToken("p93_control_refresh_", 32)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "credential_generation_failed", "The Platform user session could not be rotated.")
		return
	}
	expiresAt := s.app.Now().Add(12 * time.Hour)
	var sessionID, controlUserID string
	err = s.app.DB.QueryRow(r.Context(), `UPDATE control_user_sessions SET refresh_digest=$1,expires_at=$2,last_used_at=now(),ip_address=$3,user_agent=$4
WHERE refresh_digest=$5 AND kind='control' AND revoked_at IS NULL AND expires_at>now()
RETURNING id,control_user_id`, s.app.Vault.Digest(token), expiresAt, requestIPAddress(r), truncate(r.UserAgent(), 500), s.app.Vault.Digest(request.RefreshToken)).Scan(&sessionID, &controlUserID)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusUnauthorized, "invalid_control_user_session", "The Platform user session could not be refreshed.")
		return
	}
	access, err := s.issueControlUserAccess(r.Context(), controlUserID, sessionID, "control")
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "control_user_token_failed", "The Platform user access token could not be issued.")
		return
	}
	s.setControlUserCookies(w, access, token, 12*time.Hour)
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"access_token": access, "refresh_token": token, "token_type": "Bearer", "expires_in": 300, "refresh_expires_at": expiresAt})
}

func (s *Server) listControlUserSessions(w http.ResponseWriter, r *http.Request) {
	rows, err := s.app.DB.Query(r.Context(), `SELECT id,ip_address::text,user_agent,authenticated_at,amr,last_used_at,expires_at,revoked_at,created_at
FROM control_user_sessions WHERE control_user_id=$1 AND kind='control' ORDER BY created_at DESC,id DESC LIMIT 101`, actor(r).ID)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "Platform user sessions could not be loaded.")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, userAgent string
		var ipAddress *string
		var authenticatedAt, lastUsedAt, expiresAt, createdAt time.Time
		var amr []string
		var revokedAt *time.Time
		if rows.Scan(&id, &ipAddress, &userAgent, &authenticatedAt, &amr, &lastUsedAt, &expiresAt, &revokedAt, &createdAt) == nil {
			items = append(items, map[string]any{"id": id, "ip_address": ipAddress, "user_agent": userAgent, "last_used_at": lastUsedAt,
				"authenticated_at": authenticatedAt, "amr": amr, "expires_at": expiresAt, "revoked_at": revokedAt, "created_at": createdAt, "current": id == actor(r).SessionID})
		}
	}
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": nil})
}

func (s *Server) revokeControlUserSession(w http.ResponseWriter, r *http.Request) {
	sessionID := chi.URLParam(r, "session_id")
	result, err := s.app.DB.Exec(r.Context(), `UPDATE control_user_sessions SET revoked_at=COALESCE(revoked_at,now())
WHERE id=$1 AND control_user_id=$2 AND kind='control'`, sessionID, actor(r).ID)
	if err != nil || result.RowsAffected() != 1 {
		kernel.WriteProblem(w, r, http.StatusNotFound, "control_user_session_not_found", "The Platform user session was not found.")
		return
	}
	if sessionID == actor(r).SessionID {
		s.clearControlUserCookies(w)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) logoutAllControlUserSessions(w http.ResponseWriter, r *http.Request) {
	_, err := s.app.DB.Exec(r.Context(), `UPDATE control_user_sessions SET revoked_at=COALESCE(revoked_at,now())
WHERE control_user_id=$1 AND kind='control'`, actor(r).ID)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "control_user_logout_failed", "Platform user sessions could not be revoked.")
		return
	}
	s.clearControlUserCookies(w)
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
