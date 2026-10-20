package httpapi

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/supaapps/platform93/internal/kernel"
)

func (s *Server) listApplicationManagedSessions(w http.ResponseWriter, r *http.Request) {
	tx, _, ok := s.beginApplicationAdministration(w, r, "users:sessions:read", false)
	if !ok {
		return
	}
	defer rollback(tx, r.Context())
	app, user := chi.URLParam(r, "application_id"), chi.URLParam(r, "user_id")
	var exists bool
	if err := tx.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM users WHERE application_id=$1 AND id=$2)`, app, user).Scan(&exists); err != nil || !exists {
		kernel.WriteProblem(w, r, 404, "user_not_found", "The user was not found.")
		return
	}
	params := r.URL.Query()
	if !params.Has("limit") {
		params.Set("limit", "20")
	}
	r.URL.RawQuery = params.Encode()
	query, args, limit, ok := referenceSearch(w, r, `SELECT id,user_agent,authenticated_at,mfa_authenticated_at,amr,delegation_id::text,expires_at,last_used_at,revoked_at,created_at FROM user_sessions WHERE application_id=$1 AND user_id=$2`, []any{app, user}, "id", "user_agent")
	if !ok {
		return
	}
	rows, err := tx.Query(r.Context(), query, args...)
	if err != nil {
		kernel.WriteProblem(w, r, 503, "sessions_unavailable", "User sessions could not be loaded.")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id string
		var agent, delegation *string
		var authenticated, expires, created time.Time
		var mfa, lastUsed, revoked *time.Time
		var amr []string
		if err = rows.Scan(&id, &agent, &authenticated, &mfa, &amr, &delegation, &expires, &lastUsed, &revoked, &created); err != nil {
			break
		}
		items = append(items, map[string]any{"id": id, "user_agent": agent, "authenticated_at": authenticated, "mfa_authenticated_at": mfa, "amr": amr, "delegation_id": delegation, "expires_at": expires, "last_used_at": lastUsed, "revoked_at": revoked, "created_at": created})
	}
	if err != nil || rows.Err() != nil {
		kernel.WriteProblem(w, r, 503, "sessions_unavailable", "User sessions could not be loaded.")
		return
	}
	items, cursor := referencePage(items, limit, func(item map[string]any) string { return item["id"].(string) })
	kernel.WriteJSON(w, 200, map[string]any{"items": items, "next_cursor": cursor})
}
