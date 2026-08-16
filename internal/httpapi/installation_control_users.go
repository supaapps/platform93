package httpapi

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/supaapps/platform93/internal/kernel"
)

func (s *Server) listInstallationControlUsers(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.installationRole(r); !ok {
		kernel.WriteProblem(w, r, http.StatusForbidden, "installation_role_required", "An installation role is required.")
		return
	}
	rows, err := s.app.DB.Query(r.Context(), `SELECT o.id,o.email,o.display_name,o.status,ir.role,ir.created_at,ir.updated_at
FROM installation_control_user_roles ir JOIN control_users o ON o.id=ir.control_user_id ORDER BY ir.created_at,o.id`)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "Platform users could not be loaded.")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, email, displayName, status, role string
		var createdAt, updatedAt time.Time
		if rows.Scan(&id, &email, &displayName, &status, &role, &createdAt, &updatedAt) == nil {
			items = append(items, map[string]any{"id": id, "email": email, "display_name": displayName, "status": status, "role": role, "created_at": createdAt, "updated_at": updatedAt})
		}
	}
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": nil})
}

func (s *Server) createInstallationControlUser(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Email       string `json:"email"`
		DisplayName string `json:"display_name"`
		Role        string `json:"role"`
	}
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	callerRole, allowed := s.installationRole(r)
	if !allowed || callerRole != "owner" && callerRole != "admin" || request.Role == "owner" && callerRole != "owner" {
		kernel.WriteProblem(w, r, http.StatusForbidden, "installation_permission_required", "The Platform user cannot assign this installation role.")
		return
	}
	request.Email = kernel.NormalizeEmail(request.Email)
	if !strings.Contains(request.Email, "@") || !validInstallationRole(request.Role) {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_installation_control_user", "Email and installation role must be valid.")
		return
	}
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "The Platform user could not be created.")
		return
	}
	defer rollback(tx, r.Context())
	var controlUserID string
	err = tx.QueryRow(r.Context(), `INSERT INTO control_users(id,email,normalized_email,display_name)
VALUES($1,$2,$2,$3) ON CONFLICT(normalized_email) DO UPDATE SET
display_name=CASE WHEN EXCLUDED.display_name='' THEN control_users.display_name ELSE EXCLUDED.display_name END
RETURNING id`, kernel.NewID(), request.Email, truncate(request.DisplayName, 200)).Scan(&controlUserID)
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO installation_control_user_roles(control_user_id,role) VALUES($1,$2)
ON CONFLICT(control_user_id) DO UPDATE SET role=EXCLUDED.role,updated_at=now()`, controlUserID, request.Role)
	}
	if err != nil || tx.Commit(r.Context()) != nil {
		kernel.WriteProblem(w, r, http.StatusConflict, "installation_control_user_conflict", "The Platform user could not be created.")
		return
	}
	kernel.WriteJSON(w, http.StatusCreated, map[string]any{"id": controlUserID, "email": request.Email, "display_name": request.DisplayName, "role": request.Role})
}

func (s *Server) updateInstallationControlUser(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Role string `json:"role"`
	}
	if !kernel.DecodeJSON(w, r, &request) || !validInstallationRole(request.Role) {
		return
	}
	callerRole, allowed := s.installationRole(r)
	if !allowed || callerRole != "owner" && callerRole != "admin" || request.Role == "owner" && callerRole != "owner" {
		kernel.WriteProblem(w, r, http.StatusForbidden, "installation_permission_required", "The Platform user cannot assign this installation role.")
		return
	}
	controlUserID := chi.URLParam(r, "control_user_id")
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		return
	}
	defer rollback(tx, r.Context())
	var currentRole string
	err = tx.QueryRow(r.Context(), `SELECT role FROM installation_control_user_roles WHERE control_user_id=$1 FOR UPDATE`, controlUserID).Scan(&currentRole)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "installation_control_user_not_found", "The Platform user was not found.")
		return
	}
	if currentRole == "owner" && request.Role != "owner" && !installationHasAnotherActiveOwner(r, tx, controlUserID) {
		kernel.WriteProblem(w, r, http.StatusConflict, "last_installation_owner", "The final active installation owner cannot be demoted.")
		return
	}
	_, err = tx.Exec(r.Context(), `UPDATE installation_control_user_roles SET role=$1,updated_at=now() WHERE control_user_id=$2`, request.Role, controlUserID)
	if err != nil || tx.Commit(r.Context()) != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "installation_control_user_update_failed", "The Platform user could not be updated.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) deleteInstallationControlUser(w http.ResponseWriter, r *http.Request) {
	callerRole, allowed := s.installationRole(r)
	if !allowed || callerRole != "owner" && callerRole != "admin" {
		kernel.WriteProblem(w, r, http.StatusForbidden, "installation_permission_required", "The Platform user cannot remove installation roles.")
		return
	}
	controlUserID := chi.URLParam(r, "control_user_id")
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		return
	}
	defer rollback(tx, r.Context())
	var currentRole string
	err = tx.QueryRow(r.Context(), `SELECT role FROM installation_control_user_roles WHERE control_user_id=$1 FOR UPDATE`, controlUserID).Scan(&currentRole)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "installation_control_user_not_found", "The Platform user was not found.")
		return
	}
	if currentRole == "owner" && callerRole != "owner" {
		kernel.WriteProblem(w, r, http.StatusForbidden, "installation_permission_required", "Only an installation owner can remove another owner.")
		return
	}
	if currentRole == "owner" && !installationHasAnotherActiveOwner(r, tx, controlUserID) {
		kernel.WriteProblem(w, r, http.StatusConflict, "last_installation_owner", "The final active installation owner cannot be removed.")
		return
	}
	_, err = tx.Exec(r.Context(), `DELETE FROM installation_control_user_roles WHERE control_user_id=$1`, controlUserID)
	if err == nil {
		_, err = tx.Exec(r.Context(), `UPDATE control_user_sessions SET revoked_at=COALESCE(revoked_at,now()) WHERE control_user_id=$1`, controlUserID)
	}
	if err != nil || tx.Commit(r.Context()) != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "installation_control_user_removal_failed", "The installation role could not be removed.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) installationRole(r *http.Request) (string, bool) {
	var role string
	err := s.app.DB.QueryRow(r.Context(), `SELECT ir.role FROM installation_control_user_roles ir
JOIN control_users o ON o.id=ir.control_user_id WHERE ir.control_user_id=$1 AND o.status='active'`, actor(r).ID).Scan(&role)
	return role, err == nil
}

func installationHasAnotherActiveOwner(r *http.Request, tx interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, controlUserID string) bool {
	var exists bool
	_ = tx.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM installation_control_user_roles ir
JOIN control_users o ON o.id=ir.control_user_id WHERE ir.role='owner' AND ir.control_user_id<>$1 AND o.status='active')`, controlUserID).Scan(&exists)
	return exists
}

func validInstallationRole(value string) bool {
	return value == "owner" || value == "admin" || value == "auditor"
}
