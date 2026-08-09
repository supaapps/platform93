package httpapi

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/supaapps/platform93/internal/kernel"
)

func (s *Server) retireOrganization(w http.ResponseWriter, r *http.Request) {
	organizationID := chi.URLParam(r, "organization_id")
	var version int64
	role, allowed := s.organizationManagementRole(r, organizationID)
	err := s.app.DB.QueryRow(r.Context(), `SELECT version FROM organizations WHERE id=$1 AND deleted_at IS NULL`, organizationID).Scan(&version)
	if err != nil || !allowed {
		kernel.WriteProblem(w, r, http.StatusNotFound, "organization_not_found", "The organization was not found.")
		return
	}
	if role != "owner" {
		kernel.WriteProblem(w, r, http.StatusForbidden, "organization_owner_required", "An organization owner is required to retire the organization.")
		return
	}
	if !kernel.CheckIfMatch(w, r, version) {
		return
	}
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "The organization could not be retired.")
		return
	}
	defer rollback(tx, r.Context())
	applicationIDs, err := activeApplicationIDs(r.Context(), tx, `SELECT id FROM applications
WHERE organization_id=$1 AND deleted_at IS NULL FOR UPDATE`, organizationID)
	if err == nil {
		command, commandErr := tx.Exec(r.Context(), `UPDATE organizations SET deleted_at=now(),version=version+1,updated_at=now()
WHERE id=$1 AND version=$2 AND deleted_at IS NULL`, organizationID, version)
		err = commandErr
		if err == nil && command.RowsAffected() != 1 {
			err = pgx.ErrNoRows
		}
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `UPDATE applications SET deleted_at=now(),version=version+1,updated_at=now()
WHERE organization_id=$1 AND deleted_at IS NULL`, organizationID)
	}
	if err == nil {
		err = revokeApplicationCredentials(r.Context(), tx, applicationIDs)
	}
	if err == nil {
		_, err = s.app.Emit(r.Context(), tx, nil, "organization.retired", "organization/"+organizationID, actor(r), map[string]any{"application_count": len(applicationIDs)})
	}
	if err == nil {
		err = emitApplicationLifecycle(r.Context(), s, tx, applicationIDs, "application.retired", "organization_retired", actor(r))
	}
	if err == nil {
		err = tx.Commit(r.Context())
	}
	if err != nil {
		slog.Error("organization retirement failed", "organization_id", organizationID, "error", err)
		kernel.WriteProblem(w, r, http.StatusConflict, "organization_retirement_conflict", "The organization changed concurrently or could not be retired.")
		return
	}
	w.Header().Set("ETag", kernel.ETag(version+1))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) restoreOrganization(w http.ResponseWriter, r *http.Request) {
	organizationID := chi.URLParam(r, "organization_id")
	var version int64
	role, allowed := s.organizationManagementRole(r, organizationID)
	err := s.app.DB.QueryRow(r.Context(), `SELECT version FROM organizations WHERE id=$1 AND deleted_at IS NOT NULL`, organizationID).Scan(&version)
	if err != nil || !allowed {
		kernel.WriteProblem(w, r, http.StatusNotFound, "retired_organization_not_found", "The retired organization was not found.")
		return
	}
	if role != "owner" {
		kernel.WriteProblem(w, r, http.StatusForbidden, "organization_owner_required", "An organization owner is required to restore the organization.")
		return
	}
	if !kernel.CheckIfMatch(w, r, version) {
		return
	}
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "The organization could not be restored.")
		return
	}
	defer rollback(tx, r.Context())
	result, err := tx.Exec(r.Context(), `UPDATE organizations SET deleted_at=NULL,version=version+1,updated_at=now()
WHERE id=$1 AND version=$2 AND deleted_at IS NOT NULL`, organizationID, version)
	if err == nil && result.RowsAffected() != 1 {
		err = pgx.ErrNoRows
	}
	if err == nil {
		_, err = s.app.Emit(r.Context(), tx, nil, "organization.restored", "organization/"+organizationID, actor(r), map[string]any{"descendants_restored": false})
	}
	if err == nil {
		err = tx.Commit(r.Context())
	}
	if err != nil {
		slog.Error("organization restoration failed", "organization_id", organizationID, "error", err)
		kernel.WriteProblem(w, r, http.StatusConflict, "organization_restore_conflict", "The organization changed concurrently.")
		return
	}
	w.Header().Set("ETag", kernel.ETag(version+1))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) retireApplication(w http.ResponseWriter, r *http.Request) {
	s.setApplicationRetirement(w, r, true)
}

func (s *Server) restoreApplication(w http.ResponseWriter, r *http.Request) {
	s.setApplicationRetirement(w, r, false)
}

func (s *Server) setApplicationRetirement(w http.ResponseWriter, r *http.Request, retire bool) {
	organizationID, applicationID := chi.URLParam(r, "organization_id"), chi.URLParam(r, "application_resource_id")
	parsedApplicationID, parseErr := uuid.Parse(applicationID)
	if parseErr != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "application_not_found", "The application was not found.")
		return
	}
	var version int64
	var deletedAt *time.Time
	role, allowed := s.organizationManagementRole(r, organizationID)
	err := s.app.DB.QueryRow(r.Context(), `SELECT e.version,e.deleted_at FROM applications e
JOIN organizations o ON o.id=e.organization_id WHERE e.id=$1 AND o.id=$2 AND o.deleted_at IS NULL`, applicationID, organizationID).Scan(&version, &deletedAt)
	if err != nil || !allowed || retire && deletedAt != nil || !retire && deletedAt == nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "application_not_found", "The requested application state was not found.")
		return
	}
	if role != "owner" && role != "admin" {
		kernel.WriteProblem(w, r, http.StatusForbidden, "organization_permission_required", "An organization owner or administrator is required.")
		return
	}
	if !kernel.CheckIfMatch(w, r, version) {
		return
	}
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "The application state could not be changed.")
		return
	}
	defer rollback(tx, r.Context())
	if retire {
		result, updateErr := tx.Exec(r.Context(), `UPDATE applications SET deleted_at=now(),version=version+1,updated_at=now() WHERE id=$1 AND version=$2 AND deleted_at IS NULL`, applicationID, version)
		err = updateErr
		if err == nil && result.RowsAffected() != 1 {
			err = pgx.ErrNoRows
		}
		if err == nil {
			err = revokeApplicationCredentials(r.Context(), tx, []uuid.UUID{parsedApplicationID})
		}
	} else {
		result, updateErr := tx.Exec(r.Context(), `UPDATE applications SET deleted_at=NULL,version=version+1,updated_at=now() WHERE id=$1 AND version=$2 AND deleted_at IS NOT NULL`, applicationID, version)
		err = updateErr
		if err == nil && result.RowsAffected() != 1 {
			err = pgx.ErrNoRows
		}
	}
	if err == nil {
		event := "application.restored"
		if retire {
			event = "application.retired"
		}
		reason := "application_restored"
		if retire {
			reason = "application_retired"
		}
		_, err = s.app.Emit(r.Context(), tx, &parsedApplicationID, event, "application/"+applicationID, actor(r), map[string]any{"organization_id": organizationID, "reason": reason})
	}
	if err == nil {
		err = tx.Commit(r.Context())
	}
	if err != nil {
		slog.Error("application lifecycle update failed", "application_id", applicationID, "retire", retire, "error", err)
		kernel.WriteProblem(w, r, http.StatusConflict, "application_state_conflict", "The application changed concurrently or could not be updated.")
		return
	}
	w.Header().Set("ETag", kernel.ETag(version+1))
	w.WriteHeader(http.StatusNoContent)
}

func activeApplicationIDs(ctx context.Context, tx pgx.Tx, query string, argument any) ([]uuid.UUID, error) {
	rows, err := tx.Query(ctx, query, argument)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := []uuid.UUID{}
	for rows.Next() {
		var id uuid.UUID
		if err = rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func revokeApplicationCredentials(ctx context.Context, tx pgx.Tx, applicationIDs []uuid.UUID) error {
	if len(applicationIDs) == 0 {
		return nil
	}
	commands := []string{
		`UPDATE user_sessions SET revoked_at=COALESCE(revoked_at,now()) WHERE application_id=ANY($1) AND revoked_at IS NULL`,
		`UPDATE personal_api_keys SET revoked_at=COALESCE(revoked_at,now()) WHERE application_id=ANY($1) AND revoked_at IS NULL`,
		`UPDATE delegations SET revoked_at=COALESCE(revoked_at,now()) WHERE application_id=ANY($1) AND revoked_at IS NULL`,
		`UPDATE oauth_sessions SET active=false,updated_at=now() WHERE application_id=ANY($1) AND active`,
	}
	for _, command := range commands {
		if _, err := tx.Exec(ctx, command, applicationIDs); err != nil {
			return err
		}
	}
	return nil
}

func emitApplicationLifecycle(ctx context.Context, s *Server, tx pgx.Tx, applicationIDs []uuid.UUID, eventType, reason string, current kernel.Actor) error {
	for _, applicationID := range applicationIDs {
		var organizationID string
		if err := tx.QueryRow(ctx, "SELECT organization_id FROM applications WHERE id=$1", applicationID).Scan(&organizationID); err != nil {
			return err
		}
		if _, err := s.app.Emit(ctx, tx, &applicationID, eventType, "application/"+applicationID.String(), current, map[string]any{"organization_id": organizationID, "reason": reason}); err != nil {
			return err
		}
	}
	return nil
}
