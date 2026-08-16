package httpapi

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/supaapps/platform93/internal/platform"
)

// RunLifecycleSweep records time-driven transitions exactly once and emits their
// events in the same transaction as the state marker.
func RunLifecycleSweep(ctx context.Context, app *platform.App) error {
	for range 100 {
		processed, err := expireInvitation(ctx, app)
		if err != nil {
			return err
		}
		if !processed {
			break
		}
	}
	for range 100 {
		processed, err := expireEntitlement(ctx, app)
		if err != nil {
			return err
		}
		if !processed {
			break
		}
	}
	return nil
}

func expireInvitation(ctx context.Context, app *platform.App) (bool, error) {
	tx, err := app.DB.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	var invitationID string
	var applicationID uuid.UUID
	var workspaceID *string
	err = tx.QueryRow(ctx, `SELECT id,application_id,workspace_id FROM application_invitations
WHERE accepted_at IS NULL AND revoked_at IS NULL AND expiration_recorded_at IS NULL AND expires_at<=now()
ORDER BY expires_at,id FOR UPDATE SKIP LOCKED LIMIT 1`).Scan(&invitationID, &applicationID, &workspaceID)
	if err == pgx.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if _, err = tx.Exec(ctx, `UPDATE application_invitations SET expiration_recorded_at=now(),updated_at=now() WHERE id=$1`, invitationID); err != nil {
		return false, err
	}
	if _, err = app.Emit(ctx, tx, &applicationID, "application_invitation.expired", "application_invitation/"+invitationID, map[string]any{"type": "worker"}, map[string]any{"invitation_id": invitationID, "workspace_id": workspaceID, "status": "expired"}); err != nil {
		return false, err
	}
	return true, tx.Commit(ctx)
}

func expireEntitlement(ctx context.Context, app *platform.App) (bool, error) {
	tx, err := app.DB.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	var grantID, subjectType, subjectID string
	var applicationID uuid.UUID
	var externalReference *string
	err = tx.QueryRow(ctx, `SELECT g.id,g.application_id,g.subject_type,g.subject_id,g.external_reference
FROM entitlement_grants g LEFT JOIN LATERAL (
  SELECT action,expires_at FROM entitlement_grant_actions WHERE grant_id=g.id ORDER BY created_at DESC,id DESC LIMIT 1
) latest ON true
WHERE g.expiration_recorded_at IS NULL AND COALESCE(latest.expires_at,g.expires_at)<=now()
AND COALESCE(latest.action,'active')<>'revoked'
ORDER BY COALESCE(latest.expires_at,g.expires_at),g.id FOR UPDATE OF g SKIP LOCKED LIMIT 1`).Scan(&grantID, &applicationID, &subjectType, &subjectID, &externalReference)
	if err == pgx.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if _, err = tx.Exec(ctx, `UPDATE entitlement_grants SET expiration_recorded_at=now() WHERE id=$1`, grantID); err != nil {
		return false, err
	}
	actor := map[string]any{"type": "worker"}
	data := map[string]any{"grant_id": grantID, "subject_type": subjectType, "subject_id": subjectID, "external_reference": externalReference, "status": "expired"}
	if _, err = app.Emit(ctx, tx, &applicationID, "entitlement.expired", "entitlement/"+grantID, actor, data); err != nil {
		return false, err
	}
	if _, err = app.Emit(ctx, tx, &applicationID, "entitlement.effective_changed", subjectType+"/"+subjectID, actor, data); err != nil {
		return false, err
	}
	return true, tx.Commit(ctx)
}
