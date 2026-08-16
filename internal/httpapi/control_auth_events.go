package httpapi

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/jackc/pgx/v5"
	"github.com/supaapps/platform93/internal/kernel"
)

func (s *Server) emitControlEvent(ctx context.Context, tx pgx.Tx, r *http.Request, eventType, subject string, data map[string]any) error {
	current := actor(r)
	actorData := map[string]any{"type": "system"}
	if current.ID != "" {
		actorData = map[string]any{"type": current.Type, "id": current.ID}
	}
	_, err := s.app.Emit(ctx, tx, nil, eventType, subject, actorData, data)
	return err
}

func insertControlAuthAudit(ctx context.Context, tx pgx.Tx, r *http.Request, actorID, action, targetType, targetID string, changes map[string]any) error {
	encoded, _ := json.Marshal(changes)
	_, err := tx.Exec(ctx, `INSERT INTO audit_records
(id,actor_type,actor_id,action,target_type,target_id,request_id,changes)
VALUES($1,'control_user',$2,$3,$4,$5,$6,$7)`, kernel.NewID(), actorID, action, targetType, targetID, kernel.RequestID(ctx), encoded)
	return err
}

func controlInvitationEventData(invitationID string, organizationID *string, controlUserID, role, method, status string) map[string]any {
	data := map[string]any{
		"invitation_id": invitationID, "organization_id": organizationID, "role": role,
		"onboarding_method": method, "status": status,
	}
	if controlUserID != "" {
		data["control_user_id"] = controlUserID
	}
	return data
}
