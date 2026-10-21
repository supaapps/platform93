package httpapi

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/supaapps/platform93/internal/kernel"
)

// The caller holds the user row lock and has consumed a fresh, invitation-bound
// mailbox proof in this transaction. Established verified accounts never use it.
func (s *Server) recoverInvitationCredentials(r *http.Request, tx pgx.Tx, user, invitation string) error {
	app := chi.URLParam(r, "application_id")
	for _, query := range []string{
		`UPDATE users SET password_hash=NULL,email_verified_at=now(),authentication_epoch=authentication_epoch+1,version=version+1,updated_at=now() WHERE application_id=$1 AND id=$2`,
		`DELETE FROM oauth_consents WHERE application_id=$1 AND user_id=$2`,
		`UPDATE oauth_connections SET revoked_at=COALESCE(revoked_at,now()),version=version+1,updated_at=now() WHERE application_id=$1 AND user_id=$2 AND revoked_at IS NULL`,
		`UPDATE user_sessions SET revoked_at=COALESCE(revoked_at,now()) WHERE application_id=$1 AND user_id=$2`,
		`UPDATE oauth_sessions SET active=false,updated_at=now() WHERE application_id=$1 AND request_payload->'session'->>'subject'=$2::text`,
		`UPDATE personal_api_keys SET revoked_at=COALESCE(revoked_at,now()) WHERE application_id=$1 AND user_id=$2`,
		`UPDATE delegations SET revoked_at=COALESCE(revoked_at,now()) WHERE application_id=$1 AND user_id=$2`,
		`UPDATE user_authentication_methods SET status='disabled',disabled_at=COALESCE(disabled_at,now()),secret_ciphertext=NULL,credential_ciphertext=NULL WHERE application_id=$1 AND user_id=$2`,
		`DELETE FROM user_recovery_codes WHERE application_id=$1 AND user_id=$2`,
		`UPDATE webauthn_ceremonies SET consumed_at=COALESCE(consumed_at,now()) WHERE application_id=$1 AND user_id=$2`,
		`UPDATE mfa_login_challenges SET consumed_at=COALESCE(consumed_at,now()) WHERE application_id=$1 AND user_id=$2`,
		`UPDATE login_challenges SET consumed_at=COALESCE(consumed_at,now()) WHERE application_id=$1 AND (requested_by_user_id=$2 OR normalized_email=(SELECT normalized_email FROM users WHERE application_id=$1 AND id=$2))`,
		`UPDATE external_auth_challenges SET consumed_at=COALESCE(consumed_at,now()),locked_until=NULL WHERE application_id=$1 AND requested_by_user_id=$2`,
		`UPDATE external_auth_exchanges SET consumed_at=COALESCE(consumed_at,now()) WHERE application_id=$1 AND user_id=$2`,
		`UPDATE invitation_authorization_codes SET expires_at=LEAST(expires_at,now()) WHERE application_id=$1 AND user_id=$2 AND used_at IS NULL`,
		`UPDATE invitation_email_challenges SET consumed_at=COALESCE(consumed_at,now()) WHERE application_id=$1 AND invitation_id IN (SELECT id FROM application_invitations WHERE application_id=$1 AND normalized_email=(SELECT normalized_email FROM users WHERE application_id=$1 AND id=$2))`,
		`UPDATE external_auth_email_enrollments SET consumed_at=COALESCE(consumed_at,now()) WHERE application_id=$1 AND normalized_email=(SELECT normalized_email FROM users WHERE application_id=$1 AND id=$2)`,
		`DELETE FROM user_identities WHERE application_id=$1 AND user_id=$2`,
	} {
		if _, err := tx.Exec(r.Context(), query, app, user); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(r.Context(), `INSERT INTO audit_records(id,application_id,actor_type,actor_id,action,target_type,target_id,reason,request_id,changes)
 VALUES($1,$2,'user',$3,'user.credentials_recovered','user',$3,'Independent mailbox proof during invitation acceptance',$4,jsonb_build_object('invitation_id',$5::text))`, kernel.NewID(), app, user, kernel.RequestID(r.Context()), invitation); err != nil {
		return err
	}
	applicationID := uuid.MustParse(app)
	_, err := s.app.Emit(r.Context(), tx, &applicationID, "user.updated", "user/"+user,
		map[string]any{"type": "user", "id": user}, map[string]any{"user_id": user, "changed_fields": []string{"password", "identities", "authentication_methods", "sessions", "email_verified", "oauth_consents"}})
	return err
}
