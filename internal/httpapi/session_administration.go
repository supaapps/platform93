package httpapi

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/supaapps/platform93/internal/kernel"
)

func (s *Server) adminListUserSessions(w http.ResponseWriter, r *http.Request) {
	items, err := s.userSessions(r, chi.URLParam(r, "user_id"))
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "User sessions could not be loaded.")
		return
	}
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": nil})
}

func (s *Server) adminRevokeUserSessions(w http.ResponseWriter, r *http.Request) {
	result, err := s.app.DB.Exec(r.Context(), `UPDATE user_sessions SET revoked_at=COALESCE(revoked_at,now())
WHERE application_id=$1 AND user_id=$2 AND revoked_at IS NULL`, chi.URLParam(r, "application_id"), chi.URLParam(r, "user_id"))
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "session_revocation_failed", "User sessions could not be revoked.")
		return
	}
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"revoked_sessions": result.RowsAffected()})
}

func (s *Server) userSessions(r *http.Request, userID string) ([]map[string]any, error) {
	rows, err := s.app.DB.Query(r.Context(), `SELECT s.id,s.user_agent,s.authenticated_at,s.mfa_authenticated_at,s.amr,
s.delegation_id,s.expires_at,s.last_used_at,s.revoked_at,s.created_at
FROM user_sessions s JOIN users u ON u.id=s.user_id WHERE s.application_id=$1 AND s.user_id=$2 AND u.application_id=s.application_id
ORDER BY s.created_at DESC,s.id DESC`, chi.URLParam(r, "application_id"), userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id string
		var userAgent, delegationID *string
		var authenticatedAt, expiresAt, createdAt time.Time
		var mfaAt, lastUsedAt, revokedAt *time.Time
		var amr []string
		if rows.Scan(&id, &userAgent, &authenticatedAt, &mfaAt, &amr, &delegationID, &expiresAt, &lastUsedAt, &revokedAt, &createdAt) == nil {
			items = append(items, map[string]any{"id": id, "user_agent": userAgent, "authenticated_at": authenticatedAt,
				"mfa_authenticated_at": mfaAt, "amr": amr, "delegation_id": delegationID,
				"expires_at": expiresAt, "last_used_at": lastUsedAt, "revoked_at": revokedAt, "created_at": createdAt})
		}
	}
	return items, rows.Err()
}

func (s *Server) adminListUserAddresses(w http.ResponseWriter, r *http.Request) {
	items, err := s.userAddresses(r, chi.URLParam(r, "user_id"))
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "User addresses could not be loaded.")
		return
	}
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": nil})
}

func (s *Server) userAddresses(r *http.Request, userID string) ([]map[string]any, error) {
	rows, err := s.app.DB.Query(r.Context(), `SELECT a.id,a.name,a.line1,a.line2,a.city,a.region,a.postal_code,a.country_code,bp.tax_id,a.is_active,a.version,a.created_at,a.updated_at
FROM addresses a JOIN billing_profiles bp ON bp.id=a.billing_profile_id
WHERE a.application_id=$1 AND bp.application_id=$1 AND bp.subject_type='user' AND bp.subject_id=$2
ORDER BY a.is_active DESC,a.created_at DESC`, chi.URLParam(r, "application_id"), userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, name, line1, line2, city, region, postal, country string
		var taxID *string
		var active bool
		var version int64
		var createdAt, updatedAt time.Time
		if rows.Scan(&id, &name, &line1, &line2, &city, &region, &postal, &country, &taxID, &active, &version, &createdAt, &updatedAt) == nil {
			items = append(items, map[string]any{"id": id, "name": name, "line1": line1, "line2": line2, "city": city, "region": region,
				"postal_code": postal, "country_code": country, "tax_id": taxID, "active": active, "version": version,
				"created_at": createdAt, "updated_at": updatedAt})
		}
	}
	return items, rows.Err()
}

func (s *Server) adminListOAuthConsents(w http.ResponseWriter, r *http.Request) {
	s.writeOAuthConsents(w, r, "")
}

func (s *Server) listMyOAuthConsents(w http.ResponseWriter, r *http.Request) {
	s.writeOAuthConsents(w, r, actor(r).ID)
}

func (s *Server) writeOAuthConsents(w http.ResponseWriter, r *http.Request, userID string) {
	var userFilter *string
	if userID != "" {
		userFilter = &userID
	}
	rows, err := s.app.DB.Query(r.Context(), `SELECT c.user_id,u.email,c.client_id,cl.client_id,cl.name,c.scopes,
c.granted_at,c.updated_at,c.revoked_at FROM oauth_consents c JOIN users u ON u.id=c.user_id JOIN clients cl ON cl.id=c.client_id
WHERE c.application_id=$1 AND ($2::uuid IS NULL OR c.user_id=$2::uuid) ORDER BY c.updated_at DESC,c.user_id,c.client_id`,
		chi.URLParam(r, "application_id"), userFilter)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "OAuth consents could not be loaded.")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var consentUserID, email, clientDatabaseID, clientID, clientName string
		var scopes []string
		var grantedAt, updatedAt time.Time
		var revokedAt *time.Time
		if rows.Scan(&consentUserID, &email, &clientDatabaseID, &clientID, &clientName, &scopes, &grantedAt, &updatedAt, &revokedAt) == nil {
			items = append(items, map[string]any{"user_id": consentUserID, "user_email": email, "client_id": clientDatabaseID,
				"client_key": clientID, "client_name": clientName, "scopes": scopes, "granted_at": grantedAt,
				"updated_at": updatedAt, "revoked_at": revokedAt, "active": revokedAt == nil})
		}
	}
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": nil})
}

func (s *Server) adminRevokeOAuthConsent(w http.ResponseWriter, r *http.Request) {
	s.revokeOAuthConsent(w, r, chi.URLParam(r, "user_id"), chi.URLParam(r, "client_id"))
}

func (s *Server) revokeMyOAuthConsent(w http.ResponseWriter, r *http.Request) {
	s.revokeOAuthConsent(w, r, actor(r).ID, chi.URLParam(r, "client_id"))
}

func (s *Server) revokeOAuthConsent(w http.ResponseWriter, r *http.Request, userID, clientDatabaseID string) {
	applicationID, err := uuid.Parse(chi.URLParam(r, "application_id"))
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusBadRequest, "invalid_application_id", "The application identifier is invalid.")
		return
	}
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "The OAuth consent could not be revoked.")
		return
	}
	defer rollback(tx, r.Context())
	var clientKey string
	err = tx.QueryRow(r.Context(), `UPDATE oauth_consents c SET revoked_at=COALESCE(revoked_at,now()),updated_at=now()
FROM clients cl WHERE c.application_id=$1 AND c.user_id=$2 AND c.client_id=$3 AND cl.id=c.client_id RETURNING cl.client_id`,
		applicationID, userID, clientDatabaseID).Scan(&clientKey)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "oauth_consent_not_found", "The OAuth consent was not found.")
		return
	}
	_, err = tx.Exec(r.Context(), `UPDATE oauth_sessions SET active=false,updated_at=now()
WHERE application_id=$1 AND request_payload->>'client_id'=$2 AND request_payload->'session'->>'subject'=$3`,
		applicationID, clientKey, userID)
	if err == nil {
		_, err = s.app.Emit(r.Context(), tx, &applicationID, "oauth.consent_revoked", "oauth_consent/"+userID+"/"+clientDatabaseID,
			actor(r), map[string]any{"user_id": userID, "client_id": clientDatabaseID, "client_key": clientKey})
	}
	if err != nil || tx.Commit(r.Context()) != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "oauth_consent_revocation_failed", "The OAuth consent could not be revoked.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
