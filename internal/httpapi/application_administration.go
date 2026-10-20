package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/mail"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	platformauthz "github.com/supaapps/platform93/internal/authorization"
	"github.com/supaapps/platform93/internal/kernel"
)

// Administration always intersects the issued token with current authority.
// These checks deliberately do not change ordinary offline application tokens.
func (s *Server) applicationAdminScopes(r *http.Request, tx pgx.Tx, current kernel.Actor, requireSession ...bool) ([]string, error) {
	app := chi.URLParam(r, "application_id")
	if current.ApplicationID != app || current.DelegatedBy != "" || (current.Type != "user" && current.Type != "client") {
		return nil, fmt.Errorf("direct application actor required")
	}
	var active bool
	if current.Type == "user" {
		sessionRequired := len(requireSession) == 0 || requireSession[0]
		err := tx.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM users u JOIN applications a ON a.id=u.application_id WHERE u.application_id=$1 AND u.id=$2 AND u.status='active' AND a.deleted_at IS NULL AND (NOT $4::boolean OR EXISTS(SELECT 1 FROM user_sessions us WHERE us.user_id=u.id AND us.application_id=u.application_id AND us.id=$3 AND us.revoked_at IS NULL AND us.expires_at>now() AND us.delegation_id IS NULL)))`, app, current.ID, nullableActorID(current.SessionID), sessionRequired).Scan(&active)
		if err != nil || !active {
			return nil, fmt.Errorf("inactive administration session")
		}
	} else {
		err := tx.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM clients c JOIN applications a ON a.id=c.application_id WHERE c.application_id=$1 AND c.id=$2 AND c.disabled_at IS NULL AND NOT c.resource_only AND a.deleted_at IS NULL)`, app, current.ID).Scan(&active)
		if err != nil || !active {
			return nil, fmt.Errorf("inactive administration client")
		}
	}
	rows, err := tx.Query(r.Context(), `SELECT ro.permissions,ra.workspace_id::text FROM role_assignments ra JOIN roles ro ON ro.id=ra.role_id AND ro.application_id=ra.application_id WHERE ra.application_id=$1 AND (($3='user' AND ra.user_id=$2) OR ($3='client' AND ra.client_id=$2)) FOR SHARE OF ra,ro`, app, current.ID, current.Type)
	if err != nil {
		return nil, err
	}
	var scopes []string
	for rows.Next() {
		var permissions []string
		var workspace *string
		if err = rows.Scan(&permissions, &workspace); err != nil {
			break
		}
		for _, p := range permissions {
			var scope string
			scope, err = platformauthz.CanonicalScope(app, workspace, p)
			if err != nil {
				break
			}
			scopes = append(scopes, scope)
		}
		if err != nil {
			break
		}
	}
	rows.Close()
	if err != nil {
		return nil, err
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	rows, err = tx.Query(r.Context(), `SELECT permission,canonical_scope,workspace_id::text FROM permission_grants WHERE application_id=$1 AND (($3='user' AND user_id=$2) OR ($3='client' AND client_id=$2)) AND revoked_at IS NULL FOR SHARE`, app, current.ID, current.Type)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var p, scope string
		var workspace *string
		if err = rows.Scan(&p, &scope, &workspace); err != nil {
			break
		}
		var canonical string
		canonical, err = platformauthz.CanonicalScope(app, workspace, p)
		if err != nil || canonical != scope {
			err = fmt.Errorf("invalid persisted grant")
			break
		}
		scopes = append(scopes, scope)
	}
	rows.Close()
	if err != nil {
		return nil, err
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	if current.Type == "user" {
		rows, err = tx.Query(r.Context(), `SELECT id::text FROM workspaces WHERE application_id=$1 AND owner_user_id=$2 AND deleted_at IS NULL FOR SHARE`, app, current.ID)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var id string
			if err = rows.Scan(&id); err != nil {
				break
			}
			scope, e := platformauthz.CanonicalScope(app, &id, "*")
			if e != nil {
				err = e
				break
			}
			scopes = append(scopes, scope)
		}
		rows.Close()
		if err != nil {
			return nil, err
		}
		if err = rows.Err(); err != nil {
			return nil, err
		}
	}
	return scopes, nil
}

func administrationAllows(current kernel.Actor, live []string, scope string) bool {
	return actorHasPermission(current, scope) && containsAllowedScope(live, scope)
}

func (s *Server) beginApplicationAdministration(w http.ResponseWriter, r *http.Request, permission string, sensitive bool) (pgx.Tx, []string, bool) {
	w.Header().Set("Cache-Control", "no-store")
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		kernel.WriteProblem(w, r, 503, "administration_unavailable", "User administration is unavailable.")
		return nil, nil, false
	}
	live, err := s.applicationAdminScopes(r, tx, actor(r))
	scope, e := platformauthz.CanonicalScope(chi.URLParam(r, "application_id"), nil, permission)
	if err != nil || e != nil || !administrationAllows(actor(r), live, scope) {
		_ = tx.Rollback(r.Context())
		kernel.WriteProblem(w, r, 403, "application_administration_forbidden", "The application administration permission is not available.")
		return nil, nil, false
	}
	if sensitive && actor(r).Type == "user" {
		var recent bool
		err = tx.QueryRow(r.Context(), `SELECT authenticated_at>now()-interval '10 minutes' FROM user_sessions WHERE id=$1 AND application_id=$2 AND user_id=$3`, actor(r).SessionID, chi.URLParam(r, "application_id"), actor(r).ID).Scan(&recent)
		if err != nil || !recent {
			_ = tx.Rollback(r.Context())
			kernel.WriteProblem(w, r, 403, "recent_authentication_required", "Authentication within the last ten minutes is required.")
			return nil, nil, false
		}
	}
	return tx, live, true
}

func administrationReason(w http.ResponseWriter, r *http.Request, reason string) bool {
	if strings.TrimSpace(reason) == "" || len(reason) > 500 {
		kernel.WriteProblem(w, r, 422, "audit_reason_required", "A concise audit reason is required.")
		return false
	}
	return true
}
func requireAdministrationKey(w http.ResponseWriter, r *http.Request) bool {
	if len(strings.TrimSpace(r.Header.Get("Idempotency-Key"))) < 8 {
		kernel.WriteProblem(w, r, 400, "idempotency_key_required", "Idempotency-Key is required.")
		return false
	}
	return true
}

func administrationIfMatch(w http.ResponseWriter, r *http.Request, version int64) bool {
	if strings.TrimSpace(r.Header.Get("If-Match")) == "" || strings.TrimSpace(r.Header.Get("If-Match")) == "*" {
		kernel.WriteProblem(w, r, 428, "version_required", "An explicit resource If-Match version is required.")
		return false
	}
	return kernel.CheckIfMatch(w, r, version)
}

// Run before idempotency replay as well as rechecking inside each mutation.
func (s *Server) applicationAdministrationPermission(permission string, sensitive bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tx, _, ok := s.beginApplicationAdministration(w, r, permission, sensitive)
			if !ok {
				return
			}
			_ = tx.Rollback(r.Context())
			next.ServeHTTP(w, r)
		})
	}
}

func (s *Server) auditApplicationAdministration(r *http.Request, tx pgx.Tx, action, target, reason string) error {
	_, err := tx.Exec(r.Context(), `INSERT INTO audit_records(id,application_id,actor_type,actor_id,action,target_type,target_id,reason,request_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, kernel.NewID(), chi.URLParam(r, "application_id"), actor(r).Type, actor(r).ID, action, strings.Split(action, ".")[0], target, strings.TrimSpace(reason), kernel.RequestID(r.Context()))
	return err
}

func (s *Server) applicationAdminRead(permission string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tx, _, ok := s.beginApplicationAdministration(w, r, permission, false)
		if !ok {
			return
		}
		defer rollback(tx, r.Context())
		if permission == "users:read" || permission == "roles:read" {
			query := r.URL.Query()
			if !query.Has("limit") {
				query.Set("limit", "20")
			}
			r.URL.RawQuery = query.Encode()
		}
		if permission == "users:sessions:read" {
			var exists bool
			if err := tx.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM users WHERE application_id=$1 AND id=$2)`, chi.URLParam(r, "application_id"), chi.URLParam(r, "user_id")).Scan(&exists); err != nil || !exists {
				kernel.WriteProblem(w, r, 404, "user_not_found", "The user was not found.")
				return
			}
		}
		_ = tx.Rollback(r.Context())
		next(w, r)
	}
}

type applicationUserCreate struct {
	Email            string          `json:"email"`
	FirstName        string          `json:"first_name,omitempty"`
	LastName         string          `json:"last_name,omitempty"`
	Username         *string         `json:"username,omitempty"`
	Locale           string          `json:"locale,omitempty"`
	EmailVerified    *bool           `json:"email_verified,omitempty"`
	IsOrgVerified    *bool           `json:"is_org_verified,omitempty"`
	CustomAttributes *map[string]any `json:"custom_attributes,omitempty"`
	Reason           string          `json:"reason"`
}

func (s *Server) createApplicationManagedUser(w http.ResponseWriter, r *http.Request) {
	var in applicationUserCreate
	if !kernel.DecodeJSON(w, r, &in) || !administrationReason(w, r, in.Reason) || !requireAdministrationKey(w, r) {
		return
	}
	tx, live, ok := s.beginApplicationAdministration(w, r, "users:create", in.EmailVerified != nil || in.IsOrgVerified != nil || in.CustomAttributes != nil)
	if !ok {
		return
	}
	defer rollback(tx, r.Context())
	for p, present := range map[string]bool{"users:email_verification:manage": in.EmailVerified != nil, "users:organization_verification:manage": in.IsOrgVerified != nil, "users:attributes:write": in.CustomAttributes != nil} {
		scope, _ := platformauthz.CanonicalScope(chi.URLParam(r, "application_id"), nil, p)
		if present && !administrationAllows(actor(r), live, scope) {
			kernel.WriteProblem(w, r, 403, "sensitive_user_field_forbidden", "Additional permission is required for a sensitive field.")
			return
		}
	}
	email := kernel.NormalizeEmail(in.Email)
	parsedEmail, emailErr := mail.ParseAddress(strings.TrimSpace(in.Email))
	locale, err := normalizeNotificationLocale(in.Locale)
	if err != nil || emailErr != nil || parsedEmail.Address != strings.TrimSpace(in.Email) || !strings.Contains(email, "@") || len(email) > 320 {
		kernel.WriteProblem(w, r, 422, "invalid_user", "A valid email and locale are required.")
		return
	}
	app := chi.URLParam(r, "application_id")
	if err = enforceUserLimit(r.Context(), tx, app); err != nil {
		kernel.WriteProblem(w, r, 409, "organization_user_limit_reached", "The organization user limit has been reached.")
		return
	}
	id := kernel.NewID().String()
	attributes, _ := json.Marshal(objectOrEmpty(func() map[string]any {
		if in.CustomAttributes != nil {
			return *in.CustomAttributes
		}
		return nil
	}()))
	verified := in.EmailVerified != nil && *in.EmailVerified
	orgVerified := in.IsOrgVerified != nil && *in.IsOrgVerified
	_, err = tx.Exec(r.Context(), `INSERT INTO users(id,application_id,email,normalized_email,first_name,last_name,username,locale,email_verified_at,is_org_verified,custom_attributes) VALUES($1,$2,$3,$4,$5,$6,$7,$8,CASE WHEN $9 THEN now() END,$10,$11)`, id, app, in.Email, email, in.FirstName, in.LastName, in.Username, locale, verified, orgVerified, attributes)
	if err != nil {
		writeCreationProblem(w, r, err, "user_conflict", "An account with this email already exists.", "user_creation_failed", "users_application_id_normalized_email_key")
		return
	}
	parsed := uuid.MustParse(app)
	if err = s.auditApplicationAdministration(r, tx, "user.created", id, in.Reason); err == nil {
		_, err = s.app.Emit(r.Context(), tx, &parsed, "user.created", "user/"+id, actor(r), map[string]any{"user_id": id, "email_verified": verified, "is_org_verified": orgVerified})
	}
	if err != nil || tx.Commit(r.Context()) != nil {
		kernel.WriteProblem(w, r, 500, "user_creation_failed", "The user could not be created.")
		return
	}
	user, err := s.loadUser(r, id)
	if err != nil {
		kernel.WriteProblem(w, r, 500, "user_read_failed", "The created user could not be loaded.")
		return
	}
	w.Header().Set("ETag", kernel.ETag(user.Version))
	kernel.WriteJSON(w, 201, user)
}

type applicationUserChange struct {
	FirstName        *string         `json:"first_name,omitempty"`
	LastName         *string         `json:"last_name,omitempty"`
	Username         *string         `json:"username,omitempty"`
	Locale           *string         `json:"locale,omitempty"`
	CustomAttributes *map[string]any `json:"custom_attributes,omitempty"`
	Reason           string          `json:"reason"`
}

func decodeApplicationUserChange(w http.ResponseWriter, r *http.Request, operation string, in *applicationUserChange) bool {
	var raw map[string]json.RawMessage
	if !kernel.DecodeJSON(w, r, &raw) {
		return false
	}
	if raw == nil {
		kernel.WriteProblem(w, r, 400, "invalid_json", "A JSON object is required.")
		return false
	}
	for key, value := range raw {
		allowed := key == "reason" || operation == "profile" && (key == "first_name" || key == "last_name" || key == "username" || key == "locale") || operation == "attributes" && key == "custom_attributes"
		if !allowed || string(value) == "null" {
			kernel.WriteProblem(w, r, 400, "invalid_user_fields", "These fields are not valid for this operation.")
			return false
		}
	}
	encoded, _ := json.Marshal(raw)
	if err := json.Unmarshal(encoded, in); err != nil {
		kernel.WriteProblem(w, r, 400, "invalid_json", "The field values are invalid.")
		return false
	}
	return true
}

func (s *Server) changeApplicationManagedUser(operation string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var in applicationUserChange
		if !decodeApplicationUserChange(w, r, operation, &in) || !administrationReason(w, r, in.Reason) {
			return
		}
		permission := map[string]string{"profile": "users:update", "attributes": "users:attributes:write", "suspend": "users:suspend", "restore": "users:restore", "verify-email": "users:email_verification:manage", "unverify-email": "users:email_verification:manage", "verify-organization": "users:organization_verification:manage", "unverify-organization": "users:organization_verification:manage", "revoke-sessions": "users:sessions:revoke"}[operation]
		if operation != "profile" && (in.FirstName != nil || in.LastName != nil || in.Username != nil || in.Locale != nil) || operation != "attributes" && in.CustomAttributes != nil {
			kernel.WriteProblem(w, r, 422, "invalid_user_fields", "These fields are not allowed for this operation.")
			return
		}
		if operation == "attributes" && in.CustomAttributes == nil {
			kernel.WriteProblem(w, r, 422, "attributes_required", "custom_attributes must be a JSON object.")
			return
		}
		if r.Method == "POST" && !requireAdministrationKey(w, r) {
			return
		}
		tx, _, ok := s.beginApplicationAdministration(w, r, permission, operation != "profile")
		if !ok {
			return
		}
		defer rollback(tx, r.Context())
		app, id := chi.URLParam(r, "application_id"), chi.URLParam(r, "user_id")
		var version int64
		var status string
		if err := tx.QueryRow(r.Context(), `SELECT version,status FROM users WHERE application_id=$1 AND id=$2 FOR UPDATE`, app, id).Scan(&version, &status); err != nil {
			kernel.WriteProblem(w, r, 404, "user_not_found", "The user was not found.")
			return
		}
		if !administrationIfMatch(w, r, version) {
			return
		}
		if in.Locale != nil {
			locale, err := normalizeNotificationLocale(*in.Locale)
			if err != nil {
				kernel.WriteProblem(w, r, 422, "invalid_user_locale", "The locale is invalid.")
				return
			}
			in.Locale = &locale
		}
		var err error
		event := "user.updated"
		data := map[string]any{"user_id": id}
		if operation == "profile" || operation == "attributes" || operation == "revoke-sessions" {
			changed := []string{}
			for key, present := range map[string]bool{"first_name": in.FirstName != nil, "last_name": in.LastName != nil, "username": in.Username != nil, "locale": in.Locale != nil, "custom_attributes": in.CustomAttributes != nil} {
				if present {
					changed = append(changed, key)
				}
			}
			data["changed_fields"] = changed
			if operation == "revoke-sessions" {
				data["changed_fields"] = []string{"sessions"}
			}
		} else {
			data["reason"] = strings.TrimSpace(in.Reason)
		}
		switch operation {
		case "profile":
			_, err = tx.Exec(r.Context(), `UPDATE users SET first_name=COALESCE($3,first_name),last_name=COALESCE($4,last_name),username=COALESCE($5,username),locale=COALESCE($6,locale),version=version+1,updated_at=now() WHERE application_id=$1 AND id=$2`, app, id, in.FirstName, in.LastName, in.Username, in.Locale)
		case "attributes":
			value, _ := json.Marshal(*in.CustomAttributes)
			_, err = tx.Exec(r.Context(), `UPDATE users SET custom_attributes=$3,version=version+1,updated_at=now() WHERE application_id=$1 AND id=$2`, app, id, value)
		case "suspend", "restore":
			next := "suspended"
			expected := "active"
			event = "user.suspended"
			if operation == "restore" {
				next, expected, event = "active", "suspended", "user.restored"
			}
			if status != expected {
				kernel.WriteProblem(w, r, 409, "user_state_conflict", "The user is not in the required state.")
				return
			}
			var owns bool
			if operation == "suspend" {
				err = tx.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM workspaces WHERE application_id=$1 AND owner_user_id=$2 AND deleted_at IS NULL)`, app, id).Scan(&owns)
				if err != nil || owns {
					kernel.WriteProblem(w, r, 409, "workspace_ownership_requires_transfer", "Transfer or archive owned workspaces before suspension.")
					return
				}
			}
			_, err = tx.Exec(r.Context(), `UPDATE users SET status=$3,version=version+1,updated_at=now() WHERE application_id=$1 AND id=$2`, app, id, next)
		case "verify-email", "unverify-email":
			verified := operation == "verify-email"
			event = "user.email_unverified"
			if verified {
				event = "user.email_verified"
			}
			data["verified"] = verified
			_, err = tx.Exec(r.Context(), `UPDATE users SET email_verified_at=CASE WHEN $3 THEN COALESCE(email_verified_at,now()) END,version=version+1,updated_at=now() WHERE application_id=$1 AND id=$2`, app, id, verified)
		case "verify-organization", "unverify-organization":
			verified := operation == "verify-organization"
			event = "user.organization_unverified"
			if verified {
				event = "user.organization_verified"
			}
			data["verified"] = verified
			_, err = tx.Exec(r.Context(), `UPDATE users SET is_org_verified=$3,version=version+1,updated_at=now() WHERE application_id=$1 AND id=$2`, app, id, verified)
		case "revoke-sessions":
			_, err = tx.Exec(r.Context(), `UPDATE users SET version=version+1,updated_at=now() WHERE application_id=$1 AND id=$2`, app, id)
		}
		if err == nil && (operation == "suspend" || operation == "revoke-sessions") {
			_, err = tx.Exec(r.Context(), `UPDATE user_sessions SET revoked_at=COALESCE(revoked_at,now()) WHERE application_id=$1 AND user_id=$2 AND revoked_at IS NULL`, app, id)
			if err == nil {
				_, err = tx.Exec(r.Context(), `UPDATE oauth_sessions SET active=false,updated_at=now() WHERE application_id=$1 AND request_payload->'session'->>'subject'=$2`, app, id)
			}
		}
		if err == nil {
			err = s.auditApplicationAdministration(r, tx, "user."+operation, id, in.Reason)
		}
		if err == nil {
			parsed := uuid.MustParse(app)
			_, err = s.app.Emit(r.Context(), tx, &parsed, event, "user/"+id, actor(r), data)
		}
		if err != nil || tx.Commit(r.Context()) != nil {
			kernel.WriteProblem(w, r, 409, "user_change_failed", "The user change could not be committed.")
			return
		}
		w.Header().Set("ETag", kernel.ETag(version+1))
		w.WriteHeader(204)
	}
}
