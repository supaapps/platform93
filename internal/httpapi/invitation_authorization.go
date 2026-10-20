package httpapi

import (
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	platformauthz "github.com/supaapps/platform93/internal/authorization"
	"github.com/supaapps/platform93/internal/kernel"
)

type invitationProviderChallengeKey struct{}

func (s *Server) invitationMutationEnabled(r *http.Request, tx pgx.Tx) bool {
	if actor(r).Type != "user" {
		return true
	}
	var enabled bool
	err := tx.QueryRow(r.Context(), `SELECT COALESCE((internal_config->>'user_invitations_enabled')::boolean,false) FROM applications WHERE id=$1 AND deleted_at IS NULL FOR SHARE`, chi.URLParam(r, "application_id")).Scan(&enabled)
	return err == nil && enabled
}

func (s *Server) validateInvitationRolesAuthority(r *http.Request, tx pgx.Tx, current kernel.Actor, live []string, workspace string, appRoles, workspaceRoles []string) error {
	app := chi.URLParam(r, "application_id")
	manage, _ := platformauthz.CanonicalScope(app, nil, "invitations:manage")
	manager := current.Type == "control_user" || administrationAllows(current, live, manage)
	var ws *string
	if workspace != "" {
		ws = &workspace
		var active bool
		if err := tx.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM workspaces WHERE application_id=$1 AND id=$2 AND deleted_at IS NULL)`, app, workspace).Scan(&active); err != nil || !active {
			return fmt.Errorf("workspace unavailable")
		}
	}
	if !manager {
		if ws == nil || len(appRoles) > 0 {
			return fmt.Errorf("application invitation authority required")
		}
		if current.Type == "user" {
			var owner bool
			err := tx.QueryRow(r.Context(), `SELECT owner_user_id=$3 FROM workspaces WHERE application_id=$1 AND id=$2 AND deleted_at IS NULL FOR SHARE`, app, *ws, current.ID).Scan(&owner)
			if err != nil {
				return err
			}
			if owner {
				wildcard, _ := platformauthz.CanonicalScope(app, ws, "*")
				current.Permissions = append(append([]string{}, current.Permissions...), wildcard)
			}
		}
		scope, _ := platformauthz.CanonicalScope(app, ws, "invitations:manage")
		if !administrationAllows(current, live, scope) {
			return fmt.Errorf("workspace invitation authority required")
		}
	}
	for _, entry := range []struct {
		keys      []string
		workspace *string
		scope     string
	}{{appRoles, nil, "application"}, {workspaceRoles, ws, "workspace"}} {
		for _, key := range entry.keys {
			var role string
			if err := tx.QueryRow(r.Context(), `SELECT id FROM roles WHERE application_id=$1 AND key=$2 AND scope=$3 FOR SHARE`, app, key, entry.scope).Scan(&role); err != nil {
				return err
			}
			if err := s.roleWithinAdministration(r, tx, current, live, role, entry.workspace); err != nil {
				return err
			}
		}
	}
	return nil
}

// Re-evaluate the inviter, not the recipient. Invitation acceptance never gains
// authority from the recipient's existing roles or a currently disabled toggle.
func (s *Server) revalidateInvitationAuthority(r *http.Request, tx pgx.Tx, id string) error {
	app := chi.URLParam(r, "application_id")
	var kind string
	var inviter, workspace *string
	var appRoles, workspaceRoles []string
	if err := tx.QueryRow(r.Context(), `SELECT inviter_type,inviter_id,workspace_id,application_roles,workspace_roles FROM application_invitations WHERE application_id=$1 AND id=$2 AND EXISTS(SELECT 1 FROM applications WHERE id=$1 AND deleted_at IS NULL)`, app, id).Scan(&kind, &inviter, &workspace, &appRoles, &workspaceRoles); err != nil {
		return err
	}
	if inviter == nil {
		return fmt.Errorf("inviter unavailable")
	}
	if kind == "control_user" {
		var allowed bool
		err := tx.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM control_users u WHERE u.id=$2 AND u.status='active' AND (EXISTS(SELECT 1 FROM installation_control_user_roles i WHERE i.control_user_id=u.id AND i.role IN ('owner','admin')) OR EXISTS(SELECT 1 FROM organization_memberships m JOIN applications a ON a.organization_id=m.organization_id WHERE a.id=$1 AND a.deleted_at IS NULL AND m.control_user_id=u.id AND m.role IN ('owner','admin'))))`, app, *inviter).Scan(&allowed)
		if err != nil || !allowed {
			return fmt.Errorf("inviter authority unavailable")
		}
		ws := ""
		if workspace != nil {
			ws = *workspace
		}
		return s.validateInvitationRolesAuthority(r, tx, kernel.Actor{Type: "control_user"}, nil, ws, appRoles, workspaceRoles)
	}
	current := kernel.Actor{Type: kind, ID: *inviter, ApplicationID: app}
	live, err := s.applicationAdminScopes(r, tx, current, false)
	if err != nil {
		return err
	}
	current.Permissions = live
	ws := ""
	if workspace != nil {
		ws = *workspace
	}
	return s.validateInvitationRolesAuthority(r, tx, current, live, ws, appRoles, workspaceRoles)
}
