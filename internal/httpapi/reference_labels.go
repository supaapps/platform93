package httpapi

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/supaapps/platform93/internal/kernel"
)

type referenceLabel struct {
	Kind  string `json:"kind"`
	ID    string `json:"id"`
	Label string `json:"label"`
}

func (s *Server) listReferenceLabels(w http.ResponseWriter, r *http.Request) {
	references := r.URL.Query()["references"]
	if len(references) == 0 || len(references) > 100 {
		kernel.WriteProblem(w, r, 422, "invalid_references", "Supply between one and 100 resource references.")
		return
	}
	kinds, ids := []string{}, []string{}
	allowed := map[string]bool{"users": true, "workspaces": true, "products": true, "roles": true, "clients": true, "webhooks": true}
	for _, reference := range references {
		kind, id, found := strings.Cut(reference, ":")
		if !found || !allowed[kind] || id == "" || len(id) > 200 {
			kernel.WriteProblem(w, r, 422, "invalid_reference", "Each reference must identify a supported resource and a bounded identifier.")
			return
		}
		kinds, ids = append(kinds, kind), append(ids, id)
	}
	// The control middleware authorizes this application before any label is read.
	rows, err := s.app.DB.Query(r.Context(), `WITH wanted AS (SELECT DISTINCT kind,id FROM unnest($2::text[],$3::text[]) AS t(kind,id))
SELECT w.kind,w.id,COALESCE(NULLIF(trim(concat_ws(' ',u.first_name,u.last_name)),''),u.email) FROM wanted w JOIN users u ON w.kind='users' AND u.id::text=w.id WHERE u.application_id=$1 AND u.status<>'deleted'
UNION ALL SELECT w.kind,w.id,p.name FROM wanted w JOIN workspaces p ON w.kind='workspaces' AND p.id::text=w.id WHERE p.application_id=$1 AND p.deleted_at IS NULL
UNION ALL SELECT w.kind,w.id,p.name FROM wanted w JOIN products p ON w.kind='products' AND p.id::text=w.id WHERE p.application_id=$1
UNION ALL SELECT w.kind,w.id,p.name FROM wanted w JOIN roles p ON w.kind='roles' AND p.id::text=w.id WHERE p.application_id=$1
UNION ALL SELECT w.kind,w.id,p.name FROM wanted w JOIN clients p ON w.kind='clients' AND (p.id::text=w.id OR p.client_id=w.id) WHERE p.application_id=$1
UNION ALL SELECT w.kind,w.id,p.uri FROM wanted w JOIN webhook_endpoints p ON w.kind='webhooks' AND p.id::text=w.id WHERE p.application_id=$1`, chi.URLParam(r, "application_id"), kinds, ids)
	if err != nil {
		kernel.WriteProblem(w, r, 500, "database_error", "Resource labels could not be loaded.")
		return
	}
	defer rows.Close()
	items := []referenceLabel{}
	for rows.Next() {
		var item referenceLabel
		if err := rows.Scan(&item.Kind, &item.ID, &item.Label); err != nil {
			kernel.WriteProblem(w, r, 500, "database_error", "Resource labels could not be loaded.")
			return
		}
		items = append(items, item)
	}
	if rows.Err() != nil {
		kernel.WriteProblem(w, r, 500, "database_error", "Resource labels could not be loaded.")
		return
	}
	kernel.WriteJSON(w, 200, map[string]any{"items": items})
}
