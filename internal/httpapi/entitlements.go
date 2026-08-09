package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/supaapps/platform93/internal/kernel"
)

type grantRequest struct {
	SubjectType   string         `json:"subject_type"`
	SubjectID     string         `json:"subject_id"`
	ProductID     *string        `json:"product_id"`
	PriceID       *string        `json:"price_id"`
	FeatureValues map[string]any `json:"feature_values"`
	Configuration map[string]any `json:"configuration"`
	StartsAt      *time.Time     `json:"starts_at"`
	ExpiresAt     *time.Time     `json:"expires_at"`
	Reason        string         `json:"reason"`
}

func (s *Server) createEntitlement(w http.ResponseWriter, r *http.Request) {
	var request grantRequest
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	if request.SubjectType != "user" && request.SubjectType != "workspace" {
		kernel.WriteProblem(w, r, 422, "invalid_subject", "Subject type must be user or workspace.")
		return
	}
	if _, err := uuid.Parse(request.SubjectID); err != nil {
		kernel.WriteProblem(w, r, 422, "invalid_subject", "Subject identifier is invalid.")
		return
	}
	starts := s.app.Now()
	if request.StartsAt != nil {
		starts = *request.StartsAt
	}
	features, _ := json.Marshal(request.FeatureValues)
	configuration, _ := json.Marshal(request.Configuration)
	id := kernel.NewID()
	applicationID, _ := applicationID(r)
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		return
	}
	defer rollback(tx, r.Context())
	var subjectExists bool
	subjectTable := "users"
	activePredicate := "status='active'"
	if request.SubjectType == "workspace" {
		subjectTable = "workspaces"
		activePredicate = "deleted_at IS NULL"
	}
	err = tx.QueryRow(r.Context(), fmt.Sprintf(`SELECT EXISTS(SELECT 1 FROM %s
WHERE id=$1 AND application_id=$2 AND %s)`, subjectTable, activePredicate), request.SubjectID, applicationID).Scan(&subjectExists)
	if err != nil || !subjectExists {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_subject", "The entitlement subject is not active in this application.")
		return
	}
	if request.ProductID != nil {
		var catalogValid bool
		err = tx.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM products p
WHERE p.id=$1 AND p.application_id=$2 AND ($3::uuid IS NULL OR EXISTS(SELECT 1 FROM prices pr WHERE pr.id=$3 AND pr.product_id=p.id AND pr.application_id=p.application_id)))`,
			request.ProductID, applicationID, request.PriceID).Scan(&catalogValid)
		if err != nil || !catalogValid {
			kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_catalog_reference", "The product and price must belong to this application.")
			return
		}
	} else if request.PriceID != nil {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_catalog_reference", "A price cannot be selected without its product.")
		return
	}
	_, err = tx.Exec(r.Context(), `INSERT INTO entitlement_grants
(id,application_id,subject_type,subject_id,product_id,price_id,source_type,feature_values,configuration,starts_at,expires_at,created_by)
VALUES ($1,$2,$3,$4,$5,$6,'manual',$7,$8,$9,$10,$11)`, id, applicationID, request.SubjectType, request.SubjectID, request.ProductID, request.PriceID, features, configuration, starts, request.ExpiresAt, actor(r).ID)
	if err == nil {
		_, err = s.app.Emit(r.Context(), tx, &applicationID, "entitlement.granted", "entitlement/"+id.String(), actor(r), map[string]any{"grant_id": id, "subject_type": request.SubjectType, "subject_id": request.SubjectID, "reason": request.Reason})
	}
	if err != nil || tx.Commit(r.Context()) != nil {
		kernel.WriteProblem(w, r, 409, "entitlement_creation_failed", "The entitlement could not be granted.")
		return
	}
	kernel.WriteJSON(w, 201, map[string]any{"id": id, "subject_type": request.SubjectType, "subject_id": request.SubjectID, "source_type": "manual", "feature_values": request.FeatureValues, "configuration": request.Configuration, "starts_at": starts, "expires_at": request.ExpiresAt})
}

func (s *Server) listEntitlements(w http.ResponseWriter, r *http.Request) {
	subjectType := r.URL.Query().Get("subject_type")
	subjectID := r.URL.Query().Get("subject_id")
	rows, err := s.app.DB.Query(r.Context(), `SELECT g.id,g.subject_type,g.subject_id,g.product_id,g.price_id,g.source_type,g.source_id,g.feature_values,g.configuration,g.starts_at,
COALESCE(a.expires_at,g.expires_at),CASE WHEN a.id IS NULL THEN g.revoked_at WHEN a.action='revoked' THEN a.created_at ELSE NULL END,
CASE WHEN a.id IS NULL THEN g.revocation_reason ELSE a.reason END,g.created_at
FROM entitlement_grants g LEFT JOIN LATERAL (SELECT id,action,expires_at,reason,created_at FROM entitlement_grant_actions
WHERE grant_id=g.id ORDER BY created_at DESC,id DESC LIMIT 1) a ON true
WHERE g.application_id=$1 AND ($2='' OR g.subject_type=$2) AND ($3='' OR g.subject_id=$3::uuid)
ORDER BY g.created_at DESC,g.id LIMIT 101`, chi.URLParam(r, "application_id"), subjectType, subjectID)
	if err != nil {
		kernel.WriteProblem(w, r, 500, "database_error", "Entitlements could not be loaded.")
		return
	}
	defer rows.Close()
	kernel.WriteJSON(w, 200, map[string]any{"items": scanGrants(rows), "next_cursor": nil})
}

func (s *Server) getEntitlement(w http.ResponseWriter, r *http.Request) {
	rows, err := s.app.DB.Query(r.Context(), `SELECT g.id,g.subject_type,g.subject_id,g.product_id,g.price_id,g.source_type,g.source_id,g.feature_values,g.configuration,g.starts_at,
COALESCE(a.expires_at,g.expires_at),CASE WHEN a.id IS NULL THEN g.revoked_at WHEN a.action='revoked' THEN a.created_at ELSE NULL END,
CASE WHEN a.id IS NULL THEN g.revocation_reason ELSE a.reason END,g.created_at
FROM entitlement_grants g LEFT JOIN LATERAL (SELECT id,action,expires_at,reason,created_at FROM entitlement_grant_actions
WHERE grant_id=g.id ORDER BY created_at DESC,id DESC LIMIT 1) a ON true
WHERE g.id=$1 AND g.application_id=$2`, chi.URLParam(r, "entitlement_id"), chi.URLParam(r, "application_id"))
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "The entitlement could not be loaded.")
		return
	}
	items := scanGrants(rows)
	rows.Close()
	if len(items) != 1 {
		kernel.WriteProblem(w, r, http.StatusNotFound, "entitlement_not_found", "The entitlement was not found.")
		return
	}
	actions := []map[string]any{}
	actionRows, _ := s.app.DB.Query(r.Context(), `SELECT id,action,expires_at,reason,actor_type,actor_id,created_at
FROM entitlement_grant_actions WHERE grant_id=$1 ORDER BY created_at,id`, chi.URLParam(r, "entitlement_id"))
	if actionRows != nil {
		defer actionRows.Close()
		for actionRows.Next() {
			var id, action, actorType string
			var expiresAt *time.Time
			var createdAt time.Time
			var reason, actorID *string
			if actionRows.Scan(&id, &action, &expiresAt, &reason, &actorType, &actorID, &createdAt) == nil {
				actions = append(actions, map[string]any{"id": id, "action": action, "expires_at": expiresAt, "reason": reason, "actor_type": actorType, "actor_id": actorID, "created_at": createdAt})
			}
		}
	}
	items[0]["actions"] = actions
	kernel.WriteJSON(w, http.StatusOK, items[0])
}

func (s *Server) revokeEntitlement(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Reason string `json:"reason"`
	}
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	request.Reason = strings.TrimSpace(request.Reason)
	if request.Reason == "" || len(request.Reason) > 500 {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "revocation_reason_required", "A revocation reason of at most 500 characters is required.")
		return
	}
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "The entitlement could not be revoked.")
		return
	}
	defer rollback(tx, r.Context())
	var legacyRevoked *time.Time
	var latestAction *string
	err = tx.QueryRow(r.Context(), `SELECT g.revoked_at,(SELECT action FROM entitlement_grant_actions WHERE grant_id=g.id ORDER BY created_at DESC,id DESC LIMIT 1)
FROM entitlement_grants g WHERE g.id=$1 AND g.application_id=$2 FOR UPDATE`, chi.URLParam(r, "entitlement_id"), chi.URLParam(r, "application_id")).Scan(&legacyRevoked, &latestAction)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "entitlement_not_found", "The entitlement was not found.")
		return
	}
	if latestAction != nil && *latestAction == "revoked" || latestAction == nil && legacyRevoked != nil {
		kernel.WriteProblem(w, r, http.StatusConflict, "entitlement_already_revoked", "The entitlement is already revoked.")
		return
	}
	_, err = tx.Exec(r.Context(), `INSERT INTO entitlement_grant_actions(id,grant_id,action,reason,actor_type,actor_id)
VALUES($1,$2,'revoked',$3,'operator',$4)`, kernel.NewID(), chi.URLParam(r, "entitlement_id"), request.Reason, actor(r).ID)
	if err != nil || tx.Commit(r.Context()) != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "entitlement_revocation_failed", "The entitlement revocation could not be committed.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) restoreEntitlement(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Reason string `json:"reason"`
	}
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "The entitlement could not be restored.")
		return
	}
	defer rollback(tx, r.Context())
	var grantExpiry, legacyRevoked *time.Time
	var latestAction *string
	err = tx.QueryRow(r.Context(), `SELECT g.expires_at,g.revoked_at,(SELECT action FROM entitlement_grant_actions WHERE grant_id=g.id ORDER BY created_at DESC,id DESC LIMIT 1)
FROM entitlement_grants g WHERE g.id=$1 AND g.application_id=$2 FOR UPDATE`, chi.URLParam(r, "entitlement_id"), chi.URLParam(r, "application_id")).Scan(&grantExpiry, &legacyRevoked, &latestAction)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "entitlement_not_found", "The entitlement was not found.")
		return
	}
	if !(latestAction != nil && *latestAction == "revoked" || latestAction == nil && legacyRevoked != nil) {
		kernel.WriteProblem(w, r, http.StatusConflict, "entitlement_not_revoked", "Only a revoked entitlement can be restored.")
		return
	}
	_ = tx.QueryRow(r.Context(), `SELECT expires_at FROM entitlement_grant_actions
WHERE grant_id=$1 AND action IN ('adjusted','restored') AND expires_at IS NOT NULL ORDER BY created_at DESC,id DESC LIMIT 1`, chi.URLParam(r, "entitlement_id")).Scan(&grantExpiry)
	_, err = tx.Exec(r.Context(), `INSERT INTO entitlement_grant_actions(id,grant_id,action,expires_at,reason,actor_type,actor_id)
VALUES($1,$2,'restored',$3,NULLIF($4,''),'operator',$5)`, kernel.NewID(), chi.URLParam(r, "entitlement_id"), grantExpiry, strings.TrimSpace(request.Reason), actor(r).ID)
	if err != nil || tx.Commit(r.Context()) != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "entitlement_restoration_failed", "The entitlement restoration could not be committed.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
func (s *Server) listMyEntitlements(w http.ResponseWriter, r *http.Request) {
	workspaceID := strings.TrimSpace(r.URL.Query().Get("workspace_id"))
	if workspaceID != "" && !s.userBelongsToWorkspace(r.Context(), chi.URLParam(r, "application_id"), actor(r).ID, workspaceID) {
		kernel.WriteProblem(w, r, http.StatusForbidden, "workspace_access_required", "The user does not own or belong to this workspace.")
		return
	}
	rows, err := s.app.DB.Query(r.Context(), `SELECT g.id,g.subject_type,g.subject_id,g.product_id,g.price_id,g.source_type,g.source_id,g.feature_values,g.configuration,g.starts_at,
COALESCE(a.expires_at,g.expires_at),NULL::timestamptz,NULL::text,g.created_at
FROM entitlement_grants g LEFT JOIN LATERAL (SELECT id,action,expires_at FROM entitlement_grant_actions
WHERE grant_id=g.id ORDER BY created_at DESC,id DESC LIMIT 1) a ON true
WHERE g.application_id=$1 AND ((g.subject_type='user' AND g.subject_id=$2) OR
($3::text<>'' AND g.subject_type='workspace' AND g.subject_id=$3::uuid)) AND g.starts_at<=now()
AND (COALESCE(a.expires_at,g.expires_at) IS NULL OR COALESCE(a.expires_at,g.expires_at)>now())
AND CASE WHEN a.id IS NULL THEN g.revoked_at IS NULL ELSE a.action<>'revoked' END
ORDER BY g.created_at DESC,g.id`, chi.URLParam(r, "application_id"), actor(r).ID, workspaceID)
	if err != nil {
		kernel.WriteProblem(w, r, 500, "database_error", "Entitlements could not be loaded.")
		return
	}
	defer rows.Close()
	grants := scanGrants(rows)
	effective := aggregateGrants(grants)
	kernel.WriteJSON(w, 200, map[string]any{"workspace_id": nullableString(workspaceID), "effective": effective, "provenance": entitlementProvenance(grants, effective), "sources": grants})
}

func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

type grantRows interface {
	Next() bool
	Scan(...any) error
}

func scanGrants(rows grantRows) []map[string]any {
	items := []map[string]any{}
	for rows.Next() {
		var id, subjectType, subjectID, sourceType string
		var starts, created time.Time
		var productID, priceID, sourceID, reason *string
		var expires, revoked *time.Time
		var features, configuration []byte
		if rows.Scan(&id, &subjectType, &subjectID, &productID, &priceID, &sourceType, &sourceID, &features, &configuration, &starts, &expires, &revoked, &reason, &created) == nil {
			items = append(items, map[string]any{"id": id, "subject_type": subjectType, "subject_id": subjectID, "product_id": productID, "price_id": priceID, "source_type": sourceType, "source_id": sourceID, "feature_values": decodeMap(features), "configuration": decodeMap(configuration), "starts_at": starts, "expires_at": expires, "revoked_at": revoked, "revocation_reason": reason, "created_at": created})
		}
	}
	return items
}
func aggregateGrants(grants []map[string]any) map[string]any {
	effective := map[string]any{}
	for _, grant := range grants {
		features, _ := grant["feature_values"].(map[string]any)
		for key, value := range features {
			switch typed := value.(type) {
			case bool:
				current, exists := effective[key].(bool)
				if !exists {
					effective[key] = typed
				} else if typed && !current {
					effective[key] = true
				}
			case float64:
				current, exists := effective[key].(float64)
				if !exists || typed > current {
					effective[key] = typed
				}
			default:
				if _, exists := effective[key]; !exists {
					effective[key] = value
				}
			}
		}
	}
	return effective
}

func entitlementProvenance(grants []map[string]any, effective map[string]any) map[string][]map[string]any {
	result := map[string][]map[string]any{}
	for _, grant := range grants {
		features, _ := grant["feature_values"].(map[string]any)
		for key, value := range features {
			selected := effective[key]
			contributes := false
			switch typed := value.(type) {
			case bool:
				selectedBool, ok := selected.(bool)
				contributes = ok && typed == selectedBool
			case float64:
				selectedNumber, ok := selected.(float64)
				contributes = ok && typed == selectedNumber
			default:
				contributes = fmt.Sprint(typed) == fmt.Sprint(selected)
			}
			if contributes {
				result[key] = append(result[key], map[string]any{"grant_id": grant["id"], "source_type": grant["source_type"], "source_id": grant["source_id"], "subject_type": grant["subject_type"], "subject_id": grant["subject_id"]})
			}
		}
	}
	return result
}

func (s *Server) createLocalCheckout(w http.ResponseWriter, r *http.Request) {
	var request struct {
		PriceID        string  `json:"price_id"`
		SubjectType    string  `json:"subject_type"`
		SubjectID      string  `json:"subject_id"`
		AddressID      *string `json:"address_id"`
		LocalReference *string `json:"local_reference"`
	}
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	if request.SubjectType == "" {
		request.SubjectType = "user"
		request.SubjectID = actor(r).ID
	}
	if request.SubjectType == "user" && request.SubjectID != actor(r).ID {
		kernel.WriteProblem(w, r, 403, "subject_forbidden", "Users can request local access only for themselves.")
		return
	}
	if request.SubjectType == "workspace" && !s.canManageWorkspaceBillingFor(r, request.SubjectID) {
		kernel.WriteProblem(w, r, http.StatusForbidden, "workspace_billing_required", "Workspace billing permission is required.")
		return
	}
	if request.SubjectType != "user" && request.SubjectType != "workspace" {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_subject", "Subject type must be user or workspace.")
		return
	}
	applicationID, _ := applicationID(r)
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		return
	}
	defer rollback(tx, r.Context())
	var productID string
	var productSnapshot, priceSnapshot, featureSnapshot []byte
	err = tx.QueryRow(r.Context(), `SELECT p.id,to_jsonb(p),to_jsonb(pr) FROM prices pr JOIN products p ON p.id=pr.product_id WHERE pr.id=$1 AND pr.application_id=$2 AND pr.mode='local' AND pr.active=true AND p.status='active'`, request.PriceID, applicationID).Scan(&productID, &productSnapshot, &priceSnapshot)
	if err != nil {
		kernel.WriteProblem(w, r, 422, "local_price_unavailable", "The selected local price is unavailable.")
		return
	}
	err = tx.QueryRow(r.Context(), `SELECT COALESCE(jsonb_object_agg(f.key,
CASE WHEN pf.boolean_value IS NOT NULL THEN to_jsonb(pf.boolean_value)
WHEN pf.quantity_value IS NOT NULL THEN to_jsonb(pf.quantity_value)
ELSE pf.free_form_value END),'{}'::jsonb)
FROM price_features pf JOIN features f ON f.id=pf.feature_id WHERE pf.price_id=$1`, request.PriceID).Scan(&featureSnapshot)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "local_price_snapshot_failed", "The selected local price could not be snapshotted.")
		return
	}
	var addressSnapshot []byte
	profileID, profileErr := s.ensureBillingProfile(r.Context(), tx, applicationID.String(), request.SubjectType, request.SubjectID)
	if profileErr != nil {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "billing_profile_unavailable", "The subject billing profile is unavailable.")
		return
	}
	if request.AddressID != nil {
		err = tx.QueryRow(r.Context(), `SELECT to_jsonb(a) FROM addresses a WHERE id=$1 AND application_id=$2 AND billing_profile_id=$3`, *request.AddressID, applicationID, profileID).Scan(&addressSnapshot)
	} else {
		_ = tx.QueryRow(r.Context(), `SELECT to_jsonb(a) FROM addresses a WHERE application_id=$1 AND billing_profile_id=$2 AND is_active=true`, applicationID, profileID).Scan(&addressSnapshot)
	}
	if err != nil {
		kernel.WriteProblem(w, r, 422, "address_unavailable", "The selected address is unavailable.")
		return
	}
	id := kernel.NewID()
	_, err = tx.Exec(r.Context(), `INSERT INTO local_entitlement_requests
(id,application_id,requester_user_id,subject_type,subject_id,product_id,price_id,product_snapshot,price_snapshot,feature_snapshot,address_snapshot,local_reference)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, id, applicationID, actor(r).ID, request.SubjectType, request.SubjectID, productID, request.PriceID, productSnapshot, priceSnapshot, featureSnapshot, nullableBytes(addressSnapshot), request.LocalReference)
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO local_entitlement_request_actions(id,request_id,action,actor_type,actor_id)
VALUES($1,$2,'created','user',$3)`, kernel.NewID(), id, actor(r).ID)
	}
	if err == nil {
		_, err = s.app.Emit(r.Context(), tx, &applicationID, "local_entitlement_request.created", "local_entitlement_request/"+id.String(), actor(r), map[string]any{"request_id": id, "subject_type": request.SubjectType, "subject_id": request.SubjectID, "price_id": request.PriceID})
	}
	if err != nil || tx.Commit(r.Context()) != nil {
		kernel.WriteProblem(w, r, 409, "local_request_creation_failed", "The local entitlement request could not be created.")
		return
	}
	kernel.WriteJSON(w, 201, map[string]any{"id": id, "status": "pending", "subject_type": request.SubjectType, "subject_id": request.SubjectID, "product_snapshot": decodeMap(productSnapshot), "price_snapshot": decodeMap(priceSnapshot), "feature_snapshot": decodeMap(featureSnapshot), "address_snapshot": nullableDecoded(addressSnapshot), "local_reference": request.LocalReference})
}

func (s *Server) listMyLocalRequests(w http.ResponseWriter, r *http.Request) {
	s.listLocalRequests(w, r, true)
}
func (s *Server) adminListLocalRequests(w http.ResponseWriter, r *http.Request) {
	s.listLocalRequests(w, r, false)
}

func (s *Server) getMyLocalRequest(w http.ResponseWriter, r *http.Request) {
	s.getLocalRequest(w, r, true)
}

func (s *Server) adminGetLocalRequest(w http.ResponseWriter, r *http.Request) {
	s.getLocalRequest(w, r, false)
}

func (s *Server) getLocalRequest(w http.ResponseWriter, r *http.Request, own bool) {
	query := `SELECT id,requester_user_id,subject_type,subject_id,product_id,price_id,product_snapshot,price_snapshot,feature_snapshot,address_snapshot,
local_reference,status,decision_reason,reviewed_by,reviewed_at,entitlement_grant_id,created_at,updated_at
FROM local_entitlement_requests WHERE id=$1 AND application_id=$2`
	args := []any{chi.URLParam(r, "request_id"), chi.URLParam(r, "application_id")}
	if own {
		query += ` AND requester_user_id=$3`
		args = append(args, actor(r).ID)
	}
	rows, err := s.app.DB.Query(r.Context(), query, args...)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "The local request could not be loaded.")
		return
	}
	items := scanLocalRequests(rows)
	rows.Close()
	if len(items) != 1 {
		kernel.WriteProblem(w, r, http.StatusNotFound, "local_request_not_found", "The local entitlement request was not found.")
		return
	}
	history := []map[string]any{}
	actionRows, _ := s.app.DB.Query(r.Context(), `SELECT id,action,actor_type,actor_id,reason,created_at
FROM local_entitlement_request_actions WHERE request_id=$1 ORDER BY created_at,id`, chi.URLParam(r, "request_id"))
	if actionRows != nil {
		defer actionRows.Close()
		for actionRows.Next() {
			var id, action, actorType, actorID string
			var reason *string
			var createdAt time.Time
			if actionRows.Scan(&id, &action, &actorType, &actorID, &reason, &createdAt) == nil {
				history = append(history, map[string]any{"id": id, "action": action, "actor_type": actorType, "actor_id": actorID, "reason": reason, "created_at": createdAt})
			}
		}
	}
	items[0]["history"] = history
	kernel.WriteJSON(w, http.StatusOK, items[0])
}
func (s *Server) listLocalRequests(w http.ResponseWriter, r *http.Request, own bool) {
	query := `SELECT id,requester_user_id,subject_type,subject_id,product_id,price_id,product_snapshot,price_snapshot,feature_snapshot,address_snapshot,local_reference,status,decision_reason,reviewed_by,reviewed_at,entitlement_grant_id,created_at,updated_at FROM local_entitlement_requests WHERE application_id=$1`
	args := []any{chi.URLParam(r, "application_id")}
	if own {
		query += ` AND requester_user_id=$2`
		args = append(args, actor(r).ID)
	}
	if status := r.URL.Query().Get("status"); status != "" {
		query += ` AND status=$` + fmt.Sprint(len(args)+1)
		args = append(args, status)
	}
	query += ` ORDER BY created_at DESC,id LIMIT 101`
	rows, err := s.app.DB.Query(r.Context(), query, args...)
	if err != nil {
		kernel.WriteProblem(w, r, 500, "database_error", "Local requests could not be loaded.")
		return
	}
	defer rows.Close()
	kernel.WriteJSON(w, 200, map[string]any{"items": scanLocalRequests(rows), "next_cursor": nil})
}

type localRows interface {
	Next() bool
	Scan(...any) error
}

func scanLocalRequests(rows localRows) []map[string]any {
	items := []map[string]any{}
	for rows.Next() {
		var id, requester, subjectType, subjectID, productID, priceID, status string
		var created, updated time.Time
		var product, price, features, address []byte
		var localRef, reason, reviewer, grant *string
		var reviewed *time.Time
		if rows.Scan(&id, &requester, &subjectType, &subjectID, &productID, &priceID, &product, &price, &features, &address, &localRef, &status, &reason, &reviewer, &reviewed, &grant, &created, &updated) == nil {
			items = append(items, map[string]any{"id": id, "requester_user_id": requester, "subject_type": subjectType, "subject_id": subjectID, "product_id": productID, "price_id": priceID, "product_snapshot": decodeMap(product), "price_snapshot": decodeMap(price), "feature_snapshot": decodeMap(features), "address_snapshot": nullableDecoded(address), "local_reference": localRef, "status": status, "decision_reason": reason, "reviewed_by": reviewer, "reviewed_at": reviewed, "entitlement_grant_id": grant, "created_at": created, "updated_at": updated})
		}
	}
	return items
}

func (s *Server) approveLocalRequest(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Reason string `json:"reason"`
	}
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	applicationID, _ := applicationID(r)
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		return
	}
	defer rollback(tx, r.Context())
	var subjectType, subjectID, productID, priceID, status string
	var priceSnapshot, featureSnapshot []byte
	err = tx.QueryRow(r.Context(), `SELECT subject_type,subject_id,product_id,price_id,status,price_snapshot,feature_snapshot FROM local_entitlement_requests WHERE id=$1 AND application_id=$2 FOR UPDATE`, chi.URLParam(r, "request_id"), applicationID).Scan(&subjectType, &subjectID, &productID, &priceID, &status, &priceSnapshot, &featureSnapshot)
	if err != nil || status != "pending" {
		kernel.WriteProblem(w, r, 409, "local_request_not_pending", "The local request is not pending.")
		return
	}
	var snapshot struct {
		ValiditySeconds   *int64         `json:"validity_seconds"`
		EntitlementConfig map[string]any `json:"entitlement_config"`
	}
	_ = json.Unmarshal(priceSnapshot, &snapshot)
	features := featureSnapshot
	configuration, _ := json.Marshal(snapshot.EntitlementConfig)
	grantID := kernel.NewID()
	var expires any
	if snapshot.ValiditySeconds != nil {
		expires = s.app.Now().Add(time.Duration(*snapshot.ValiditySeconds) * time.Second)
	}
	_, err = tx.Exec(r.Context(), `INSERT INTO entitlement_grants
(id,application_id,subject_type,subject_id,product_id,price_id,source_type,source_id,feature_values,configuration,starts_at,expires_at,created_by) VALUES ($1,$2,$3,$4,$5,$6,'local_request',$7,$8,$9,now(),$10,$11)`, grantID, applicationID, subjectType, subjectID, productID, priceID, chi.URLParam(r, "request_id"), features, configuration, expires, actor(r).ID)
	if err == nil {
		_, err = tx.Exec(r.Context(), `UPDATE local_entitlement_requests SET status='approved',decision_reason=$1,reviewed_by=$2,reviewed_at=now(),entitlement_grant_id=$3,updated_at=now() WHERE id=$4`, request.Reason, actor(r).ID, grantID, chi.URLParam(r, "request_id"))
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO local_entitlement_request_actions(id,request_id,action,actor_type,actor_id,reason)
VALUES($1,$2,'approved','operator',$3,NULLIF($4,''))`, kernel.NewID(), chi.URLParam(r, "request_id"), actor(r).ID, request.Reason)
	}
	if err == nil {
		_, err = s.app.Emit(r.Context(), tx, &applicationID, "local_entitlement_request.approved", "local_entitlement_request/"+chi.URLParam(r, "request_id"), actor(r), map[string]any{"request_id": chi.URLParam(r, "request_id"), "grant_id": grantID})
	}
	if err != nil || tx.Commit(r.Context()) != nil {
		kernel.WriteProblem(w, r, 500, "local_request_approval_failed", "The local request could not be approved.")
		return
	}
	kernel.WriteJSON(w, 200, map[string]any{"status": "approved", "entitlement_grant_id": grantID})
}

func (s *Server) rejectLocalRequest(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Reason string `json:"reason"`
	}
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "The local request could not be rejected.")
		return
	}
	defer rollback(tx, r.Context())
	result, err := tx.Exec(r.Context(), `UPDATE local_entitlement_requests SET status='rejected',decision_reason=$1,reviewed_by=$2,reviewed_at=now(),updated_at=now() WHERE id=$3 AND application_id=$4 AND status='pending'`, request.Reason, actor(r).ID, chi.URLParam(r, "request_id"), chi.URLParam(r, "application_id"))
	if err != nil || result.RowsAffected() != 1 {
		kernel.WriteProblem(w, r, 409, "local_request_not_pending", "The local request is not pending.")
		return
	}
	_, err = tx.Exec(r.Context(), `INSERT INTO local_entitlement_request_actions(id,request_id,action,actor_type,actor_id,reason)
VALUES($1,$2,'rejected','operator',$3,NULLIF($4,''))`, kernel.NewID(), chi.URLParam(r, "request_id"), actor(r).ID, request.Reason)
	if err != nil || tx.Commit(r.Context()) != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "local_request_rejection_failed", "The local request rejection could not be committed.")
		return
	}
	w.WriteHeader(204)
}
func (s *Server) cancelLocalRequest(w http.ResponseWriter, r *http.Request) {
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "The local request could not be canceled.")
		return
	}
	defer rollback(tx, r.Context())
	result, err := tx.Exec(r.Context(), `UPDATE local_entitlement_requests SET status='canceled',updated_at=now() WHERE id=$1 AND application_id=$2 AND requester_user_id=$3 AND status='pending'`, chi.URLParam(r, "request_id"), chi.URLParam(r, "application_id"), actor(r).ID)
	if err != nil || result.RowsAffected() != 1 {
		kernel.WriteProblem(w, r, 409, "local_request_not_cancelable", "The local request cannot be canceled.")
		return
	}
	_, err = tx.Exec(r.Context(), `INSERT INTO local_entitlement_request_actions(id,request_id,action,actor_type,actor_id)
VALUES($1,$2,'canceled','user',$3)`, kernel.NewID(), chi.URLParam(r, "request_id"), actor(r).ID)
	if err != nil || tx.Commit(r.Context()) != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "local_request_cancellation_failed", "The local request cancellation could not be committed.")
		return
	}
	w.WriteHeader(204)
}

func (s *Server) reopenLocalRequest(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Reason string `json:"reason"`
	}
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	if strings.TrimSpace(request.Reason) == "" || len(request.Reason) > 500 {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "reopen_reason_required", "A reopen reason of at most 500 characters is required.")
		return
	}
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "The local request could not be reopened.")
		return
	}
	defer rollback(tx, r.Context())
	result, err := tx.Exec(r.Context(), `UPDATE local_entitlement_requests SET status='pending',decision_reason=NULL,reviewed_by=NULL,reviewed_at=NULL,updated_at=now()
WHERE id=$1 AND application_id=$2 AND status IN ('rejected','canceled')`, chi.URLParam(r, "request_id"), chi.URLParam(r, "application_id"))
	if err != nil || result.RowsAffected() != 1 {
		kernel.WriteProblem(w, r, http.StatusConflict, "local_request_not_reopenable", "Only rejected or canceled requests can be reopened.")
		return
	}
	_, err = tx.Exec(r.Context(), `INSERT INTO local_entitlement_request_actions(id,request_id,action,actor_type,actor_id,reason)
VALUES($1,$2,'reopened','operator',$3,$4)`, kernel.NewID(), chi.URLParam(r, "request_id"), actor(r).ID, request.Reason)
	if err != nil || tx.Commit(r.Context()) != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "local_request_reopen_failed", "The local request could not be reopened.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func nullableBytes(value []byte) any {
	if len(value) == 0 {
		return nil
	}
	return value
}
func nullableDecoded(value []byte) any {
	if len(value) == 0 {
		return nil
	}
	return decodeMap(value)
}
