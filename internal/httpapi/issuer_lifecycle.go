package httpapi

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/supaapps/platform93/internal/identity"
	"github.com/supaapps/platform93/internal/kernel"
	"github.com/supaapps/platform93/internal/secure"
)

func (s *Server) updateClient(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Name          *string  `json:"name"`
		RedirectURIs  []string `json:"redirect_uris"`
		AllowedGrants []string `json:"allowed_grants"`
		AllowedScopes []string `json:"allowed_scopes"`
	}
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	result, err := s.app.DB.Exec(r.Context(), `UPDATE clients SET name=COALESCE($1,name),
redirect_uris=CASE WHEN $2::text[] IS NULL THEN redirect_uris ELSE $2 END,
allowed_grants=CASE WHEN $3::text[] IS NULL THEN allowed_grants ELSE $3 END,
allowed_scopes=CASE WHEN $4::text[] IS NULL THEN allowed_scopes ELSE $4 END,updated_at=now()
WHERE application_id=$5 AND client_id=$6 AND disabled_at IS NULL`, request.Name, request.RedirectURIs,
		request.AllowedGrants, request.AllowedScopes, chi.URLParam(r, "application_id"), chi.URLParam(r, "client_id"))
	if err != nil || result.RowsAffected() != 1 {
		kernel.WriteProblem(w, r, http.StatusNotFound, "client_not_found", "The client was not found.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) rotateClientSecret(w http.ResponseWriter, r *http.Request) {
	secret, err := secure.RandomToken("p93_client_", 32)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "credential_generation_failed", "The client secret could not be generated.")
		return
	}
	result, err := s.app.DB.Exec(r.Context(), `UPDATE clients SET secret_digest=$1,updated_at=now()
WHERE application_id=$2 AND client_id=$3 AND client_type IN ('confidential','machine') AND disabled_at IS NULL`,
		s.app.Vault.Digest(secret), chi.URLParam(r, "application_id"), chi.URLParam(r, "client_id"))
	if err != nil || result.RowsAffected() != 1 {
		kernel.WriteProblem(w, r, http.StatusNotFound, "client_not_found", "An active confidential or machine client was not found.")
		return
	}
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"client_id": chi.URLParam(r, "client_id"), "client_secret": secret})
}

func (s *Server) disableClient(w http.ResponseWriter, r *http.Request) {
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "The client could not be disabled.")
		return
	}
	defer rollback(tx, r.Context())
	result, err := tx.Exec(r.Context(), `UPDATE clients SET disabled_at=now(),updated_at=now()
WHERE application_id=$1 AND client_id=$2 AND disabled_at IS NULL`, chi.URLParam(r, "application_id"), chi.URLParam(r, "client_id"))
	if err == nil && result.RowsAffected() == 1 {
		_, err = tx.Exec(r.Context(), `UPDATE oauth_sessions SET active=false,updated_at=now()
WHERE application_id=$1 AND request_payload->>'client_id'=$2 AND active`, chi.URLParam(r, "application_id"), chi.URLParam(r, "client_id"))
	}
	if err != nil || result.RowsAffected() != 1 || tx.Commit(r.Context()) != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "client_not_found", "The active client was not found.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listSigningKeys(w http.ResponseWriter, r *http.Request) {
	rows, err := s.app.DB.Query(r.Context(), `SELECT kid,public_jwk,status,activates_at,retires_at,created_at
FROM signing_keys ORDER BY created_at DESC`)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "Signing keys could not be loaded.")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var kid, status string
		var raw []byte
		var activatesAt, retiresAt *time.Time
		var createdAt time.Time
		if rows.Scan(&kid, &raw, &status, &activatesAt, &retiresAt, &createdAt) == nil {
			var jwk map[string]any
			_ = json.Unmarshal(raw, &jwk)
			items = append(items, map[string]any{"kid": kid, "public_jwk": jwk, "status": status, "activates_at": activatesAt, "retires_at": retiresAt, "created_at": createdAt})
		}
	}
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": nil})
}

func (s *Server) rotateSigningKey(w http.ResponseWriter, r *http.Request) {
	pair, err := identity.GenerateKeyPair()
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "key_generation_failed", "A signing key could not be generated.")
		return
	}
	ciphertext, err := s.app.Vault.Encrypt(pair.PrivatePEM, "signing-key:"+pair.KID)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "key_encryption_failed", "The signing key could not be encrypted.")
		return
	}
	publicJWK, _ := json.Marshal(pair.PublicJWK)
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "The signing key could not be rotated.")
		return
	}
	defer rollback(tx, r.Context())
	_, err = tx.Exec(r.Context(), `UPDATE signing_keys SET status='retiring',retires_at=now()+interval '15 minutes'
WHERE status='active'`)
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO signing_keys
(id,kid,public_jwk,private_key_ciphertext,status,activates_at)
VALUES ($1,$2,$3,$4,'active',now())`, kernel.NewID(), pair.KID, publicJWK, ciphertext)
	}
	if err != nil || tx.Commit(r.Context()) != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "key_rotation_failed", "The signing key rotation could not be committed.")
		return
	}
	kernel.WriteJSON(w, http.StatusCreated, map[string]any{"kid": pair.KID, "public_jwk": pair.PublicJWK, "status": "active"})
}
