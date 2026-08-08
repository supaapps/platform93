package oauthserver

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/url"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ory/fosite"
	"github.com/supaapps/platform93/internal/secure"
)

type Store struct {
	DB            *pgxpool.Pool
	Vault         *secure.Vault
	ApplicationID uuid.UUID
}

var _ fosite.Storage = (*Store)(nil)

type persistedRequest struct {
	ID                string     `json:"id"`
	RequestedAt       time.Time  `json:"requested_at"`
	ClientID          string     `json:"client_id"`
	RequestedScopes   []string   `json:"requested_scopes"`
	GrantedScopes     []string   `json:"granted_scopes"`
	Form              url.Values `json:"form"`
	RequestedAudience []string   `json:"requested_audience"`
	GrantedAudience   []string   `json:"granted_audience"`
	Session           *Session   `json:"session"`
}

func (s *Store) GetClient(ctx context.Context, clientID string) (fosite.Client, error) {
	var secret []byte
	var clientType string
	var redirects, grants, scopes []string
	err := s.DB.QueryRow(ctx, `SELECT client_type,redirect_uris,allowed_grants,allowed_scopes,secret_digest
FROM clients WHERE application_id=$1 AND client_id=$2 AND disabled_at IS NULL`, s.ApplicationID, clientID).
		Scan(&clientType, &redirects, &grants, &scopes, &secret)
	if err != nil {
		return nil, fosite.ErrNotFound
	}
	if len(grants) == 0 {
		if clientType == "machine" {
			grants = []string{"client_credentials"}
		} else {
			grants = []string{"authorization_code", "refresh_token"}
		}
	}
	client := &fosite.DefaultClient{
		ID: clientID, Secret: secret, RedirectURIs: redirects, GrantTypes: grants,
		ResponseTypes: []string{"code"}, Scopes: scopes, Audience: []string{"platform93:application:" + s.ApplicationID.String()}, Public: clientType == "public",
	}
	method := "client_secret_basic"
	if client.Public {
		method = "none"
	}
	return &fosite.DefaultOpenIDConnectClient{DefaultClient: client, TokenEndpointAuthMethod: method}, nil
}

func (s *Store) ClientAssertionJWTValid(ctx context.Context, jti string) error {
	var known bool
	err := s.DB.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM oauth_client_assertion_jtis
WHERE application_id=$1 AND jti_digest=$2 AND expires_at>now())`, s.ApplicationID, s.Vault.Digest(jti)).Scan(&known)
	if err != nil {
		return err
	}
	if known {
		return fosite.ErrJTIKnown
	}
	return nil
}

func (s *Store) SetClientAssertionJWT(ctx context.Context, jti string, expiresAt time.Time) error {
	_, _ = s.DB.Exec(ctx, `DELETE FROM oauth_client_assertion_jtis WHERE application_id=$1 AND expires_at<=now()`, s.ApplicationID)
	_, err := s.DB.Exec(ctx, `INSERT INTO oauth_client_assertion_jtis(application_id,jti_digest,expires_at)
VALUES ($1,$2,$3)`, s.ApplicationID, s.Vault.Digest(jti), expiresAt)
	if err != nil {
		return fosite.ErrJTIKnown
	}
	return nil
}

func (s *Store) CreateAuthorizeCodeSession(ctx context.Context, signature string, request fosite.Requester) error {
	return s.create(ctx, "authorize_code", signature, "", request)
}

func (s *Store) GetAuthorizeCodeSession(ctx context.Context, signature string, _ fosite.Session) (fosite.Requester, error) {
	request, active, err := s.get(ctx, "authorize_code", signature)
	if err != nil {
		return nil, err
	}
	if !active {
		return request, fosite.ErrInvalidatedAuthorizeCode
	}
	return request, nil
}

func (s *Store) InvalidateAuthorizeCodeSession(ctx context.Context, signature string) error {
	return s.deactivate(ctx, "authorize_code", signature)
}

func (s *Store) CreatePKCERequestSession(ctx context.Context, signature string, request fosite.Requester) error {
	return s.create(ctx, "pkce", signature, "", request)
}

func (s *Store) GetPKCERequestSession(ctx context.Context, signature string, _ fosite.Session) (fosite.Requester, error) {
	request, _, err := s.get(ctx, "pkce", signature)
	return request, err
}

func (s *Store) DeletePKCERequestSession(ctx context.Context, signature string) error {
	return s.delete(ctx, "pkce", signature)
}

func (s *Store) CreateOpenIDConnectSession(ctx context.Context, signature string, request fosite.Requester) error {
	return s.create(ctx, "openid", signature, "", request)
}

func (s *Store) GetOpenIDConnectSession(ctx context.Context, signature string, _ fosite.Requester) (fosite.Requester, error) {
	request, _, err := s.get(ctx, "openid", signature)
	return request, err
}

func (s *Store) DeleteOpenIDConnectSession(ctx context.Context, signature string) error {
	return s.delete(ctx, "openid", signature)
}

func (s *Store) CreateAccessTokenSession(ctx context.Context, signature string, request fosite.Requester) error {
	return s.create(ctx, "access", signature, "", request)
}

func (s *Store) GetAccessTokenSession(ctx context.Context, signature string, _ fosite.Session) (fosite.Requester, error) {
	request, active, err := s.get(ctx, "access", signature)
	if err != nil {
		return nil, err
	}
	if !active {
		return request, fosite.ErrInactiveToken
	}
	return request, nil
}

func (s *Store) DeleteAccessTokenSession(ctx context.Context, signature string) error {
	return s.delete(ctx, "access", signature)
}

func (s *Store) CreateRefreshTokenSession(ctx context.Context, signature, accessSignature string, request fosite.Requester) error {
	return s.create(ctx, "refresh", signature, accessSignature, request)
}

func (s *Store) GetRefreshTokenSession(ctx context.Context, signature string, _ fosite.Session) (fosite.Requester, error) {
	request, active, err := s.get(ctx, "refresh", signature)
	if err != nil {
		return nil, err
	}
	if !active {
		return request, fosite.ErrInactiveToken
	}
	return request, nil
}

func (s *Store) DeleteRefreshTokenSession(ctx context.Context, signature string) error {
	return s.delete(ctx, "refresh", signature)
}

func (s *Store) RevokeRefreshToken(ctx context.Context, requestID string) error {
	_, err := s.DB.Exec(ctx, `UPDATE oauth_sessions SET active=false,updated_at=now()
WHERE application_id=$1 AND request_id=$2 AND kind IN ('refresh','access')`, s.ApplicationID, requestID)
	return err
}

func (s *Store) RevokeAccessToken(ctx context.Context, requestID string) error {
	_, err := s.DB.Exec(ctx, `UPDATE oauth_sessions SET active=false,updated_at=now()
WHERE application_id=$1 AND request_id=$2 AND kind='access'`, s.ApplicationID, requestID)
	return err
}

func (s *Store) RotateRefreshToken(ctx context.Context, requestID, _ string) error {
	return s.RevokeRefreshToken(ctx, requestID)
}

func (s *Store) create(ctx context.Context, kind, signature, accessSignature string, request fosite.Requester) error {
	payload, expiresAt, err := marshalRequest(request, kind)
	if err != nil {
		return err
	}
	var accessDigest []byte
	if accessSignature != "" {
		accessDigest = s.Vault.Digest(accessSignature)
	}
	_, err = s.DB.Exec(ctx, `INSERT INTO oauth_sessions
(id,application_id,signature_digest,kind,request_id,request_payload,access_signature_digest,expires_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, uuid.Must(uuid.NewV7()), s.ApplicationID, s.Vault.Digest(signature), kind,
		request.GetID(), payload, accessDigest, expiresAt)
	return err
}

func (s *Store) get(ctx context.Context, kind, signature string) (fosite.Requester, bool, error) {
	var payload []byte
	var active bool
	err := s.DB.QueryRow(ctx, `SELECT request_payload,active FROM oauth_sessions
WHERE application_id=$1 AND kind=$2 AND signature_digest=$3 AND expires_at>now()`,
		s.ApplicationID, kind, s.Vault.Digest(signature)).Scan(&payload, &active)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, fosite.ErrNotFound
	}
	if err != nil {
		return nil, false, err
	}
	request, err := s.unmarshalRequest(ctx, payload)
	return request, active, err
}

func (s *Store) deactivate(ctx context.Context, kind, signature string) error {
	result, err := s.DB.Exec(ctx, `UPDATE oauth_sessions SET active=false,updated_at=now()
WHERE application_id=$1 AND kind=$2 AND signature_digest=$3`, s.ApplicationID, kind, s.Vault.Digest(signature))
	if err != nil {
		return err
	}
	if result.RowsAffected() == 0 {
		return fosite.ErrNotFound
	}
	return nil
}

func (s *Store) delete(ctx context.Context, kind, signature string) error {
	_, err := s.DB.Exec(ctx, `DELETE FROM oauth_sessions WHERE application_id=$1 AND kind=$2 AND signature_digest=$3`,
		s.ApplicationID, kind, s.Vault.Digest(signature))
	return err
}

func marshalRequest(request fosite.Requester, kind string) ([]byte, time.Time, error) {
	session, ok := request.GetSession().(*Session)
	if !ok {
		return nil, time.Time{}, errors.New("oauth request contains an unsupported session type")
	}
	persisted := persistedRequest{
		ID: request.GetID(), RequestedAt: request.GetRequestedAt(), ClientID: request.GetClient().GetID(),
		RequestedScopes: request.GetRequestedScopes(), GrantedScopes: request.GetGrantedScopes(), Form: request.GetRequestForm(),
		RequestedAudience: request.GetRequestedAudience(), GrantedAudience: request.GetGrantedAudience(), Session: session,
	}
	payload, err := json.Marshal(persisted)
	expiresAt := session.GetExpiresAt(fosite.AccessToken)
	switch kind {
	case "authorize_code", "pkce", "openid":
		expiresAt = session.GetExpiresAt(fosite.AuthorizeCode)
	case "refresh":
		expiresAt = session.GetExpiresAt(fosite.RefreshToken)
	}
	if expiresAt.IsZero() {
		expiresAt = time.Now().UTC().Add(15 * time.Minute)
	}
	return payload, expiresAt, err
}

func (s *Store) unmarshalRequest(ctx context.Context, payload []byte) (fosite.Requester, error) {
	var persisted persistedRequest
	if err := json.Unmarshal(payload, &persisted); err != nil {
		return nil, err
	}
	client, err := s.GetClient(ctx, persisted.ClientID)
	if err != nil {
		return nil, err
	}
	request := fosite.NewRequest()
	request.ID = persisted.ID
	request.RequestedAt = persisted.RequestedAt
	request.Client = client
	request.RequestedScope = persisted.RequestedScopes
	request.GrantedScope = persisted.GrantedScopes
	request.Form = persisted.Form
	request.RequestedAudience = persisted.RequestedAudience
	request.GrantedAudience = persisted.GrantedAudience
	request.Session = persisted.Session
	return request, nil
}

type ClientSecretHasher struct{ Vault *secure.Vault }

func (h ClientSecretHasher) Hash(_ context.Context, data []byte) ([]byte, error) {
	return h.Vault.Digest(string(data)), nil
}

func (h ClientSecretHasher) Compare(_ context.Context, hash, data []byte) error {
	wanted := h.Vault.Digest(string(data))
	if len(hash) != len(wanted) || subtle.ConstantTimeCompare(hash, wanted) != 1 {
		return errors.New("client credential mismatch")
	}
	return nil
}
