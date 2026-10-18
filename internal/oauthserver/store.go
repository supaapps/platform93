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
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ory/fosite"
	"github.com/ory/fosite/storage"
	"github.com/supaapps/platform93/internal/secure"
)

type Store struct {
	DB             *pgxpool.Pool
	Vault          *secure.Vault
	ApplicationID  uuid.UUID
	ResourceURI    string
	ResourceScopes []string
}

var _ fosite.Storage = (*Store)(nil)
var _ storage.Transactional = (*Store)(nil)

type transactionKey struct{ store *Store }

type executor interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

func (s *Store) executor(ctx context.Context) executor {
	if tx, ok := ctx.Value(transactionKey{s}).(pgx.Tx); ok {
		return tx
	}
	return s.DB
}

// Transaction exposes the request-local transaction for atomic domain changes.
func (s *Store) Transaction(ctx context.Context) (pgx.Tx, bool) {
	tx, ok := ctx.Value(transactionKey{s}).(pgx.Tx)
	return tx, ok
}

// Fosite brackets token consumption and successor persistence with these hooks.
// Transactions belong to the request context, never to a shared Store field.
func (s *Store) BeginTX(ctx context.Context) (context.Context, error) {
	if _, ok := ctx.Value(transactionKey{s}).(pgx.Tx); ok {
		return nil, errors.New("OAuth transaction is already active")
	}
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return context.WithValue(ctx, transactionKey{s}, tx), nil
}

func (s *Store) Commit(ctx context.Context) error {
	tx, ok := ctx.Value(transactionKey{s}).(pgx.Tx)
	if !ok {
		return errors.New("OAuth transaction is missing")
	}
	return tx.Commit(ctx)
}

func (s *Store) Rollback(ctx context.Context) error {
	tx, ok := ctx.Value(transactionKey{s}).(pgx.Tx)
	if !ok {
		return errors.New("OAuth transaction is missing")
	}
	err := tx.Rollback(ctx)
	if errors.Is(err, pgx.ErrTxClosed) {
		return nil
	}
	return err
}

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
	lookupID := clientID
	if s.ResourceURI != "" {
		var boundID string
		err := s.executor(ctx).QueryRow(ctx, `SELECT c.client_id FROM oauth_resource_clients b JOIN oauth_resources r ON r.id=b.resource_id JOIN clients c ON c.id=b.client_database_id WHERE b.application_id=$1 AND r.uri=$2 AND b.client_id=$3`, s.ApplicationID, s.ResourceURI, clientID).Scan(&boundID)
		if err == nil {
			lookupID = boundID
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return nil, fosite.ErrNotFound
		}
	}
	err := s.executor(ctx).QueryRow(ctx, `SELECT client_type,redirect_uris,allowed_grants,allowed_scopes,secret_digest
FROM clients WHERE application_id=$1 AND client_id=$2 AND disabled_at IS NULL AND (NOT resource_only OR $3)`, s.ApplicationID, lookupID, s.ResourceURI != "").
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
	audiences := []string{"platform93:application:" + s.ApplicationID.String()}
	if s.ResourceURI != "" {
		if clientType == "machine" {
			return nil, fosite.ErrNotFound
		}
		audiences = []string{s.ResourceURI}
		scopes = append([]string{"openid", "email", "profile", "offline_access"}, s.ResourceScopes...)
		grants = []string{"authorization_code", "refresh_token"}
	}
	client := &fosite.DefaultClient{
		ID: clientID, Secret: secret, RedirectURIs: redirects, GrantTypes: grants,
		ResponseTypes: []string{"code"}, Scopes: scopes, Audience: audiences, Public: clientType == "public",
	}
	if !client.Public {
		// DefaultClient accepts Basic and POST secret authentication, both verified
		// against the same installation-keyed digest. Assertion methods stay disabled.
		return client, nil
	}
	return &fosite.DefaultOpenIDConnectClient{DefaultClient: client, TokenEndpointAuthMethod: "none"}, nil
}

func (s *Store) ClientAssertionJWTValid(ctx context.Context, jti string) error {
	var known bool
	err := s.executor(ctx).QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM oauth_client_assertion_jtis
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
	_, _ = s.executor(ctx).Exec(ctx, `DELETE FROM oauth_client_assertion_jtis WHERE application_id=$1 AND expires_at<=now()`, s.ApplicationID)
	_, err := s.executor(ctx).Exec(ctx, `INSERT INTO oauth_client_assertion_jtis(application_id,jti_digest,expires_at)
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
	var requestID string
	err := s.executor(ctx).QueryRow(ctx, `SELECT request_id FROM oauth_sessions
WHERE application_id=$1 AND kind='refresh' AND signature_digest=$2`, s.ApplicationID, s.Vault.Digest(signature)).Scan(&requestID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	return s.withFamilyTransaction(ctx, requestID, func(ctx context.Context) error {
		return s.delete(ctx, "refresh", signature)
	})
}

func (s *Store) RevokeRefreshToken(ctx context.Context, requestID string) error {
	return s.withFamilyTransaction(ctx, requestID, func(ctx context.Context) error {
		_, err := s.executor(ctx).Exec(ctx, `UPDATE oauth_sessions SET active=false,updated_at=now()
WHERE application_id=$1 AND request_id=$2 AND kind IN ('refresh','access')`, s.ApplicationID, requestID)
		return err
	})
}

func (s *Store) RevokeAccessToken(ctx context.Context, requestID string) error {
	return s.withFamilyTransaction(ctx, requestID, func(ctx context.Context) error {
		_, err := s.executor(ctx).Exec(ctx, `UPDATE oauth_sessions SET active=false,updated_at=now()
WHERE application_id=$1 AND request_id=$2 AND kind='access'`, s.ApplicationID, requestID)
		return err
	})
}

func (s *Store) lockFamily(ctx context.Context, requestID string) error {
	// Keep lock acquisition separate so the following statement sees a fresh
	// READ COMMITTED snapshot after a competing rotation commits its successors.
	_, err := s.executor(ctx).Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "oauth-family:"+s.ApplicationID.String()+":"+requestID)
	return err
}

func (s *Store) withFamilyTransaction(ctx context.Context, requestID string, operation func(context.Context) error) error {
	_, existing := s.Transaction(ctx)
	if !existing {
		var err error
		ctx, err = s.BeginTX(ctx)
		if err != nil {
			return err
		}
		defer s.Rollback(ctx)
	}
	if err := s.lockFamily(ctx, requestID); err != nil {
		return err
	}
	if err := operation(ctx); err != nil {
		return err
	}
	if !existing {
		return s.Commit(ctx)
	}
	return nil
}

func (s *Store) RotateRefreshToken(ctx context.Context, requestID, signature string) error {
	if _, ok := ctx.Value(transactionKey{s}).(pgx.Tx); !ok {
		return errors.New("refresh rotation requires a transaction")
	}
	if err := s.lockFamily(ctx, requestID); err != nil {
		return err
	}
	result, err := s.executor(ctx).Exec(ctx, `UPDATE oauth_sessions SET active=false,updated_at=now()
WHERE application_id=$1 AND request_id=$2 AND kind='refresh' AND signature_digest=$3 AND active AND expires_at>now()`,
		s.ApplicationID, requestID, s.Vault.Digest(signature))
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		var consumed bool
		if err := s.executor(ctx).QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM oauth_sessions
WHERE application_id=$1 AND request_id=$2 AND kind='refresh' AND signature_digest=$3 AND NOT active)`,
			s.ApplicationID, requestID, s.Vault.Digest(signature)).Scan(&consumed); err != nil {
			return err
		}
		if !consumed {
			return fosite.ErrInactiveToken
		}
		// Fosite rolls back response-stage failures. Release this transaction's
		// family lock first, then commit reuse revocation independently.
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if err := s.Rollback(cleanup); err != nil {
			return err
		}
		cleanup = context.WithValue(cleanup, transactionKey{s}, struct{}{})
		if err := s.RevokeRefreshToken(cleanup, requestID); err != nil {
			return err
		}
		return fosite.ErrInactiveToken
	}
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
	_, err = s.executor(ctx).Exec(ctx, `INSERT INTO oauth_sessions
(id,application_id,signature_digest,kind,request_id,request_payload,access_signature_digest,expires_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, uuid.Must(uuid.NewV7()), s.ApplicationID, s.Vault.Digest(signature), kind,
		request.GetID(), payload, accessDigest, expiresAt)
	return err
}

func (s *Store) get(ctx context.Context, kind, signature string) (fosite.Requester, bool, error) {
	var payload []byte
	var active bool
	err := s.executor(ctx).QueryRow(ctx, `SELECT request_payload,active FROM oauth_sessions
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
	result, err := s.executor(ctx).Exec(ctx, `UPDATE oauth_sessions SET active=false,updated_at=now()
WHERE application_id=$1 AND kind=$2 AND signature_digest=$3 AND active`, s.ApplicationID, kind, s.Vault.Digest(signature))
	if err != nil {
		return err
	}
	if result.RowsAffected() == 0 {
		return fosite.ErrNotFound
	}
	return nil
}

func (s *Store) delete(ctx context.Context, kind, signature string) error {
	_, err := s.executor(ctx).Exec(ctx, `DELETE FROM oauth_sessions WHERE application_id=$1 AND kind=$2 AND signature_digest=$3`,
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
