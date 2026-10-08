package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/supaapps/platform93/internal/platform"
)

func (s *Server) retainAppleToken(ctx context.Context, applicationID, userID, subject string, provider externalAuthProviderConfig, token string) error {
	if token == "" {
		return fmt.Errorf("Apple refresh token is missing")
	}
	tx, err := s.app.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = s.retainAppleTokenTx(ctx, tx, applicationID, userID, subject, provider, token); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Server) retainAppleTokenTx(ctx context.Context, tx pgx.Tx, applicationID, userID, subject string, provider externalAuthProviderConfig, token string) error {
	if token == "" {
		return fmt.Errorf("Apple refresh token is missing")
	}
	// Serialize retention against deletion so a late callback cannot restore credentials.
	var active bool
	if err := tx.QueryRow(ctx, `SELECT status='active' AND deleted_at IS NULL FROM users WHERE id=$1 AND application_id=$2 FOR UPDATE`, userID, applicationID).Scan(&active); err != nil || !active {
		return fmt.Errorf("Apple identity unavailable")
	}
	var identityID string
	if err := tx.QueryRow(ctx, `SELECT id FROM user_identities WHERE application_id=$1 AND user_id=$2 AND provider='apple' AND provider_subject=$3`, applicationID, userID, subject).Scan(&identityID); err != nil {
		return err
	}
	sealed, err := s.app.Vault.Encrypt([]byte(token), "apple-identity:"+identityID)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO apple_identity_tokens(identity_id,auth_provider_config_id,client_id,token_ciphertext) VALUES($1,$2,$3,$4) ON CONFLICT(identity_id) DO UPDATE SET auth_provider_config_id=EXCLUDED.auth_provider_config_id,client_id=EXCLUDED.client_id,token_ciphertext=EXCLUDED.token_ciphertext,updated_at=now()`, identityID, provider.ID, provider.ClientID, sealed)
	if err != nil {
		return err
	}
	return nil
}

// Credentials are copied into a durable outbox in the same transaction as deletion.
func queueAppleRevocations(ctx context.Context, tx pgx.Tx, userID, applicationID string) error {
	return queueAppleRevocationsForIdentity(ctx, tx, userID, applicationID, nil)
}

func queueAppleRevocationsForIdentity(ctx context.Context, tx pgx.Tx, userID, applicationID string, identityID *string) error {
	var missing bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM user_identities i LEFT JOIN apple_identity_tokens t ON t.identity_id=i.id WHERE i.user_id=$1 AND i.application_id=$2 AND i.provider='apple' AND ($3::uuid IS NULL OR i.id=$3) AND t.identity_id IS NULL)`, userID, applicationID, identityID).Scan(&missing)
	if err != nil {
		return err
	}
	if missing {
		return fmt.Errorf("apple_reauthentication_required")
	}
	_, err = tx.Exec(ctx, `INSERT INTO apple_token_revocations(identity_id,auth_provider_config_id,client_id,token_ciphertext) SELECT t.identity_id,t.auth_provider_config_id,t.client_id,t.token_ciphertext FROM apple_identity_tokens t JOIN user_identities i ON i.id=t.identity_id WHERE i.user_id=$1 AND i.application_id=$2 AND i.provider='apple' AND ($3::uuid IS NULL OR i.id=$3) ON CONFLICT(identity_id) DO NOTHING`, userID, applicationID, identityID)
	return err
}

func revokeAppleToken(ctx context.Context, client *http.Client, endpoint string, provider externalAuthProviderConfig, token string, now time.Time) error {
	secret, err := createAppleClientSecret(provider, now)
	if err != nil {
		return fmt.Errorf("Apple signing configuration unavailable")
	}
	form := url.Values{"client_id": {provider.ClientID}, "client_secret": {secret}, "token": {token}, "token_type_hint": {"refresh_token"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("Apple revocation unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("Apple revocation returned status %d", response.StatusCode)
	}
	return nil
}

func runAppleRevocations(ctx context.Context, app *platform.App) error {
	client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for range 20 {
		processed, err := revokeOneAppleIdentity(ctx, app, client, "https://appleid.apple.com/auth/revoke")
		if err != nil {
			return err
		}
		if !processed {
			return nil
		}
	}
	return nil
}

func revokeOneAppleIdentity(ctx context.Context, app *platform.App, client *http.Client, endpoint string) (bool, error) {
	tx, err := app.DB.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	var id, providerID, clientID, sealed string
	err = tx.QueryRow(ctx, `SELECT identity_id,auth_provider_config_id,client_id,token_ciphertext FROM apple_token_revocations WHERE available_at<=now() ORDER BY available_at FOR UPDATE SKIP LOCKED LIMIT 1`).Scan(&id, &providerID, &clientID, &sealed)
	if err == pgx.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var configCiphertext string
	provider := externalAuthProviderConfig{ID: providerID, ClientID: clientID, Provider: "apple"}
	err = tx.QueryRow(ctx, `SELECT config_ciphertext FROM auth_provider_configs WHERE id=$1 AND provider='apple'`, providerID).Scan(&configCiphertext)
	var token, config []byte
	if err == nil {
		config, err = app.Vault.Decrypt(configCiphertext, "auth-provider:"+providerID)
	}
	if err == nil {
		err = json.Unmarshal(config, &provider.Credentials)
	}
	if err == nil {
		token, err = app.Vault.Decrypt(sealed, "apple-identity:"+id)
	}
	if err == nil {
		err = revokeAppleToken(ctx, client, endpoint, provider, string(token), app.Now())
	}
	if err != nil {
		// Never persist Apple response bodies, tokens, or private keys as error messages.
		_, err = tx.Exec(ctx, `UPDATE apple_token_revocations SET attempts=attempts+1,available_at=now()+make_interval(secs=>LEAST(3600,30*power(2,LEAST(attempts,7)))::int) WHERE identity_id=$1`, id)
	} else {
		_, err = tx.Exec(ctx, `DELETE FROM apple_token_revocations WHERE identity_id=$1`, id)
	}
	if err != nil {
		return false, err
	}
	return true, tx.Commit(ctx)
}
