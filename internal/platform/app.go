package platform

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/supaapps/platform93/internal/identity"
	"github.com/supaapps/platform93/internal/kernel"
	"github.com/supaapps/platform93/internal/secure"
)

type App struct {
	DB        *pgxpool.Pool
	Vault     *secure.Vault
	PublicURL string
	Now       func() time.Time
}

func New(db *pgxpool.Pool, vault *secure.Vault, publicURL string) *App {
	return &App{DB: db, Vault: vault, PublicURL: strings.TrimRight(publicURL, "/"), Now: time.Now}
}

func (a *App) Issuer() string { return a.PublicURL + "/oidc" }

func (a *App) ControlAudience() string { return "platform93:control" }

func (a *App) ApplicationAudience(applicationID uuid.UUID) string {
	return "platform93:application:" + applicationID.String()
}

func (a *App) CreateBootstrapCredential(ctx context.Context, force bool) (string, error) {
	token, err := secure.RandomToken("p93_bootstrap_", 32)
	if err != nil {
		return "", err
	}
	digest := a.Vault.Digest(token)
	command := `INSERT INTO installations (bootstrap_digest)
SELECT $1 WHERE NOT EXISTS (SELECT 1 FROM installations)`
	if _, err := a.DB.Exec(ctx, command, digest); err != nil {
		return "", err
	}
	var completedAt *time.Time
	var existing []byte
	err = a.DB.QueryRow(ctx, "SELECT setup_completed_at, bootstrap_digest FROM installations LIMIT 1").Scan(&completedAt, &existing)
	if err != nil {
		return "", err
	}
	if completedAt != nil && !force {
		return "", errors.New("installation setup is already complete; use recover explicitly")
	}
	if !force && len(existing) > 0 && !equalDigest(existing, digest) {
		return "", errors.New("a bootstrap credential already exists; use recover to replace it")
	}
	if force {
		_, err = a.DB.Exec(ctx, "UPDATE installations SET bootstrap_digest=$1, setup_completed_at=NULL, updated_at=now()", digest)
		if err != nil {
			return "", err
		}
	}
	return token, nil
}

func (a *App) Emit(ctx context.Context, tx pgx.Tx, applicationID *uuid.UUID, eventType, subject string, actor any, data any) (uuid.UUID, error) {
	eventID := kernel.NewID()
	actorJSON, err := json.Marshal(actor)
	if err != nil {
		return uuid.Nil, err
	}
	dataJSON, err := json.Marshal(data)
	if err != nil {
		return uuid.Nil, err
	}
	var schemaVersion string
	var schemaJSON []byte
	if err = tx.QueryRow(ctx, `SELECT schema_version,data_schema FROM event_type_definitions
WHERE application_id IS NULL AND name=$1 AND source='platform93' AND status='active'`, eventType).Scan(&schemaVersion, &schemaJSON); err != nil {
		return uuid.Nil, fmt.Errorf("platform event contract %q is unavailable: %w", eventType, err)
	}
	if err = validateEventContract(schemaJSON, dataJSON); err != nil {
		return uuid.Nil, fmt.Errorf("platform event %q violates contract %s: %w", eventType, schemaVersion, err)
	}
	_, err = tx.Exec(ctx, `INSERT INTO domain_events
(id,application_id,event_type,schema_version,contract_source,subject,actor,data) VALUES ($1,$2,$3,$4,'platform93',$5,$6,$7)`,
		eventID, applicationID, eventType, schemaVersion, subject, actorJSON, dataJSON)
	if err != nil {
		return uuid.Nil, err
	}
	_, err = tx.Exec(ctx, "INSERT INTO outbox (id,event_id) VALUES ($1,$2)", kernel.NewID(), eventID)
	return eventID, err
}

func validateEventContract(schemaJSON, dataJSON []byte) error {
	var schema map[string]any
	var data any
	if err := json.Unmarshal(schemaJSON, &schema); err != nil {
		return err
	}
	if err := json.Unmarshal(dataJSON, &data); err != nil {
		return err
	}
	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource("platform-event-contract.json", schema); err != nil {
		return err
	}
	contract, err := compiler.Compile("platform-event-contract.json")
	if err != nil {
		return err
	}
	return contract.Validate(data)
}

func (a *App) ActiveSigningKey(ctx context.Context) (string, []byte, error) {
	return a.ActiveSigningKeyWith(ctx, a.DB)
}

func (a *App) ActiveSigningKeyWith(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}) (string, []byte, error) {
	var kid, ciphertext string
	err := q.QueryRow(ctx, `SELECT kid, private_key_ciphertext FROM signing_keys
WHERE status='active' ORDER BY created_at DESC LIMIT 1`).Scan(&kid, &ciphertext)
	if err != nil {
		return "", nil, err
	}
	key, err := a.Vault.Decrypt(ciphertext, "signing-key:"+kid)
	return kid, key, err
}

func (a *App) ResolvePublicKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	var value []byte
	if err := a.DB.QueryRow(ctx, `SELECT public_jwk FROM signing_keys
WHERE kid=$1 AND (status='active' OR status='retiring' AND retires_at>now())`, kid).Scan(&value); err != nil {
		return nil, err
	}
	var jwk struct{ N, E string }
	if err := json.Unmarshal(value, &jwk); err != nil {
		return nil, err
	}
	n, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, err
	}
	e, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, err
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}, nil
}

func (a *App) EnsureSigningKey(ctx context.Context, tx pgx.Tx) error {
	var count int
	if err := tx.QueryRow(ctx, "SELECT count(*) FROM signing_keys WHERE status='active'").Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return nil
	}
	pair, err := identity.GenerateKeyPair()
	if err != nil {
		return err
	}
	ciphertext, err := a.Vault.Encrypt(pair.PrivatePEM, "signing-key:"+pair.KID)
	if err != nil {
		return err
	}
	publicJWK, _ := json.Marshal(pair.PublicJWK)
	_, err = tx.Exec(ctx, `INSERT INTO signing_keys
(id,kid,public_jwk,private_key_ciphertext,status,activates_at)
VALUES ($1,$2,$3,$4,'active',now())`, kernel.NewID(), pair.KID, publicJWK, ciphertext)
	return err
}

func ParsePrivateKey(value []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(value)
	if block == nil {
		return nil, fmt.Errorf("invalid private key")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func equalDigest(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var result byte
	for i := range left {
		result |= left[i] ^ right[i]
	}
	return result == 0
}
