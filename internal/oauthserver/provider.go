package oauthserver

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/token/jwt"
	"github.com/supaapps/platform93/internal/platform"
)

type Provider struct {
	OAuth  fosite.OAuth2Provider
	Store  *Store
	KID    string
	Issuer string
}

func NewProvider(ctx context.Context, app *platform.App, applicationID uuid.UUID) (*Provider, error) {
	var active bool
	if err := app.DB.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM applications
WHERE id=$1 AND deleted_at IS NULL)`, applicationID).Scan(&active); err != nil {
		return nil, err
	}
	if !active {
		return nil, fmt.Errorf("application is unavailable")
	}
	issuer := app.Issuer()
	kid, encodedKey, err := app.ActiveSigningKey(ctx)
	if err != nil {
		return nil, err
	}
	privateKey, err := platform.ParsePrivateKey(encodedKey)
	if err != nil {
		return nil, err
	}
	store := &Store{DB: app.DB, Vault: app.Vault, ApplicationID: applicationID}
	config := &fosite.Config{
		AccessTokenLifespan:            5 * time.Minute,
		RefreshTokenLifespan:           30 * 24 * time.Hour,
		AuthorizeCodeLifespan:          5 * time.Minute,
		IDTokenLifespan:                5 * time.Minute,
		AccessTokenIssuer:              issuer,
		IDTokenIssuer:                  issuer,
		TokenURL:                       issuer + "/token",
		GlobalSecret:                   app.Vault.Digest("oauth-hmac:" + applicationID.String()),
		ClientSecretsHasher:            ClientSecretHasher{Vault: app.Vault},
		EnforcePKCE:                    true,
		EnforcePKCEForPublicClients:    true,
		EnablePKCEPlainChallengeMethod: false,
		RefreshTokenScopes:             []string{"offline_access"},
		ScopeStrategy:                  fosite.ExactScopeStrategy,
		SendDebugMessagesToClients:     false,
		UseLegacyErrorFormat:           false,
		JWTScopeClaimKey:               jwt.JWTScopeFieldString,
	}
	keyGetter := func(context.Context) (interface{}, error) { return privateKey, nil }
	hmacStrategy := compose.NewOAuth2HMACStrategy(config)
	strategy := &compose.CommonStrategy{
		CoreStrategy:               compose.NewOAuth2JWTStrategy(keyGetter, hmacStrategy, config),
		OpenIDConnectTokenStrategy: compose.NewOpenIDConnectStrategy(keyGetter, config),
		Signer:                     &jwt.DefaultSigner{GetPrivateKey: keyGetter},
	}
	provider := compose.Compose(config, store, strategy,
		compose.OAuth2AuthorizeExplicitFactory,
		compose.OAuth2ClientCredentialsGrantFactory,
		compose.OAuth2RefreshTokenGrantFactory,
		compose.OpenIDConnectExplicitFactory,
		compose.OpenIDConnectRefreshFactory,
		compose.OAuth2TokenIntrospectionFactory,
		compose.OAuth2TokenRevocationFactory,
		compose.OAuth2PKCEFactory,
	)
	return &Provider{OAuth: provider, Store: store, KID: kid, Issuer: issuer}, nil
}
