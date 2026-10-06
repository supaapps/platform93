-- +goose Up
CREATE TABLE apple_identity_tokens (
    identity_id UUID PRIMARY KEY REFERENCES user_identities(id) ON DELETE CASCADE,
    auth_provider_config_id UUID NOT NULL REFERENCES auth_provider_configs(id),
    client_id TEXT NOT NULL,
    token_ciphertext TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE apple_token_revocations (
    identity_id UUID PRIMARY KEY,
    auth_provider_config_id UUID NOT NULL REFERENCES auth_provider_configs(id),
    client_id TEXT NOT NULL,
    token_ciphertext TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    available_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX apple_token_revocations_available ON apple_token_revocations(available_at);
-- +goose Down
DROP TABLE apple_token_revocations;
DROP TABLE apple_identity_tokens;
