-- +goose Up
ALTER TABLE applications
    ADD COLUMN public_config jsonb NOT NULL DEFAULT '{}',
    ADD COLUMN internal_config jsonb NOT NULL DEFAULT '{"registration_mode":"public","password_enabled":true,"passwordless_enabled":true,"personal_api_keys_enabled":false,"delegation_enabled":false}';

UPDATE applications SET internal_config = jsonb_build_object(
    'registration_mode', CASE WHEN COALESCE((auth_config->>'registration_enabled')::boolean, true) THEN 'public' ELSE 'invite_only' END,
    'password_enabled', COALESCE((auth_config->>'password_enabled')::boolean, true),
    'passwordless_enabled', COALESCE((auth_config->>'passwordless_enabled')::boolean, true),
    'personal_api_keys_enabled', COALESCE((auth_config->'personal_api_keys'->>'enabled')::boolean, false),
    'delegation_enabled', true
), auth_config = auth_config - 'registration_enabled' - 'password_enabled' - 'passwordless_enabled' - 'personal_api_keys';

ALTER TABLE applications ALTER COLUMN auth_config SET DEFAULT '{}';
ALTER TABLE applications ADD CONSTRAINT applications_internal_config_check CHECK (
    jsonb_typeof(public_config) = 'object' AND
    jsonb_typeof(internal_config) = 'object' AND
    internal_config ?& ARRAY['registration_mode','password_enabled','passwordless_enabled','personal_api_keys_enabled','delegation_enabled'] AND
    internal_config->>'registration_mode' IN ('public','invite_only') AND
    jsonb_typeof(internal_config->'password_enabled') = 'boolean' AND
    jsonb_typeof(internal_config->'passwordless_enabled') = 'boolean' AND
    jsonb_typeof(internal_config->'personal_api_keys_enabled') = 'boolean' AND
    jsonb_typeof(internal_config->'delegation_enabled') = 'boolean'
);

-- +goose Down
ALTER TABLE applications DROP CONSTRAINT applications_internal_config_check;
UPDATE applications SET auth_config = auth_config || jsonb_build_object(
    'registration_enabled', internal_config->>'registration_mode' = 'public',
    'password_enabled', internal_config->'password_enabled',
    'passwordless_enabled', internal_config->'passwordless_enabled',
    'personal_api_keys', jsonb_build_object('enabled', internal_config->'personal_api_keys_enabled')
);
ALTER TABLE applications ALTER COLUMN auth_config SET DEFAULT '{"registration_enabled":true,"password_enabled":true,"passwordless_enabled":true,"personal_api_keys":{"enabled":false}}';
ALTER TABLE applications DROP COLUMN internal_config, DROP COLUMN public_config;
