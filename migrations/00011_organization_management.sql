-- +goose Up
ALTER TABLE installations ADD COLUMN management_api_enabled boolean NOT NULL DEFAULT false;

COMMENT ON COLUMN installations.management_api_enabled IS 'Live kill switch for machine-only installation organization management.';

CREATE TABLE management_clients (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id text NOT NULL UNIQUE,
    name text NOT NULL,
    secret_digest bytea NOT NULL,
    allowed_scopes text[] NOT NULL DEFAULT ARRAY['/management/organizations/*']::text[],
    disabled_at timestamptz,
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE organization_policies (
    organization_id uuid PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
    max_applications integer CHECK (max_applications IS NULL OR max_applications >= 0),
    max_users integer CHECK (max_users IS NULL OR max_users >= 0),
    enabled_settings jsonb NOT NULL DEFAULT '{
      "public_registration": true,
      "password_authentication": true,
      "passwordless_authentication": true,
      "personal_api_keys": true,
      "delegation": true,
      "organization_provider_overrides": true,
      "application_provider_overrides": true,
      "custom_events": true,
      "webhooks": true
    }'::jsonb,
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CHECK (jsonb_typeof(enabled_settings) = 'object')
);

INSERT INTO organization_policies(organization_id)
SELECT id FROM organizations ON CONFLICT DO NOTHING;

-- +goose StatementBegin
CREATE FUNCTION create_default_organization_policy() RETURNS trigger AS $$
BEGIN
    INSERT INTO organization_policies(organization_id) VALUES(NEW.id);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

CREATE TRIGGER organizations_default_policy
AFTER INSERT ON organizations FOR EACH ROW EXECUTE FUNCTION create_default_organization_policy();

-- +goose Down
DROP TRIGGER IF EXISTS organizations_default_policy ON organizations;
DROP FUNCTION IF EXISTS create_default_organization_policy();
DROP TABLE IF EXISTS organization_policies;
DROP TABLE IF EXISTS management_clients;
ALTER TABLE installations DROP COLUMN management_api_enabled;
