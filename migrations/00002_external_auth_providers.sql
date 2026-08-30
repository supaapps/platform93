-- +goose Up
-- +goose StatementBegin
ALTER TABLE auth_provider_configs DROP CONSTRAINT auth_provider_configs_provider_check;
ALTER TABLE auth_provider_configs ADD CONSTRAINT auth_provider_configs_provider_check
    CHECK (provider = ANY (ARRAY['google', 'apple', 'microsoft', 'facebook', 'linkedin']));

ALTER TABLE control_user_identities DROP CONSTRAINT control_user_identities_provider_check;
ALTER TABLE control_user_identities ADD CONSTRAINT control_user_identities_provider_check
    CHECK (provider = ANY (ARRAY['google', 'apple', 'microsoft', 'facebook', 'linkedin']));

ALTER TABLE control_user_external_auth_challenges DROP CONSTRAINT control_user_external_auth_challenges_provider_check;
ALTER TABLE control_user_external_auth_challenges ADD CONSTRAINT control_user_external_auth_challenges_provider_check
    CHECK (provider = ANY (ARRAY['google', 'apple', 'microsoft', 'facebook', 'linkedin']));

ALTER TABLE control_user_invitations DROP CONSTRAINT control_user_invitations_method_check;
ALTER TABLE control_user_invitations ADD CONSTRAINT control_user_invitations_method_check
    CHECK (onboarding_method = ANY (ARRAY['email', 'google', 'apple', 'microsoft', 'facebook', 'linkedin']));

ALTER TABLE application_invitations
    ADD COLUMN onboarding_method text NOT NULL DEFAULT 'email';
ALTER TABLE application_invitations ADD CONSTRAINT application_invitations_method_check
    CHECK (onboarding_method = ANY (ARRAY['email', 'google', 'apple', 'microsoft', 'facebook', 'linkedin']));

ALTER TABLE external_auth_challenges
    ADD COLUMN auth_provider_config_id uuid REFERENCES auth_provider_configs(id),
    ADD COLUMN invitation_id uuid REFERENCES application_invitations(id),
    ADD COLUMN code_challenge text;
ALTER TABLE external_auth_challenges DROP CONSTRAINT external_auth_challenges_flow_check;
ALTER TABLE external_auth_challenges ADD CONSTRAINT external_auth_challenges_flow_check
    CHECK (flow = ANY (ARRAY['sign_in', 'sign_up', 'automatic', 'link', 'invitation']));
ALTER TABLE external_auth_challenges ADD CONSTRAINT external_auth_challenges_code_challenge_check
    CHECK (code_challenge IS NULL OR code_challenge ~ '^[A-Za-z0-9_-]{43}$');

ALTER TABLE external_auth_exchanges ADD COLUMN code_challenge text;
ALTER TABLE external_auth_exchanges ADD CONSTRAINT external_auth_exchanges_code_challenge_check
    CHECK (code_challenge IS NULL OR code_challenge ~ '^[A-Za-z0-9_-]{43}$');

CREATE TABLE external_auth_email_enrollments (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id uuid NOT NULL REFERENCES applications(id),
    auth_provider_config_id uuid NOT NULL REFERENCES auth_provider_configs(id),
    provider text NOT NULL,
    provider_subject text NOT NULL,
    first_name text NOT NULL DEFAULT '',
    last_name text NOT NULL DEFAULT '',
    suggested_email text,
    app_redirect_uri text NOT NULL,
    credential_digest bytea NOT NULL UNIQUE,
    code_challenge text NOT NULL,
    pkce_verified_at timestamptz,
    normalized_email text,
    code_digest bytea,
    link_digest bytea,
    attempts integer NOT NULL DEFAULT 0,
    email_sent_at timestamptz,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT external_auth_email_enrollments_provider_check
        CHECK (provider = ANY (ARRAY['microsoft', 'facebook', 'linkedin'])),
    CONSTRAINT external_auth_email_enrollments_code_challenge_check
        CHECK (code_challenge ~ '^[A-Za-z0-9_-]{43}$'),
    CONSTRAINT external_auth_email_enrollments_attempts_check CHECK (attempts >= 0 AND attempts <= 20)
);
CREATE INDEX external_auth_email_enrollments_active
    ON external_auth_email_enrollments(application_id, provider, expires_at)
    WHERE consumed_at IS NULL;

UPDATE event_type_definitions
SET data_schema = replace(
    replace(
        replace(data_schema::text, '["google","apple"]', '["google","apple","microsoft","facebook","linkedin"]'),
        '["google", "apple"]', '["google", "apple", "microsoft", "facebook", "linkedin"]'),
    '["email","google","apple"]', '["email","google","apple","microsoft","facebook","linkedin"]')::jsonb
WHERE name IN ('control_user.identity_linked', 'control_user.identity_unlinked', 'control_auth.provider_login_enabled',
               'control_auth.provider_login_disabled', 'control_user.invitation_created', 'control_user.invitation_resent', 'control_user.invitation_accepted',
               'control_user.invitation_revoked');

UPDATE event_type_definitions
SET data_schema = jsonb_set(data_schema, '{properties,onboarding_method}',
    '{"enum":["email","google","apple","microsoft","facebook","linkedin"]}'::jsonb, true)
WHERE name LIKE 'application_invitation.%';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
UPDATE event_type_definitions
SET data_schema = replace(
    replace(
        replace(data_schema::text, '["google","apple","microsoft","facebook","linkedin"]', '["google","apple"]'),
        '["google", "apple", "microsoft", "facebook", "linkedin"]', '["google", "apple"]'),
    '["email","google","apple","microsoft","facebook","linkedin"]', '["email","google","apple"]')::jsonb
WHERE name IN ('control_user.identity_linked', 'control_user.identity_unlinked', 'control_auth.provider_login_enabled',
               'control_auth.provider_login_disabled', 'control_user.invitation_created', 'control_user.invitation_resent', 'control_user.invitation_accepted',
               'control_user.invitation_revoked');

UPDATE event_type_definitions
SET data_schema = data_schema #- '{properties,onboarding_method}'
WHERE name LIKE 'application_invitation.%';

DROP TABLE IF EXISTS external_auth_email_enrollments;

ALTER TABLE external_auth_exchanges DROP CONSTRAINT IF EXISTS external_auth_exchanges_code_challenge_check;
ALTER TABLE external_auth_exchanges DROP COLUMN IF EXISTS code_challenge;

ALTER TABLE external_auth_challenges DROP CONSTRAINT IF EXISTS external_auth_challenges_code_challenge_check;
ALTER TABLE external_auth_challenges DROP CONSTRAINT external_auth_challenges_flow_check;
ALTER TABLE external_auth_challenges ADD CONSTRAINT external_auth_challenges_flow_check
    CHECK (flow = ANY (ARRAY['sign_in', 'sign_up', 'automatic', 'link']));
ALTER TABLE external_auth_challenges DROP COLUMN IF EXISTS code_challenge;
ALTER TABLE external_auth_challenges DROP COLUMN IF EXISTS invitation_id;
ALTER TABLE external_auth_challenges DROP COLUMN IF EXISTS auth_provider_config_id;

ALTER TABLE application_invitations DROP CONSTRAINT IF EXISTS application_invitations_method_check;
ALTER TABLE application_invitations DROP COLUMN IF EXISTS onboarding_method;

ALTER TABLE control_user_invitations DROP CONSTRAINT control_user_invitations_method_check;
ALTER TABLE control_user_invitations ADD CONSTRAINT control_user_invitations_method_check
    CHECK (onboarding_method = ANY (ARRAY['email', 'google', 'apple']));

ALTER TABLE control_user_external_auth_challenges DROP CONSTRAINT control_user_external_auth_challenges_provider_check;
ALTER TABLE control_user_external_auth_challenges ADD CONSTRAINT control_user_external_auth_challenges_provider_check
    CHECK (provider = ANY (ARRAY['google', 'apple']));

ALTER TABLE control_user_identities DROP CONSTRAINT control_user_identities_provider_check;
ALTER TABLE control_user_identities ADD CONSTRAINT control_user_identities_provider_check
    CHECK (provider = ANY (ARRAY['google', 'apple']));

ALTER TABLE auth_provider_configs DROP CONSTRAINT auth_provider_configs_provider_check;
ALTER TABLE auth_provider_configs ADD CONSTRAINT auth_provider_configs_provider_check
    CHECK (provider = ANY (ARRAY['google', 'apple']));
-- +goose StatementEnd
