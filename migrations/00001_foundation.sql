-- +goose Up
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE installations (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    setup_completed_at timestamptz,
    bootstrap_digest bytea,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX installations_singleton ON installations ((true));

CREATE TABLE signing_keys (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    kid text NOT NULL UNIQUE,
    public_jwk jsonb NOT NULL,
    private_key_ciphertext text NOT NULL,
    status text NOT NULL CHECK (status IN ('prepared','active','retiring','retired')),
    activates_at timestamptz,
    retires_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE operators (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    email text NOT NULL,
    normalized_email text NOT NULL UNIQUE,
    display_name text NOT NULL DEFAULT '',
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active','suspended','deleted')),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE operator_sessions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    operator_id uuid NOT NULL REFERENCES operators(id),
    refresh_digest bytea NOT NULL UNIQUE,
    kind text NOT NULL DEFAULT 'operator' CHECK (kind IN ('setup','operator')),
    ip_address inet,
    user_agent text NOT NULL DEFAULT '',
    last_used_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE installation_operator_roles (
    operator_id uuid PRIMARY KEY REFERENCES operators(id),
    role text NOT NULL CHECK (role IN ('owner','admin','auditor')),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE operator_login_challenges (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    normalized_email text NOT NULL,
    code_digest bytea,
    link_digest bytea,
    attempts integer NOT NULL DEFAULT 0,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE auth_rate_limits (
    bucket_digest bytea PRIMARY KEY,
    attempts integer NOT NULL,
    window_started_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL
);
CREATE INDEX auth_rate_limits_expiry ON auth_rate_limits(expires_at);

CREATE TABLE organizations (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name text NOT NULL,
    slug text NOT NULL UNIQUE,
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    deleted_at timestamptz
);

CREATE TABLE organization_memberships (
    organization_id uuid NOT NULL REFERENCES organizations(id),
    operator_id uuid NOT NULL REFERENCES operators(id),
    role text NOT NULL CHECK (role IN ('owner','admin','member','auditor')),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, operator_id)
);

CREATE TABLE organization_invitations (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL REFERENCES organizations(id),
    normalized_email text NOT NULL,
    role text NOT NULL CHECK (role IN ('owner','admin','member','auditor')),
    credential_digest bytea NOT NULL,
    invited_by uuid NOT NULL REFERENCES operators(id),
    accepted_by uuid REFERENCES operators(id),
    expires_at timestamptz NOT NULL,
    accepted_at timestamptz,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX organization_invitations_pending ON organization_invitations(organization_id,normalized_email)
WHERE accepted_at IS NULL AND revoked_at IS NULL;

CREATE TABLE applications (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL REFERENCES organizations(id),
    name text NOT NULL,
    slug text NOT NULL,
    auth_config jsonb NOT NULL DEFAULT '{"registration_enabled":true,"password_enabled":true,"passwordless_enabled":true,"personal_api_keys":{"enabled":false}}',
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    deleted_at timestamptz,
    UNIQUE (organization_id, slug)
);

CREATE TABLE application_domains (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id uuid NOT NULL REFERENCES applications(id),
    hostname text NOT NULL,
    verification_ciphertext text NOT NULL,
    verified_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (application_id, hostname)
);

CREATE TABLE application_secrets (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id uuid NOT NULL REFERENCES applications(id),
    kind text NOT NULL,
    name text NOT NULL,
    ciphertext text NOT NULL,
    metadata jsonb NOT NULL DEFAULT '{}',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (application_id, kind, name)
);

CREATE TABLE clients (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id uuid NOT NULL REFERENCES applications(id),
    client_id text NOT NULL,
    name text NOT NULL,
    client_type text NOT NULL CHECK (client_type IN ('public','confidential','machine')),
    redirect_uris text[] NOT NULL DEFAULT '{}',
    post_logout_redirect_uris text[] NOT NULL DEFAULT '{}',
    allowed_grants text[] NOT NULL DEFAULT '{}',
    allowed_scopes text[] NOT NULL DEFAULT '{}',
    secret_digest bytea,
    disabled_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (client_id)
);

CREATE TABLE users (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id uuid NOT NULL REFERENCES applications(id),
    email text NOT NULL,
    normalized_email text NOT NULL,
    first_name text NOT NULL DEFAULT '',
    last_name text NOT NULL DEFAULT '',
    username text,
    password_hash text,
    email_verified_at timestamptz,
    is_org_verified boolean NOT NULL DEFAULT false,
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active','suspended','pending_deletion','anonymized','deleted')),
    custom_attributes jsonb NOT NULL DEFAULT '{}',
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    deleted_at timestamptz,
    UNIQUE (application_id, normalized_email)
);
CREATE UNIQUE INDEX users_application_identity ON users(application_id,id);

CREATE TABLE user_identities (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id uuid NOT NULL REFERENCES applications(id),
    user_id uuid NOT NULL REFERENCES users(id),
    provider text NOT NULL,
    provider_subject text NOT NULL,
    metadata jsonb NOT NULL DEFAULT '{}',
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (application_id, provider, provider_subject)
);

CREATE TABLE login_challenges (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id uuid NOT NULL REFERENCES applications(id),
    normalized_email text NOT NULL,
	requested_by_user_id uuid REFERENCES users(id),
    intent text NOT NULL CHECK (intent IN ('sign_in','sign_up','automatic','verify_email','change_email','password_reset')),
    code_digest bytea,
    link_digest bytea,
    redirect_uri text,
    attempts integer NOT NULL DEFAULT 0,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE external_auth_challenges (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id uuid NOT NULL REFERENCES applications(id),
    provider text NOT NULL,
    flow text NOT NULL CHECK (flow IN ('sign_in','sign_up','automatic','link')),
    requested_by_user_id uuid REFERENCES users(id),
    app_redirect_uri text NOT NULL,
    state_digest bytea NOT NULL UNIQUE,
    nonce_digest bytea NOT NULL,
    verifier_ciphertext text NOT NULL,
    expires_at timestamptz NOT NULL,
    locked_until timestamptz,
    consumed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE external_auth_exchanges (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id uuid NOT NULL REFERENCES applications(id),
    user_id uuid NOT NULL REFERENCES users(id),
    credential_digest bytea NOT NULL UNIQUE,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE delegations (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id uuid NOT NULL REFERENCES applications(id),
    operator_id uuid NOT NULL REFERENCES operators(id),
    user_id uuid NOT NULL REFERENCES users(id),
    workspace_id uuid,
    reason text NOT NULL,
    redirect_uri text NOT NULL,
    permissions text[] NOT NULL,
    exchange_digest bytea NOT NULL UNIQUE,
    expires_at timestamptz NOT NULL,
    exchanged_at timestamptz,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE user_sessions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id uuid NOT NULL REFERENCES applications(id),
    user_id uuid NOT NULL REFERENCES users(id),
    delegation_id uuid REFERENCES delegations(id),
    refresh_digest bytea NOT NULL UNIQUE,
    previous_refresh_digest bytea,
    previous_valid_until timestamptz,
    user_agent text,
    ip_hash bytea,
    authenticated_at timestamptz NOT NULL DEFAULT now(),
    mfa_authenticated_at timestamptz,
    amr text[] NOT NULL DEFAULT '{}',
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz
);

CREATE TABLE user_authentication_methods (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id uuid NOT NULL REFERENCES applications(id),
    user_id uuid NOT NULL REFERENCES users(id),
    method_type text NOT NULL CHECK (method_type IN ('totp','webauthn')),
    label text NOT NULL DEFAULT '',
    secret_ciphertext text,
    credential_id bytea,
    credential_ciphertext text,
    webauthn_rp_id text,
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','active','disabled')),
    created_at timestamptz NOT NULL DEFAULT now(),
    activated_at timestamptz,
    last_used_at timestamptz,
    disabled_at timestamptz
);
CREATE INDEX user_authentication_methods_user ON user_authentication_methods(application_id,user_id,status);
CREATE UNIQUE INDEX user_authentication_methods_webauthn_credential ON user_authentication_methods(application_id,credential_id)
WHERE method_type='webauthn' AND status<>'disabled';

CREATE TABLE user_recovery_codes (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id uuid NOT NULL REFERENCES applications(id),
    user_id uuid NOT NULL REFERENCES users(id),
    code_digest bytea NOT NULL,
    used_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (application_id,code_digest)
);

CREATE TABLE mfa_login_challenges (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id uuid NOT NULL REFERENCES applications(id),
    user_id uuid NOT NULL REFERENCES users(id),
    primary_amr text[] NOT NULL,
    attempts integer NOT NULL DEFAULT 0,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE webauthn_ceremonies (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id uuid NOT NULL REFERENCES applications(id),
    user_id uuid NOT NULL REFERENCES users(id),
    user_session_id uuid REFERENCES user_sessions(id),
    mfa_challenge_id uuid REFERENCES mfa_login_challenges(id),
    intent text NOT NULL CHECK (intent IN ('register','authenticate')),
    origin text NOT NULL,
    label text NOT NULL DEFAULT '',
    session_ciphertext text NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);

-- Fosite stores only token signatures and sanitized request state. Raw OAuth
-- credentials never enter PostgreSQL and cannot be reconstructed from it.
CREATE TABLE oauth_sessions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id uuid NOT NULL REFERENCES applications(id),
    signature_digest bytea NOT NULL,
    kind text NOT NULL CHECK (kind IN ('authorize_code','pkce','openid','access','refresh')),
    request_id text NOT NULL,
    request_payload jsonb NOT NULL,
    access_signature_digest bytea,
    expires_at timestamptz NOT NULL,
    active boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (application_id, kind, signature_digest)
);
CREATE INDEX oauth_sessions_request ON oauth_sessions(application_id,request_id,kind) WHERE active;
CREATE INDEX oauth_sessions_expiry ON oauth_sessions(expires_at);

CREATE TABLE oauth_client_assertion_jtis (
    application_id uuid NOT NULL REFERENCES applications(id),
    jti_digest bytea NOT NULL,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (application_id,jti_digest)
);
CREATE INDEX oauth_client_assertion_jtis_expiry ON oauth_client_assertion_jtis(expires_at);

CREATE TABLE oauth_consents (
    application_id uuid NOT NULL REFERENCES applications(id),
    user_id uuid NOT NULL REFERENCES users(id),
    client_id uuid NOT NULL REFERENCES clients(id),
    scopes text[] NOT NULL DEFAULT '{}',
    granted_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz,
    PRIMARY KEY (application_id,user_id,client_id)
);

CREATE TABLE personal_api_keys (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id uuid NOT NULL REFERENCES applications(id),
    user_id uuid NOT NULL REFERENCES users(id),
    label text,
    token_prefix text NOT NULL,
    token_digest bytea NOT NULL UNIQUE,
    scopes text[] NOT NULL DEFAULT '{}',
    expires_at timestamptz NOT NULL,
    last_used_at timestamptz,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE billing_profiles (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id uuid NOT NULL REFERENCES applications(id),
    subject_type text NOT NULL CHECK (subject_type IN ('user','workspace')),
    subject_id uuid NOT NULL,
    name text NOT NULL DEFAULT '',
    email text,
    tax_id text,
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (application_id,subject_type,subject_id)
);

CREATE TABLE addresses (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id uuid NOT NULL REFERENCES applications(id),
    billing_profile_id uuid NOT NULL REFERENCES billing_profiles(id),
    name text NOT NULL DEFAULT '',
    line1 text NOT NULL,
    line2 text NOT NULL DEFAULT '',
    city text NOT NULL,
    region text NOT NULL DEFAULT '',
    postal_code text NOT NULL,
    country_code char(2) NOT NULL,
    is_active boolean NOT NULL DEFAULT false,
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX addresses_one_active ON addresses(billing_profile_id) WHERE is_active;

CREATE TABLE roles (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id uuid NOT NULL REFERENCES applications(id),
    key text NOT NULL,
    name text NOT NULL,
    scope text NOT NULL CHECK (scope IN ('application','workspace')),
    permissions text[] NOT NULL DEFAULT '{}',
    built_in boolean NOT NULL DEFAULT false,
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (application_id, key)
);

CREATE TABLE workspaces (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id uuid NOT NULL REFERENCES applications(id),
    owner_user_id uuid NOT NULL,
    key text NOT NULL,
    name text NOT NULL,
    metadata jsonb NOT NULL DEFAULT '{}',
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    deleted_at timestamptz,
    UNIQUE (application_id, key),
    UNIQUE (application_id, id),
    FOREIGN KEY (application_id,owner_user_id) REFERENCES users(application_id,id)
);

CREATE TABLE workspace_memberships (
    application_id uuid NOT NULL,
    workspace_id uuid NOT NULL,
    user_id uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (workspace_id,user_id),
    FOREIGN KEY (application_id,workspace_id) REFERENCES workspaces(application_id,id),
    FOREIGN KEY (application_id,user_id) REFERENCES users(application_id,id)
);

-- +goose StatementBegin
CREATE FUNCTION workspace_accessible_to_user(target_application_id uuid, target_workspace_id uuid, target_user_id uuid)
RETURNS boolean LANGUAGE sql STABLE PARALLEL SAFE AS $$
    SELECT EXISTS(
        SELECT 1 FROM workspaces w
        WHERE w.application_id=target_application_id AND w.id=target_workspace_id AND w.deleted_at IS NULL
          AND (w.owner_user_id=target_user_id OR EXISTS(
              SELECT 1 FROM workspace_memberships m
              WHERE m.application_id=w.application_id AND m.workspace_id=w.id AND m.user_id=target_user_id
          ))
    );
$$;
-- +goose StatementEnd

CREATE TABLE role_assignments (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id uuid NOT NULL REFERENCES applications(id),
    user_id uuid REFERENCES users(id),
    client_id uuid REFERENCES clients(id),
    role_id uuid NOT NULL REFERENCES roles(id),
    workspace_id uuid REFERENCES workspaces(id),
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK ((user_id IS NOT NULL) <> (client_id IS NOT NULL))
);
CREATE UNIQUE INDEX role_assignments_unique_user ON role_assignments(application_id,user_id,role_id,workspace_id) NULLS NOT DISTINCT WHERE user_id IS NOT NULL;
CREATE UNIQUE INDEX role_assignments_unique_client ON role_assignments(application_id,client_id,role_id,workspace_id) NULLS NOT DISTINCT WHERE client_id IS NOT NULL;

-- +goose StatementBegin
CREATE FUNCTION enforce_workspace_owner_membership_separation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM workspaces w WHERE w.id=NEW.workspace_id AND w.owner_user_id=NEW.user_id) THEN
        RAISE EXCEPTION 'workspace owner cannot also be a member';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER workspace_memberships_owner_guard BEFORE INSERT OR UPDATE ON workspace_memberships
FOR EACH ROW EXECUTE FUNCTION enforce_workspace_owner_membership_separation();

-- +goose StatementBegin
CREATE FUNCTION enforce_workspace_owner_is_active_non_member() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    owner_status text;
BEGIN
    SELECT status INTO owner_status FROM users
    WHERE id=NEW.owner_user_id AND application_id=NEW.application_id
    FOR UPDATE;
    IF owner_status IS DISTINCT FROM 'active' THEN
        RAISE EXCEPTION 'workspace owner must be an active user in the same application';
    END IF;
    IF EXISTS (SELECT 1 FROM workspace_memberships m WHERE m.workspace_id=NEW.id AND m.user_id=NEW.owner_user_id) THEN
        RAISE EXCEPTION 'workspace member cannot become owner before membership removal';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER workspaces_owner_guard BEFORE INSERT OR UPDATE OF owner_user_id ON workspaces
FOR EACH ROW EXECUTE FUNCTION enforce_workspace_owner_is_active_non_member();

-- +goose StatementBegin
CREATE FUNCTION prevent_inactive_workspace_owner() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.status='active' AND NEW.status<>'active' AND EXISTS (
        SELECT 1 FROM workspaces w
        WHERE w.application_id=NEW.application_id AND w.owner_user_id=NEW.id AND w.deleted_at IS NULL
    ) THEN
        RAISE EXCEPTION 'active workspace ownership must be transferred or archived first';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER users_active_workspace_owner_guard BEFORE UPDATE OF status ON users
FOR EACH ROW EXECUTE FUNCTION prevent_inactive_workspace_owner();

CREATE TABLE workspace_invitations (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id uuid NOT NULL REFERENCES applications(id),
    workspace_id uuid NOT NULL REFERENCES workspaces(id),
    normalized_email text NOT NULL,
    credential_digest bytea NOT NULL,
    roles text[] NOT NULL DEFAULT '{}',
    expires_at timestamptz NOT NULL,
    accepted_at timestamptz,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE delegations ADD CONSTRAINT delegations_workspace_fk
FOREIGN KEY (workspace_id) REFERENCES workspaces(id);
CREATE UNIQUE INDEX workspace_invitations_pending_email ON workspace_invitations(application_id,workspace_id,normalized_email)
WHERE accepted_at IS NULL AND revoked_at IS NULL;

CREATE TABLE features (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id uuid NOT NULL REFERENCES applications(id),
    key text NOT NULL,
    name text NOT NULL,
    value_type text NOT NULL CHECK (value_type IN ('boolean','quantity','configuration')),
    metadata jsonb NOT NULL DEFAULT '{}',
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (application_id, key)
);

CREATE TABLE products (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id uuid NOT NULL REFERENCES applications(id),
    key text NOT NULL,
    name text NOT NULL,
    description text NOT NULL DEFAULT '',
    listable boolean NOT NULL DEFAULT true,
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('draft','active','archived')),
    metadata jsonb NOT NULL DEFAULT '{}',
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (application_id, key)
);

CREATE TABLE prices (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id uuid NOT NULL REFERENCES applications(id),
    product_id uuid NOT NULL REFERENCES products(id),
    key text NOT NULL,
    mode text NOT NULL CHECK (mode IN ('recurring','one_time','local')),
    amount_minor bigint NOT NULL CHECK (amount_minor >= 0),
    currency char(3) NOT NULL,
    currency_exponent smallint NOT NULL DEFAULT 2,
    interval_unit text CHECK (interval_unit IN ('day','week','month','year')),
    interval_count integer,
    validity_seconds bigint,
    grace_seconds bigint NOT NULL DEFAULT 0,
    tax_behavior text NOT NULL DEFAULT 'inclusive' CHECK (tax_behavior IN ('inclusive','exclusive','unspecified')),
    checkout_config jsonb NOT NULL DEFAULT '{}',
    entitlement_config jsonb NOT NULL DEFAULT '{}',
    active boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (application_id, key)
);

CREATE TABLE price_features (
    price_id uuid NOT NULL REFERENCES prices(id),
    feature_id uuid NOT NULL REFERENCES features(id),
    boolean_value boolean,
    quantity_value bigint,
    configuration_value jsonb,
    PRIMARY KEY (price_id, feature_id)
);

CREATE TABLE entitlement_grants (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id uuid NOT NULL REFERENCES applications(id),
    subject_type text NOT NULL CHECK (subject_type IN ('user','workspace')),
    subject_id uuid NOT NULL,
    product_id uuid REFERENCES products(id),
    price_id uuid REFERENCES prices(id),
    source_type text NOT NULL CHECK (source_type IN ('manual','local_request','subscription','one_time','system')),
    source_id uuid,
    feature_values jsonb NOT NULL DEFAULT '{}',
    configuration jsonb NOT NULL DEFAULT '{}',
    starts_at timestamptz NOT NULL,
    expires_at timestamptz,
    revoked_at timestamptz,
    revocation_reason text,
    created_by uuid,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX entitlement_grants_effective ON entitlement_grants(application_id, subject_type, subject_id, starts_at, expires_at);
CREATE UNIQUE INDEX entitlement_grants_unique_source ON entitlement_grants(application_id,source_type,source_id,product_id) WHERE source_id IS NOT NULL;

CREATE TABLE entitlement_grant_actions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    grant_id uuid NOT NULL REFERENCES entitlement_grants(id) ON DELETE CASCADE,
    action text NOT NULL CHECK (action IN ('adjusted','revoked','restored')),
    action_key text,
    expires_at timestamptz,
    reason text,
    actor_type text NOT NULL CHECK (actor_type IN ('operator','provider','system')),
    actor_id uuid,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE NULLS DISTINCT (grant_id,action_key)
);
CREATE INDEX entitlement_grant_actions_history ON entitlement_grant_actions(grant_id,created_at,id);

CREATE TABLE local_entitlement_requests (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id uuid NOT NULL REFERENCES applications(id),
    requester_user_id uuid NOT NULL REFERENCES users(id),
    subject_type text NOT NULL CHECK (subject_type IN ('user','workspace')),
    subject_id uuid NOT NULL,
    product_id uuid NOT NULL REFERENCES products(id),
    price_id uuid NOT NULL REFERENCES prices(id),
    product_snapshot jsonb NOT NULL,
    price_snapshot jsonb NOT NULL,
    feature_snapshot jsonb NOT NULL DEFAULT '{}',
    address_snapshot jsonb,
    local_reference text,
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','rejected','canceled')),
    decision_reason text,
    reviewed_by uuid REFERENCES operators(id),
    reviewed_at timestamptz,
    entitlement_grant_id uuid REFERENCES entitlement_grants(id),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE local_entitlement_request_actions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id uuid NOT NULL REFERENCES local_entitlement_requests(id) ON DELETE CASCADE,
    action text NOT NULL CHECK (action IN ('created','approved','rejected','canceled','reopened')),
    actor_type text NOT NULL CHECK (actor_type IN ('user','operator')),
    actor_id uuid NOT NULL,
    reason text,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX local_entitlement_request_actions_history ON local_entitlement_request_actions(request_id,created_at,id);

CREATE TABLE provider_connections (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id uuid NOT NULL REFERENCES applications(id),
    provider text NOT NULL,
    public_id text NOT NULL UNIQUE,
    api_version text NOT NULL,
    secret_ciphertext text NOT NULL,
    webhook_secret_ciphertext text,
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled','error')),
    metadata jsonb NOT NULL DEFAULT '{}',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE provider_mappings (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id uuid NOT NULL REFERENCES applications(id),
    provider_connection_id uuid NOT NULL REFERENCES provider_connections(id),
    object_type text NOT NULL CHECK (object_type IN ('product','price')),
    internal_id uuid NOT NULL,
    provider_id text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (provider_connection_id, object_type, internal_id),
    UNIQUE (provider_connection_id, object_type, provider_id)
);

CREATE TABLE billing_customers (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id uuid NOT NULL REFERENCES applications(id),
    subject_type text NOT NULL CHECK (subject_type IN ('user','workspace')),
    subject_id uuid NOT NULL,
    provider_connection_id uuid NOT NULL REFERENCES provider_connections(id),
    provider_customer_id text,
    name text,
    email text,
    address_snapshot jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (provider_connection_id, subject_type, subject_id)
);

CREATE TABLE checkout_sessions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id uuid NOT NULL REFERENCES applications(id),
    subject_type text NOT NULL CHECK (subject_type IN ('user','workspace')),
    subject_id uuid NOT NULL,
    price_id uuid NOT NULL REFERENCES prices(id),
    provider_connection_id uuid REFERENCES provider_connections(id),
    provider_session_id text,
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','open','completed','expired','failed')),
    payment_methods text[] NOT NULL DEFAULT '{}',
    policy_snapshot jsonb NOT NULL,
    success_uri text NOT NULL,
    cancel_uri text NOT NULL,
    checkout_uri text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE subscriptions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id uuid NOT NULL REFERENCES applications(id),
    subject_type text NOT NULL,
    subject_id uuid NOT NULL,
    price_id uuid NOT NULL REFERENCES prices(id),
    provider_connection_id uuid NOT NULL REFERENCES provider_connections(id),
    provider_subscription_id text NOT NULL,
    provider_item_id text,
    status text NOT NULL,
    current_period_start timestamptz,
    current_period_end timestamptz,
    cancel_at timestamptz,
    canceled_at timestamptz,
    trial_end timestamptz,
    cancel_at_period_end boolean NOT NULL DEFAULT false,
    metadata jsonb NOT NULL DEFAULT '{}',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (provider_connection_id, provider_subscription_id)
);

CREATE TABLE invoices (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id uuid NOT NULL REFERENCES applications(id),
    provider_connection_id uuid NOT NULL REFERENCES provider_connections(id),
    provider_invoice_id text NOT NULL,
    provider_customer_id text,
    provider_subscription_id text,
    billing_customer_id uuid REFERENCES billing_customers(id),
    subscription_id uuid REFERENCES subscriptions(id),
    status text NOT NULL,
    amount_due_minor bigint NOT NULL DEFAULT 0,
    amount_paid_minor bigint NOT NULL DEFAULT 0,
    tax_minor bigint NOT NULL DEFAULT 0,
    currency char(3) NOT NULL,
    due_at timestamptz,
    paid_at timestamptz,
    hosted_uri text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (provider_connection_id, provider_invoice_id)
);

CREATE TABLE payments (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id uuid NOT NULL REFERENCES applications(id),
    provider_connection_id uuid NOT NULL REFERENCES provider_connections(id),
    provider_payment_id text NOT NULL,
    provider_customer_id text,
    provider_invoice_id text,
    billing_customer_id uuid REFERENCES billing_customers(id),
    checkout_session_id uuid REFERENCES checkout_sessions(id),
    invoice_id uuid REFERENCES invoices(id),
    status text NOT NULL,
    amount_minor bigint NOT NULL DEFAULT 0,
    amount_received_minor bigint NOT NULL DEFAULT 0,
    currency char(3) NOT NULL,
    payment_method_type text,
    failure_code text,
    failure_message text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (provider_connection_id, provider_payment_id)
);

CREATE TABLE refunds (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id uuid NOT NULL REFERENCES applications(id),
    provider_connection_id uuid NOT NULL REFERENCES provider_connections(id),
    provider_payment_id text,
    payment_id uuid REFERENCES payments(id),
    provider_refund_id text NOT NULL,
    status text NOT NULL,
    amount_minor bigint NOT NULL,
    currency char(3) NOT NULL,
    reason text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (provider_connection_id, provider_refund_id)
);

CREATE TABLE disputes (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id uuid NOT NULL REFERENCES applications(id),
    provider_connection_id uuid NOT NULL REFERENCES provider_connections(id),
    provider_payment_id text,
    payment_id uuid REFERENCES payments(id),
    provider_dispute_id text NOT NULL,
    status text NOT NULL,
    amount_minor bigint NOT NULL,
    currency char(3) NOT NULL,
    reason text,
    evidence_due_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (provider_connection_id, provider_dispute_id)
);

CREATE TABLE reconciliation_runs (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id uuid NOT NULL REFERENCES applications(id),
    provider_connection_id uuid NOT NULL REFERENCES provider_connections(id),
    status text NOT NULL CHECK (status IN ('pending','running','completed','failed')),
    findings jsonb NOT NULL DEFAULT '[]',
    repairs jsonb NOT NULL DEFAULT '[]',
    last_error text,
    started_at timestamptz,
    completed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE provider_events (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id uuid NOT NULL REFERENCES applications(id),
    provider_connection_id uuid NOT NULL REFERENCES provider_connections(id),
    provider_event_id text NOT NULL,
    api_version text,
    event_type text NOT NULL,
    raw_body_ciphertext text NOT NULL,
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','processed','failed','ignored')),
    attempts integer NOT NULL DEFAULT 0,
    last_error text,
    received_at timestamptz NOT NULL DEFAULT now(),
    processed_at timestamptz,
    UNIQUE (provider_connection_id, provider_event_id)
);

CREATE TABLE notification_providers (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id uuid REFERENCES applications(id),
    provider text NOT NULL DEFAULT 'smtp',
    name text NOT NULL,
    config_ciphertext text NOT NULL,
    sender_email text NOT NULL,
    sender_name text NOT NULL DEFAULT '',
    verified_at timestamptz,
    disabled_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE sender_identities (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id uuid REFERENCES applications(id),
    notification_provider_id uuid NOT NULL REFERENCES notification_providers(id),
    email text NOT NULL,
    name text NOT NULL DEFAULT '',
    is_default boolean NOT NULL DEFAULT false,
    verified_at timestamptz,
    disabled_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (notification_provider_id, email)
);

CREATE TABLE notification_templates (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id uuid NOT NULL REFERENCES applications(id),
    key text NOT NULL,
    locale text NOT NULL DEFAULT 'en',
    category text NOT NULL,
    version integer NOT NULL,
    subject_template text NOT NULL,
    text_template text NOT NULL,
    html_template text,
    variable_schema jsonb NOT NULL DEFAULT '{}',
    status text NOT NULL DEFAULT 'draft' CHECK (status IN ('draft','published','archived')),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (application_id, key, locale, version)
);

CREATE TABLE notifications (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id uuid REFERENCES applications(id),
    template_id uuid REFERENCES notification_templates(id),
    notification_provider_id uuid REFERENCES notification_providers(id),
    user_id uuid REFERENCES users(id),
    recipient text NOT NULL,
    category text NOT NULL DEFAULT 'security',
    locale text NOT NULL DEFAULT 'en',
    payload_ciphertext text NOT NULL,
    status text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued','sending','delivered','failed','dead','suppressed')),
    attempt_count integer NOT NULL DEFAULT 0,
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    last_error text,
    delivered_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE notification_preferences (
    application_id uuid NOT NULL REFERENCES applications(id),
    user_id uuid NOT NULL REFERENCES users(id),
    category text NOT NULL,
    email_enabled boolean NOT NULL DEFAULT true,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (application_id,user_id,category)
);

CREATE TABLE notification_attachments (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    notification_id uuid NOT NULL REFERENCES notifications(id) ON DELETE CASCADE,
    filename text NOT NULL,
    content_type text NOT NULL,
    content bytea NOT NULL,
    size_bytes integer NOT NULL CHECK (size_bytes>=0 AND size_bytes<=2097152),
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE notification_attempts (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    notification_id uuid NOT NULL REFERENCES notifications(id) ON DELETE CASCADE,
    notification_provider_id uuid REFERENCES notification_providers(id),
    attempt_number integer NOT NULL,
    status text NOT NULL CHECK (status IN ('sending','delivered','failed')),
    error text,
    started_at timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz,
    UNIQUE (notification_id,attempt_number)
);

CREATE TABLE domain_events (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id uuid REFERENCES applications(id),
    event_type text NOT NULL,
    schema_version text NOT NULL DEFAULT '1.0',
    subject text,
    actor jsonb,
    correlation_id uuid,
    causation_id uuid,
    data jsonb NOT NULL,
    occurred_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE outbox (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id uuid NOT NULL REFERENCES domain_events(id),
    available_at timestamptz NOT NULL DEFAULT now(),
    attempts integer NOT NULL DEFAULT 0,
    locked_at timestamptz,
    locked_by text,
    dispatched_at timestamptz,
    last_error text
);

CREATE TABLE webhook_endpoints (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id uuid NOT NULL REFERENCES applications(id),
    uri text NOT NULL,
    event_filters text[] NOT NULL DEFAULT '{}',
    secret_ciphertext text NOT NULL,
    previous_secret_ciphertext text,
    previous_valid_until timestamptz,
    disabled_at timestamptz,
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE webhook_deliveries (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id uuid NOT NULL REFERENCES applications(id),
    webhook_endpoint_id uuid NOT NULL REFERENCES webhook_endpoints(id),
    event_id uuid NOT NULL REFERENCES domain_events(id),
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','delivering','delivered','failed','dead')),
    attempt_count integer NOT NULL DEFAULT 0,
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    response_status integer,
    response_excerpt text,
    delivered_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (webhook_endpoint_id, event_id)
);

CREATE TABLE audit_records (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid REFERENCES organizations(id),
    application_id uuid REFERENCES applications(id),
    actor_type text NOT NULL,
    actor_id uuid,
    action text NOT NULL,
    target_type text,
    target_id uuid,
    reason text,
    request_id text,
    changes jsonb NOT NULL DEFAULT '{}',
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE audit_exports (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid REFERENCES organizations(id),
    application_id uuid REFERENCES applications(id),
    requested_by uuid NOT NULL REFERENCES operators(id),
    filter_snapshot jsonb NOT NULL DEFAULT '{}',
    payload_ciphertext text NOT NULL,
    record_count integer NOT NULL,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX audit_exports_expiry ON audit_exports(expires_at);

CREATE TABLE idempotency_records (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id uuid,
    actor_key text NOT NULL,
    idempotency_key text NOT NULL,
    request_hash bytea NOT NULL,
    response_status integer,
    response_headers jsonb,
    response_body bytea,
    locked_until timestamptz,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE NULLS NOT DISTINCT (application_id, actor_key, idempotency_key)
);

-- Composite keys make application ownership part of every critical reference.
CREATE UNIQUE INDEX clients_application_identity ON clients(application_id,id);
CREATE UNIQUE INDEX billing_profiles_application_identity ON billing_profiles(application_id,id);
CREATE UNIQUE INDEX roles_application_identity ON roles(application_id,id);
CREATE UNIQUE INDEX products_application_identity ON products(application_id,id);
CREATE UNIQUE INDEX prices_application_identity ON prices(application_id,id);
CREATE UNIQUE INDEX provider_connections_application_identity ON provider_connections(application_id,id);
CREATE UNIQUE INDEX billing_customers_application_identity ON billing_customers(application_id,id);
CREATE UNIQUE INDEX checkout_sessions_application_identity ON checkout_sessions(application_id,id);
CREATE UNIQUE INDEX subscriptions_application_identity ON subscriptions(application_id,id);
CREATE UNIQUE INDEX invoices_application_identity ON invoices(application_id,id);
CREATE UNIQUE INDEX payments_application_identity ON payments(application_id,id);

ALTER TABLE role_assignments
    ADD CONSTRAINT role_assignments_user_application_fk FOREIGN KEY(application_id,user_id) REFERENCES users(application_id,id),
    ADD CONSTRAINT role_assignments_client_application_fk FOREIGN KEY(application_id,client_id) REFERENCES clients(application_id,id),
    ADD CONSTRAINT role_assignments_role_application_fk FOREIGN KEY(application_id,role_id) REFERENCES roles(application_id,id),
    ADD CONSTRAINT role_assignments_workspace_application_fk FOREIGN KEY(application_id,workspace_id) REFERENCES workspaces(application_id,id);
ALTER TABLE addresses ADD CONSTRAINT addresses_profile_application_fk
    FOREIGN KEY(application_id,billing_profile_id) REFERENCES billing_profiles(application_id,id);
ALTER TABLE prices ADD CONSTRAINT prices_product_application_fk
    FOREIGN KEY(application_id,product_id) REFERENCES products(application_id,id);
ALTER TABLE entitlement_grants
    ADD CONSTRAINT entitlement_product_application_fk FOREIGN KEY(application_id,product_id) REFERENCES products(application_id,id),
    ADD CONSTRAINT entitlement_price_application_fk FOREIGN KEY(application_id,price_id) REFERENCES prices(application_id,id);
ALTER TABLE local_entitlement_requests
    ADD CONSTRAINT local_request_user_application_fk FOREIGN KEY(application_id,requester_user_id) REFERENCES users(application_id,id),
    ADD CONSTRAINT local_request_product_application_fk FOREIGN KEY(application_id,product_id) REFERENCES products(application_id,id),
    ADD CONSTRAINT local_request_price_application_fk FOREIGN KEY(application_id,price_id) REFERENCES prices(application_id,id);
ALTER TABLE billing_customers ADD CONSTRAINT billing_customer_provider_application_fk
    FOREIGN KEY(application_id,provider_connection_id) REFERENCES provider_connections(application_id,id);
ALTER TABLE checkout_sessions
    ADD CONSTRAINT checkout_price_application_fk FOREIGN KEY(application_id,price_id) REFERENCES prices(application_id,id),
    ADD CONSTRAINT checkout_provider_application_fk FOREIGN KEY(application_id,provider_connection_id) REFERENCES provider_connections(application_id,id);
ALTER TABLE subscriptions
    ADD CONSTRAINT subscription_price_application_fk FOREIGN KEY(application_id,price_id) REFERENCES prices(application_id,id),
    ADD CONSTRAINT subscription_provider_application_fk FOREIGN KEY(application_id,provider_connection_id) REFERENCES provider_connections(application_id,id);
ALTER TABLE invoices
    ADD CONSTRAINT invoice_provider_application_fk FOREIGN KEY(application_id,provider_connection_id) REFERENCES provider_connections(application_id,id),
    ADD CONSTRAINT invoice_customer_application_fk FOREIGN KEY(application_id,billing_customer_id) REFERENCES billing_customers(application_id,id),
    ADD CONSTRAINT invoice_subscription_application_fk FOREIGN KEY(application_id,subscription_id) REFERENCES subscriptions(application_id,id);
ALTER TABLE payments
    ADD CONSTRAINT payment_provider_application_fk FOREIGN KEY(application_id,provider_connection_id) REFERENCES provider_connections(application_id,id),
    ADD CONSTRAINT payment_customer_application_fk FOREIGN KEY(application_id,billing_customer_id) REFERENCES billing_customers(application_id,id),
    ADD CONSTRAINT payment_checkout_application_fk FOREIGN KEY(application_id,checkout_session_id) REFERENCES checkout_sessions(application_id,id),
    ADD CONSTRAINT payment_invoice_application_fk FOREIGN KEY(application_id,invoice_id) REFERENCES invoices(application_id,id);
ALTER TABLE refunds
    ADD CONSTRAINT refund_provider_application_fk FOREIGN KEY(application_id,provider_connection_id) REFERENCES provider_connections(application_id,id),
    ADD CONSTRAINT refund_payment_application_fk FOREIGN KEY(application_id,payment_id) REFERENCES payments(application_id,id);
ALTER TABLE disputes
    ADD CONSTRAINT dispute_provider_application_fk FOREIGN KEY(application_id,provider_connection_id) REFERENCES provider_connections(application_id,id),
    ADD CONSTRAINT dispute_payment_application_fk FOREIGN KEY(application_id,payment_id) REFERENCES payments(application_id,id);
ALTER TABLE reconciliation_runs ADD CONSTRAINT reconciliation_provider_application_fk
    FOREIGN KEY(application_id,provider_connection_id) REFERENCES provider_connections(application_id,id);
ALTER TABLE provider_events ADD CONSTRAINT provider_event_connection_application_fk
    FOREIGN KEY(application_id,provider_connection_id) REFERENCES provider_connections(application_id,id);

-- +goose StatementBegin
CREATE FUNCTION enforce_application_subject() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.subject_type='user' AND NOT EXISTS (
        SELECT 1 FROM users u WHERE u.application_id=NEW.application_id AND u.id=NEW.subject_id
    ) THEN
        RAISE EXCEPTION 'user subject must belong to the row application';
    ELSIF NEW.subject_type='workspace' AND NOT EXISTS (
        SELECT 1 FROM workspaces w WHERE w.application_id=NEW.application_id AND w.id=NEW.subject_id
    ) THEN
        RAISE EXCEPTION 'workspace subject must belong to the row application';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER billing_profiles_subject_guard BEFORE INSERT OR UPDATE OF application_id,subject_type,subject_id ON billing_profiles FOR EACH ROW EXECUTE FUNCTION enforce_application_subject();
CREATE TRIGGER entitlement_grants_subject_guard BEFORE INSERT OR UPDATE OF application_id,subject_type,subject_id ON entitlement_grants FOR EACH ROW EXECUTE FUNCTION enforce_application_subject();
CREATE TRIGGER local_requests_subject_guard BEFORE INSERT OR UPDATE OF application_id,subject_type,subject_id ON local_entitlement_requests FOR EACH ROW EXECUTE FUNCTION enforce_application_subject();
CREATE TRIGGER billing_customers_subject_guard BEFORE INSERT OR UPDATE OF application_id,subject_type,subject_id ON billing_customers FOR EACH ROW EXECUTE FUNCTION enforce_application_subject();
CREATE TRIGGER checkout_sessions_subject_guard BEFORE INSERT OR UPDATE OF application_id,subject_type,subject_id ON checkout_sessions FOR EACH ROW EXECUTE FUNCTION enforce_application_subject();
CREATE TRIGGER subscriptions_subject_guard BEFORE INSERT OR UPDATE OF application_id,subject_type,subject_id ON subscriptions FOR EACH ROW EXECUTE FUNCTION enforce_application_subject();

-- +goose Down
DROP TABLE IF EXISTS idempotency_records, audit_exports, audit_records, webhook_deliveries,
webhook_endpoints, outbox, domain_events, notifications, notification_templates,
notification_attempts, notification_attachments, notification_preferences, sender_identities,
notification_providers, provider_events, reconciliation_runs, disputes, refunds, payments, invoices, subscriptions,
checkout_sessions, billing_customers, provider_mappings, provider_connections,
local_entitlement_request_actions, local_entitlement_requests, entitlement_grant_actions, entitlement_grants, price_features, prices,
products, features, workspace_invitations, role_assignments, workspace_memberships, workspaces, roles,
addresses, billing_profiles, personal_api_keys, webauthn_ceremonies, mfa_login_challenges,
user_recovery_codes, user_authentication_methods, user_sessions, external_auth_exchanges,
external_auth_challenges, login_challenges, user_identities,
delegations, users, clients, application_secrets, application_domains, applications,
organization_invitations, organization_memberships, organizations, auth_rate_limits, operator_login_challenges, installation_operator_roles, operator_sessions, operators, signing_keys,
installations CASCADE;
DROP FUNCTION IF EXISTS enforce_application_subject();
DROP FUNCTION IF EXISTS prevent_inactive_workspace_owner();
DROP FUNCTION IF EXISTS enforce_workspace_owner_is_active_non_member();
DROP FUNCTION IF EXISTS enforce_workspace_owner_membership_separation();
DROP FUNCTION IF EXISTS workspace_accessible_to_user(uuid,uuid,uuid);
