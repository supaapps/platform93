-- +goose Up
-- +goose StatementBegin
SET LOCAL check_function_bodies = false;

CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;

COMMENT ON EXTENSION pgcrypto IS 'cryptographic functions';

CREATE FUNCTION public.valid_permission_key(value text) RETURNS boolean
    LANGUAGE sql IMMUTABLE
    AS $$
SELECT value IS NOT NULL
   AND length(value) BETWEEN 1 AND 160
   AND octet_length(value)=length(value)
   AND value ~ '^(\*|[a-z0-9][a-z0-9._-]{0,63}(:[a-z0-9][a-z0-9._-]{0,63})*(:\*)?)$';
$$;

CREATE FUNCTION public.valid_canonical_scope(application uuid, value text) RETURNS boolean
    LANGUAGE sql IMMUTABLE
    AS $$
SELECT value IS NOT NULL
   AND octet_length(value)=length(value)
   AND value LIKE '/applications/' || application::text || '/%'
   AND value ~ '^/applications/[0-9a-f-]+/(\*|[a-z0-9][a-z0-9._-]{0,63}(/[a-z0-9][a-z0-9._-]{0,63})*(/\*)?)$';
$$;

CREATE FUNCTION public.valid_canonical_scopes(application uuid, scope_values text[], allow_empty boolean) RETURNS boolean
    LANGUAGE sql IMMUTABLE
    AS $$
SELECT scope_values IS NOT NULL
   AND (allow_empty OR cardinality(scope_values)>0)
   AND cardinality(scope_values)<=200
   AND cardinality(scope_values)=cardinality(ARRAY(SELECT DISTINCT item FROM unnest(scope_values) item))
   AND NOT EXISTS (SELECT 1 FROM unnest(scope_values) item WHERE NOT public.valid_canonical_scope(application,item));
$$;

CREATE FUNCTION public.valid_permission_keys(permission_values text[]) RETURNS boolean
    LANGUAGE sql IMMUTABLE
    AS $$
SELECT permission_values IS NOT NULL
   AND cardinality(permission_values) BETWEEN 1 AND 200
   AND cardinality(permission_values)=cardinality(ARRAY(SELECT DISTINCT item FROM unnest(permission_values) item))
   AND NOT EXISTS (SELECT 1 FROM unnest(permission_values) item WHERE NOT public.valid_permission_key(item));
$$;

CREATE FUNCTION public.enforce_permission_grant() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    expected_scope text;
BEGIN
    IF TG_OP='UPDATE' AND (
        NEW.application_id IS DISTINCT FROM OLD.application_id OR NEW.user_id IS DISTINCT FROM OLD.user_id OR
        NEW.client_id IS DISTINCT FROM OLD.client_id OR NEW.workspace_id IS DISTINCT FROM OLD.workspace_id OR
        NEW.permission IS DISTINCT FROM OLD.permission OR NEW.canonical_scope IS DISTINCT FROM OLD.canonical_scope OR
        NEW.reason IS DISTINCT FROM OLD.reason OR NEW.created_by_type IS DISTINCT FROM OLD.created_by_type OR
        NEW.created_by_id IS DISTINCT FROM OLD.created_by_id OR NEW.created_at IS DISTINCT FROM OLD.created_at OR
        OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS NULL
    ) THEN
        RAISE EXCEPTION 'permission grants are immutable except for one-way revocation';
    END IF;
    IF NOT public.valid_permission_key(NEW.permission) OR split_part(NEW.permission,':',1)='roles' THEN
        RAISE EXCEPTION 'permission grant contains an invalid or reserved permission';
    END IF;
    IF NEW.user_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM users u WHERE u.id=NEW.user_id AND u.application_id=NEW.application_id AND u.status='active'
    ) THEN
        RAISE EXCEPTION 'permission grant user must be active in the application';
    END IF;
    IF NEW.client_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM clients c WHERE c.id=NEW.client_id AND c.application_id=NEW.application_id AND c.disabled_at IS NULL
    ) THEN
        RAISE EXCEPTION 'permission grant client must be active in the application';
    END IF;
    IF NEW.workspace_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM workspaces w WHERE w.id=NEW.workspace_id AND w.application_id=NEW.application_id AND w.deleted_at IS NULL
    ) THEN
        RAISE EXCEPTION 'permission grant workspace must be active in the application';
    END IF;
    IF NEW.workspace_id IS NOT NULL AND NEW.user_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM workspaces w WHERE w.id=NEW.workspace_id AND w.application_id=NEW.application_id
          AND (w.owner_user_id=NEW.user_id OR EXISTS (
              SELECT 1 FROM workspace_memberships m WHERE m.workspace_id=w.id AND m.user_id=NEW.user_id
          ))
    ) THEN
        RAISE EXCEPTION 'permission grant user must belong to the workspace';
    END IF;
    expected_scope := '/applications/' || NEW.application_id::text ||
        CASE WHEN NEW.workspace_id IS NULL THEN '' ELSE '/workspaces/' || NEW.workspace_id::text END ||
        '/' || replace(NEW.permission,':','/');
    IF NEW.canonical_scope<>expected_scope THEN
        RAISE EXCEPTION 'permission grant canonical scope is invalid';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION public.create_default_organization_policy() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    INSERT INTO organization_policies(organization_id) VALUES(NEW.id);
    RETURN NEW;
END;
$$;

CREATE FUNCTION public.enforce_application_subject() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
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

CREATE FUNCTION public.enforce_notification_template_asset_scope() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM notification_templates t JOIN storage_objects o ON o.id=NEW.storage_object_id
        WHERE t.id=NEW.notification_template_id AND o.status='ready' AND o.visibility='public'
          AND o.content_type IN ('image/png','image/jpeg','image/gif')
          AND ((t.application_id IS NULL AND o.owner_type='installation') OR
               (t.application_id IS NOT NULL AND (
                   (o.application_id=t.application_id AND o.owner_type='application') OR
                   o.owner_type='installation'
               )))
    ) THEN
        RAISE EXCEPTION 'template assets must be ready public images from the template scope';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION public.enforce_storage_object_scope() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    provider_application uuid;
    provider_organization uuid;
    provider_public_bucket text;
    provider_private_bucket text;
BEGIN
    SELECT application_id,organization_id,public_bucket,private_bucket
      INTO provider_application,provider_organization,provider_public_bucket,provider_private_bucket
      FROM storage_providers WHERE id=NEW.storage_provider_id;
    IF NEW.bucket_role='public' AND provider_public_bucket IS DISTINCT FROM NEW.bucket_name THEN
        RAISE EXCEPTION 'public object bucket must match its storage provider';
    END IF;
    IF NEW.bucket_role='private' AND provider_private_bucket IS DISTINCT FROM NEW.bucket_name THEN
        RAISE EXCEPTION 'private object bucket must match its storage provider';
    END IF;
    IF NEW.owner_type='installation' THEN
        IF provider_application IS NOT NULL OR provider_organization IS NOT NULL THEN
            RAISE EXCEPTION 'installation assets require an installation storage provider';
        END IF;
        RETURN NEW;
    END IF;
    IF provider_application IS NOT NULL AND provider_application<>NEW.application_id THEN
        RAISE EXCEPTION 'storage provider belongs to another application';
    END IF;
    IF provider_organization IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM applications a WHERE a.id=NEW.application_id AND a.organization_id=provider_organization
    ) THEN
        RAISE EXCEPTION 'storage provider belongs to another organization';
    END IF;
    IF NEW.owner_type='user' AND NOT EXISTS (
        SELECT 1 FROM users u WHERE u.id=NEW.owner_id AND u.application_id=NEW.application_id AND u.status='active'
    ) THEN
        RAISE EXCEPTION 'storage object user must be active in the application';
    END IF;
    IF NEW.owner_type='workspace' AND NOT EXISTS (
        SELECT 1 FROM workspaces w WHERE w.id=NEW.owner_id AND w.application_id=NEW.application_id AND w.deleted_at IS NULL
    ) THEN
        RAISE EXCEPTION 'storage object workspace must be active in the application';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION public.enforce_workspace_owner_is_active_non_member() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
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

CREATE FUNCTION public.enforce_workspace_owner_membership_separation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM workspaces w WHERE w.id=NEW.workspace_id AND w.owner_user_id=NEW.user_id) THEN
        RAISE EXCEPTION 'workspace owner cannot also be a member';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION public.prevent_inactive_workspace_owner() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
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

CREATE FUNCTION public.workspace_accessible_to_user(target_application_id uuid, target_workspace_id uuid, target_user_id uuid) RETURNS boolean
    LANGUAGE sql STABLE PARALLEL SAFE
    AS $$
    SELECT EXISTS(
        SELECT 1 FROM workspaces w
        WHERE w.application_id=target_application_id AND w.id=target_workspace_id AND w.deleted_at IS NULL
          AND (w.owner_user_id=target_user_id OR EXISTS(
              SELECT 1 FROM workspace_memberships m
              WHERE m.application_id=w.application_id AND m.workspace_id=w.id AND m.user_id=target_user_id
          ))
    );
$$;



CREATE TABLE public.addresses (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    application_id uuid NOT NULL,
    billing_profile_id uuid NOT NULL,
    name text DEFAULT ''::text NOT NULL,
    line1 text NOT NULL,
    line2 text DEFAULT ''::text NOT NULL,
    city text NOT NULL,
    region text DEFAULT ''::text NOT NULL,
    postal_code text NOT NULL,
    country_code character(2) NOT NULL,
    is_active boolean DEFAULT false NOT NULL,
    version bigint DEFAULT 1 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public.application_domains (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    application_id uuid NOT NULL,
    hostname text NOT NULL,
    verification_ciphertext text NOT NULL,
    verified_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public.application_invitations (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    application_id uuid NOT NULL,
    workspace_id uuid,
    normalized_email text NOT NULL,
    link_credential_digest bytea NOT NULL,
    workspace_roles text[] DEFAULT '{}'::text[] NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    accepted_at timestamp with time zone,
    revoked_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    code_credential_digest bytea,
    application_roles text[] DEFAULT '{}'::text[] NOT NULL,
    inviter_type text DEFAULT 'control_user'::text NOT NULL,
    inviter_id uuid,
    last_sent_at timestamp with time zone DEFAULT now() NOT NULL,
    resend_available_at timestamp with time zone DEFAULT (now() + '00:01:00'::interval) NOT NULL,
    expiration_recorded_at timestamp with time zone,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT application_invitations_inviter_type_check CHECK ((inviter_type = ANY (ARRAY['control_user'::text, 'user'::text, 'client'::text])))
);

CREATE TABLE public.application_secrets (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    application_id uuid NOT NULL,
    kind text NOT NULL,
    name text NOT NULL,
    ciphertext text NOT NULL,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public.applications (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    organization_id uuid NOT NULL,
    name text NOT NULL,
    slug text NOT NULL,
    auth_config jsonb DEFAULT '{}'::jsonb NOT NULL,
    version bigint DEFAULT 1 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone,
    public_config jsonb DEFAULT '{}'::jsonb NOT NULL,
    internal_config jsonb DEFAULT '{"password_enabled": true, "registration_mode": "public", "delegation_enabled": false, "passwordless_enabled": true, "custom_token_claim_keys": [], "user_invitations_enabled": false, "personal_api_keys_enabled": false}'::jsonb NOT NULL,
    CONSTRAINT applications_internal_config_check CHECK (((jsonb_typeof(public_config) = 'object'::text) AND (jsonb_typeof(internal_config) = 'object'::text) AND (internal_config ?& ARRAY['registration_mode'::text, 'password_enabled'::text, 'passwordless_enabled'::text, 'personal_api_keys_enabled'::text, 'delegation_enabled'::text, 'user_invitations_enabled'::text, 'custom_token_claim_keys'::text]) AND ((internal_config ->> 'registration_mode'::text) = ANY (ARRAY['public'::text, 'invite_only'::text])) AND (jsonb_typeof((internal_config -> 'password_enabled'::text)) = 'boolean'::text) AND (jsonb_typeof((internal_config -> 'passwordless_enabled'::text)) = 'boolean'::text) AND (jsonb_typeof((internal_config -> 'personal_api_keys_enabled'::text)) = 'boolean'::text) AND (jsonb_typeof((internal_config -> 'delegation_enabled'::text)) = 'boolean'::text) AND (jsonb_typeof((internal_config -> 'user_invitations_enabled'::text)) = 'boolean'::text) AND (jsonb_typeof((internal_config -> 'custom_token_claim_keys'::text)) = 'array'::text)))
);

CREATE TABLE public.audit_exports (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    organization_id uuid,
    application_id uuid,
    requested_by uuid NOT NULL,
    filter_snapshot jsonb DEFAULT '{}'::jsonb NOT NULL,
    payload_ciphertext text NOT NULL,
    record_count integer NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public.audit_records (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    organization_id uuid,
    application_id uuid,
    actor_type text NOT NULL,
    actor_id uuid,
    action text NOT NULL,
    target_type text,
    target_id uuid,
    reason text,
    request_id text,
    changes jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public.auth_provider_configs (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    organization_id uuid,
    application_id uuid,
    provider text NOT NULL,
    client_id text NOT NULL,
    config_ciphertext text NOT NULL,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    inheritable boolean DEFAULT false NOT NULL,
    control_login_enabled boolean DEFAULT false NOT NULL,
    disabled_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT auth_provider_configs_check CHECK ((((application_id IS NOT NULL) AND (organization_id IS NULL)) OR ((application_id IS NULL) AND (organization_id IS NOT NULL)) OR ((application_id IS NULL) AND (organization_id IS NULL)))),
    CONSTRAINT auth_provider_configs_provider_check CHECK ((provider = ANY (ARRAY['google'::text, 'apple'::text]))),
    CONSTRAINT auth_provider_configs_control_login_scope_check CHECK ((control_login_enabled = false) OR ((application_id IS NULL) AND (organization_id IS NULL)))
);

CREATE TABLE public.auth_rate_limits (
    bucket_digest bytea NOT NULL,
    attempts integer NOT NULL,
    window_started_at timestamp with time zone NOT NULL,
    expires_at timestamp with time zone NOT NULL
);

CREATE TABLE public.billing_customers (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    application_id uuid NOT NULL,
    subject_type text NOT NULL,
    subject_id uuid NOT NULL,
    provider_connection_id uuid NOT NULL,
    provider_customer_id text,
    name text,
    email text,
    address_snapshot jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT billing_customers_subject_type_check CHECK ((subject_type = ANY (ARRAY['user'::text, 'workspace'::text])))
);

CREATE TABLE public.billing_profiles (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    application_id uuid NOT NULL,
    subject_type text NOT NULL,
    subject_id uuid NOT NULL,
    name text DEFAULT ''::text NOT NULL,
    email text,
    tax_id text,
    version bigint DEFAULT 1 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT billing_profiles_subject_type_check CHECK ((subject_type = ANY (ARRAY['user'::text, 'workspace'::text])))
);

CREATE TABLE public.checkout_sessions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    application_id uuid NOT NULL,
    subject_type text NOT NULL,
    subject_id uuid NOT NULL,
    price_id uuid NOT NULL,
    provider_connection_id uuid,
    provider_session_id text,
    status text DEFAULT 'pending'::text NOT NULL,
    payment_methods text[] DEFAULT '{}'::text[] NOT NULL,
    policy_snapshot jsonb NOT NULL,
    success_uri text NOT NULL,
    cancel_uri text NOT NULL,
    checkout_uri text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    external_reference text,
    CONSTRAINT checkout_sessions_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'open'::text, 'completed'::text, 'expired'::text, 'failed'::text]))),
    CONSTRAINT checkout_sessions_subject_type_check CHECK ((subject_type = ANY (ARRAY['user'::text, 'workspace'::text])))
);

CREATE TABLE public.clients (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    application_id uuid NOT NULL,
    client_id text NOT NULL,
    name text NOT NULL,
    client_type text NOT NULL,
    redirect_uris text[] DEFAULT '{}'::text[] NOT NULL,
    post_logout_redirect_uris text[] DEFAULT '{}'::text[] NOT NULL,
    allowed_grants text[] DEFAULT '{}'::text[] NOT NULL,
    allowed_scopes text[] DEFAULT '{}'::text[] NOT NULL,
    secret_digest bytea,
    disabled_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT clients_client_type_check CHECK ((client_type = ANY (ARRAY['public'::text, 'confidential'::text, 'machine'::text])))
);

CREATE TABLE public.delegations (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    application_id uuid NOT NULL,
    control_user_id uuid NOT NULL,
    user_id uuid NOT NULL,
    workspace_id uuid,
    reason text NOT NULL,
    redirect_uri text NOT NULL,
    permissions text[] NOT NULL,
    exchange_digest bytea NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    exchanged_at timestamp with time zone,
    revoked_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT delegations_permissions_format_check CHECK (public.valid_canonical_scopes(application_id,permissions,false) AND cardinality(permissions)<=50)
);

CREATE TABLE public.disputes (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    application_id uuid NOT NULL,
    provider_connection_id uuid NOT NULL,
    provider_payment_id text,
    payment_id uuid,
    provider_dispute_id text NOT NULL,
    status text NOT NULL,
    amount_minor bigint NOT NULL,
    currency character(3) NOT NULL,
    reason text,
    evidence_due_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public.domain_events (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    application_id uuid,
    event_type text NOT NULL,
    schema_version text DEFAULT '1.0'::text NOT NULL,
    subject text,
    actor jsonb,
    correlation_id uuid,
    causation_id uuid,
    data jsonb NOT NULL,
    occurred_at timestamp with time zone DEFAULT now() NOT NULL,
    contract_source text DEFAULT 'platform93'::text NOT NULL,
    CONSTRAINT domain_events_contract_source_check CHECK ((contract_source = ANY (ARRAY['platform93'::text, 'application'::text])))
);

CREATE TABLE public.entitlement_grant_actions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    grant_id uuid NOT NULL,
    action text NOT NULL,
    action_key text,
    expires_at timestamp with time zone,
    reason text,
    actor_type text NOT NULL,
    actor_id uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT entitlement_grant_actions_action_check CHECK ((action = ANY (ARRAY['adjusted'::text, 'revoked'::text, 'restored'::text]))),
    CONSTRAINT entitlement_grant_actions_actor_type_check CHECK ((actor_type = ANY (ARRAY['control_user'::text, 'provider'::text, 'system'::text])))
);

CREATE TABLE public.entitlement_grants (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    application_id uuid NOT NULL,
    subject_type text NOT NULL,
    subject_id uuid NOT NULL,
    product_id uuid,
    price_id uuid,
    source_type text NOT NULL,
    source_id uuid,
    feature_values jsonb DEFAULT '{}'::jsonb NOT NULL,
    configuration jsonb DEFAULT '{}'::jsonb NOT NULL,
    starts_at timestamp with time zone NOT NULL,
    expires_at timestamp with time zone,
    revoked_at timestamp with time zone,
    revocation_reason text,
    created_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    external_reference text,
    expiration_recorded_at timestamp with time zone,
    CONSTRAINT entitlement_grants_source_type_check CHECK ((source_type = ANY (ARRAY['manual'::text, 'local_request'::text, 'subscription'::text, 'one_time'::text, 'system'::text]))),
    CONSTRAINT entitlement_grants_subject_type_check CHECK ((subject_type = ANY (ARRAY['user'::text, 'workspace'::text])))
);

CREATE TABLE public.event_type_definitions (
    id uuid NOT NULL,
    application_id uuid,
    name text NOT NULL,
    description text DEFAULT ''::text NOT NULL,
    schema_version text DEFAULT '1.0'::text NOT NULL,
    data_schema jsonb DEFAULT '{}'::jsonb NOT NULL,
    source text NOT NULL,
    status text DEFAULT 'active'::text NOT NULL,
    version bigint DEFAULT 1 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    example_subject text DEFAULT 'resource/example'::text NOT NULL,
    example_data jsonb DEFAULT '{}'::jsonb NOT NULL,
    CONSTRAINT event_type_definition_contract_check CHECK (((example_subject <> ''::text) AND (length(example_subject) <= 500) AND (jsonb_typeof(data_schema) = 'object'::text) AND (jsonb_typeof(example_data) = 'object'::text))),
    CONSTRAINT event_type_definitions_check CHECK ((((source = 'platform93'::text) AND (application_id IS NULL)) OR ((source = 'application'::text) AND (application_id IS NOT NULL)))),
    CONSTRAINT event_type_definitions_name_check CHECK ((name ~ '^[a-z][a-z0-9_-]*(\.[a-z][a-z0-9_-]*)+$'::text)),
    CONSTRAINT event_type_definitions_schema_version_check CHECK ((schema_version ~ '^[1-9][0-9]*\.[0-9]+$'::text)),
    CONSTRAINT event_type_definitions_source_check CHECK ((source = ANY (ARRAY['platform93'::text, 'application'::text]))),
    CONSTRAINT event_type_definitions_status_check CHECK ((status = ANY (ARRAY['active'::text, 'archived'::text])))
);

CREATE TABLE public.external_auth_challenges (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    application_id uuid NOT NULL,
    provider text NOT NULL,
    flow text NOT NULL,
    requested_by_user_id uuid,
    app_redirect_uri text NOT NULL,
    state_digest bytea NOT NULL,
    nonce_digest bytea NOT NULL,
    verifier_ciphertext text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    locked_until timestamp with time zone,
    consumed_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT external_auth_challenges_flow_check CHECK ((flow = ANY (ARRAY['sign_in'::text, 'sign_up'::text, 'automatic'::text, 'link'::text])))
);

CREATE TABLE public.external_auth_exchanges (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    application_id uuid NOT NULL,
    user_id uuid NOT NULL,
    credential_digest bytea NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    consumed_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public.features (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    application_id uuid NOT NULL,
    key text NOT NULL,
    name text NOT NULL,
    value_type text NOT NULL,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    free_form_format text,
    CONSTRAINT features_free_form_format_check CHECK ((((value_type = 'free_form'::text) AND (free_form_format = ANY (ARRAY['text'::text, 'csv'::text, 'json'::text]))) OR ((value_type <> 'free_form'::text) AND (free_form_format IS NULL)))),
    CONSTRAINT features_value_type_check CHECK ((value_type = ANY (ARRAY['boolean'::text, 'quantity'::text, 'free_form'::text])))
);

CREATE TABLE public.idempotency_records (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    application_id uuid,
    actor_key text NOT NULL,
    idempotency_key text NOT NULL,
    request_hash bytea NOT NULL,
    response_status integer,
    response_headers jsonb,
    response_body bytea,
    locked_until timestamp with time zone,
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public.installation_control_user_roles (
    control_user_id uuid NOT NULL,
    role text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT installation_control_user_roles_role_check CHECK ((role = ANY (ARRAY['owner'::text, 'admin'::text, 'auditor'::text])))
);

CREATE TABLE public.installations (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    setup_completed_at timestamp with time zone,
    bootstrap_digest bytea,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    management_api_enabled boolean DEFAULT false NOT NULL,
    control_email_code_enabled boolean DEFAULT true NOT NULL,
    control_magic_link_enabled boolean DEFAULT true NOT NULL,
    control_password_enabled boolean DEFAULT true NOT NULL
);

COMMENT ON COLUMN public.installations.management_api_enabled IS 'Live kill switch for machine-only installation organization management.';

CREATE TABLE public.invitation_authorization_codes (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    application_id uuid NOT NULL,
    user_id uuid NOT NULL,
    code_digest bytea NOT NULL,
    code_challenge text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    used_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public.invoices (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    application_id uuid NOT NULL,
    provider_connection_id uuid NOT NULL,
    provider_invoice_id text NOT NULL,
    provider_customer_id text,
    provider_subscription_id text,
    billing_customer_id uuid,
    subscription_id uuid,
    status text NOT NULL,
    amount_due_minor bigint DEFAULT 0 NOT NULL,
    amount_paid_minor bigint DEFAULT 0 NOT NULL,
    tax_minor bigint DEFAULT 0 NOT NULL,
    currency character(3) NOT NULL,
    due_at timestamp with time zone,
    paid_at timestamp with time zone,
    hosted_uri text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    external_reference text
);

CREATE TABLE public.local_entitlement_request_actions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    request_id uuid NOT NULL,
    action text NOT NULL,
    actor_type text NOT NULL,
    actor_id uuid NOT NULL,
    reason text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT local_entitlement_request_actions_action_check CHECK ((action = ANY (ARRAY['created'::text, 'approved'::text, 'rejected'::text, 'canceled'::text, 'reopened'::text]))),
    CONSTRAINT local_entitlement_request_actions_actor_type_check CHECK ((actor_type = ANY (ARRAY['user'::text, 'control_user'::text])))
);

CREATE TABLE public.local_entitlement_requests (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    application_id uuid NOT NULL,
    requester_user_id uuid NOT NULL,
    subject_type text NOT NULL,
    subject_id uuid NOT NULL,
    product_id uuid NOT NULL,
    price_id uuid NOT NULL,
    product_snapshot jsonb NOT NULL,
    price_snapshot jsonb NOT NULL,
    feature_snapshot jsonb DEFAULT '{}'::jsonb NOT NULL,
    address_snapshot jsonb,
    external_reference text,
    status text DEFAULT 'pending'::text NOT NULL,
    decision_reason text,
    reviewed_by uuid,
    reviewed_at timestamp with time zone,
    entitlement_grant_id uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT local_entitlement_requests_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'approved'::text, 'rejected'::text, 'canceled'::text]))),
    CONSTRAINT local_entitlement_requests_subject_type_check CHECK ((subject_type = ANY (ARRAY['user'::text, 'workspace'::text])))
);

CREATE TABLE public.login_challenges (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    application_id uuid NOT NULL,
    normalized_email text NOT NULL,
    requested_by_user_id uuid,
    intent text NOT NULL,
    code_digest bytea,
    link_digest bytea,
    redirect_uri text,
    attempts integer DEFAULT 0 NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    consumed_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT login_challenges_intent_check CHECK ((intent = ANY (ARRAY['sign_in'::text, 'sign_up'::text, 'automatic'::text, 'verify_email'::text, 'change_email'::text, 'password_reset'::text])))
);

CREATE TABLE public.management_clients (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    client_id text NOT NULL,
    name text NOT NULL,
    secret_digest bytea NOT NULL,
    allowed_scopes text[] DEFAULT ARRAY['/management/organizations/*'::text] NOT NULL,
    disabled_at timestamp with time zone,
    version bigint DEFAULT 1 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public.mfa_login_challenges (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    application_id uuid NOT NULL,
    user_id uuid NOT NULL,
    primary_amr text[] NOT NULL,
    attempts integer DEFAULT 0 NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    consumed_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public.notification_attachments (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    notification_id uuid NOT NULL,
    filename text NOT NULL,
    content_type text NOT NULL,
    content bytea NOT NULL,
    size_bytes integer NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT notification_attachments_size_bytes_check CHECK (((size_bytes >= 0) AND (size_bytes <= 2097152)))
);

CREATE TABLE public.notification_attempts (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    notification_id uuid NOT NULL,
    notification_provider_id uuid,
    attempt_number integer NOT NULL,
    status text NOT NULL,
    error text,
    started_at timestamp with time zone DEFAULT now() NOT NULL,
    completed_at timestamp with time zone,
    CONSTRAINT notification_attempts_status_check CHECK ((status = ANY (ARRAY['sending'::text, 'delivered'::text, 'failed'::text])))
);

CREATE TABLE public.notification_preferences (
    application_id uuid NOT NULL,
    user_id uuid NOT NULL,
    category text NOT NULL,
    email_enabled boolean DEFAULT true NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public.notification_providers (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    application_id uuid,
    provider text DEFAULT 'smtp'::text NOT NULL,
    name text NOT NULL,
    config_ciphertext text NOT NULL,
    sender_email text NOT NULL,
    sender_name text DEFAULT ''::text NOT NULL,
    verified_at timestamp with time zone,
    disabled_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    organization_id uuid,
    inheritable boolean DEFAULT false NOT NULL,
    CONSTRAINT notification_provider_scope_check CHECK ((((application_id IS NOT NULL) AND (organization_id IS NULL)) OR ((application_id IS NULL) AND (organization_id IS NOT NULL)) OR ((application_id IS NULL) AND (organization_id IS NULL))))
);

CREATE TABLE public.notification_template_assets (
    notification_template_id uuid NOT NULL,
    storage_object_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public.notification_templates (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    application_id uuid,
    key text NOT NULL,
    locale text DEFAULT 'en'::text NOT NULL,
    category text NOT NULL,
    version integer NOT NULL,
    subject_template text NOT NULL,
    text_template text NOT NULL,
    html_template text,
    variable_schema jsonb DEFAULT '{}'::jsonb NOT NULL,
    status text DEFAULT 'draft'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    system_managed boolean DEFAULT false NOT NULL,
    CONSTRAINT notification_templates_status_check CHECK ((status = ANY (ARRAY['draft'::text, 'published'::text, 'archived'::text])))
);

CREATE TABLE public.notifications (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    application_id uuid,
    template_id uuid,
    notification_provider_id uuid,
    user_id uuid,
    recipient text NOT NULL,
    category text DEFAULT 'security'::text NOT NULL,
    locale text DEFAULT 'en'::text NOT NULL,
    payload_ciphertext text NOT NULL,
    status text DEFAULT 'queued'::text NOT NULL,
    attempt_count integer DEFAULT 0 NOT NULL,
    next_attempt_at timestamp with time zone DEFAULT now() NOT NULL,
    last_error text,
    delivered_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    organization_id uuid,
    CONSTRAINT notification_scope_check CHECK (((application_id IS NULL) OR (organization_id IS NULL))),
    CONSTRAINT notifications_status_check CHECK ((status = ANY (ARRAY['queued'::text, 'sending'::text, 'delivered'::text, 'failed'::text, 'dead'::text, 'suppressed'::text])))
);

CREATE TABLE public.oauth_client_assertion_jtis (
    application_id uuid NOT NULL,
    jti_digest bytea NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public.oauth_consents (
    application_id uuid NOT NULL,
    user_id uuid NOT NULL,
    client_id uuid NOT NULL,
    scopes text[] DEFAULT '{}'::text[] NOT NULL,
    granted_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    revoked_at timestamp with time zone
);

CREATE TABLE public.oauth_sessions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    application_id uuid NOT NULL,
    signature_digest bytea NOT NULL,
    kind text NOT NULL,
    request_id text NOT NULL,
    request_payload jsonb NOT NULL,
    access_signature_digest bytea,
    expires_at timestamp with time zone NOT NULL,
    active boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT oauth_sessions_kind_check CHECK ((kind = ANY (ARRAY['authorize_code'::text, 'pkce'::text, 'openid'::text, 'access'::text, 'refresh'::text])))
);

CREATE TABLE public.control_user_login_challenges (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    normalized_email text NOT NULL,
    code_digest bytea,
    link_digest bytea,
    attempts integer DEFAULT 0 NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    consumed_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public.control_user_sessions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    control_user_id uuid NOT NULL,
    refresh_digest bytea NOT NULL,
    kind text DEFAULT 'control'::text NOT NULL,
    ip_address inet,
    user_agent text DEFAULT ''::text NOT NULL,
    authenticated_at timestamp with time zone DEFAULT now() NOT NULL,
    amr text[] DEFAULT '{}'::text[] NOT NULL,
    last_used_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    revoked_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT control_user_sessions_kind_check CHECK ((kind = ANY (ARRAY['setup'::text, 'control'::text])))
);

CREATE TABLE public.control_users (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    email text NOT NULL,
    normalized_email text NOT NULL,
    display_name text DEFAULT ''::text NOT NULL,
    status text DEFAULT 'active'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    password_hash text,
    CONSTRAINT control_users_status_check CHECK ((status = ANY (ARRAY['active'::text, 'suspended'::text, 'deleted'::text])))
);

CREATE TABLE public.control_user_identities (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    control_user_id uuid NOT NULL,
    auth_provider_config_id uuid NOT NULL,
    provider text NOT NULL,
    provider_subject text NOT NULL,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    last_used_at timestamp with time zone,
    CONSTRAINT control_user_identities_provider_check CHECK ((provider = ANY (ARRAY['google'::text, 'apple'::text])))
);

CREATE TABLE public.control_user_external_auth_challenges (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    auth_provider_config_id uuid NOT NULL,
    provider text NOT NULL,
    flow text NOT NULL,
    requested_by_control_user_id uuid,
    invitation_id uuid,
    state_digest bytea NOT NULL,
    nonce_digest bytea NOT NULL,
    verifier_ciphertext text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    locked_until timestamp with time zone,
    consumed_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT control_user_external_auth_challenges_provider_check CHECK ((provider = ANY (ARRAY['google'::text, 'apple'::text]))),
    CONSTRAINT control_user_external_auth_challenges_flow_check CHECK ((flow = ANY (ARRAY['login'::text, 'link'::text, 'invitation'::text]))),
    CONSTRAINT control_user_external_auth_challenges_context_check CHECK (((flow = 'login'::text) AND (requested_by_control_user_id IS NULL) AND (invitation_id IS NULL)) OR ((flow = 'link'::text) AND (requested_by_control_user_id IS NOT NULL) AND (invitation_id IS NULL)) OR ((flow = 'invitation'::text) AND (requested_by_control_user_id IS NULL) AND (invitation_id IS NOT NULL)))
);

CREATE TABLE public.control_user_invitations (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    organization_id uuid,
    normalized_email text NOT NULL,
    role text NOT NULL,
    onboarding_method text DEFAULT 'email'::text NOT NULL,
    credential_digest bytea NOT NULL,
    invited_by uuid NOT NULL,
    accepted_by uuid,
    expires_at timestamp with time zone NOT NULL,
    accepted_at timestamp with time zone,
    revoked_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT control_user_invitations_method_check CHECK ((onboarding_method = ANY (ARRAY['email'::text, 'google'::text, 'apple'::text]))),
    CONSTRAINT control_user_invitations_role_check CHECK (((organization_id IS NULL) AND (role = ANY (ARRAY['owner'::text, 'admin'::text, 'auditor'::text]))) OR ((organization_id IS NOT NULL) AND (role = ANY (ARRAY['owner'::text, 'admin'::text, 'member'::text, 'auditor'::text]))))
);

CREATE TABLE public.organization_memberships (
    organization_id uuid NOT NULL,
    control_user_id uuid NOT NULL,
    role text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT organization_memberships_role_check CHECK ((role = ANY (ARRAY['owner'::text, 'admin'::text, 'member'::text, 'auditor'::text])))
);

CREATE TABLE public.organization_policies (
    organization_id uuid NOT NULL,
    max_applications integer,
    max_users integer,
    enabled_settings jsonb DEFAULT '{"webhooks": true, "delegation": true, "custom_events": true, "personal_api_keys": true, "public_registration": true, "password_authentication": true, "passwordless_authentication": true, "application_provider_overrides": true, "organization_provider_overrides": true}'::jsonb NOT NULL,
    version bigint DEFAULT 1 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT organization_policies_enabled_settings_check CHECK ((jsonb_typeof(enabled_settings) = 'object'::text)),
    CONSTRAINT organization_policies_max_applications_check CHECK (((max_applications IS NULL) OR (max_applications >= 0))),
    CONSTRAINT organization_policies_max_users_check CHECK (((max_users IS NULL) OR (max_users >= 0)))
);

CREATE TABLE public.organizations (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name text NOT NULL,
    slug text NOT NULL,
    version bigint DEFAULT 1 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone
);

CREATE TABLE public.outbox (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    event_id uuid NOT NULL,
    available_at timestamp with time zone DEFAULT now() NOT NULL,
    attempts integer DEFAULT 0 NOT NULL,
    locked_at timestamp with time zone,
    locked_by text,
    dispatched_at timestamp with time zone,
    last_error text
);

CREATE TABLE public.payments (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    application_id uuid NOT NULL,
    provider_connection_id uuid NOT NULL,
    provider_payment_id text NOT NULL,
    provider_customer_id text,
    provider_invoice_id text,
    billing_customer_id uuid,
    checkout_session_id uuid,
    invoice_id uuid,
    status text NOT NULL,
    amount_minor bigint DEFAULT 0 NOT NULL,
    amount_received_minor bigint DEFAULT 0 NOT NULL,
    currency character(3) NOT NULL,
    payment_method_type text,
    failure_code text,
    failure_message text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    external_reference text
);

CREATE TABLE public.personal_api_keys (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    application_id uuid NOT NULL,
    user_id uuid NOT NULL,
    label text,
    token_prefix text NOT NULL,
    token_digest bytea NOT NULL,
    scopes text[] DEFAULT '{}'::text[] NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    last_used_at timestamp with time zone,
    revoked_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT personal_api_keys_scopes_format_check CHECK (public.valid_canonical_scopes(application_id,scopes,true))
);

CREATE TABLE public.price_features (
    price_id uuid NOT NULL,
    feature_id uuid NOT NULL,
    boolean_value boolean,
    quantity_value bigint,
    free_form_value jsonb
);

CREATE TABLE public.prices (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    application_id uuid NOT NULL,
    product_id uuid NOT NULL,
    key text NOT NULL,
    mode text NOT NULL,
    amount_minor bigint NOT NULL,
    currency character(3) NOT NULL,
    currency_exponent smallint DEFAULT 2 NOT NULL,
    interval_unit text,
    interval_count integer,
    validity_seconds bigint,
    grace_seconds bigint DEFAULT 0 NOT NULL,
    tax_behavior text DEFAULT 'inclusive'::text NOT NULL,
    checkout_config jsonb DEFAULT '{}'::jsonb NOT NULL,
    entitlement_config jsonb DEFAULT '{}'::jsonb NOT NULL,
    active boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT prices_amount_minor_check CHECK ((amount_minor >= 0)),
    CONSTRAINT prices_interval_unit_check CHECK ((interval_unit = ANY (ARRAY['day'::text, 'week'::text, 'month'::text, 'year'::text]))),
    CONSTRAINT prices_mode_check CHECK ((mode = ANY (ARRAY['recurring'::text, 'one_time'::text, 'local'::text]))),
    CONSTRAINT prices_tax_behavior_check CHECK ((tax_behavior = ANY (ARRAY['inclusive'::text, 'exclusive'::text, 'unspecified'::text])))
);

CREATE TABLE public.product_features (
    product_id uuid NOT NULL,
    feature_id uuid NOT NULL,
    boolean_value boolean,
    quantity_value bigint,
    free_form_value jsonb
);

CREATE TABLE public.products (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    application_id uuid NOT NULL,
    key text NOT NULL,
    name text NOT NULL,
    description text DEFAULT ''::text NOT NULL,
    listable boolean DEFAULT true NOT NULL,
    status text DEFAULT 'active'::text NOT NULL,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    version bigint DEFAULT 1 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    entitlement_config jsonb DEFAULT '{}'::jsonb NOT NULL,
    CONSTRAINT products_status_check CHECK ((status = ANY (ARRAY['draft'::text, 'active'::text, 'archived'::text])))
);

CREATE TABLE public.provider_connections (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    application_id uuid,
    provider text NOT NULL,
    public_id text NOT NULL,
    api_version text NOT NULL,
    secret_ciphertext text NOT NULL,
    webhook_secret_ciphertext text,
    status text DEFAULT 'active'::text NOT NULL,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    organization_id uuid,
    inheritable boolean DEFAULT false NOT NULL,
    CONSTRAINT billing_provider_scope_check CHECK ((((application_id IS NOT NULL) AND (organization_id IS NULL)) OR ((application_id IS NULL) AND (organization_id IS NOT NULL)) OR ((application_id IS NULL) AND (organization_id IS NULL)))),
    CONSTRAINT provider_connections_status_check CHECK ((status = ANY (ARRAY['active'::text, 'disabled'::text, 'error'::text])))
);

CREATE TABLE public.provider_events (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    application_id uuid NOT NULL,
    provider_connection_id uuid NOT NULL,
    provider_event_id text NOT NULL,
    api_version text,
    event_type text NOT NULL,
    raw_body_ciphertext text NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    attempts integer DEFAULT 0 NOT NULL,
    last_error text,
    received_at timestamp with time zone DEFAULT now() NOT NULL,
    processed_at timestamp with time zone,
    CONSTRAINT provider_events_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'processed'::text, 'failed'::text, 'ignored'::text])))
);

CREATE TABLE public.provider_mappings (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    application_id uuid NOT NULL,
    provider_connection_id uuid NOT NULL,
    object_type text NOT NULL,
    internal_id uuid NOT NULL,
    provider_id text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT provider_mappings_object_type_check CHECK ((object_type = ANY (ARRAY['product'::text, 'price'::text])))
);

CREATE TABLE public.reconciliation_runs (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    application_id uuid NOT NULL,
    provider_connection_id uuid NOT NULL,
    status text NOT NULL,
    findings jsonb DEFAULT '[]'::jsonb NOT NULL,
    repairs jsonb DEFAULT '[]'::jsonb NOT NULL,
    last_error text,
    started_at timestamp with time zone,
    completed_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT reconciliation_runs_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'running'::text, 'completed'::text, 'failed'::text])))
);

CREATE TABLE public.refunds (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    application_id uuid NOT NULL,
    provider_connection_id uuid NOT NULL,
    provider_payment_id text,
    payment_id uuid,
    provider_refund_id text NOT NULL,
    status text NOT NULL,
    amount_minor bigint NOT NULL,
    currency character(3) NOT NULL,
    reason text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public.role_assignments (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    application_id uuid NOT NULL,
    user_id uuid,
    client_id uuid,
    role_id uuid NOT NULL,
    workspace_id uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT role_assignments_check CHECK (((user_id IS NOT NULL) <> (client_id IS NOT NULL)))
);

CREATE TABLE public.permission_grants (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    application_id uuid NOT NULL,
    user_id uuid,
    client_id uuid,
    workspace_id uuid,
    permission text NOT NULL,
    canonical_scope text NOT NULL,
    reason text DEFAULT ''::text NOT NULL,
    created_by_type text NOT NULL,
    created_by_id uuid NOT NULL,
    revoked_by_type text,
    revoked_by_id uuid,
    revoked_reason text,
    revoked_at timestamp with time zone,
    version bigint DEFAULT 1 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT permission_grants_subject_check CHECK (((user_id IS NOT NULL) <> (client_id IS NOT NULL))),
    CONSTRAINT permission_grants_actor_type_check CHECK ((created_by_type = ANY (ARRAY['control_user'::text, 'user'::text, 'client'::text]))),
    CONSTRAINT permission_grants_revocation_check CHECK (((revoked_at IS NULL) = (revoked_by_type IS NULL)) AND ((revoked_at IS NULL) = (revoked_by_id IS NULL)) AND (revoked_by_type IS NULL OR revoked_by_type = ANY (ARRAY['control_user'::text, 'user'::text, 'client'::text])))
);

CREATE TABLE public.roles (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    application_id uuid NOT NULL,
    key text NOT NULL,
    name text NOT NULL,
    scope text NOT NULL,
    permissions text[] DEFAULT '{}'::text[] NOT NULL,
    built_in boolean DEFAULT false NOT NULL,
    version bigint DEFAULT 1 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT roles_scope_check CHECK ((scope = ANY (ARRAY['application'::text, 'workspace'::text]))),
    CONSTRAINT roles_key_format_check CHECK ((key ~ '^[a-z][a-z0-9_-]{0,62}$'::text)),
    CONSTRAINT roles_permissions_format_check CHECK (public.valid_permission_keys(permissions))
);

CREATE TABLE public.sender_identities (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    application_id uuid,
    notification_provider_id uuid NOT NULL,
    email text NOT NULL,
    name text DEFAULT ''::text NOT NULL,
    is_default boolean DEFAULT false NOT NULL,
    verified_at timestamp with time zone,
    disabled_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    organization_id uuid
);

CREATE TABLE public.signing_keys (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    kid text NOT NULL,
    public_jwk jsonb NOT NULL,
    private_key_ciphertext text NOT NULL,
    status text NOT NULL,
    activates_at timestamp with time zone,
    retires_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT signing_keys_status_check CHECK ((status = ANY (ARRAY['prepared'::text, 'active'::text, 'retiring'::text, 'retired'::text])))
);

CREATE TABLE public.storage_objects (
    id uuid NOT NULL,
    application_id uuid,
    storage_provider_id uuid NOT NULL,
    owner_type text NOT NULL,
    owner_id uuid,
    visibility text NOT NULL,
    bucket_role text NOT NULL,
    bucket_name text NOT NULL,
    object_key text NOT NULL,
    filename text NOT NULL,
    content_type text NOT NULL,
    size_bytes bigint NOT NULL,
    etag text,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    upload_expires_at timestamp with time zone,
    ready_at timestamp with time zone,
    deleted_at timestamp with time zone,
    last_error text,
    version bigint DEFAULT 1 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT storage_objects_bucket_role_check CHECK ((bucket_role = ANY (ARRAY['public'::text, 'private'::text]))),
    CONSTRAINT storage_objects_check CHECK ((((owner_type = 'installation'::text) AND (application_id IS NULL) AND (owner_id IS NULL)) OR ((owner_type = 'application'::text) AND (application_id IS NOT NULL) AND (owner_id IS NULL)) OR ((owner_type = ANY (ARRAY['user'::text, 'workspace'::text])) AND (application_id IS NOT NULL) AND (owner_id IS NOT NULL)))),
    CONSTRAINT storage_objects_check1 CHECK ((visibility = bucket_role)),
    CONSTRAINT storage_objects_check2 CHECK ((((status = 'pending'::text) AND (upload_expires_at IS NOT NULL)) OR (status <> 'pending'::text))),
    CONSTRAINT storage_objects_content_type_check CHECK (((content_type <> ''::text) AND (length(content_type) <= 255))),
    CONSTRAINT storage_objects_filename_check CHECK (((filename <> ''::text) AND (length(filename) <= 500))),
    CONSTRAINT storage_objects_object_key_check CHECK (((object_key <> ''::text) AND (length(object_key) <= 1024))),
    CONSTRAINT storage_objects_owner_type_check CHECK ((owner_type = ANY (ARRAY['installation'::text, 'application'::text, 'user'::text, 'workspace'::text]))),
    CONSTRAINT storage_objects_size_bytes_check CHECK ((size_bytes > 0)),
    CONSTRAINT storage_objects_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'ready'::text, 'deleting'::text, 'deleted'::text, 'failed'::text]))),
    CONSTRAINT storage_objects_visibility_check CHECK ((visibility = ANY (ARRAY['public'::text, 'private'::text])))
);

CREATE TABLE public.storage_providers (
    id uuid NOT NULL,
    organization_id uuid,
    application_id uuid,
    provider text DEFAULT 's3'::text NOT NULL,
    name text NOT NULL,
    endpoint text NOT NULL,
    region text NOT NULL,
    force_path_style boolean DEFAULT false NOT NULL,
    public_bucket text,
    private_bucket text,
    public_base_url text,
    credentials_ciphertext text NOT NULL,
    inheritable boolean DEFAULT false NOT NULL,
    allow_private_endpoint boolean DEFAULT false NOT NULL,
    max_object_bytes bigint DEFAULT 26214400 NOT NULL,
    max_email_image_bytes bigint DEFAULT 2097152 NOT NULL,
    max_application_bytes bigint DEFAULT '10737418240'::bigint NOT NULL,
    max_application_objects bigint DEFAULT 100000 NOT NULL,
    status text DEFAULT 'unverified'::text NOT NULL,
    verified_at timestamp with time zone,
    disabled_at timestamp with time zone,
    last_error text,
    version bigint DEFAULT 1 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT storage_providers_check CHECK ((max_application_bytes >= max_object_bytes)),
    CONSTRAINT storage_providers_check1 CHECK ((((application_id IS NOT NULL) AND (organization_id IS NULL)) OR ((application_id IS NULL) AND (organization_id IS NOT NULL)) OR ((application_id IS NULL) AND (organization_id IS NULL)))),
    CONSTRAINT storage_providers_check2 CHECK (((public_bucket IS NOT NULL) OR (private_bucket IS NOT NULL))),
    CONSTRAINT storage_providers_check3 CHECK (((public_bucket IS NULL) OR (private_bucket IS NULL) OR (public_bucket <> private_bucket))),
    CONSTRAINT storage_providers_check4 CHECK (((application_id IS NULL) OR (inheritable = false))),
    CONSTRAINT storage_providers_check5 CHECK (((allow_private_endpoint = false) OR ((application_id IS NULL) AND (organization_id IS NULL)))),
    CONSTRAINT storage_providers_endpoint_check CHECK (((endpoint <> ''::text) AND (length(endpoint) <= 2000))),
    CONSTRAINT storage_providers_max_application_objects_check CHECK (((max_application_objects >= 1) AND (max_application_objects <= 100000000))),
    CONSTRAINT storage_providers_max_email_image_bytes_check CHECK (((max_email_image_bytes >= 1) AND (max_email_image_bytes <= 26214400))),
    CONSTRAINT storage_providers_max_object_bytes_check CHECK (((max_object_bytes >= 1) AND (max_object_bytes <= '5368709120'::bigint))),
    CONSTRAINT storage_providers_name_check CHECK (((name <> ''::text) AND (length(name) <= 200))),
    CONSTRAINT storage_providers_provider_check CHECK ((provider = 's3'::text)),
    CONSTRAINT storage_providers_region_check CHECK (((region <> ''::text) AND (length(region) <= 100))),
    CONSTRAINT storage_providers_status_check CHECK ((status = ANY (ARRAY['unverified'::text, 'active'::text, 'error'::text, 'disabled'::text])))
);

CREATE TABLE public.subscriptions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    application_id uuid NOT NULL,
    subject_type text NOT NULL,
    subject_id uuid NOT NULL,
    price_id uuid NOT NULL,
    provider_connection_id uuid NOT NULL,
    provider_subscription_id text NOT NULL,
    provider_item_id text,
    status text NOT NULL,
    current_period_start timestamp with time zone,
    current_period_end timestamp with time zone,
    cancel_at timestamp with time zone,
    canceled_at timestamp with time zone,
    trial_end timestamp with time zone,
    cancel_at_period_end boolean DEFAULT false NOT NULL,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    external_reference text
);

CREATE TABLE public.user_authentication_methods (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    application_id uuid NOT NULL,
    user_id uuid NOT NULL,
    method_type text NOT NULL,
    label text DEFAULT ''::text NOT NULL,
    secret_ciphertext text,
    credential_id bytea,
    credential_ciphertext text,
    webauthn_rp_id text,
    status text DEFAULT 'pending'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    activated_at timestamp with time zone,
    last_used_at timestamp with time zone,
    disabled_at timestamp with time zone,
    CONSTRAINT user_authentication_methods_method_type_check CHECK ((method_type = ANY (ARRAY['totp'::text, 'webauthn'::text]))),
    CONSTRAINT user_authentication_methods_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'active'::text, 'disabled'::text])))
);

CREATE TABLE public.user_identities (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    application_id uuid NOT NULL,
    user_id uuid NOT NULL,
    provider text NOT NULL,
    provider_subject text NOT NULL,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public.user_recovery_codes (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    application_id uuid NOT NULL,
    user_id uuid NOT NULL,
    code_digest bytea NOT NULL,
    used_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public.user_sessions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    application_id uuid NOT NULL,
    user_id uuid NOT NULL,
    delegation_id uuid,
    refresh_digest bytea NOT NULL,
    previous_refresh_digest bytea,
    previous_valid_until timestamp with time zone,
    user_agent text,
    ip_hash bytea,
    authenticated_at timestamp with time zone DEFAULT now() NOT NULL,
    mfa_authenticated_at timestamp with time zone,
    amr text[] DEFAULT '{}'::text[] NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    revoked_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    last_used_at timestamp with time zone
);

CREATE TABLE public.users (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    application_id uuid NOT NULL,
    email text NOT NULL,
    normalized_email text NOT NULL,
    first_name text DEFAULT ''::text NOT NULL,
    last_name text DEFAULT ''::text NOT NULL,
    username text,
    password_hash text,
    email_verified_at timestamp with time zone,
    is_org_verified boolean DEFAULT false NOT NULL,
    status text DEFAULT 'active'::text NOT NULL,
    custom_attributes jsonb DEFAULT '{}'::jsonb NOT NULL,
    version bigint DEFAULT 1 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone,
    locale text DEFAULT ''::text NOT NULL,
    CONSTRAINT users_locale_length CHECK ((length(locale) <= 35)),
    CONSTRAINT users_status_check CHECK ((status = ANY (ARRAY['active'::text, 'suspended'::text, 'pending_deletion'::text, 'anonymized'::text, 'deleted'::text])))
);

CREATE TABLE public.webauthn_ceremonies (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    application_id uuid NOT NULL,
    user_id uuid NOT NULL,
    user_session_id uuid,
    mfa_challenge_id uuid,
    intent text NOT NULL,
    origin text NOT NULL,
    label text DEFAULT ''::text NOT NULL,
    session_ciphertext text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    consumed_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT webauthn_ceremonies_intent_check CHECK ((intent = ANY (ARRAY['register'::text, 'authenticate'::text])))
);

CREATE TABLE public.webhook_deliveries (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    application_id uuid NOT NULL,
    webhook_endpoint_id uuid NOT NULL,
    event_id uuid NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    attempt_count integer DEFAULT 0 NOT NULL,
    next_attempt_at timestamp with time zone DEFAULT now() NOT NULL,
    response_status integer,
    response_excerpt text,
    delivered_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT webhook_deliveries_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'delivering'::text, 'delivered'::text, 'failed'::text, 'dead'::text])))
);

CREATE TABLE public.webhook_endpoints (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    application_id uuid NOT NULL,
    uri text NOT NULL,
    event_filters text[] DEFAULT '{}'::text[] NOT NULL,
    secret_ciphertext text NOT NULL,
    previous_secret_ciphertext text,
    previous_valid_until timestamp with time zone,
    disabled_at timestamp with time zone,
    version bigint DEFAULT 1 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public.workspace_memberships (
    application_id uuid NOT NULL,
    workspace_id uuid NOT NULL,
    user_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public.workspaces (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    application_id uuid NOT NULL,
    owner_user_id uuid NOT NULL,
    key text NOT NULL,
    name text NOT NULL,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    version bigint DEFAULT 1 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone
);

ALTER TABLE ONLY public.addresses
    ADD CONSTRAINT addresses_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.application_domains
    ADD CONSTRAINT application_domains_application_id_hostname_key UNIQUE (application_id, hostname);

ALTER TABLE ONLY public.application_domains
    ADD CONSTRAINT application_domains_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.application_secrets
    ADD CONSTRAINT application_secrets_application_id_kind_name_key UNIQUE (application_id, kind, name);

ALTER TABLE ONLY public.application_secrets
    ADD CONSTRAINT application_secrets_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.applications
    ADD CONSTRAINT applications_organization_id_slug_key UNIQUE (organization_id, slug);

ALTER TABLE ONLY public.applications
    ADD CONSTRAINT applications_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.audit_exports
    ADD CONSTRAINT audit_exports_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.audit_records
    ADD CONSTRAINT audit_records_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.auth_provider_configs
    ADD CONSTRAINT auth_provider_configs_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.auth_rate_limits
    ADD CONSTRAINT auth_rate_limits_pkey PRIMARY KEY (bucket_digest);

ALTER TABLE ONLY public.billing_customers
    ADD CONSTRAINT billing_customers_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.billing_customers
    ADD CONSTRAINT billing_customers_provider_connection_id_subject_type_subje_key UNIQUE (provider_connection_id, subject_type, subject_id);

ALTER TABLE ONLY public.billing_profiles
    ADD CONSTRAINT billing_profiles_application_id_subject_type_subject_id_key UNIQUE (application_id, subject_type, subject_id);

ALTER TABLE ONLY public.billing_profiles
    ADD CONSTRAINT billing_profiles_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.checkout_sessions
    ADD CONSTRAINT checkout_sessions_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.clients
    ADD CONSTRAINT clients_client_id_key UNIQUE (client_id);

ALTER TABLE ONLY public.clients
    ADD CONSTRAINT clients_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.delegations
    ADD CONSTRAINT delegations_exchange_digest_key UNIQUE (exchange_digest);

ALTER TABLE ONLY public.delegations
    ADD CONSTRAINT delegations_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.disputes
    ADD CONSTRAINT disputes_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.disputes
    ADD CONSTRAINT disputes_provider_connection_id_provider_dispute_id_key UNIQUE (provider_connection_id, provider_dispute_id);

ALTER TABLE ONLY public.domain_events
    ADD CONSTRAINT domain_events_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.entitlement_grant_actions
    ADD CONSTRAINT entitlement_grant_actions_grant_id_action_key_key UNIQUE (grant_id, action_key);

ALTER TABLE ONLY public.entitlement_grant_actions
    ADD CONSTRAINT entitlement_grant_actions_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.entitlement_grants
    ADD CONSTRAINT entitlement_grants_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.event_type_definitions
    ADD CONSTRAINT event_type_definitions_application_id_name_key UNIQUE NULLS NOT DISTINCT (application_id, name);

ALTER TABLE ONLY public.event_type_definitions
    ADD CONSTRAINT event_type_definitions_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.external_auth_challenges
    ADD CONSTRAINT external_auth_challenges_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.external_auth_challenges
    ADD CONSTRAINT external_auth_challenges_state_digest_key UNIQUE (state_digest);

ALTER TABLE ONLY public.external_auth_exchanges
    ADD CONSTRAINT external_auth_exchanges_credential_digest_key UNIQUE (credential_digest);

ALTER TABLE ONLY public.external_auth_exchanges
    ADD CONSTRAINT external_auth_exchanges_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.features
    ADD CONSTRAINT features_application_id_key_key UNIQUE (application_id, key);

ALTER TABLE ONLY public.features
    ADD CONSTRAINT features_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.idempotency_records
    ADD CONSTRAINT idempotency_records_application_id_actor_key_idempotency_ke_key UNIQUE NULLS NOT DISTINCT (application_id, actor_key, idempotency_key);

ALTER TABLE ONLY public.idempotency_records
    ADD CONSTRAINT idempotency_records_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.installation_control_user_roles
    ADD CONSTRAINT installation_control_user_roles_pkey PRIMARY KEY (control_user_id);

ALTER TABLE ONLY public.installations
    ADD CONSTRAINT installations_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.invitation_authorization_codes
    ADD CONSTRAINT invitation_authorization_codes_code_digest_key UNIQUE (code_digest);

ALTER TABLE ONLY public.invitation_authorization_codes
    ADD CONSTRAINT invitation_authorization_codes_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.invoices
    ADD CONSTRAINT invoices_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.invoices
    ADD CONSTRAINT invoices_provider_connection_id_provider_invoice_id_key UNIQUE (provider_connection_id, provider_invoice_id);

ALTER TABLE ONLY public.local_entitlement_request_actions
    ADD CONSTRAINT local_entitlement_request_actions_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.local_entitlement_requests
    ADD CONSTRAINT local_entitlement_requests_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.login_challenges
    ADD CONSTRAINT login_challenges_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.management_clients
    ADD CONSTRAINT management_clients_client_id_key UNIQUE (client_id);

ALTER TABLE ONLY public.management_clients
    ADD CONSTRAINT management_clients_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.mfa_login_challenges
    ADD CONSTRAINT mfa_login_challenges_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.notification_attachments
    ADD CONSTRAINT notification_attachments_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.notification_attempts
    ADD CONSTRAINT notification_attempts_notification_id_attempt_number_key UNIQUE (notification_id, attempt_number);

ALTER TABLE ONLY public.notification_attempts
    ADD CONSTRAINT notification_attempts_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.notification_preferences
    ADD CONSTRAINT notification_preferences_pkey PRIMARY KEY (application_id, user_id, category);

ALTER TABLE ONLY public.notification_providers
    ADD CONSTRAINT notification_providers_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.notification_template_assets
    ADD CONSTRAINT notification_template_assets_pkey PRIMARY KEY (notification_template_id, storage_object_id);

ALTER TABLE ONLY public.notification_templates
    ADD CONSTRAINT notification_templates_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.notifications
    ADD CONSTRAINT notifications_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.oauth_client_assertion_jtis
    ADD CONSTRAINT oauth_client_assertion_jtis_pkey PRIMARY KEY (application_id, jti_digest);

ALTER TABLE ONLY public.oauth_consents
    ADD CONSTRAINT oauth_consents_pkey PRIMARY KEY (application_id, user_id, client_id);

ALTER TABLE ONLY public.oauth_sessions
    ADD CONSTRAINT oauth_sessions_application_id_kind_signature_digest_key UNIQUE (application_id, kind, signature_digest);

ALTER TABLE ONLY public.oauth_sessions
    ADD CONSTRAINT oauth_sessions_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.control_user_login_challenges
    ADD CONSTRAINT control_user_login_challenges_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.control_user_external_auth_challenges
    ADD CONSTRAINT control_user_external_auth_challenges_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.control_user_external_auth_challenges
    ADD CONSTRAINT control_user_external_auth_challenges_state_digest_key UNIQUE (state_digest);

ALTER TABLE ONLY public.control_user_identities
    ADD CONSTRAINT control_user_identities_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.control_user_invitations
    ADD CONSTRAINT control_user_invitations_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.control_user_sessions
    ADD CONSTRAINT control_user_sessions_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.control_user_sessions
    ADD CONSTRAINT control_user_sessions_refresh_digest_key UNIQUE (refresh_digest);

ALTER TABLE ONLY public.control_users
    ADD CONSTRAINT control_users_normalized_email_key UNIQUE (normalized_email);

ALTER TABLE ONLY public.control_users
    ADD CONSTRAINT control_users_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.organization_memberships
    ADD CONSTRAINT organization_memberships_pkey PRIMARY KEY (organization_id, control_user_id);

ALTER TABLE ONLY public.organization_policies
    ADD CONSTRAINT organization_policies_pkey PRIMARY KEY (organization_id);

ALTER TABLE ONLY public.organizations
    ADD CONSTRAINT organizations_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.organizations
    ADD CONSTRAINT organizations_slug_key UNIQUE (slug);

ALTER TABLE ONLY public.outbox
    ADD CONSTRAINT outbox_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.payments
    ADD CONSTRAINT payments_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.payments
    ADD CONSTRAINT payments_provider_connection_id_provider_payment_id_key UNIQUE (provider_connection_id, provider_payment_id);

ALTER TABLE ONLY public.personal_api_keys
    ADD CONSTRAINT personal_api_keys_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.personal_api_keys
    ADD CONSTRAINT personal_api_keys_token_digest_key UNIQUE (token_digest);

ALTER TABLE ONLY public.permission_grants
    ADD CONSTRAINT permission_grants_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.price_features
    ADD CONSTRAINT price_features_pkey PRIMARY KEY (price_id, feature_id);

ALTER TABLE ONLY public.prices
    ADD CONSTRAINT prices_application_id_key_key UNIQUE (application_id, key);

ALTER TABLE ONLY public.prices
    ADD CONSTRAINT prices_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.product_features
    ADD CONSTRAINT product_features_pkey PRIMARY KEY (product_id, feature_id);

ALTER TABLE ONLY public.products
    ADD CONSTRAINT products_application_id_key_key UNIQUE (application_id, key);

ALTER TABLE ONLY public.products
    ADD CONSTRAINT products_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.provider_connections
    ADD CONSTRAINT provider_connections_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.provider_connections
    ADD CONSTRAINT provider_connections_public_id_key UNIQUE (public_id);

ALTER TABLE ONLY public.provider_events
    ADD CONSTRAINT provider_events_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.provider_events
    ADD CONSTRAINT provider_events_provider_connection_id_provider_event_id_key UNIQUE (provider_connection_id, provider_event_id);

ALTER TABLE ONLY public.provider_mappings
    ADD CONSTRAINT provider_mappings_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.provider_mappings
    ADD CONSTRAINT provider_mappings_provider_connection_id_object_type_intern_key UNIQUE (provider_connection_id, object_type, internal_id);

ALTER TABLE ONLY public.provider_mappings
    ADD CONSTRAINT provider_mappings_provider_connection_id_object_type_provid_key UNIQUE (provider_connection_id, object_type, provider_id);

ALTER TABLE ONLY public.reconciliation_runs
    ADD CONSTRAINT reconciliation_runs_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.refunds
    ADD CONSTRAINT refunds_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.refunds
    ADD CONSTRAINT refunds_provider_connection_id_provider_refund_id_key UNIQUE (provider_connection_id, provider_refund_id);

ALTER TABLE ONLY public.role_assignments
    ADD CONSTRAINT role_assignments_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.roles
    ADD CONSTRAINT roles_application_id_key_key UNIQUE (application_id, key);

ALTER TABLE ONLY public.roles
    ADD CONSTRAINT roles_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.sender_identities
    ADD CONSTRAINT sender_identities_notification_provider_id_email_key UNIQUE (notification_provider_id, email);

ALTER TABLE ONLY public.sender_identities
    ADD CONSTRAINT sender_identities_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.signing_keys
    ADD CONSTRAINT signing_keys_kid_key UNIQUE (kid);

ALTER TABLE ONLY public.signing_keys
    ADD CONSTRAINT signing_keys_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.storage_objects
    ADD CONSTRAINT storage_objects_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.storage_objects
    ADD CONSTRAINT storage_objects_storage_provider_id_bucket_name_object_key_key UNIQUE (storage_provider_id, bucket_name, object_key);

ALTER TABLE ONLY public.storage_providers
    ADD CONSTRAINT storage_providers_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.subscriptions
    ADD CONSTRAINT subscriptions_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.subscriptions
    ADD CONSTRAINT subscriptions_provider_connection_id_provider_subscription__key UNIQUE (provider_connection_id, provider_subscription_id);

ALTER TABLE ONLY public.user_authentication_methods
    ADD CONSTRAINT user_authentication_methods_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.user_identities
    ADD CONSTRAINT user_identities_application_id_provider_provider_subject_key UNIQUE (application_id, provider, provider_subject);

ALTER TABLE ONLY public.user_identities
    ADD CONSTRAINT user_identities_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.user_recovery_codes
    ADD CONSTRAINT user_recovery_codes_application_id_code_digest_key UNIQUE (application_id, code_digest);

ALTER TABLE ONLY public.user_recovery_codes
    ADD CONSTRAINT user_recovery_codes_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.user_sessions
    ADD CONSTRAINT user_sessions_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.user_sessions
    ADD CONSTRAINT user_sessions_refresh_digest_key UNIQUE (refresh_digest);

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_application_id_normalized_email_key UNIQUE (application_id, normalized_email);

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.webauthn_ceremonies
    ADD CONSTRAINT webauthn_ceremonies_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.webhook_deliveries
    ADD CONSTRAINT webhook_deliveries_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.webhook_deliveries
    ADD CONSTRAINT webhook_deliveries_webhook_endpoint_id_event_id_key UNIQUE (webhook_endpoint_id, event_id);

ALTER TABLE ONLY public.webhook_endpoints
    ADD CONSTRAINT webhook_endpoints_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.application_invitations
    ADD CONSTRAINT application_invitations_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.workspace_memberships
    ADD CONSTRAINT workspace_memberships_pkey PRIMARY KEY (workspace_id, user_id);

ALTER TABLE ONLY public.workspaces
    ADD CONSTRAINT workspaces_application_id_id_key UNIQUE (application_id, id);

ALTER TABLE ONLY public.workspaces
    ADD CONSTRAINT workspaces_application_id_key_key UNIQUE (application_id, key);

ALTER TABLE ONLY public.workspaces
    ADD CONSTRAINT workspaces_pkey PRIMARY KEY (id);

CREATE UNIQUE INDEX addresses_one_active ON public.addresses USING btree (billing_profile_id) WHERE is_active;

CREATE UNIQUE INDEX application_invitations_pending_email ON public.application_invitations USING btree (application_id, COALESCE(workspace_id, '00000000-0000-0000-0000-000000000000'::uuid), normalized_email) WHERE ((accepted_at IS NULL) AND (revoked_at IS NULL) AND (expiration_recorded_at IS NULL));

CREATE INDEX audit_exports_expiry ON public.audit_exports USING btree (expires_at);

CREATE UNIQUE INDEX auth_provider_configs_application_unique ON public.auth_provider_configs USING btree (application_id, provider) WHERE ((application_id IS NOT NULL) AND (disabled_at IS NULL));

CREATE INDEX auth_provider_configs_effective_scope ON public.auth_provider_configs USING btree (provider, application_id, organization_id, inheritable) WHERE (disabled_at IS NULL);

CREATE UNIQUE INDEX auth_provider_configs_installation_unique ON public.auth_provider_configs USING btree (provider) WHERE ((application_id IS NULL) AND (organization_id IS NULL) AND (disabled_at IS NULL));

CREATE UNIQUE INDEX auth_provider_configs_organization_unique ON public.auth_provider_configs USING btree (organization_id, provider) WHERE ((organization_id IS NOT NULL) AND (disabled_at IS NULL));

CREATE INDEX auth_rate_limits_expiry ON public.auth_rate_limits USING btree (expires_at);

CREATE UNIQUE INDEX billing_customers_application_identity ON public.billing_customers USING btree (application_id, id);

CREATE UNIQUE INDEX billing_profiles_application_identity ON public.billing_profiles USING btree (application_id, id);

CREATE UNIQUE INDEX checkout_sessions_application_identity ON public.checkout_sessions USING btree (application_id, id);

CREATE UNIQUE INDEX clients_application_identity ON public.clients USING btree (application_id, id);

CREATE INDEX entitlement_grant_actions_history ON public.entitlement_grant_actions USING btree (grant_id, created_at, id);

CREATE INDEX entitlement_grants_effective ON public.entitlement_grants USING btree (application_id, subject_type, subject_id, starts_at, expires_at);

CREATE UNIQUE INDEX entitlement_grants_unique_source ON public.entitlement_grants USING btree (application_id, source_type, source_id, product_id) WHERE (source_id IS NOT NULL);

CREATE UNIQUE INDEX installations_singleton ON public.installations USING btree ((true));

CREATE INDEX invitation_authorization_codes_expiry ON public.invitation_authorization_codes USING btree (expires_at) WHERE (used_at IS NULL);

CREATE UNIQUE INDEX invoices_application_identity ON public.invoices USING btree (application_id, id);

CREATE INDEX local_entitlement_request_actions_history ON public.local_entitlement_request_actions USING btree (request_id, created_at, id);

CREATE INDEX notification_providers_effective_scope ON public.notification_providers USING btree (provider, application_id, organization_id, inheritable) WHERE (disabled_at IS NULL);

CREATE UNIQUE INDEX notification_templates_application_published ON public.notification_templates USING btree (application_id, key, locale) WHERE ((application_id IS NOT NULL) AND (status = 'published'::text));

CREATE UNIQUE INDEX notification_templates_application_version ON public.notification_templates USING btree (application_id, key, locale, version) WHERE (application_id IS NOT NULL);

CREATE UNIQUE INDEX notification_templates_installation_published ON public.notification_templates USING btree (key, locale) WHERE ((application_id IS NULL) AND (status = 'published'::text));

CREATE UNIQUE INDEX notification_templates_installation_version ON public.notification_templates USING btree (key, locale, version) WHERE (application_id IS NULL);

CREATE INDEX notifications_organization_queue ON public.notifications USING btree (organization_id, status, next_attempt_at) WHERE ((organization_id IS NOT NULL) AND (status = ANY (ARRAY['queued'::text, 'failed'::text])));

CREATE INDEX oauth_client_assertion_jtis_expiry ON public.oauth_client_assertion_jtis USING btree (expires_at);

CREATE INDEX oauth_sessions_expiry ON public.oauth_sessions USING btree (expires_at);

CREATE INDEX oauth_sessions_request ON public.oauth_sessions USING btree (application_id, request_id, kind) WHERE active;

CREATE UNIQUE INDEX control_user_identities_provider_subject_unique ON public.control_user_identities USING btree (auth_provider_config_id, provider_subject);

CREATE UNIQUE INDEX control_user_identities_user_provider_unique ON public.control_user_identities USING btree (control_user_id, auth_provider_config_id);

CREATE UNIQUE INDEX control_user_invitations_installation_pending ON public.control_user_invitations USING btree (normalized_email) WHERE ((organization_id IS NULL) AND (accepted_at IS NULL) AND (revoked_at IS NULL));

CREATE UNIQUE INDEX control_user_invitations_organization_pending ON public.control_user_invitations USING btree (organization_id, normalized_email) WHERE ((organization_id IS NOT NULL) AND (accepted_at IS NULL) AND (revoked_at IS NULL));

CREATE UNIQUE INDEX payments_application_identity ON public.payments USING btree (application_id, id);

CREATE UNIQUE INDEX permission_grants_active_client ON public.permission_grants USING btree (application_id, client_id, workspace_id, permission) NULLS NOT DISTINCT WHERE ((client_id IS NOT NULL) AND (revoked_at IS NULL));

CREATE UNIQUE INDEX permission_grants_active_user ON public.permission_grants USING btree (application_id, user_id, workspace_id, permission) NULLS NOT DISTINCT WHERE ((user_id IS NOT NULL) AND (revoked_at IS NULL));

CREATE INDEX permission_grants_subject_history ON public.permission_grants USING btree (application_id, user_id, client_id, workspace_id, created_at DESC);

CREATE UNIQUE INDEX prices_application_identity ON public.prices USING btree (application_id, id);

CREATE UNIQUE INDEX products_application_identity ON public.products USING btree (application_id, id);

CREATE INDEX provider_connections_effective_scope ON public.provider_connections USING btree (provider, application_id, organization_id, inheritable) WHERE (status <> 'disabled'::text);

CREATE UNIQUE INDEX role_assignments_unique_client ON public.role_assignments USING btree (application_id, client_id, role_id, workspace_id) NULLS NOT DISTINCT WHERE (client_id IS NOT NULL);

CREATE UNIQUE INDEX role_assignments_unique_user ON public.role_assignments USING btree (application_id, user_id, role_id, workspace_id) NULLS NOT DISTINCT WHERE (user_id IS NOT NULL);

CREATE UNIQUE INDEX roles_application_identity ON public.roles USING btree (application_id, id);

CREATE INDEX storage_objects_application ON public.storage_objects USING btree (application_id, owner_type, owner_id, status, created_at DESC);

CREATE INDEX storage_objects_pending ON public.storage_objects USING btree (upload_expires_at) WHERE (status = 'pending'::text);

CREATE INDEX storage_objects_provider ON public.storage_objects USING btree (storage_provider_id, status, created_at DESC);

CREATE INDEX storage_providers_scope ON public.storage_providers USING btree (application_id, organization_id, status, created_at DESC);

CREATE UNIQUE INDEX subscriptions_application_identity ON public.subscriptions USING btree (application_id, id);

CREATE INDEX user_authentication_methods_user ON public.user_authentication_methods USING btree (application_id, user_id, status);

CREATE UNIQUE INDEX user_authentication_methods_webauthn_credential ON public.user_authentication_methods USING btree (application_id, credential_id) WHERE ((method_type = 'webauthn'::text) AND (status <> 'disabled'::text));

CREATE UNIQUE INDEX users_application_identity ON public.users USING btree (application_id, id);

CREATE TRIGGER billing_customers_subject_guard BEFORE INSERT OR UPDATE OF application_id, subject_type, subject_id ON public.billing_customers FOR EACH ROW EXECUTE FUNCTION public.enforce_application_subject();

CREATE TRIGGER billing_profiles_subject_guard BEFORE INSERT OR UPDATE OF application_id, subject_type, subject_id ON public.billing_profiles FOR EACH ROW EXECUTE FUNCTION public.enforce_application_subject();

CREATE TRIGGER checkout_sessions_subject_guard BEFORE INSERT OR UPDATE OF application_id, subject_type, subject_id ON public.checkout_sessions FOR EACH ROW EXECUTE FUNCTION public.enforce_application_subject();

CREATE TRIGGER entitlement_grants_subject_guard BEFORE INSERT OR UPDATE OF application_id, subject_type, subject_id ON public.entitlement_grants FOR EACH ROW EXECUTE FUNCTION public.enforce_application_subject();

CREATE TRIGGER local_requests_subject_guard BEFORE INSERT OR UPDATE OF application_id, subject_type, subject_id ON public.local_entitlement_requests FOR EACH ROW EXECUTE FUNCTION public.enforce_application_subject();

CREATE TRIGGER notification_template_asset_scope_guard BEFORE INSERT OR UPDATE ON public.notification_template_assets FOR EACH ROW EXECUTE FUNCTION public.enforce_notification_template_asset_scope();

CREATE TRIGGER organizations_default_policy AFTER INSERT ON public.organizations FOR EACH ROW EXECUTE FUNCTION public.create_default_organization_policy();

CREATE TRIGGER permission_grants_guard BEFORE INSERT OR UPDATE ON public.permission_grants FOR EACH ROW EXECUTE FUNCTION public.enforce_permission_grant();

CREATE TRIGGER storage_object_scope_guard BEFORE INSERT OR UPDATE OF application_id, storage_provider_id, owner_type, owner_id, bucket_role, bucket_name ON public.storage_objects FOR EACH ROW EXECUTE FUNCTION public.enforce_storage_object_scope();

CREATE TRIGGER subscriptions_subject_guard BEFORE INSERT OR UPDATE OF application_id, subject_type, subject_id ON public.subscriptions FOR EACH ROW EXECUTE FUNCTION public.enforce_application_subject();

CREATE TRIGGER users_active_workspace_owner_guard BEFORE UPDATE OF status ON public.users FOR EACH ROW EXECUTE FUNCTION public.prevent_inactive_workspace_owner();

CREATE TRIGGER workspace_memberships_owner_guard BEFORE INSERT OR UPDATE ON public.workspace_memberships FOR EACH ROW EXECUTE FUNCTION public.enforce_workspace_owner_membership_separation();

CREATE TRIGGER workspaces_owner_guard BEFORE INSERT OR UPDATE OF owner_user_id ON public.workspaces FOR EACH ROW EXECUTE FUNCTION public.enforce_workspace_owner_is_active_non_member();

ALTER TABLE ONLY public.addresses
    ADD CONSTRAINT addresses_application_id_fkey FOREIGN KEY (application_id) REFERENCES public.applications(id);

ALTER TABLE ONLY public.addresses
    ADD CONSTRAINT addresses_billing_profile_id_fkey FOREIGN KEY (billing_profile_id) REFERENCES public.billing_profiles(id);

ALTER TABLE ONLY public.addresses
    ADD CONSTRAINT addresses_profile_application_fk FOREIGN KEY (application_id, billing_profile_id) REFERENCES public.billing_profiles(application_id, id);

ALTER TABLE ONLY public.application_domains
    ADD CONSTRAINT application_domains_application_id_fkey FOREIGN KEY (application_id) REFERENCES public.applications(id);

ALTER TABLE ONLY public.application_secrets
    ADD CONSTRAINT application_secrets_application_id_fkey FOREIGN KEY (application_id) REFERENCES public.applications(id);

ALTER TABLE ONLY public.applications
    ADD CONSTRAINT applications_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organizations(id);

ALTER TABLE ONLY public.audit_exports
    ADD CONSTRAINT audit_exports_application_id_fkey FOREIGN KEY (application_id) REFERENCES public.applications(id);

ALTER TABLE ONLY public.audit_exports
    ADD CONSTRAINT audit_exports_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organizations(id);

ALTER TABLE ONLY public.audit_exports
    ADD CONSTRAINT audit_exports_requested_by_fkey FOREIGN KEY (requested_by) REFERENCES public.control_users(id);

ALTER TABLE ONLY public.audit_records
    ADD CONSTRAINT audit_records_application_id_fkey FOREIGN KEY (application_id) REFERENCES public.applications(id);

ALTER TABLE ONLY public.audit_records
    ADD CONSTRAINT audit_records_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organizations(id);

ALTER TABLE ONLY public.auth_provider_configs
    ADD CONSTRAINT auth_provider_configs_application_id_fkey FOREIGN KEY (application_id) REFERENCES public.applications(id);

ALTER TABLE ONLY public.auth_provider_configs
    ADD CONSTRAINT auth_provider_configs_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organizations(id);

ALTER TABLE ONLY public.billing_customers
    ADD CONSTRAINT billing_customers_application_id_fkey FOREIGN KEY (application_id) REFERENCES public.applications(id);

ALTER TABLE ONLY public.billing_customers
    ADD CONSTRAINT billing_customers_provider_connection_id_fkey FOREIGN KEY (provider_connection_id) REFERENCES public.provider_connections(id);

ALTER TABLE ONLY public.billing_profiles
    ADD CONSTRAINT billing_profiles_application_id_fkey FOREIGN KEY (application_id) REFERENCES public.applications(id);

ALTER TABLE ONLY public.checkout_sessions
    ADD CONSTRAINT checkout_price_application_fk FOREIGN KEY (application_id, price_id) REFERENCES public.prices(application_id, id);

ALTER TABLE ONLY public.checkout_sessions
    ADD CONSTRAINT checkout_sessions_application_id_fkey FOREIGN KEY (application_id) REFERENCES public.applications(id);

ALTER TABLE ONLY public.checkout_sessions
    ADD CONSTRAINT checkout_sessions_price_id_fkey FOREIGN KEY (price_id) REFERENCES public.prices(id);

ALTER TABLE ONLY public.checkout_sessions
    ADD CONSTRAINT checkout_sessions_provider_connection_id_fkey FOREIGN KEY (provider_connection_id) REFERENCES public.provider_connections(id);

ALTER TABLE ONLY public.clients
    ADD CONSTRAINT clients_application_id_fkey FOREIGN KEY (application_id) REFERENCES public.applications(id);

ALTER TABLE ONLY public.delegations
    ADD CONSTRAINT delegations_application_id_fkey FOREIGN KEY (application_id) REFERENCES public.applications(id);

ALTER TABLE ONLY public.delegations
    ADD CONSTRAINT delegations_control_user_id_fkey FOREIGN KEY (control_user_id) REFERENCES public.control_users(id);

ALTER TABLE ONLY public.delegations
    ADD CONSTRAINT delegations_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);

ALTER TABLE ONLY public.delegations
    ADD CONSTRAINT delegations_workspace_fk FOREIGN KEY (workspace_id) REFERENCES public.workspaces(id);

ALTER TABLE ONLY public.disputes
    ADD CONSTRAINT dispute_payment_application_fk FOREIGN KEY (application_id, payment_id) REFERENCES public.payments(application_id, id);

ALTER TABLE ONLY public.disputes
    ADD CONSTRAINT disputes_application_id_fkey FOREIGN KEY (application_id) REFERENCES public.applications(id);

ALTER TABLE ONLY public.disputes
    ADD CONSTRAINT disputes_payment_id_fkey FOREIGN KEY (payment_id) REFERENCES public.payments(id);

ALTER TABLE ONLY public.disputes
    ADD CONSTRAINT disputes_provider_connection_id_fkey FOREIGN KEY (provider_connection_id) REFERENCES public.provider_connections(id);

ALTER TABLE ONLY public.domain_events
    ADD CONSTRAINT domain_events_application_id_fkey FOREIGN KEY (application_id) REFERENCES public.applications(id);

ALTER TABLE ONLY public.entitlement_grant_actions
    ADD CONSTRAINT entitlement_grant_actions_grant_id_fkey FOREIGN KEY (grant_id) REFERENCES public.entitlement_grants(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.entitlement_grants
    ADD CONSTRAINT entitlement_grants_application_id_fkey FOREIGN KEY (application_id) REFERENCES public.applications(id);

ALTER TABLE ONLY public.entitlement_grants
    ADD CONSTRAINT entitlement_grants_price_id_fkey FOREIGN KEY (price_id) REFERENCES public.prices(id);

ALTER TABLE ONLY public.entitlement_grants
    ADD CONSTRAINT entitlement_grants_product_id_fkey FOREIGN KEY (product_id) REFERENCES public.products(id);

ALTER TABLE ONLY public.entitlement_grants
    ADD CONSTRAINT entitlement_price_application_fk FOREIGN KEY (application_id, price_id) REFERENCES public.prices(application_id, id);

ALTER TABLE ONLY public.entitlement_grants
    ADD CONSTRAINT entitlement_product_application_fk FOREIGN KEY (application_id, product_id) REFERENCES public.products(application_id, id);

ALTER TABLE ONLY public.event_type_definitions
    ADD CONSTRAINT event_type_definitions_application_id_fkey FOREIGN KEY (application_id) REFERENCES public.applications(id);

ALTER TABLE ONLY public.external_auth_challenges
    ADD CONSTRAINT external_auth_challenges_application_id_fkey FOREIGN KEY (application_id) REFERENCES public.applications(id);

ALTER TABLE ONLY public.external_auth_challenges
    ADD CONSTRAINT external_auth_challenges_requested_by_user_id_fkey FOREIGN KEY (requested_by_user_id) REFERENCES public.users(id);

ALTER TABLE ONLY public.external_auth_exchanges
    ADD CONSTRAINT external_auth_exchanges_application_id_fkey FOREIGN KEY (application_id) REFERENCES public.applications(id);

ALTER TABLE ONLY public.external_auth_exchanges
    ADD CONSTRAINT external_auth_exchanges_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);

ALTER TABLE ONLY public.features
    ADD CONSTRAINT features_application_id_fkey FOREIGN KEY (application_id) REFERENCES public.applications(id);

ALTER TABLE ONLY public.installation_control_user_roles
    ADD CONSTRAINT installation_control_user_roles_control_user_id_fkey FOREIGN KEY (control_user_id) REFERENCES public.control_users(id);

ALTER TABLE ONLY public.invitation_authorization_codes
    ADD CONSTRAINT invitation_authorization_codes_application_id_fkey FOREIGN KEY (application_id) REFERENCES public.applications(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.invitation_authorization_codes
    ADD CONSTRAINT invitation_authorization_codes_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.invoices
    ADD CONSTRAINT invoice_customer_application_fk FOREIGN KEY (application_id, billing_customer_id) REFERENCES public.billing_customers(application_id, id);

ALTER TABLE ONLY public.invoices
    ADD CONSTRAINT invoice_subscription_application_fk FOREIGN KEY (application_id, subscription_id) REFERENCES public.subscriptions(application_id, id);

ALTER TABLE ONLY public.invoices
    ADD CONSTRAINT invoices_application_id_fkey FOREIGN KEY (application_id) REFERENCES public.applications(id);

ALTER TABLE ONLY public.invoices
    ADD CONSTRAINT invoices_billing_customer_id_fkey FOREIGN KEY (billing_customer_id) REFERENCES public.billing_customers(id);

ALTER TABLE ONLY public.invoices
    ADD CONSTRAINT invoices_provider_connection_id_fkey FOREIGN KEY (provider_connection_id) REFERENCES public.provider_connections(id);

ALTER TABLE ONLY public.invoices
    ADD CONSTRAINT invoices_subscription_id_fkey FOREIGN KEY (subscription_id) REFERENCES public.subscriptions(id);

ALTER TABLE ONLY public.local_entitlement_request_actions
    ADD CONSTRAINT local_entitlement_request_actions_request_id_fkey FOREIGN KEY (request_id) REFERENCES public.local_entitlement_requests(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.local_entitlement_requests
    ADD CONSTRAINT local_entitlement_requests_application_id_fkey FOREIGN KEY (application_id) REFERENCES public.applications(id);

ALTER TABLE ONLY public.local_entitlement_requests
    ADD CONSTRAINT local_entitlement_requests_entitlement_grant_id_fkey FOREIGN KEY (entitlement_grant_id) REFERENCES public.entitlement_grants(id);

ALTER TABLE ONLY public.local_entitlement_requests
    ADD CONSTRAINT local_entitlement_requests_price_id_fkey FOREIGN KEY (price_id) REFERENCES public.prices(id);

ALTER TABLE ONLY public.local_entitlement_requests
    ADD CONSTRAINT local_entitlement_requests_product_id_fkey FOREIGN KEY (product_id) REFERENCES public.products(id);

ALTER TABLE ONLY public.local_entitlement_requests
    ADD CONSTRAINT local_entitlement_requests_requester_user_id_fkey FOREIGN KEY (requester_user_id) REFERENCES public.users(id);

ALTER TABLE ONLY public.local_entitlement_requests
    ADD CONSTRAINT local_entitlement_requests_reviewed_by_fkey FOREIGN KEY (reviewed_by) REFERENCES public.control_users(id);

ALTER TABLE ONLY public.local_entitlement_requests
    ADD CONSTRAINT local_request_price_application_fk FOREIGN KEY (application_id, price_id) REFERENCES public.prices(application_id, id);

ALTER TABLE ONLY public.local_entitlement_requests
    ADD CONSTRAINT local_request_product_application_fk FOREIGN KEY (application_id, product_id) REFERENCES public.products(application_id, id);

ALTER TABLE ONLY public.local_entitlement_requests
    ADD CONSTRAINT local_request_user_application_fk FOREIGN KEY (application_id, requester_user_id) REFERENCES public.users(application_id, id);

ALTER TABLE ONLY public.login_challenges
    ADD CONSTRAINT login_challenges_application_id_fkey FOREIGN KEY (application_id) REFERENCES public.applications(id);

ALTER TABLE ONLY public.login_challenges
    ADD CONSTRAINT login_challenges_requested_by_user_id_fkey FOREIGN KEY (requested_by_user_id) REFERENCES public.users(id);

ALTER TABLE ONLY public.mfa_login_challenges
    ADD CONSTRAINT mfa_login_challenges_application_id_fkey FOREIGN KEY (application_id) REFERENCES public.applications(id);

ALTER TABLE ONLY public.mfa_login_challenges
    ADD CONSTRAINT mfa_login_challenges_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);

ALTER TABLE ONLY public.notification_attachments
    ADD CONSTRAINT notification_attachments_notification_id_fkey FOREIGN KEY (notification_id) REFERENCES public.notifications(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.notification_attempts
    ADD CONSTRAINT notification_attempts_notification_id_fkey FOREIGN KEY (notification_id) REFERENCES public.notifications(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.notification_attempts
    ADD CONSTRAINT notification_attempts_notification_provider_id_fkey FOREIGN KEY (notification_provider_id) REFERENCES public.notification_providers(id);

ALTER TABLE ONLY public.notification_preferences
    ADD CONSTRAINT notification_preferences_application_id_fkey FOREIGN KEY (application_id) REFERENCES public.applications(id);

ALTER TABLE ONLY public.notification_preferences
    ADD CONSTRAINT notification_preferences_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);

ALTER TABLE ONLY public.notification_providers
    ADD CONSTRAINT notification_providers_application_id_fkey FOREIGN KEY (application_id) REFERENCES public.applications(id);

ALTER TABLE ONLY public.notification_providers
    ADD CONSTRAINT notification_providers_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organizations(id);

ALTER TABLE ONLY public.notification_template_assets
    ADD CONSTRAINT notification_template_assets_notification_template_id_fkey FOREIGN KEY (notification_template_id) REFERENCES public.notification_templates(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.notification_template_assets
    ADD CONSTRAINT notification_template_assets_storage_object_id_fkey FOREIGN KEY (storage_object_id) REFERENCES public.storage_objects(id);

ALTER TABLE ONLY public.notification_templates
    ADD CONSTRAINT notification_templates_application_id_fkey FOREIGN KEY (application_id) REFERENCES public.applications(id);

ALTER TABLE ONLY public.notifications
    ADD CONSTRAINT notifications_application_id_fkey FOREIGN KEY (application_id) REFERENCES public.applications(id);

ALTER TABLE ONLY public.notifications
    ADD CONSTRAINT notifications_notification_provider_id_fkey FOREIGN KEY (notification_provider_id) REFERENCES public.notification_providers(id);

ALTER TABLE ONLY public.notifications
    ADD CONSTRAINT notifications_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organizations(id);

ALTER TABLE ONLY public.notifications
    ADD CONSTRAINT notifications_template_id_fkey FOREIGN KEY (template_id) REFERENCES public.notification_templates(id);

ALTER TABLE ONLY public.notifications
    ADD CONSTRAINT notifications_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);

ALTER TABLE ONLY public.oauth_client_assertion_jtis
    ADD CONSTRAINT oauth_client_assertion_jtis_application_id_fkey FOREIGN KEY (application_id) REFERENCES public.applications(id);

ALTER TABLE ONLY public.oauth_consents
    ADD CONSTRAINT oauth_consents_application_id_fkey FOREIGN KEY (application_id) REFERENCES public.applications(id);

ALTER TABLE ONLY public.oauth_consents
    ADD CONSTRAINT oauth_consents_client_id_fkey FOREIGN KEY (client_id) REFERENCES public.clients(id);

ALTER TABLE ONLY public.oauth_consents
    ADD CONSTRAINT oauth_consents_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);

ALTER TABLE ONLY public.oauth_sessions
    ADD CONSTRAINT oauth_sessions_application_id_fkey FOREIGN KEY (application_id) REFERENCES public.applications(id);

ALTER TABLE ONLY public.control_user_sessions
    ADD CONSTRAINT control_user_sessions_control_user_id_fkey FOREIGN KEY (control_user_id) REFERENCES public.control_users(id);

ALTER TABLE ONLY public.control_user_identities
    ADD CONSTRAINT control_user_identities_control_user_id_fkey FOREIGN KEY (control_user_id) REFERENCES public.control_users(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.control_user_identities
    ADD CONSTRAINT control_user_identities_auth_provider_config_id_fkey FOREIGN KEY (auth_provider_config_id) REFERENCES public.auth_provider_configs(id);

ALTER TABLE ONLY public.control_user_external_auth_challenges
    ADD CONSTRAINT control_user_external_auth_challenges_provider_id_fkey FOREIGN KEY (auth_provider_config_id) REFERENCES public.auth_provider_configs(id);

ALTER TABLE ONLY public.control_user_external_auth_challenges
    ADD CONSTRAINT control_user_external_auth_challenges_control_user_id_fkey FOREIGN KEY (requested_by_control_user_id) REFERENCES public.control_users(id);

ALTER TABLE ONLY public.control_user_external_auth_challenges
    ADD CONSTRAINT control_user_external_auth_challenges_invitation_id_fkey FOREIGN KEY (invitation_id) REFERENCES public.control_user_invitations(id);

ALTER TABLE ONLY public.control_user_invitations
    ADD CONSTRAINT control_user_invitations_accepted_by_fkey FOREIGN KEY (accepted_by) REFERENCES public.control_users(id);

ALTER TABLE ONLY public.control_user_invitations
    ADD CONSTRAINT control_user_invitations_invited_by_fkey FOREIGN KEY (invited_by) REFERENCES public.control_users(id);

ALTER TABLE ONLY public.control_user_invitations
    ADD CONSTRAINT control_user_invitations_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organizations(id);

ALTER TABLE ONLY public.organization_memberships
    ADD CONSTRAINT organization_memberships_control_user_id_fkey FOREIGN KEY (control_user_id) REFERENCES public.control_users(id);

ALTER TABLE ONLY public.organization_memberships
    ADD CONSTRAINT organization_memberships_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organizations(id);

ALTER TABLE ONLY public.organization_policies
    ADD CONSTRAINT organization_policies_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.outbox
    ADD CONSTRAINT outbox_event_id_fkey FOREIGN KEY (event_id) REFERENCES public.domain_events(id);

ALTER TABLE ONLY public.payments
    ADD CONSTRAINT payment_checkout_application_fk FOREIGN KEY (application_id, checkout_session_id) REFERENCES public.checkout_sessions(application_id, id);

ALTER TABLE ONLY public.payments
    ADD CONSTRAINT payment_customer_application_fk FOREIGN KEY (application_id, billing_customer_id) REFERENCES public.billing_customers(application_id, id);

ALTER TABLE ONLY public.payments
    ADD CONSTRAINT payment_invoice_application_fk FOREIGN KEY (application_id, invoice_id) REFERENCES public.invoices(application_id, id);

ALTER TABLE ONLY public.payments
    ADD CONSTRAINT payments_application_id_fkey FOREIGN KEY (application_id) REFERENCES public.applications(id);

ALTER TABLE ONLY public.payments
    ADD CONSTRAINT payments_billing_customer_id_fkey FOREIGN KEY (billing_customer_id) REFERENCES public.billing_customers(id);

ALTER TABLE ONLY public.payments
    ADD CONSTRAINT payments_checkout_session_id_fkey FOREIGN KEY (checkout_session_id) REFERENCES public.checkout_sessions(id);

ALTER TABLE ONLY public.payments
    ADD CONSTRAINT payments_invoice_id_fkey FOREIGN KEY (invoice_id) REFERENCES public.invoices(id);

ALTER TABLE ONLY public.payments
    ADD CONSTRAINT payments_provider_connection_id_fkey FOREIGN KEY (provider_connection_id) REFERENCES public.provider_connections(id);

ALTER TABLE ONLY public.personal_api_keys
    ADD CONSTRAINT personal_api_keys_application_id_fkey FOREIGN KEY (application_id) REFERENCES public.applications(id);

ALTER TABLE ONLY public.personal_api_keys
    ADD CONSTRAINT personal_api_keys_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);

ALTER TABLE ONLY public.permission_grants
    ADD CONSTRAINT permission_grants_application_id_fkey FOREIGN KEY (application_id) REFERENCES public.applications(id);

ALTER TABLE ONLY public.permission_grants
    ADD CONSTRAINT permission_grants_client_application_fk FOREIGN KEY (application_id, client_id) REFERENCES public.clients(application_id, id);

ALTER TABLE ONLY public.permission_grants
    ADD CONSTRAINT permission_grants_user_application_fk FOREIGN KEY (application_id, user_id) REFERENCES public.users(application_id, id);

ALTER TABLE ONLY public.permission_grants
    ADD CONSTRAINT permission_grants_workspace_application_fk FOREIGN KEY (application_id, workspace_id) REFERENCES public.workspaces(application_id, id);

ALTER TABLE ONLY public.price_features
    ADD CONSTRAINT price_features_feature_id_fkey FOREIGN KEY (feature_id) REFERENCES public.features(id);

ALTER TABLE ONLY public.price_features
    ADD CONSTRAINT price_features_price_id_fkey FOREIGN KEY (price_id) REFERENCES public.prices(id);

ALTER TABLE ONLY public.prices
    ADD CONSTRAINT prices_application_id_fkey FOREIGN KEY (application_id) REFERENCES public.applications(id);

ALTER TABLE ONLY public.prices
    ADD CONSTRAINT prices_product_application_fk FOREIGN KEY (application_id, product_id) REFERENCES public.products(application_id, id);

ALTER TABLE ONLY public.prices
    ADD CONSTRAINT prices_product_id_fkey FOREIGN KEY (product_id) REFERENCES public.products(id);

ALTER TABLE ONLY public.product_features
    ADD CONSTRAINT product_features_feature_id_fkey FOREIGN KEY (feature_id) REFERENCES public.features(id);

ALTER TABLE ONLY public.product_features
    ADD CONSTRAINT product_features_product_id_fkey FOREIGN KEY (product_id) REFERENCES public.products(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.products
    ADD CONSTRAINT products_application_id_fkey FOREIGN KEY (application_id) REFERENCES public.applications(id);

ALTER TABLE ONLY public.provider_connections
    ADD CONSTRAINT provider_connections_application_id_fkey FOREIGN KEY (application_id) REFERENCES public.applications(id);

ALTER TABLE ONLY public.provider_connections
    ADD CONSTRAINT provider_connections_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organizations(id);

ALTER TABLE ONLY public.provider_events
    ADD CONSTRAINT provider_events_application_id_fkey FOREIGN KEY (application_id) REFERENCES public.applications(id);

ALTER TABLE ONLY public.provider_events
    ADD CONSTRAINT provider_events_provider_connection_id_fkey FOREIGN KEY (provider_connection_id) REFERENCES public.provider_connections(id);

ALTER TABLE ONLY public.provider_mappings
    ADD CONSTRAINT provider_mappings_application_id_fkey FOREIGN KEY (application_id) REFERENCES public.applications(id);

ALTER TABLE ONLY public.provider_mappings
    ADD CONSTRAINT provider_mappings_provider_connection_id_fkey FOREIGN KEY (provider_connection_id) REFERENCES public.provider_connections(id);

ALTER TABLE ONLY public.reconciliation_runs
    ADD CONSTRAINT reconciliation_runs_application_id_fkey FOREIGN KEY (application_id) REFERENCES public.applications(id);

ALTER TABLE ONLY public.reconciliation_runs
    ADD CONSTRAINT reconciliation_runs_provider_connection_id_fkey FOREIGN KEY (provider_connection_id) REFERENCES public.provider_connections(id);

ALTER TABLE ONLY public.refunds
    ADD CONSTRAINT refund_payment_application_fk FOREIGN KEY (application_id, payment_id) REFERENCES public.payments(application_id, id);

ALTER TABLE ONLY public.refunds
    ADD CONSTRAINT refunds_application_id_fkey FOREIGN KEY (application_id) REFERENCES public.applications(id);

ALTER TABLE ONLY public.refunds
    ADD CONSTRAINT refunds_payment_id_fkey FOREIGN KEY (payment_id) REFERENCES public.payments(id);

ALTER TABLE ONLY public.refunds
    ADD CONSTRAINT refunds_provider_connection_id_fkey FOREIGN KEY (provider_connection_id) REFERENCES public.provider_connections(id);

ALTER TABLE ONLY public.role_assignments
    ADD CONSTRAINT role_assignments_application_id_fkey FOREIGN KEY (application_id) REFERENCES public.applications(id);

ALTER TABLE ONLY public.role_assignments
    ADD CONSTRAINT role_assignments_client_application_fk FOREIGN KEY (application_id, client_id) REFERENCES public.clients(application_id, id);

ALTER TABLE ONLY public.role_assignments
    ADD CONSTRAINT role_assignments_client_id_fkey FOREIGN KEY (client_id) REFERENCES public.clients(id);

ALTER TABLE ONLY public.role_assignments
    ADD CONSTRAINT role_assignments_role_application_fk FOREIGN KEY (application_id, role_id) REFERENCES public.roles(application_id, id);

ALTER TABLE ONLY public.role_assignments
    ADD CONSTRAINT role_assignments_role_id_fkey FOREIGN KEY (role_id) REFERENCES public.roles(id);

ALTER TABLE ONLY public.role_assignments
    ADD CONSTRAINT role_assignments_user_application_fk FOREIGN KEY (application_id, user_id) REFERENCES public.users(application_id, id);

ALTER TABLE ONLY public.role_assignments
    ADD CONSTRAINT role_assignments_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);

ALTER TABLE ONLY public.role_assignments
    ADD CONSTRAINT role_assignments_workspace_application_fk FOREIGN KEY (application_id, workspace_id) REFERENCES public.workspaces(application_id, id);

ALTER TABLE ONLY public.role_assignments
    ADD CONSTRAINT role_assignments_workspace_id_fkey FOREIGN KEY (workspace_id) REFERENCES public.workspaces(id);

ALTER TABLE ONLY public.roles
    ADD CONSTRAINT roles_application_id_fkey FOREIGN KEY (application_id) REFERENCES public.applications(id);

ALTER TABLE ONLY public.sender_identities
    ADD CONSTRAINT sender_identities_application_id_fkey FOREIGN KEY (application_id) REFERENCES public.applications(id);

ALTER TABLE ONLY public.sender_identities
    ADD CONSTRAINT sender_identities_notification_provider_id_fkey FOREIGN KEY (notification_provider_id) REFERENCES public.notification_providers(id);

ALTER TABLE ONLY public.sender_identities
    ADD CONSTRAINT sender_identities_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organizations(id);

ALTER TABLE ONLY public.storage_objects
    ADD CONSTRAINT storage_objects_application_id_fkey FOREIGN KEY (application_id) REFERENCES public.applications(id);

ALTER TABLE ONLY public.storage_objects
    ADD CONSTRAINT storage_objects_storage_provider_id_fkey FOREIGN KEY (storage_provider_id) REFERENCES public.storage_providers(id);

ALTER TABLE ONLY public.storage_providers
    ADD CONSTRAINT storage_providers_application_id_fkey FOREIGN KEY (application_id) REFERENCES public.applications(id);

ALTER TABLE ONLY public.storage_providers
    ADD CONSTRAINT storage_providers_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organizations(id);

ALTER TABLE ONLY public.subscriptions
    ADD CONSTRAINT subscription_price_application_fk FOREIGN KEY (application_id, price_id) REFERENCES public.prices(application_id, id);

ALTER TABLE ONLY public.subscriptions
    ADD CONSTRAINT subscriptions_application_id_fkey FOREIGN KEY (application_id) REFERENCES public.applications(id);

ALTER TABLE ONLY public.subscriptions
    ADD CONSTRAINT subscriptions_price_id_fkey FOREIGN KEY (price_id) REFERENCES public.prices(id);

ALTER TABLE ONLY public.subscriptions
    ADD CONSTRAINT subscriptions_provider_connection_id_fkey FOREIGN KEY (provider_connection_id) REFERENCES public.provider_connections(id);

ALTER TABLE ONLY public.user_authentication_methods
    ADD CONSTRAINT user_authentication_methods_application_id_fkey FOREIGN KEY (application_id) REFERENCES public.applications(id);

ALTER TABLE ONLY public.user_authentication_methods
    ADD CONSTRAINT user_authentication_methods_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);

ALTER TABLE ONLY public.user_identities
    ADD CONSTRAINT user_identities_application_id_fkey FOREIGN KEY (application_id) REFERENCES public.applications(id);

ALTER TABLE ONLY public.user_identities
    ADD CONSTRAINT user_identities_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);

ALTER TABLE ONLY public.user_recovery_codes
    ADD CONSTRAINT user_recovery_codes_application_id_fkey FOREIGN KEY (application_id) REFERENCES public.applications(id);

ALTER TABLE ONLY public.user_recovery_codes
    ADD CONSTRAINT user_recovery_codes_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);

ALTER TABLE ONLY public.user_sessions
    ADD CONSTRAINT user_sessions_application_id_fkey FOREIGN KEY (application_id) REFERENCES public.applications(id);

ALTER TABLE ONLY public.user_sessions
    ADD CONSTRAINT user_sessions_delegation_id_fkey FOREIGN KEY (delegation_id) REFERENCES public.delegations(id);

ALTER TABLE ONLY public.user_sessions
    ADD CONSTRAINT user_sessions_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_application_id_fkey FOREIGN KEY (application_id) REFERENCES public.applications(id);

ALTER TABLE ONLY public.webauthn_ceremonies
    ADD CONSTRAINT webauthn_ceremonies_application_id_fkey FOREIGN KEY (application_id) REFERENCES public.applications(id);

ALTER TABLE ONLY public.webauthn_ceremonies
    ADD CONSTRAINT webauthn_ceremonies_mfa_challenge_id_fkey FOREIGN KEY (mfa_challenge_id) REFERENCES public.mfa_login_challenges(id);

ALTER TABLE ONLY public.webauthn_ceremonies
    ADD CONSTRAINT webauthn_ceremonies_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);

ALTER TABLE ONLY public.webauthn_ceremonies
    ADD CONSTRAINT webauthn_ceremonies_user_session_id_fkey FOREIGN KEY (user_session_id) REFERENCES public.user_sessions(id);

ALTER TABLE ONLY public.webhook_deliveries
    ADD CONSTRAINT webhook_deliveries_application_id_fkey FOREIGN KEY (application_id) REFERENCES public.applications(id);

ALTER TABLE ONLY public.webhook_deliveries
    ADD CONSTRAINT webhook_deliveries_event_id_fkey FOREIGN KEY (event_id) REFERENCES public.domain_events(id);

ALTER TABLE ONLY public.webhook_deliveries
    ADD CONSTRAINT webhook_deliveries_webhook_endpoint_id_fkey FOREIGN KEY (webhook_endpoint_id) REFERENCES public.webhook_endpoints(id);

ALTER TABLE ONLY public.webhook_endpoints
    ADD CONSTRAINT webhook_endpoints_application_id_fkey FOREIGN KEY (application_id) REFERENCES public.applications(id);

ALTER TABLE ONLY public.application_invitations
    ADD CONSTRAINT application_invitations_application_id_fkey FOREIGN KEY (application_id) REFERENCES public.applications(id);

ALTER TABLE ONLY public.application_invitations
    ADD CONSTRAINT application_invitations_workspace_id_fkey FOREIGN KEY (workspace_id) REFERENCES public.workspaces(id);

ALTER TABLE ONLY public.workspace_memberships
    ADD CONSTRAINT workspace_memberships_application_id_user_id_fkey FOREIGN KEY (application_id, user_id) REFERENCES public.users(application_id, id);

ALTER TABLE ONLY public.workspace_memberships
    ADD CONSTRAINT workspace_memberships_application_id_workspace_id_fkey FOREIGN KEY (application_id, workspace_id) REFERENCES public.workspaces(application_id, id);

ALTER TABLE ONLY public.workspaces
    ADD CONSTRAINT workspaces_application_id_fkey FOREIGN KEY (application_id) REFERENCES public.applications(id);

ALTER TABLE ONLY public.workspaces
    ADD CONSTRAINT workspaces_application_id_owner_user_id_fkey FOREIGN KEY (application_id, owner_user_id) REFERENCES public.users(application_id, id);

INSERT INTO public.event_type_definitions
(id,application_id,name,description,schema_version,source,status,example_subject,data_schema,example_data,version) VALUES
    (gen_random_uuid(),NULL,'application.created','An application was created.','1.0','platform93','active','application/01900000-0000-7000-8000-000000000002','{"type": "object", "required": ["name", "slug"], "properties": {"name": {"type": "string"}, "slug": {"type": "string"}}, "additionalProperties": false}'::jsonb,'{"name": "Production", "slug": "production"}'::jsonb,1),
    (gen_random_uuid(),NULL,'application.restored','An application was restored.','1.0','platform93','active','application/01900000-0000-7000-8000-000000000002','{"type": "object", "required": ["organization_id", "reason"], "properties": {"reason": {"type": "string"}, "organization_id": {"type": "string", "format": "uuid"}}, "additionalProperties": false}'::jsonb,'{"reason": "application_restored", "organization_id": "01900000-0000-7000-8000-000000000001"}'::jsonb,1),
    (gen_random_uuid(),NULL,'application.retired','An application was retired.','1.0','platform93','active','application/01900000-0000-7000-8000-000000000002','{"type": "object", "required": ["organization_id", "reason"], "properties": {"reason": {"type": "string"}, "organization_id": {"type": "string", "format": "uuid"}}, "additionalProperties": false}'::jsonb,'{"reason": "application_retired", "organization_id": "01900000-0000-7000-8000-000000000001"}'::jsonb,1),
    (gen_random_uuid(),NULL,'application_invitation.accepted','An application invitation was accepted.','1.0','platform93','active','application_invitation/example','{"type": "object", "required": ["invitation_id", "status"], "properties": {"status": {"enum": ["pending", "accepted", "revoked", "expired"]}, "user_id": {"type": "string", "format": "uuid"}, "expires_at": {"type": "string", "format": "date-time"}, "workspace_id": {"type": ["string", "null"], "format": "uuid"}, "invitation_id": {"type": "string", "format": "uuid"}, "workspace_role_keys": {"type": "array", "items": {"type": "string"}}, "application_role_keys": {"type": "array", "items": {"type": "string"}}}, "additionalProperties": false}'::jsonb,'{"status": "accepted", "invitation_id": "01900000-0000-7000-8000-000000000030"}'::jsonb,1),
    (gen_random_uuid(),NULL,'application_invitation.created','An application invitation was created.','1.0','platform93','active','application_invitation/example','{"type": "object", "required": ["invitation_id", "status"], "properties": {"status": {"enum": ["pending", "accepted", "revoked", "expired"]}, "user_id": {"type": "string", "format": "uuid"}, "expires_at": {"type": "string", "format": "date-time"}, "workspace_id": {"type": ["string", "null"], "format": "uuid"}, "invitation_id": {"type": "string", "format": "uuid"}, "workspace_role_keys": {"type": "array", "items": {"type": "string"}}, "application_role_keys": {"type": "array", "items": {"type": "string"}}}, "additionalProperties": false}'::jsonb,'{"status": "pending", "invitation_id": "01900000-0000-7000-8000-000000000030"}'::jsonb,1),
    (gen_random_uuid(),NULL,'application_invitation.expired','An application invitation expired.','1.0','platform93','active','application_invitation/example','{"type": "object", "required": ["invitation_id", "status"], "properties": {"status": {"enum": ["pending", "accepted", "revoked", "expired"]}, "user_id": {"type": "string", "format": "uuid"}, "expires_at": {"type": "string", "format": "date-time"}, "workspace_id": {"type": ["string", "null"], "format": "uuid"}, "invitation_id": {"type": "string", "format": "uuid"}, "workspace_role_keys": {"type": "array", "items": {"type": "string"}}, "application_role_keys": {"type": "array", "items": {"type": "string"}}}, "additionalProperties": false}'::jsonb,'{"status": "expired", "invitation_id": "01900000-0000-7000-8000-000000000030"}'::jsonb,1),
    (gen_random_uuid(),NULL,'application_invitation.resent','An application invitation was resent.','1.0','platform93','active','application_invitation/example','{"type": "object", "required": ["invitation_id", "status"], "properties": {"status": {"enum": ["pending", "accepted", "revoked", "expired"]}, "user_id": {"type": "string", "format": "uuid"}, "expires_at": {"type": "string", "format": "date-time"}, "workspace_id": {"type": ["string", "null"], "format": "uuid"}, "invitation_id": {"type": "string", "format": "uuid"}, "workspace_role_keys": {"type": "array", "items": {"type": "string"}}, "application_role_keys": {"type": "array", "items": {"type": "string"}}}, "additionalProperties": false}'::jsonb,'{"status": "pending", "invitation_id": "01900000-0000-7000-8000-000000000030"}'::jsonb,1),
    (gen_random_uuid(),NULL,'application_invitation.revoked','An application invitation was revoked.','1.0','platform93','active','application_invitation/example','{"type": "object", "required": ["invitation_id", "status"], "properties": {"status": {"enum": ["pending", "accepted", "revoked", "expired"]}, "user_id": {"type": "string", "format": "uuid"}, "expires_at": {"type": "string", "format": "date-time"}, "workspace_id": {"type": ["string", "null"], "format": "uuid"}, "invitation_id": {"type": "string", "format": "uuid"}, "workspace_role_keys": {"type": "array", "items": {"type": "string"}}, "application_role_keys": {"type": "array", "items": {"type": "string"}}}, "additionalProperties": false}'::jsonb,'{"status": "revoked", "invitation_id": "01900000-0000-7000-8000-000000000030"}'::jsonb,1),
    (gen_random_uuid(),NULL,'billing.dispute.updated','A dispute changed.','1.0','platform93','active','dispute/example','{"type": "object", "required": ["status", "external_reference"], "properties": {"status": {"type": "string", "minLength": 1}, "refund_id": {"type": "string", "format": "uuid"}, "dispute_id": {"type": "string", "format": "uuid"}, "invoice_id": {"type": "string", "format": "uuid"}, "payment_id": {"type": "string", "format": "uuid"}, "subject_id": {"type": "string", "format": "uuid"}, "subject_type": {"enum": ["user", "workspace"]}, "subscription_id": {"type": "string", "format": "uuid"}, "external_reference": {"type": ["string", "null"], "maxLength": 255, "minLength": 1}}, "additionalProperties": false}'::jsonb,'{"status": "active", "dispute_id": "01900000-0000-7000-8000-000000000035", "external_reference": null}'::jsonb,1),
    (gen_random_uuid(),NULL,'billing.invoice.updated','An invoice changed.','1.0','platform93','active','invoice/example','{"type": "object", "required": ["status", "external_reference"], "properties": {"status": {"type": "string", "minLength": 1}, "refund_id": {"type": "string", "format": "uuid"}, "dispute_id": {"type": "string", "format": "uuid"}, "invoice_id": {"type": "string", "format": "uuid"}, "payment_id": {"type": "string", "format": "uuid"}, "subject_id": {"type": "string", "format": "uuid"}, "subject_type": {"enum": ["user", "workspace"]}, "subscription_id": {"type": "string", "format": "uuid"}, "external_reference": {"type": ["string", "null"], "maxLength": 255, "minLength": 1}}, "additionalProperties": false}'::jsonb,'{"status": "active", "invoice_id": "01900000-0000-7000-8000-000000000032", "external_reference": null}'::jsonb,1),
    (gen_random_uuid(),NULL,'billing.payment.updated','A payment changed.','1.0','platform93','active','payment/example','{"type": "object", "required": ["status", "external_reference"], "properties": {"status": {"type": "string", "minLength": 1}, "refund_id": {"type": "string", "format": "uuid"}, "dispute_id": {"type": "string", "format": "uuid"}, "invoice_id": {"type": "string", "format": "uuid"}, "payment_id": {"type": "string", "format": "uuid"}, "subject_id": {"type": "string", "format": "uuid"}, "subject_type": {"enum": ["user", "workspace"]}, "subscription_id": {"type": "string", "format": "uuid"}, "external_reference": {"type": ["string", "null"], "maxLength": 255, "minLength": 1}}, "additionalProperties": false}'::jsonb,'{"status": "active", "payment_id": "01900000-0000-7000-8000-000000000033", "external_reference": null}'::jsonb,1),
    (gen_random_uuid(),NULL,'billing.refund.updated','A refund changed.','1.0','platform93','active','refund/example','{"type": "object", "required": ["status", "external_reference"], "properties": {"status": {"type": "string", "minLength": 1}, "refund_id": {"type": "string", "format": "uuid"}, "dispute_id": {"type": "string", "format": "uuid"}, "invoice_id": {"type": "string", "format": "uuid"}, "payment_id": {"type": "string", "format": "uuid"}, "subject_id": {"type": "string", "format": "uuid"}, "subject_type": {"enum": ["user", "workspace"]}, "subscription_id": {"type": "string", "format": "uuid"}, "external_reference": {"type": ["string", "null"], "maxLength": 255, "minLength": 1}}, "additionalProperties": false}'::jsonb,'{"status": "active", "refund_id": "01900000-0000-7000-8000-000000000034", "external_reference": null}'::jsonb,1),
    (gen_random_uuid(),NULL,'billing.subscription.updated','A subscription changed.','1.0','platform93','active','subscription/example','{"type": "object", "required": ["status", "external_reference"], "properties": {"status": {"type": "string", "minLength": 1}, "refund_id": {"type": "string", "format": "uuid"}, "dispute_id": {"type": "string", "format": "uuid"}, "invoice_id": {"type": "string", "format": "uuid"}, "payment_id": {"type": "string", "format": "uuid"}, "subject_id": {"type": "string", "format": "uuid"}, "subject_type": {"enum": ["user", "workspace"]}, "subscription_id": {"type": "string", "format": "uuid"}, "external_reference": {"type": ["string", "null"], "maxLength": 255, "minLength": 1}}, "additionalProperties": false}'::jsonb,'{"status": "active", "subscription_id": "01900000-0000-7000-8000-000000000031", "external_reference": null}'::jsonb,1),
    (gen_random_uuid(),NULL,'authorization.permission_grant.created','A direct permission grant was created.','1.0','platform93','active','permission_grant/01900000-0000-7000-8000-000000000040','{"type":"object","required":["grant_id","subject_type","subject_id","workspace_id","permission","canonical_scope"],"properties":{"grant_id":{"type":"string","format":"uuid"},"subject_type":{"enum":["user","client"]},"subject_id":{"type":"string","format":"uuid"},"workspace_id":{"type":["string","null"],"format":"uuid"},"permission":{"type":"string","minLength":1,"maxLength":160},"canonical_scope":{"type":"string","minLength":1}},"additionalProperties":false}'::jsonb,'{"grant_id":"01900000-0000-7000-8000-000000000040","subject_type":"user","subject_id":"01900000-0000-7000-8000-000000000004","workspace_id":null,"permission":"invoices:read","canonical_scope":"/applications/01900000-0000-7000-8000-000000000002/invoices/read"}'::jsonb,1),
    (gen_random_uuid(),NULL,'authorization.permission_grant.revoked','A direct permission grant was revoked.','1.0','platform93','active','permission_grant/01900000-0000-7000-8000-000000000040','{"type":"object","required":["grant_id","subject_type","subject_id","workspace_id","permission","canonical_scope"],"properties":{"grant_id":{"type":"string","format":"uuid"},"subject_type":{"enum":["user","client"]},"subject_id":{"type":"string","format":"uuid"},"workspace_id":{"type":["string","null"],"format":"uuid"},"permission":{"type":"string","minLength":1,"maxLength":160},"canonical_scope":{"type":"string","minLength":1}},"additionalProperties":false}'::jsonb,'{"grant_id":"01900000-0000-7000-8000-000000000040","subject_type":"user","subject_id":"01900000-0000-7000-8000-000000000004","workspace_id":null,"permission":"invoices:read","canonical_scope":"/applications/01900000-0000-7000-8000-000000000002/invoices/read"}'::jsonb,1),
    (gen_random_uuid(),NULL,'delegation.created','Platform user delegation was created.','1.0','platform93','active','delegation/01900000-0000-7000-8000-000000000003','{"type": "object", "required": ["delegation_id", "user_id", "workspace_id", "permissions", "reason", "expires_at"], "properties": {"reason": {"type": "string"}, "user_id": {"type": "string", "format": "uuid"}, "expires_at": {"type": "string", "format": "date-time"}, "permissions": {"type": "array", "items": {"type": "string"}}, "workspace_id": {"type": ["string", "null"], "format": "uuid"}, "delegation_id": {"type": "string", "format": "uuid"}}, "additionalProperties": false}'::jsonb,'{"reason": "Investigate support request", "user_id": "01900000-0000-7000-8000-000000000004", "expires_at": "2026-01-01T00:15:00Z", "permissions": ["/applications/01900000-0000-7000-8000-000000000002/users/read"], "workspace_id": null, "delegation_id": "01900000-0000-7000-8000-000000000003"}'::jsonb,1),
    (gen_random_uuid(),NULL,'delegation.exchanged','Platform user delegation was exchanged.','1.0','platform93','active','delegation/01900000-0000-7000-8000-000000000003','{"type": "object", "required": ["delegation_id", "user_id"], "properties": {"user_id": {"type": "string", "format": "uuid"}, "delegation_id": {"type": "string", "format": "uuid"}}, "additionalProperties": false}'::jsonb,'{"user_id": "01900000-0000-7000-8000-000000000004", "delegation_id": "01900000-0000-7000-8000-000000000003"}'::jsonb,1),
    (gen_random_uuid(),NULL,'delegation.revoked','Platform user delegation was revoked.','1.0','platform93','active','delegation/01900000-0000-7000-8000-000000000003','{"type": "object", "required": ["delegation_id"], "properties": {"delegation_id": {"type": "string", "format": "uuid"}}, "additionalProperties": false}'::jsonb,'{"delegation_id": "01900000-0000-7000-8000-000000000003"}'::jsonb,1),
    (gen_random_uuid(),NULL,'entitlement.adjusted','An entitlement was adjusted.','1.0','platform93','active','entitlement/example','{"type": "object", "required": ["grant_id"], "properties": {"reason": {"type": "string"}, "status": {"enum": ["active", "revoked", "expired"]}, "grant_id": {"type": "string", "format": "uuid"}, "expires_at": {"type": ["string", "null"], "format": "date-time"}, "subject_id": {"type": "string", "format": "uuid"}, "subject_type": {"enum": ["user", "workspace"]}, "external_reference": {"type": ["string", "null"], "maxLength": 255, "minLength": 1}}, "additionalProperties": false}'::jsonb,'{"status": "active", "grant_id": "01900000-0000-7000-8000-000000000005", "external_reference": null}'::jsonb,1),
    (gen_random_uuid(),NULL,'entitlement.effective_changed','Effective entitlement values changed.','1.0','platform93','active','entitlement/example','{"type": "object", "required": ["grant_id"], "properties": {"reason": {"type": "string"}, "status": {"enum": ["active", "revoked", "expired"]}, "grant_id": {"type": "string", "format": "uuid"}, "expires_at": {"type": ["string", "null"], "format": "date-time"}, "subject_id": {"type": "string", "format": "uuid"}, "subject_type": {"enum": ["user", "workspace"]}, "external_reference": {"type": ["string", "null"], "maxLength": 255, "minLength": 1}}, "additionalProperties": false}'::jsonb,'{"status": "active", "grant_id": "01900000-0000-7000-8000-000000000005", "subject_id": "01900000-0000-7000-8000-000000000004", "subject_type": "user", "external_reference": null}'::jsonb,1),
    (gen_random_uuid(),NULL,'entitlement.expired','An entitlement expired.','1.0','platform93','active','entitlement/example','{"type": "object", "required": ["grant_id"], "properties": {"reason": {"type": "string"}, "status": {"enum": ["active", "revoked", "expired"]}, "grant_id": {"type": "string", "format": "uuid"}, "expires_at": {"type": ["string", "null"], "format": "date-time"}, "subject_id": {"type": "string", "format": "uuid"}, "subject_type": {"enum": ["user", "workspace"]}, "external_reference": {"type": ["string", "null"], "maxLength": 255, "minLength": 1}}, "additionalProperties": false}'::jsonb,'{"status": "expired", "grant_id": "01900000-0000-7000-8000-000000000005", "external_reference": null}'::jsonb,1),
    (gen_random_uuid(),NULL,'entitlement.granted','An entitlement grant was created.','1.0','platform93','active','entitlement/01900000-0000-7000-8000-000000000005','{"type": "object", "required": ["grant_id", "subject_type", "subject_id", "reason", "status", "external_reference"], "properties": {"reason": {"type": "string"}, "status": {"enum": ["active", "revoked", "expired"]}, "grant_id": {"type": "string", "format": "uuid"}, "subject_id": {"type": "string", "format": "uuid"}, "subject_type": {"enum": ["user", "workspace"]}, "external_reference": {"type": ["string", "null"], "maxLength": 255, "minLength": 1}}, "additionalProperties": false}'::jsonb,'{"reason": "subscription", "status": "active", "grant_id": "01900000-0000-7000-8000-000000000005", "subject_id": "01900000-0000-7000-8000-000000000006", "subject_type": "workspace", "external_reference": null}'::jsonb,1),
    (gen_random_uuid(),NULL,'entitlement.restored','An entitlement was restored.','1.0','platform93','active','entitlement/example','{"type": "object", "required": ["grant_id"], "properties": {"reason": {"type": "string"}, "status": {"enum": ["active", "revoked", "expired"]}, "grant_id": {"type": "string", "format": "uuid"}, "expires_at": {"type": ["string", "null"], "format": "date-time"}, "subject_id": {"type": "string", "format": "uuid"}, "subject_type": {"enum": ["user", "workspace"]}, "external_reference": {"type": ["string", "null"], "maxLength": 255, "minLength": 1}}, "additionalProperties": false}'::jsonb,'{"status": "active", "grant_id": "01900000-0000-7000-8000-000000000005", "external_reference": null}'::jsonb,1),
    (gen_random_uuid(),NULL,'entitlement.revoked','An entitlement was revoked.','1.0','platform93','active','entitlement/example','{"type": "object", "required": ["grant_id"], "properties": {"reason": {"type": "string"}, "status": {"enum": ["active", "revoked", "expired"]}, "grant_id": {"type": "string", "format": "uuid"}, "expires_at": {"type": ["string", "null"], "format": "date-time"}, "subject_id": {"type": "string", "format": "uuid"}, "subject_type": {"enum": ["user", "workspace"]}, "external_reference": {"type": ["string", "null"], "maxLength": 255, "minLength": 1}}, "additionalProperties": false}'::jsonb,'{"status": "revoked", "grant_id": "01900000-0000-7000-8000-000000000005", "external_reference": null}'::jsonb,1),
    (gen_random_uuid(),NULL,'local_entitlement_request.approved','A local entitlement request was approved.','1.0','platform93','active','local_entitlement_request/01900000-0000-7000-8000-000000000007','{"type": "object", "required": ["request_id", "grant_id", "external_reference"], "properties": {"grant_id": {"type": "string", "format": "uuid"}, "request_id": {"type": "string", "format": "uuid"}, "external_reference": {"type": ["string", "null"], "maxLength": 255, "minLength": 1}}, "additionalProperties": false}'::jsonb,'{"grant_id": "01900000-0000-7000-8000-000000000005", "request_id": "01900000-0000-7000-8000-000000000007", "external_reference": null}'::jsonb,1),
    (gen_random_uuid(),NULL,'local_entitlement_request.created','A local entitlement request was created.','1.0','platform93','active','local_entitlement_request/01900000-0000-7000-8000-000000000007','{"type": "object", "required": ["request_id", "subject_type", "subject_id", "price_id", "external_reference"], "properties": {"price_id": {"type": "string", "format": "uuid"}, "request_id": {"type": "string", "format": "uuid"}, "subject_id": {"type": "string", "format": "uuid"}, "subject_type": {"enum": ["user", "workspace"]}, "external_reference": {"type": ["string", "null"], "maxLength": 255, "minLength": 1}}, "additionalProperties": false}'::jsonb,'{"price_id": "01900000-0000-7000-8000-000000000008", "request_id": "01900000-0000-7000-8000-000000000007", "subject_id": "01900000-0000-7000-8000-000000000004", "subject_type": "user", "external_reference": null}'::jsonb,1),
    (gen_random_uuid(),NULL,'oauth.consent_revoked','OAuth consent was revoked.','1.0','platform93','active','oauth_consent/01900000-0000-7000-8000-000000000004/01900000-0000-7000-8000-000000000009','{"type": "object", "required": ["user_id", "client_id", "client_key"], "properties": {"user_id": {"type": "string", "format": "uuid"}, "client_id": {"type": "string", "format": "uuid"}, "client_key": {"type": "string"}}, "additionalProperties": false}'::jsonb,'{"user_id": "01900000-0000-7000-8000-000000000004", "client_id": "01900000-0000-7000-8000-000000000009", "client_key": "web"}'::jsonb,1),
    (gen_random_uuid(),NULL,'organization.created','An organization was created.','1.0','platform93','active','organization/01900000-0000-7000-8000-000000000001','{"type": "object", "required": ["name", "slug"], "properties": {"name": {"type": "string"}, "slug": {"type": "string"}}, "additionalProperties": false}'::jsonb,'{"name": "Example Organization", "slug": "example-organization"}'::jsonb,1),
    (gen_random_uuid(),NULL,'organization.restored','An organization was restored without restoring descendants.','1.0','platform93','active','organization/01900000-0000-7000-8000-000000000001','{"type": "object", "required": ["descendants_restored"], "properties": {"descendants_restored": {"type": "boolean"}}, "additionalProperties": false}'::jsonb,'{"descendants_restored": false}'::jsonb,1),
    (gen_random_uuid(),NULL,'organization.retired','An organization and its active applications were retired.','1.0','platform93','active','organization/01900000-0000-7000-8000-000000000001','{"type": "object", "required": ["application_count"], "properties": {"application_count": {"type": "integer", "minimum": 0}}, "additionalProperties": false}'::jsonb,'{"application_count": 2}'::jsonb,1),
    (gen_random_uuid(),NULL,'platform93.webhook.test','A targeted Platform93 webhook test was requested.','1.0','platform93','active','webhook/01900000-0000-7000-8000-000000000010','{"type": "object", "required": ["webhook_endpoint_id", "test"], "properties": {"test": {"const": true}, "webhook_endpoint_id": {"type": "string", "format": "uuid"}}, "additionalProperties": false}'::jsonb,'{"test": true, "webhook_endpoint_id": "01900000-0000-7000-8000-000000000010"}'::jsonb,1),
    (gen_random_uuid(),NULL,'storage.object.deleted','An object was deleted.','1.0','platform93','active','storage_object/01900000-0000-7000-8000-000000000020','{"type": "object", "required": ["object_id", "owner_type", "visibility", "size_bytes"], "properties": {"object_id": {"type": "string", "format": "uuid"}, "owner_type": {"enum": ["installation", "application", "user", "workspace"]}, "size_bytes": {"type": "integer", "minimum": 1}, "visibility": {"enum": ["public", "private"]}}, "additionalProperties": false}'::jsonb,'{"object_id": "01900000-0000-7000-8000-000000000020", "owner_type": "workspace", "size_bytes": 1024, "visibility": "private"}'::jsonb,1),
    (gen_random_uuid(),NULL,'storage.object.ready','An object upload completed and was verified.','1.0','platform93','active','storage_object/01900000-0000-7000-8000-000000000020','{"type": "object", "required": ["object_id", "owner_type", "visibility", "size_bytes"], "properties": {"object_id": {"type": "string", "format": "uuid"}, "owner_type": {"enum": ["installation", "application", "user", "workspace"]}, "size_bytes": {"type": "integer", "minimum": 1}, "visibility": {"enum": ["public", "private"]}}, "additionalProperties": false}'::jsonb,'{"object_id": "01900000-0000-7000-8000-000000000020", "owner_type": "workspace", "size_bytes": 1024, "visibility": "private"}'::jsonb,1),
    (gen_random_uuid(),NULL,'storage.object.upload_requested','An object upload was authorized.','1.0','platform93','active','storage_object/01900000-0000-7000-8000-000000000020','{"type": "object", "required": ["object_id", "owner_type", "visibility", "size_bytes"], "properties": {"object_id": {"type": "string", "format": "uuid"}, "owner_type": {"enum": ["installation", "application", "user", "workspace"]}, "size_bytes": {"type": "integer", "minimum": 1}, "visibility": {"enum": ["public", "private"]}}, "additionalProperties": false}'::jsonb,'{"object_id": "01900000-0000-7000-8000-000000000020", "owner_type": "workspace", "size_bytes": 1024, "visibility": "private"}'::jsonb,1),
    (gen_random_uuid(),NULL,'storage.provider.disabled','An S3-compatible storage provider was disabled in Platform93.','1.0','platform93','active','storage_provider/01900000-0000-7000-8000-000000000021','{"type": "object", "required": ["provider_id", "scope", "public_enabled", "private_enabled"], "properties": {"scope": {"enum": ["installation", "organization", "application"]}, "provider_id": {"type": "string", "format": "uuid"}, "public_enabled": {"type": "boolean"}, "private_enabled": {"type": "boolean"}}, "additionalProperties": false}'::jsonb,'{"scope": "application", "provider_id": "01900000-0000-7000-8000-000000000021", "public_enabled": true, "private_enabled": true}'::jsonb,1),
    (gen_random_uuid(),NULL,'storage.provider.verified','An S3-compatible storage provider was verified.','1.0','platform93','active','storage_provider/01900000-0000-7000-8000-000000000021','{"type": "object", "required": ["provider_id", "scope", "public_enabled", "private_enabled"], "properties": {"scope": {"enum": ["installation", "organization", "application"]}, "provider_id": {"type": "string", "format": "uuid"}, "public_enabled": {"type": "boolean"}, "private_enabled": {"type": "boolean"}}, "additionalProperties": false}'::jsonb,'{"scope": "application", "provider_id": "01900000-0000-7000-8000-000000000021", "public_enabled": true, "private_enabled": true}'::jsonb,1),
    (gen_random_uuid(),NULL,'user.anonymized','A user account was anonymized.','1.0','platform93','active','user/01900000-0000-7000-8000-000000000004','{"type": "object", "required": ["user_id"], "properties": {"user_id": {"type": "string", "format": "uuid"}}, "additionalProperties": false}'::jsonb,'{"user_id": "01900000-0000-7000-8000-000000000004"}'::jsonb,1),
    (gen_random_uuid(),NULL,'user.created','A user account was created.','1.0','platform93','active','user/01900000-0000-7000-8000-000000000004','{"type": "object", "required": ["user_id", "email_verified", "is_org_verified"], "properties": {"user_id": {"type": "string", "format": "uuid"}, "email_verified": {"type": "boolean"}, "is_org_verified": {"type": "boolean"}}, "additionalProperties": false}'::jsonb,'{"user_id": "01900000-0000-7000-8000-000000000004", "email_verified": false, "is_org_verified": false}'::jsonb,1),
    (gen_random_uuid(),NULL,'user.deleted','A user account was deleted.','1.0','platform93','active','user/01900000-0000-7000-8000-000000000004','{"type": "object", "required": ["user_id"], "properties": {"user_id": {"type": "string", "format": "uuid"}}, "additionalProperties": false}'::jsonb,'{"user_id": "01900000-0000-7000-8000-000000000004"}'::jsonb,1),
    (gen_random_uuid(),NULL,'user.email_changed','A user email address was changed.','1.0','platform93','active','user/01900000-0000-7000-8000-000000000004','{"type": "object", "required": ["user_id"], "properties": {"user_id": {"type": "string", "format": "uuid"}}, "additionalProperties": false}'::jsonb,'{"user_id": "01900000-0000-7000-8000-000000000004"}'::jsonb,1),
    (gen_random_uuid(),NULL,'user.email_unverified','A user email address was administratively unverified.','1.0','platform93','active','user/01900000-0000-7000-8000-000000000004','{"type": "object", "required": ["user_id", "verified", "reason"], "properties": {"reason": {"type": "string"}, "user_id": {"type": "string", "format": "uuid"}, "verified": {"const": false}}, "additionalProperties": false}'::jsonb,'{"reason": "control_user_request", "user_id": "01900000-0000-7000-8000-000000000004", "verified": false}'::jsonb,1),
    (gen_random_uuid(),NULL,'user.email_verified','A user email address was verified.','1.0','platform93','active','user/01900000-0000-7000-8000-000000000004','{"type": "object", "required": ["user_id", "verified", "reason"], "properties": {"reason": {"type": "string"}, "user_id": {"type": "string", "format": "uuid"}, "verified": {"const": true}}, "additionalProperties": false}'::jsonb,'{"reason": "self_service", "user_id": "01900000-0000-7000-8000-000000000004", "verified": true}'::jsonb,1),
    (gen_random_uuid(),NULL,'user.organization_unverified','Organization verification was removed from a user.','1.0','platform93','active','user/01900000-0000-7000-8000-000000000004','{"type": "object", "required": ["user_id", "verified", "reason"], "properties": {"reason": {"type": "string"}, "user_id": {"type": "string", "format": "uuid"}, "verified": {"const": false}}, "additionalProperties": false}'::jsonb,'{"reason": "organization_review", "user_id": "01900000-0000-7000-8000-000000000004", "verified": false}'::jsonb,1),
    (gen_random_uuid(),NULL,'user.organization_verified','A user was verified for an organization.','1.0','platform93','active','user/01900000-0000-7000-8000-000000000004','{"type": "object", "required": ["user_id", "verified", "reason"], "properties": {"reason": {"type": "string"}, "user_id": {"type": "string", "format": "uuid"}, "verified": {"const": true}}, "additionalProperties": false}'::jsonb,'{"reason": "organization_approved", "user_id": "01900000-0000-7000-8000-000000000004", "verified": true}'::jsonb,1),
    (gen_random_uuid(),NULL,'user.password_reset','A user password was reset.','1.0','platform93','active','user/01900000-0000-7000-8000-000000000004','{"type": "object", "required": ["user_id"], "properties": {"user_id": {"type": "string", "format": "uuid"}}, "additionalProperties": false}'::jsonb,'{"user_id": "01900000-0000-7000-8000-000000000004"}'::jsonb,1),
    (gen_random_uuid(),NULL,'user.pending_deletion','A user account entered pending deletion.','1.0','platform93','active','user/01900000-0000-7000-8000-000000000004','{"type": "object", "required": ["user_id"], "properties": {"user_id": {"type": "string", "format": "uuid"}}, "additionalProperties": false}'::jsonb,'{"user_id": "01900000-0000-7000-8000-000000000004"}'::jsonb,1),
    (gen_random_uuid(),NULL,'user.restored','A suspended user was restored.','1.0','platform93','active','user/01900000-0000-7000-8000-000000000004','{"type": "object", "required": ["user_id", "reason"], "properties": {"reason": {"type": "string"}, "user_id": {"type": "string", "format": "uuid"}}, "additionalProperties": false}'::jsonb,'{"reason": "control_user_request", "user_id": "01900000-0000-7000-8000-000000000004"}'::jsonb,1),
    (gen_random_uuid(),NULL,'user.suspended','A user was suspended.','1.0','platform93','active','user/01900000-0000-7000-8000-000000000004','{"type": "object", "required": ["user_id", "reason"], "properties": {"reason": {"type": "string"}, "user_id": {"type": "string", "format": "uuid"}}, "additionalProperties": false}'::jsonb,'{"reason": "control_user_request", "user_id": "01900000-0000-7000-8000-000000000004"}'::jsonb,1),
    (gen_random_uuid(),NULL,'user.updated','A user profile was updated.','1.0','platform93','active','user/example','{"type": "object", "required": ["user_id", "changed_fields"], "properties": {"user_id": {"type": "string", "format": "uuid"}, "changed_fields": {"type": "array", "items": {"type": "string"}}}, "additionalProperties": false}'::jsonb,'{"user_id": "01900000-0000-7000-8000-000000000004", "changed_fields": []}'::jsonb,1),
    (gen_random_uuid(),NULL,'workspace.archived','A workspace was archived.','1.0','platform93','active','workspace/example','{"type": "object", "required": ["workspace_id", "status"], "properties": {"key": {"type": "string"}, "name": {"type": "string"}, "status": {"enum": ["active", "archived", "removed"]}, "user_id": {"type": "string", "format": "uuid"}, "role_keys": {"type": "array", "items": {"type": "string"}}, "workspace_id": {"type": "string", "format": "uuid"}, "owner_user_id": {"type": "string", "format": "uuid"}, "changed_fields": {"type": "array", "items": {"type": "string"}}}, "additionalProperties": false}'::jsonb,'{"status": "archived", "workspace_id": "01900000-0000-7000-8000-000000000006"}'::jsonb,1),
    (gen_random_uuid(),NULL,'workspace.created','A workspace was created.','1.0','platform93','active','workspace/example','{"type": "object", "required": ["workspace_id", "status"], "properties": {"key": {"type": "string"}, "name": {"type": "string"}, "status": {"enum": ["active", "archived", "removed"]}, "user_id": {"type": "string", "format": "uuid"}, "role_keys": {"type": "array", "items": {"type": "string"}}, "workspace_id": {"type": "string", "format": "uuid"}, "owner_user_id": {"type": "string", "format": "uuid"}, "changed_fields": {"type": "array", "items": {"type": "string"}}}, "additionalProperties": false}'::jsonb,'{"status": "active", "workspace_id": "01900000-0000-7000-8000-000000000006"}'::jsonb,1),
    (gen_random_uuid(),NULL,'workspace.invitation_accepted','A workspace invitation was accepted.','1.0','platform93','active','workspace_invitation/01900000-0000-7000-8000-000000000011','{"type": "object", "required": ["invitation_id", "workspace_id", "user_id"], "properties": {"user_id": {"type": "string", "format": "uuid"}, "workspace_id": {"type": "string", "format": "uuid"}, "invitation_id": {"type": "string", "format": "uuid"}}, "additionalProperties": false}'::jsonb,'{"user_id": "01900000-0000-7000-8000-000000000004", "workspace_id": "01900000-0000-7000-8000-000000000006", "invitation_id": "01900000-0000-7000-8000-000000000011"}'::jsonb,1),
    (gen_random_uuid(),NULL,'workspace.invitation_created','A workspace invitation was created.','1.0','platform93','active','workspace_invitation/01900000-0000-7000-8000-000000000011','{"type": "object", "required": ["invitation_id", "workspace_id", "role_keys"], "properties": {"role_keys": {"type": "array", "items": {"type": "string"}}, "workspace_id": {"type": "string", "format": "uuid"}, "invitation_id": {"type": "string", "format": "uuid"}}, "additionalProperties": false}'::jsonb,'{"role_keys": ["workspace_member"], "workspace_id": "01900000-0000-7000-8000-000000000006", "invitation_id": "01900000-0000-7000-8000-000000000011"}'::jsonb,1),
    (gen_random_uuid(),NULL,'workspace.member_added','A workspace member was added.','1.0','platform93','active','workspace/example','{"type": "object", "required": ["workspace_id", "status"], "properties": {"key": {"type": "string"}, "name": {"type": "string"}, "status": {"enum": ["active", "archived", "removed"]}, "user_id": {"type": "string", "format": "uuid"}, "role_keys": {"type": "array", "items": {"type": "string"}}, "workspace_id": {"type": "string", "format": "uuid"}, "owner_user_id": {"type": "string", "format": "uuid"}, "changed_fields": {"type": "array", "items": {"type": "string"}}}, "additionalProperties": false}'::jsonb,'{"status": "active", "workspace_id": "01900000-0000-7000-8000-000000000006"}'::jsonb,1),
    (gen_random_uuid(),NULL,'workspace.member_removed','A workspace member was removed.','1.0','platform93','active','workspace/example','{"type": "object", "required": ["workspace_id", "status"], "properties": {"key": {"type": "string"}, "name": {"type": "string"}, "status": {"enum": ["active", "archived", "removed"]}, "user_id": {"type": "string", "format": "uuid"}, "role_keys": {"type": "array", "items": {"type": "string"}}, "workspace_id": {"type": "string", "format": "uuid"}, "owner_user_id": {"type": "string", "format": "uuid"}, "changed_fields": {"type": "array", "items": {"type": "string"}}}, "additionalProperties": false}'::jsonb,'{"status": "removed", "workspace_id": "01900000-0000-7000-8000-000000000006"}'::jsonb,1),
    (gen_random_uuid(),NULL,'workspace.member_updated','Workspace member roles changed.','1.0','platform93','active','workspace/example','{"type": "object", "required": ["workspace_id", "status"], "properties": {"key": {"type": "string"}, "name": {"type": "string"}, "status": {"enum": ["active", "archived", "removed"]}, "user_id": {"type": "string", "format": "uuid"}, "role_keys": {"type": "array", "items": {"type": "string"}}, "workspace_id": {"type": "string", "format": "uuid"}, "owner_user_id": {"type": "string", "format": "uuid"}, "changed_fields": {"type": "array", "items": {"type": "string"}}}, "additionalProperties": false}'::jsonb,'{"status": "active", "workspace_id": "01900000-0000-7000-8000-000000000006"}'::jsonb,1),
    (gen_random_uuid(),NULL,'workspace.owner_transferred','Workspace ownership was transferred.','1.0','platform93','active','workspace/01900000-0000-7000-8000-000000000006','{"type": "object", "required": ["workspace_id", "previous_owner_user_id", "new_owner_user_id", "previous_owner_disposition"], "properties": {"workspace_id": {"type": "string", "format": "uuid"}, "new_owner_user_id": {"type": "string", "format": "uuid"}, "previous_owner_user_id": {"type": "string", "format": "uuid"}, "previous_owner_disposition": {"enum": ["member", "remove"]}}, "additionalProperties": false}'::jsonb,'{"workspace_id": "01900000-0000-7000-8000-000000000006", "new_owner_user_id": "01900000-0000-7000-8000-000000000012", "previous_owner_user_id": "01900000-0000-7000-8000-000000000004", "previous_owner_disposition": "member"}'::jsonb,1),
    (gen_random_uuid(),NULL,'workspace.updated','A workspace was updated.','1.0','platform93','active','workspace/example','{"type": "object", "required": ["workspace_id", "status"], "properties": {"key": {"type": "string"}, "name": {"type": "string"}, "status": {"enum": ["active", "archived", "removed"]}, "user_id": {"type": "string", "format": "uuid"}, "role_keys": {"type": "array", "items": {"type": "string"}}, "workspace_id": {"type": "string", "format": "uuid"}, "owner_user_id": {"type": "string", "format": "uuid"}, "changed_fields": {"type": "array", "items": {"type": "string"}}}, "additionalProperties": false}'::jsonb,'{"status": "active", "workspace_id": "01900000-0000-7000-8000-000000000006"}'::jsonb,1);
INSERT INTO public.event_type_definitions
(id,application_id,name,description,schema_version,source,status,example_subject,data_schema,example_data,version) VALUES
    (gen_random_uuid(),NULL,'control_user.identity_linked','A Platform user linked an external identity.','1.0','platform93','active','control_user/01900000-0000-7000-8000-000000000050','{"type":"object","required":["control_user_id","provider"],"properties":{"control_user_id":{"type":"string","format":"uuid"},"provider":{"enum":["google","apple"]}},"additionalProperties":false}'::jsonb,'{"control_user_id":"01900000-0000-7000-8000-000000000050","provider":"google"}'::jsonb,1),
    (gen_random_uuid(),NULL,'control_user.identity_unlinked','A Platform user unlinked an external identity.','1.0','platform93','active','control_user/01900000-0000-7000-8000-000000000050','{"type":"object","required":["control_user_id","provider"],"properties":{"control_user_id":{"type":"string","format":"uuid"},"provider":{"enum":["google","apple"]}},"additionalProperties":false}'::jsonb,'{"control_user_id":"01900000-0000-7000-8000-000000000050","provider":"google"}'::jsonb,1),
    (gen_random_uuid(),NULL,'control_auth.policy_updated','The Platform user authentication policy changed.','1.0','platform93','active','installation/identity','{"type":"object","required":["email_code_enabled","magic_link_enabled","password_enabled"],"properties":{"email_code_enabled":{"type":"boolean"},"magic_link_enabled":{"type":"boolean"},"password_enabled":{"type":"boolean"}},"additionalProperties":false}'::jsonb,'{"email_code_enabled":true,"magic_link_enabled":true,"password_enabled":true}'::jsonb,1),
    (gen_random_uuid(),NULL,'control_auth.provider_login_enabled','An installation provider was enabled for Platform user sign-in.','1.0','platform93','active','auth_provider/google','{"type":"object","required":["provider","enabled"],"properties":{"provider":{"enum":["google","apple"]},"enabled":{"type":"boolean"}},"additionalProperties":false}'::jsonb,'{"provider":"google","enabled":true}'::jsonb,1),
    (gen_random_uuid(),NULL,'control_auth.provider_login_disabled','An installation provider was disabled for Platform user sign-in.','1.0','platform93','active','auth_provider/google','{"type":"object","required":["provider","enabled"],"properties":{"provider":{"enum":["google","apple"]},"enabled":{"type":"boolean"}},"additionalProperties":false}'::jsonb,'{"provider":"google","enabled":false}'::jsonb,1),
    (gen_random_uuid(),NULL,'control_user.invitation_created','A Platform user invitation was created.','1.0','platform93','active','control_user_invitation/01900000-0000-7000-8000-000000000051','{"type":"object","required":["invitation_id","role","onboarding_method","status"],"properties":{"invitation_id":{"type":"string","format":"uuid"},"organization_id":{"type":["string","null"],"format":"uuid"},"control_user_id":{"type":"string","format":"uuid"},"role":{"enum":["owner","admin","member","auditor"]},"onboarding_method":{"enum":["email","google","apple"]},"status":{"enum":["pending","accepted","revoked"]}},"additionalProperties":false}'::jsonb,'{"invitation_id":"01900000-0000-7000-8000-000000000051","organization_id":null,"role":"admin","onboarding_method":"google","status":"pending"}'::jsonb,1),
    (gen_random_uuid(),NULL,'control_user.invitation_resent','A Platform user invitation credential was rotated.','1.0','platform93','active','control_user_invitation/01900000-0000-7000-8000-000000000051','{"type":"object","required":["invitation_id","role","onboarding_method","status"],"properties":{"invitation_id":{"type":"string","format":"uuid"},"organization_id":{"type":["string","null"],"format":"uuid"},"control_user_id":{"type":"string","format":"uuid"},"role":{"enum":["owner","admin","member","auditor"]},"onboarding_method":{"enum":["email","google","apple"]},"status":{"enum":["pending","accepted","revoked"]}},"additionalProperties":false}'::jsonb,'{"invitation_id":"01900000-0000-7000-8000-000000000051","organization_id":null,"role":"admin","onboarding_method":"google","status":"pending"}'::jsonb,1),
    (gen_random_uuid(),NULL,'control_user.invitation_revoked','A Platform user invitation was revoked.','1.0','platform93','active','control_user_invitation/01900000-0000-7000-8000-000000000051','{"type":"object","required":["invitation_id","role","onboarding_method","status"],"properties":{"invitation_id":{"type":"string","format":"uuid"},"organization_id":{"type":["string","null"],"format":"uuid"},"control_user_id":{"type":"string","format":"uuid"},"role":{"enum":["owner","admin","member","auditor"]},"onboarding_method":{"enum":["email","google","apple"]},"status":{"enum":["pending","accepted","revoked"]}},"additionalProperties":false}'::jsonb,'{"invitation_id":"01900000-0000-7000-8000-000000000051","organization_id":null,"role":"admin","onboarding_method":"google","status":"revoked"}'::jsonb,1),
    (gen_random_uuid(),NULL,'control_user.invitation_accepted','A Platform user invitation was accepted.','1.0','platform93','active','control_user_invitation/01900000-0000-7000-8000-000000000051','{"type":"object","required":["invitation_id","control_user_id","role","onboarding_method","status"],"properties":{"invitation_id":{"type":"string","format":"uuid"},"organization_id":{"type":["string","null"],"format":"uuid"},"control_user_id":{"type":"string","format":"uuid"},"role":{"enum":["owner","admin","member","auditor"]},"onboarding_method":{"enum":["email","google","apple"]},"status":{"enum":["pending","accepted","revoked"]}},"additionalProperties":false}'::jsonb,'{"invitation_id":"01900000-0000-7000-8000-000000000051","organization_id":null,"control_user_id":"01900000-0000-7000-8000-000000000050","role":"admin","onboarding_method":"google","status":"accepted"}'::jsonb,1);
INSERT INTO public.notification_templates
(application_id,key,locale,category,version,subject_template,text_template,html_template,variable_schema,status,system_managed) VALUES
	(NULL,'platform93.control_user_invitation','en','security',1,'Your Platform93 invitation','You were invited as a Platform93 {{role}}.

Onboarding method: {{onboarding_method}}

Accept invitation: {{invitation_link}}

Expires at: {{expires_at}}.',$email$<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="width:100%;background:#f2f0e6;border-collapse:collapse"><tr><td align="center" style="padding:36px 16px"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="width:100%;max-width:600px;background:#fffef8;border:1px solid #d8d4c4;border-top:6px solid #d9ff43;border-radius:12px;border-collapse:separate"><tr><td style="padding:26px 34px 8px;font-family:Arial,sans-serif"><span style="font-size:13px;font-weight:800;letter-spacing:2px;color:#17251e">PLATFORM93</span></td></tr><tr><td style="padding:12px 34px 34px;font-family:Arial,sans-serif;color:#17251e"><p style="margin:0 0 12px;font-size:12px;font-weight:800;letter-spacing:1.5px;color:#657169">PLATFORM ACCESS</p><h1 style="margin:0 0 16px;font-size:30px;line-height:1.15">You are invited</h1><p style="margin:0 0 22px;font-size:16px;line-height:1.6;color:#4a564f">You were invited to join Platform93 as <strong style="color:#17251e">{{role}}</strong> using {{onboarding_method}}.</p><a href="{{invitation_link}}" style="display:inline-block;padding:13px 20px;background:#17251e;color:#ffffff;text-decoration:none;font-size:15px;font-weight:700;border-radius:7px">Accept invitation</a><p style="margin:22px 0 0;font-size:13px;line-height:1.5;color:#657169">This invitation expires at {{expires_at}}.</p></td></tr><tr><td style="padding:18px 34px;background:#f8f6ee;border-top:1px solid #e2dfd2;font-family:Arial,sans-serif"><p style="margin:0;font-size:12px;line-height:1.5;color:#747d77">If you did not expect this invitation, you can safely ignore this email.</p></td></tr></table></td></tr></table>$email$,'{"required": ["role", "onboarding_method", "invitation_link", "expires_at"], "properties": {"role": {"type": "string"}, "onboarding_method": {"type": "string"}, "invitation_link": {"type": "string"}, "invitation_token": {"type": "string"}, "expires_at": {"type": "string"}}}'::jsonb,'published',true),
    (NULL,'platform93.application_invitation','en','security',1,'Invitation to {{application_name}}','You were invited to {{application_name}}.

Code: {{invitation_code}}

Accept invitation: {{invitation_link}}

Roles: {{role_keys}}

Expires at: {{expires_at}}.',$email$<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="width:100%;background:#f2f0e6;border-collapse:collapse"><tr><td align="center" style="padding:36px 16px"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="width:100%;max-width:600px;background:#fffef8;border:1px solid #d8d4c4;border-top:6px solid #d9ff43;border-radius:12px;border-collapse:separate"><tr><td style="padding:26px 34px 8px;font-family:Arial,sans-serif"><span style="font-size:13px;font-weight:800;letter-spacing:2px;color:#17251e">{{application_name}}</span></td></tr><tr><td style="padding:12px 34px 34px;font-family:Arial,sans-serif;color:#17251e"><p style="margin:0 0 12px;font-size:12px;font-weight:800;letter-spacing:1.5px;color:#657169">APPLICATION INVITATION</p><h1 style="margin:0 0 16px;font-size:30px;line-height:1.15">You are invited</h1><p style="margin:0 0 18px;font-size:16px;line-height:1.6;color:#4a564f">Join {{application_name}} with the assigned access: <strong style="color:#17251e">{{role_keys}}</strong>.</p><div style="margin:0 0 20px;padding:16px 18px;background:#f1f3e8;border:1px solid #d9ddca;border-radius:8px"><p style="margin:0 0 6px;font-size:11px;font-weight:800;letter-spacing:1.5px;color:#657169">ONE-TIME CODE</p><p style="margin:0;font-family:Courier New,monospace;font-size:25px;font-weight:700;letter-spacing:4px;color:#17251e">{{invitation_code}}</p></div><a href="{{invitation_link}}" style="display:inline-block;padding:13px 20px;background:#17251e;color:#ffffff;text-decoration:none;font-size:15px;font-weight:700;border-radius:7px">Accept invitation</a><p style="margin:22px 0 0;font-size:13px;line-height:1.5;color:#657169">This invitation expires at {{expires_at}}.</p></td></tr><tr><td style="padding:18px 34px;background:#f8f6ee;border-top:1px solid #e2dfd2;font-family:Arial,sans-serif"><p style="margin:0;font-size:12px;line-height:1.5;color:#747d77">If the button does not work, use the one-time code in the application. Powered by Platform93.</p></td></tr></table></td></tr></table>$email$,'{"required": ["invitation_code", "invitation_link", "role_keys", "expires_at"], "properties": {"role_keys": {"type": "string"}, "expires_at": {"type": "string"}, "inviter_name": {"type": "string"}, "invitation_code": {"type": "string"}, "invitation_link": {"type": "string"}}}'::jsonb,'published',true),
    (NULL,'platform93.application_sign_in','en','security',1,'Sign in to {{application_name}}','A sign-in was requested for {{application_name}}.

Code: {{code}}

Magic link: {{magic_link}}

This credential expires in {{expires_minutes}} minutes. If you did not request it, ignore this message.',$email$<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="width:100%;background:#f2f0e6;border-collapse:collapse"><tr><td align="center" style="padding:36px 16px"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="width:100%;max-width:600px;background:#fffef8;border:1px solid #d8d4c4;border-top:6px solid #d9ff43;border-radius:12px;border-collapse:separate"><tr><td style="padding:26px 34px 8px;font-family:Arial,sans-serif"><span style="font-size:13px;font-weight:800;letter-spacing:2px;color:#17251e">{{application_name}}</span></td></tr><tr><td style="padding:12px 34px 34px;font-family:Arial,sans-serif;color:#17251e"><p style="margin:0 0 12px;font-size:12px;font-weight:800;letter-spacing:1.5px;color:#657169">SECURE SIGN-IN</p><h1 style="margin:0 0 16px;font-size:30px;line-height:1.15">Continue to {{application_name}}</h1><p style="margin:0 0 18px;font-size:16px;line-height:1.6;color:#4a564f">Use this one-time code or the secure link below to finish signing in.</p><div style="margin:0 0 20px;padding:16px 18px;background:#f1f3e8;border:1px solid #d9ddca;border-radius:8px"><p style="margin:0 0 6px;font-size:11px;font-weight:800;letter-spacing:1.5px;color:#657169">SIGN-IN CODE</p><p style="margin:0;font-family:Courier New,monospace;font-size:25px;font-weight:700;letter-spacing:4px;color:#17251e">{{code}}</p></div><a href="{{magic_link}}" style="display:inline-block;padding:13px 20px;background:#17251e;color:#ffffff;text-decoration:none;font-size:15px;font-weight:700;border-radius:7px">Continue signing in</a><p style="margin:22px 0 0;font-size:13px;line-height:1.5;color:#657169">The code and link expire in {{expires_minutes}} minutes.</p></td></tr><tr><td style="padding:18px 34px;background:#f8f6ee;border-top:1px solid #e2dfd2;font-family:Arial,sans-serif"><p style="margin:0;font-size:12px;line-height:1.5;color:#747d77">If you did not request this sign-in, ignore this email. No changes will be made to your account.</p></td></tr></table></td></tr></table>$email$,'{"required": ["code", "magic_link", "expires_minutes", "intent"], "properties": {"code": {"type": "string", "title": "Sign-in code", "example": "AB12CD34"}, "intent": {"type": "string", "title": "Authentication intent", "example": "sign_in"}, "magic_link": {"type": "string", "title": "Magic link", "example": "https://app.example/auth/callback"}, "expires_minutes": {"type": "integer", "title": "Expiry in minutes", "example": 10}}}'::jsonb,'published',true),
    (NULL,'platform93.change_email','en','security',1,'Confirm your new email for {{application_name}}','Confirm this email address for {{application_name}}.

Code: {{code}}

Confirmation link: {{magic_link}}

This credential expires in {{expires_minutes}} minutes.',$email$<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="width:100%;background:#f2f0e6;border-collapse:collapse"><tr><td align="center" style="padding:36px 16px"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="width:100%;max-width:600px;background:#fffef8;border:1px solid #d8d4c4;border-top:6px solid #d9ff43;border-radius:12px;border-collapse:separate"><tr><td style="padding:26px 34px 8px;font-family:Arial,sans-serif"><span style="font-size:13px;font-weight:800;letter-spacing:2px;color:#17251e">{{application_name}}</span></td></tr><tr><td style="padding:12px 34px 34px;font-family:Arial,sans-serif;color:#17251e"><p style="margin:0 0 12px;font-size:12px;font-weight:800;letter-spacing:1.5px;color:#657169">EMAIL CHANGE</p><h1 style="margin:0 0 16px;font-size:30px;line-height:1.15">Confirm your new email</h1><p style="margin:0 0 18px;font-size:16px;line-height:1.6;color:#4a564f">Use this code or secure link to confirm the new email address for {{application_name}}.</p><div style="margin:0 0 20px;padding:16px 18px;background:#f1f3e8;border:1px solid #d9ddca;border-radius:8px"><p style="margin:0 0 6px;font-size:11px;font-weight:800;letter-spacing:1.5px;color:#657169">CONFIRMATION CODE</p><p style="margin:0;font-family:Courier New,monospace;font-size:25px;font-weight:700;letter-spacing:4px;color:#17251e">{{code}}</p></div><a href="{{magic_link}}" style="display:inline-block;padding:13px 20px;background:#17251e;color:#ffffff;text-decoration:none;font-size:15px;font-weight:700;border-radius:7px">Confirm email</a><p style="margin:22px 0 0;font-size:13px;line-height:1.5;color:#657169">This confirmation expires in {{expires_minutes}} minutes.</p></td></tr><tr><td style="padding:18px 34px;background:#f8f6ee;border-top:1px solid #e2dfd2;font-family:Arial,sans-serif"><p style="margin:0;font-size:12px;line-height:1.5;color:#747d77">If you did not request this change, do not use the code or link.</p></td></tr></table></td></tr></table>$email$,'{"required": ["code", "magic_link", "expires_minutes"], "properties": {"code": {"type": "string", "title": "Confirmation code", "example": "AB12CD34"}, "magic_link": {"type": "string", "title": "Confirmation link", "example": "https://app.example/auth/callback"}, "expires_minutes": {"type": "integer", "title": "Expiry in minutes", "example": 10}}}'::jsonb,'published',true),
    (NULL,'platform93.control_user_sign_in','en','security',1,'Your Platform93 sign-in code','A sign-in was requested for your Platform93 user account.

Code: {{code}}

Magic link: {{magic_link}}

This credential expires in {{expires_minutes}} minutes. If you did not request it, ignore this message.',$email$<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="width:100%;background:#f2f0e6;border-collapse:collapse"><tr><td align="center" style="padding:36px 16px"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="width:100%;max-width:600px;background:#fffef8;border:1px solid #d8d4c4;border-top:6px solid #d9ff43;border-radius:12px;border-collapse:separate"><tr><td style="padding:26px 34px 8px;font-family:Arial,sans-serif"><span style="font-size:13px;font-weight:800;letter-spacing:2px;color:#17251e">PLATFORM93</span></td></tr><tr><td style="padding:12px 34px 34px;font-family:Arial,sans-serif;color:#17251e"><p style="margin:0 0 12px;font-size:12px;font-weight:800;letter-spacing:1.5px;color:#657169">PLATFORM USER SIGN-IN</p><h1 style="margin:0 0 16px;font-size:30px;line-height:1.15">Sign in securely</h1><p style="margin:0 0 18px;font-size:16px;line-height:1.6;color:#4a564f">Use this one-time code or secure link to access the Platform93 control panel.</p><div style="margin:0 0 20px;padding:16px 18px;background:#f1f3e8;border:1px solid #d9ddca;border-radius:8px"><p style="margin:0 0 6px;font-size:11px;font-weight:800;letter-spacing:1.5px;color:#657169">SIGN-IN CODE</p><p style="margin:0;font-family:Courier New,monospace;font-size:25px;font-weight:700;letter-spacing:4px;color:#17251e">{{code}}</p></div><a href="{{magic_link}}" style="display:inline-block;padding:13px 20px;background:#17251e;color:#ffffff;text-decoration:none;font-size:15px;font-weight:700;border-radius:7px">Open Platform93</a><p style="margin:22px 0 0;font-size:13px;line-height:1.5;color:#657169">The code and link expire in {{expires_minutes}} minutes.</p></td></tr><tr><td style="padding:18px 34px;background:#f8f6ee;border-top:1px solid #e2dfd2;font-family:Arial,sans-serif"><p style="margin:0;font-size:12px;line-height:1.5;color:#747d77">If you did not request this sign-in, ignore this email. No changes will be made to your account.</p></td></tr></table></td></tr></table>$email$,'{"required": ["code", "magic_link", "expires_minutes"], "properties": {"code": {"type": "string", "title": "Sign-in code", "example": "AB12CD34"}, "magic_link": {"type": "string", "title": "Magic link", "example": "https://platform93.example/?control_user_challenge=true"}, "expires_minutes": {"type": "integer", "title": "Expiry in minutes", "example": 10}}}'::jsonb,'published',true),
    (NULL,'platform93.organization_invitation','en','security',1,'Invitation to administer {{organization_name}}','You were invited to administer {{organization_name}} as {{role}}.

Accept invitation: {{invitation_link}}

One-time invitation code: {{invitation_token}}

Expires at: {{expires_at}}

If you did not expect this invitation, ignore this message.',$email$<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="width:100%;background:#f2f0e6;border-collapse:collapse"><tr><td align="center" style="padding:36px 16px"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="width:100%;max-width:600px;background:#fffef8;border:1px solid #d8d4c4;border-top:6px solid #d9ff43;border-radius:12px;border-collapse:separate"><tr><td style="padding:26px 34px 8px;font-family:Arial,sans-serif"><span style="font-size:13px;font-weight:800;letter-spacing:2px;color:#17251e">PLATFORM93</span></td></tr><tr><td style="padding:12px 34px 34px;font-family:Arial,sans-serif;color:#17251e"><p style="margin:0 0 12px;font-size:12px;font-weight:800;letter-spacing:1.5px;color:#657169">ORGANIZATION ACCESS</p><h1 style="margin:0 0 16px;font-size:30px;line-height:1.15">Join {{organization_name}}</h1><p style="margin:0 0 18px;font-size:16px;line-height:1.6;color:#4a564f">You were invited to administer <strong style="color:#17251e">{{organization_name}}</strong> as {{role}}.</p><div style="margin:0 0 20px;padding:16px 18px;background:#f1f3e8;border:1px solid #d9ddca;border-radius:8px"><p style="margin:0 0 6px;font-size:11px;font-weight:800;letter-spacing:1.5px;color:#657169">ONE-TIME INVITATION CODE</p><p style="margin:0;font-family:Courier New,monospace;font-size:18px;font-weight:700;word-break:break-all;color:#17251e">{{invitation_token}}</p></div><a href="{{invitation_link}}" style="display:inline-block;padding:13px 20px;background:#17251e;color:#ffffff;text-decoration:none;font-size:15px;font-weight:700;border-radius:7px">Accept invitation</a><p style="margin:22px 0 0;font-size:13px;line-height:1.5;color:#657169">This invitation expires at {{expires_at}}.</p></td></tr><tr><td style="padding:18px 34px;background:#f8f6ee;border-top:1px solid #e2dfd2;font-family:Arial,sans-serif"><p style="margin:0;font-size:12px;line-height:1.5;color:#747d77">If you did not expect this invitation, you can safely ignore this email.</p></td></tr></table></td></tr></table>$email$,'{"required": ["organization_name", "role", "invitation_link", "invitation_token", "expires_at"], "properties": {"role": {"type": "string", "title": "Organization role", "example": "admin"}, "expires_at": {"type": "string", "title": "Expiry time", "example": "2026-08-15T12:00:00Z"}, "invitation_link": {"type": "string", "title": "Invitation link", "example": "https://platform93.example/?organization_invitation=true"}, "invitation_token": {"type": "string", "title": "One-time invitation code", "example": "p93_org_invite_example"}, "organization_name": {"type": "string", "title": "Organization name", "example": "Acme GmbH"}}}'::jsonb,'published',true),
    (NULL,'platform93.password_reset','en','security',1,'Reset your {{application_name}} password','A password reset was requested for {{application_name}}.

Code: {{code}}

Reset link: {{magic_link}}

This credential expires in {{expires_minutes}} minutes. If you did not request it, ignore this message.',$email$<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="width:100%;background:#f2f0e6;border-collapse:collapse"><tr><td align="center" style="padding:36px 16px"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="width:100%;max-width:600px;background:#fffef8;border:1px solid #d8d4c4;border-top:6px solid #d9ff43;border-radius:12px;border-collapse:separate"><tr><td style="padding:26px 34px 8px;font-family:Arial,sans-serif"><span style="font-size:13px;font-weight:800;letter-spacing:2px;color:#17251e">{{application_name}}</span></td></tr><tr><td style="padding:12px 34px 34px;font-family:Arial,sans-serif;color:#17251e"><p style="margin:0 0 12px;font-size:12px;font-weight:800;letter-spacing:1.5px;color:#657169">PASSWORD RESET</p><h1 style="margin:0 0 16px;font-size:30px;line-height:1.15">Reset your password</h1><p style="margin:0 0 18px;font-size:16px;line-height:1.6;color:#4a564f">A password reset was requested for your {{application_name}} account.</p><div style="margin:0 0 20px;padding:16px 18px;background:#f1f3e8;border:1px solid #d9ddca;border-radius:8px"><p style="margin:0 0 6px;font-size:11px;font-weight:800;letter-spacing:1.5px;color:#657169">RESET CODE</p><p style="margin:0;font-family:Courier New,monospace;font-size:25px;font-weight:700;letter-spacing:4px;color:#17251e">{{code}}</p></div><a href="{{magic_link}}" style="display:inline-block;padding:13px 20px;background:#17251e;color:#ffffff;text-decoration:none;font-size:15px;font-weight:700;border-radius:7px">Reset password</a><p style="margin:22px 0 0;font-size:13px;line-height:1.5;color:#657169">The code and link expire in {{expires_minutes}} minutes.</p></td></tr><tr><td style="padding:18px 34px;background:#f8f6ee;border-top:1px solid #e2dfd2;font-family:Arial,sans-serif"><p style="margin:0;font-size:12px;line-height:1.5;color:#747d77">If you did not request a password reset, ignore this email and keep your current password.</p></td></tr></table></td></tr></table>$email$,'{"required": ["code", "magic_link", "expires_minutes"], "properties": {"code": {"type": "string", "title": "Reset code", "example": "AB12CD34"}, "magic_link": {"type": "string", "title": "Reset link", "example": "https://app.example/auth/callback"}, "expires_minutes": {"type": "integer", "title": "Expiry in minutes", "example": 10}}}'::jsonb,'published',true),
    (NULL,'platform93.verify_email','en','security',1,'Verify your email for {{application_name}}','Confirm your email address for {{application_name}}.

Code: {{code}}

Verification link: {{magic_link}}

This credential expires in {{expires_minutes}} minutes.',$email$<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="width:100%;background:#f2f0e6;border-collapse:collapse"><tr><td align="center" style="padding:36px 16px"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="width:100%;max-width:600px;background:#fffef8;border:1px solid #d8d4c4;border-top:6px solid #d9ff43;border-radius:12px;border-collapse:separate"><tr><td style="padding:26px 34px 8px;font-family:Arial,sans-serif"><span style="font-size:13px;font-weight:800;letter-spacing:2px;color:#17251e">{{application_name}}</span></td></tr><tr><td style="padding:12px 34px 34px;font-family:Arial,sans-serif;color:#17251e"><p style="margin:0 0 12px;font-size:12px;font-weight:800;letter-spacing:1.5px;color:#657169">EMAIL VERIFICATION</p><h1 style="margin:0 0 16px;font-size:30px;line-height:1.15">Verify your email</h1><p style="margin:0 0 18px;font-size:16px;line-height:1.6;color:#4a564f">Confirm your email address to finish setting up your {{application_name}} account.</p><div style="margin:0 0 20px;padding:16px 18px;background:#f1f3e8;border:1px solid #d9ddca;border-radius:8px"><p style="margin:0 0 6px;font-size:11px;font-weight:800;letter-spacing:1.5px;color:#657169">VERIFICATION CODE</p><p style="margin:0;font-family:Courier New,monospace;font-size:25px;font-weight:700;letter-spacing:4px;color:#17251e">{{code}}</p></div><a href="{{magic_link}}" style="display:inline-block;padding:13px 20px;background:#17251e;color:#ffffff;text-decoration:none;font-size:15px;font-weight:700;border-radius:7px">Verify email</a><p style="margin:22px 0 0;font-size:13px;line-height:1.5;color:#657169">The code and link expire in {{expires_minutes}} minutes.</p></td></tr><tr><td style="padding:18px 34px;background:#f8f6ee;border-top:1px solid #e2dfd2;font-family:Arial,sans-serif"><p style="margin:0;font-size:12px;line-height:1.5;color:#747d77">If you did not create this account, you can safely ignore this email.</p></td></tr></table></td></tr></table>$email$,'{"required": ["code", "magic_link", "expires_minutes"], "properties": {"code": {"type": "string", "title": "Verification code", "example": "AB12CD34"}, "magic_link": {"type": "string", "title": "Verification link", "example": "https://app.example/auth/callback"}, "expires_minutes": {"type": "integer", "title": "Expiry in minutes", "example": 10}}}'::jsonb,'published',true),
    (NULL,'platform93.workspace_invitation','en','security',1,'Invitation to {{workspace_name}} in {{application_name}}','You were invited to join {{workspace_name}} in {{application_name}}.

Code: {{invitation_code}}

Accept invitation: {{invitation_link}}

Roles: {{role_keys}}

Expires at: {{expires_at}}.',$email$<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="width:100%;background:#f2f0e6;border-collapse:collapse"><tr><td align="center" style="padding:36px 16px"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="width:100%;max-width:600px;background:#fffef8;border:1px solid #d8d4c4;border-top:6px solid #d9ff43;border-radius:12px;border-collapse:separate"><tr><td style="padding:26px 34px 8px;font-family:Arial,sans-serif"><span style="font-size:13px;font-weight:800;letter-spacing:2px;color:#17251e">{{application_name}}</span></td></tr><tr><td style="padding:12px 34px 34px;font-family:Arial,sans-serif;color:#17251e"><p style="margin:0 0 12px;font-size:12px;font-weight:800;letter-spacing:1.5px;color:#657169">WORKSPACE INVITATION</p><h1 style="margin:0 0 16px;font-size:30px;line-height:1.15">Join {{workspace_name}}</h1><p style="margin:0 0 18px;font-size:16px;line-height:1.6;color:#4a564f">You were invited to join <strong style="color:#17251e">{{workspace_name}}</strong> in {{application_name}} with access: {{role_keys}}.</p><div style="margin:0 0 20px;padding:16px 18px;background:#f1f3e8;border:1px solid #d9ddca;border-radius:8px"><p style="margin:0 0 6px;font-size:11px;font-weight:800;letter-spacing:1.5px;color:#657169">ONE-TIME CODE</p><p style="margin:0;font-family:Courier New,monospace;font-size:25px;font-weight:700;letter-spacing:4px;color:#17251e">{{invitation_code}}</p></div><a href="{{invitation_link}}" style="display:inline-block;padding:13px 20px;background:#17251e;color:#ffffff;text-decoration:none;font-size:15px;font-weight:700;border-radius:7px">Join workspace</a><p style="margin:22px 0 0;font-size:13px;line-height:1.5;color:#657169">This invitation expires at {{expires_at}}.</p></td></tr><tr><td style="padding:18px 34px;background:#f8f6ee;border-top:1px solid #e2dfd2;font-family:Arial,sans-serif"><p style="margin:0;font-size:12px;line-height:1.5;color:#747d77">If the button does not work, use the one-time code in the application. Powered by Platform93.</p></td></tr></table></td></tr></table>$email$,'{"required": ["workspace_id", "workspace_name", "role_keys", "invitation_code", "invitation_link", "expires_at"], "properties": {"role_keys": {"type": "string"}, "expires_at": {"type": "string"}, "inviter_name": {"type": "string"}, "workspace_id": {"type": "string"}, "workspace_name": {"type": "string"}, "invitation_code": {"type": "string"}, "invitation_link": {"type": "string"}}}'::jsonb,'published',true);
-- +goose StatementEnd

-- +goose Down
DROP TABLE IF EXISTS public.addresses, public.application_domains, public.application_invitations, public.application_secrets, public.applications, public.audit_exports, public.audit_records, public.auth_provider_configs, public.auth_rate_limits, public.billing_customers, public.billing_profiles, public.checkout_sessions, public.clients, public.control_user_external_auth_challenges, public.control_user_identities, public.control_user_invitations, public.delegations, public.disputes, public.domain_events, public.entitlement_grant_actions, public.entitlement_grants, public.event_type_definitions, public.external_auth_challenges, public.external_auth_exchanges, public.features, public.idempotency_records, public.installation_control_user_roles, public.installations, public.invitation_authorization_codes, public.invoices, public.local_entitlement_request_actions, public.local_entitlement_requests, public.login_challenges, public.management_clients, public.mfa_login_challenges, public.notification_attachments, public.notification_attempts, public.notification_preferences, public.notification_providers, public.notification_template_assets, public.notification_templates, public.notifications, public.oauth_client_assertion_jtis, public.oauth_consents, public.oauth_sessions, public.control_user_login_challenges, public.control_user_sessions, public.control_users, public.organization_memberships, public.organization_policies, public.organizations, public.outbox, public.payments, public.permission_grants, public.personal_api_keys, public.price_features, public.prices, public.product_features, public.products, public.provider_connections, public.provider_events, public.provider_mappings, public.reconciliation_runs, public.refunds, public.role_assignments, public.roles, public.sender_identities, public.signing_keys, public.storage_objects, public.storage_providers, public.subscriptions, public.user_authentication_methods, public.user_identities, public.user_recovery_codes, public.user_sessions, public.users, public.webauthn_ceremonies, public.webhook_deliveries, public.webhook_endpoints, public.workspace_memberships, public.workspaces CASCADE;
DROP FUNCTION IF EXISTS public.create_default_organization_policy() CASCADE;
DROP FUNCTION IF EXISTS public.enforce_application_subject() CASCADE;
DROP FUNCTION IF EXISTS public.enforce_notification_template_asset_scope() CASCADE;
DROP FUNCTION IF EXISTS public.enforce_permission_grant() CASCADE;
DROP FUNCTION IF EXISTS public.enforce_storage_object_scope() CASCADE;
DROP FUNCTION IF EXISTS public.enforce_workspace_owner_is_active_non_member() CASCADE;
DROP FUNCTION IF EXISTS public.enforce_workspace_owner_membership_separation() CASCADE;
DROP FUNCTION IF EXISTS public.prevent_inactive_workspace_owner() CASCADE;
DROP FUNCTION IF EXISTS public.workspace_accessible_to_user(uuid,uuid,uuid) CASCADE;
DROP FUNCTION IF EXISTS public.valid_permission_key(text) CASCADE;
DROP FUNCTION IF EXISTS public.valid_permission_keys(text[]) CASCADE;
DROP FUNCTION IF EXISTS public.valid_canonical_scope(uuid,text) CASCADE;
DROP FUNCTION IF EXISTS public.valid_canonical_scopes(uuid,text[],boolean) CASCADE;
