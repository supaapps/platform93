-- +goose Up
ALTER TABLE notification_providers
    ADD COLUMN organization_id uuid REFERENCES organizations(id),
    ADD COLUMN inheritable boolean NOT NULL DEFAULT false;
UPDATE notification_providers SET inheritable=true WHERE application_id IS NULL;
ALTER TABLE notification_providers ADD CONSTRAINT notification_provider_scope_check CHECK (
    (application_id IS NOT NULL AND organization_id IS NULL) OR
    (application_id IS NULL AND organization_id IS NOT NULL) OR
    (application_id IS NULL AND organization_id IS NULL)
);
CREATE INDEX notification_providers_effective_scope
    ON notification_providers(provider,application_id,organization_id,inheritable) WHERE disabled_at IS NULL;

ALTER TABLE sender_identities ADD COLUMN organization_id uuid REFERENCES organizations(id);

ALTER TABLE billing_customers DROP CONSTRAINT billing_customer_provider_application_fk;
ALTER TABLE checkout_sessions DROP CONSTRAINT checkout_provider_application_fk;
ALTER TABLE subscriptions DROP CONSTRAINT subscription_provider_application_fk;
ALTER TABLE invoices DROP CONSTRAINT invoice_provider_application_fk;
ALTER TABLE payments DROP CONSTRAINT payment_provider_application_fk;
ALTER TABLE refunds DROP CONSTRAINT refund_provider_application_fk;
ALTER TABLE disputes DROP CONSTRAINT dispute_provider_application_fk;
ALTER TABLE reconciliation_runs DROP CONSTRAINT reconciliation_provider_application_fk;
ALTER TABLE provider_events DROP CONSTRAINT provider_event_connection_application_fk;
DROP INDEX provider_connections_application_identity;

ALTER TABLE provider_connections
    ALTER COLUMN application_id DROP NOT NULL,
    ADD COLUMN organization_id uuid REFERENCES organizations(id),
    ADD COLUMN inheritable boolean NOT NULL DEFAULT false;
ALTER TABLE provider_connections ADD CONSTRAINT billing_provider_scope_check CHECK (
    (application_id IS NOT NULL AND organization_id IS NULL) OR
    (application_id IS NULL AND organization_id IS NOT NULL) OR
    (application_id IS NULL AND organization_id IS NULL)
);
CREATE INDEX provider_connections_effective_scope
    ON provider_connections(provider,application_id,organization_id,inheritable) WHERE status<>'disabled';

CREATE TABLE auth_provider_configs (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid REFERENCES organizations(id),
    application_id uuid REFERENCES applications(id),
    provider text NOT NULL CHECK (provider IN ('google','apple')),
    client_id text NOT NULL,
    config_ciphertext text NOT NULL,
    metadata jsonb NOT NULL DEFAULT '{}',
    inheritable boolean NOT NULL DEFAULT false,
    disabled_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CHECK (
        (application_id IS NOT NULL AND organization_id IS NULL) OR
        (application_id IS NULL AND organization_id IS NOT NULL) OR
        (application_id IS NULL AND organization_id IS NULL)
    )
);
CREATE UNIQUE INDEX auth_provider_configs_installation_unique
    ON auth_provider_configs(provider) WHERE application_id IS NULL AND organization_id IS NULL AND disabled_at IS NULL;
CREATE UNIQUE INDEX auth_provider_configs_organization_unique
    ON auth_provider_configs(organization_id,provider) WHERE organization_id IS NOT NULL AND disabled_at IS NULL;
CREATE UNIQUE INDEX auth_provider_configs_application_unique
    ON auth_provider_configs(application_id,provider) WHERE application_id IS NOT NULL AND disabled_at IS NULL;
CREATE INDEX auth_provider_configs_effective_scope
    ON auth_provider_configs(provider,application_id,organization_id,inheritable) WHERE disabled_at IS NULL;

-- +goose Down
DROP TABLE auth_provider_configs;
DROP INDEX provider_connections_effective_scope;
ALTER TABLE provider_connections DROP CONSTRAINT billing_provider_scope_check;
ALTER TABLE provider_connections DROP COLUMN inheritable, DROP COLUMN organization_id;
ALTER TABLE provider_connections ALTER COLUMN application_id SET NOT NULL;
CREATE UNIQUE INDEX provider_connections_application_identity ON provider_connections(application_id,id);
ALTER TABLE billing_customers ADD CONSTRAINT billing_customer_provider_application_fk FOREIGN KEY(application_id,provider_connection_id) REFERENCES provider_connections(application_id,id);
ALTER TABLE checkout_sessions ADD CONSTRAINT checkout_provider_application_fk FOREIGN KEY(application_id,provider_connection_id) REFERENCES provider_connections(application_id,id);
ALTER TABLE subscriptions ADD CONSTRAINT subscription_provider_application_fk FOREIGN KEY(application_id,provider_connection_id) REFERENCES provider_connections(application_id,id);
ALTER TABLE invoices ADD CONSTRAINT invoice_provider_application_fk FOREIGN KEY(application_id,provider_connection_id) REFERENCES provider_connections(application_id,id);
ALTER TABLE payments ADD CONSTRAINT payment_provider_application_fk FOREIGN KEY(application_id,provider_connection_id) REFERENCES provider_connections(application_id,id);
ALTER TABLE refunds ADD CONSTRAINT refund_provider_application_fk FOREIGN KEY(application_id,provider_connection_id) REFERENCES provider_connections(application_id,id);
ALTER TABLE disputes ADD CONSTRAINT dispute_provider_application_fk FOREIGN KEY(application_id,provider_connection_id) REFERENCES provider_connections(application_id,id);
ALTER TABLE reconciliation_runs ADD CONSTRAINT reconciliation_provider_application_fk FOREIGN KEY(application_id,provider_connection_id) REFERENCES provider_connections(application_id,id);
ALTER TABLE provider_events ADD CONSTRAINT provider_event_connection_application_fk FOREIGN KEY(application_id,provider_connection_id) REFERENCES provider_connections(application_id,id);
ALTER TABLE sender_identities DROP COLUMN organization_id;
DROP INDEX notification_providers_effective_scope;
ALTER TABLE notification_providers DROP CONSTRAINT notification_provider_scope_check;
ALTER TABLE notification_providers DROP COLUMN inheritable, DROP COLUMN organization_id;
