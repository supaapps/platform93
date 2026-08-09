-- +goose Up
CREATE TABLE event_type_definitions (
    id uuid PRIMARY KEY,
    application_id uuid REFERENCES applications(id),
    name text NOT NULL CHECK (name ~ '^[a-z][a-z0-9_-]*(\.[a-z][a-z0-9_-]*)+$'),
    description text NOT NULL DEFAULT '',
    schema_version text NOT NULL DEFAULT '1.0' CHECK (schema_version ~ '^[1-9][0-9]*\.[0-9]+$'),
    data_schema jsonb NOT NULL DEFAULT '{}',
    source text NOT NULL CHECK (source IN ('platform93','application')),
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active','archived')),
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE NULLS NOT DISTINCT (application_id,name),
    CHECK ((source='platform93' AND application_id IS NULL) OR (source='application' AND application_id IS NOT NULL))
);

INSERT INTO event_type_definitions(id,application_id,name,description,source) VALUES
(gen_random_uuid(),NULL,'application.created','An application was created.','platform93'),
(gen_random_uuid(),NULL,'application.retired','An application was retired.','platform93'),
(gen_random_uuid(),NULL,'application.restored','An application was restored.','platform93'),
(gen_random_uuid(),NULL,'delegation.created','Operator delegation was created.','platform93'),
(gen_random_uuid(),NULL,'delegation.exchanged','Operator delegation was exchanged.','platform93'),
(gen_random_uuid(),NULL,'delegation.revoked','Operator delegation was revoked.','platform93'),
(gen_random_uuid(),NULL,'entitlement.granted','An entitlement grant was created.','platform93'),
(gen_random_uuid(),NULL,'local_entitlement_request.approved','A local entitlement request was approved.','platform93'),
(gen_random_uuid(),NULL,'local_entitlement_request.created','A local entitlement request was created.','platform93'),
(gen_random_uuid(),NULL,'oauth.consent_revoked','OAuth consent was revoked.','platform93'),
(gen_random_uuid(),NULL,'platform93.webhook.test.v1','A targeted Platform93 webhook test was requested.','platform93'),
(gen_random_uuid(),NULL,'user.anonymized','A user account was anonymized.','platform93'),
(gen_random_uuid(),NULL,'user.created','A user account was created.','platform93'),
(gen_random_uuid(),NULL,'user.deleted','A user account was deleted.','platform93'),
(gen_random_uuid(),NULL,'user.email_changed','A user email address was changed.','platform93'),
(gen_random_uuid(),NULL,'user.email_unverified','A user email address was administratively unverified.','platform93'),
(gen_random_uuid(),NULL,'user.email_verified','A user email address was verified.','platform93'),
(gen_random_uuid(),NULL,'user.organization_unverified','Organization verification was removed from a user.','platform93'),
(gen_random_uuid(),NULL,'user.organization_verified','A user was verified for an organization.','platform93'),
(gen_random_uuid(),NULL,'user.password_reset','A user password was reset.','platform93'),
(gen_random_uuid(),NULL,'user.pending_deletion','A user account entered pending deletion.','platform93'),
(gen_random_uuid(),NULL,'user.restored','A suspended user was restored.','platform93'),
(gen_random_uuid(),NULL,'user.suspended','A user was suspended.','platform93'),
(gen_random_uuid(),NULL,'workspace.invitation_accepted','A workspace invitation was accepted.','platform93'),
(gen_random_uuid(),NULL,'workspace.invitation_created','A workspace invitation was created.','platform93'),
(gen_random_uuid(),NULL,'workspace.owner_transferred','Workspace ownership was transferred.','platform93');

INSERT INTO roles(id,application_id,key,name,scope,permissions,built_in)
SELECT gen_random_uuid(),id,'event_publisher','Event publisher','application',ARRAY['events:publish'],true
FROM applications ON CONFLICT(application_id,key) DO NOTHING;

-- +goose Down
DELETE FROM roles WHERE key='event_publisher' AND built_in=true;
DROP TABLE IF EXISTS event_type_definitions;
