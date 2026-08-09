-- +goose Up
ALTER TABLE event_type_definitions
    ADD COLUMN example_subject text NOT NULL DEFAULT 'resource/example',
    ADD COLUMN example_data jsonb NOT NULL DEFAULT '{}';

ALTER TABLE event_type_definitions ADD CONSTRAINT event_type_definition_contract_check CHECK (
    example_subject <> '' AND length(example_subject) <= 500 AND
    jsonb_typeof(data_schema) = 'object' AND jsonb_typeof(example_data) = 'object'
);

ALTER TABLE domain_events
    ADD COLUMN contract_source text NOT NULL DEFAULT 'platform93'
    CHECK (contract_source IN ('platform93','application'));

UPDATE domain_events e SET contract_source='application'
WHERE EXISTS (
    SELECT 1 FROM event_type_definitions d
    WHERE d.application_id=e.application_id AND d.name=e.event_type AND d.source='application'
);

UPDATE event_type_definitions SET name='platform93.webhook.test'
WHERE application_id IS NULL AND name='platform93.webhook.test.v1';
UPDATE domain_events SET event_type='platform93.webhook.test'
WHERE event_type='platform93.webhook.test.v1';
UPDATE webhook_endpoints SET event_filters=array_replace(event_filters,'platform93.webhook.test.v1','platform93.webhook.test')
WHERE 'platform93.webhook.test.v1'=ANY(event_filters);

INSERT INTO event_type_definitions(id,application_id,name,description,source) VALUES
(gen_random_uuid(),NULL,'organization.created','An organization was created.','platform93'),
(gen_random_uuid(),NULL,'organization.retired','An organization and its active applications were retired.','platform93'),
(gen_random_uuid(),NULL,'organization.restored','An organization was restored without restoring descendants.','platform93')
ON CONFLICT(application_id,name) DO NOTHING;

WITH contracts(name,example_subject,data_schema,example_data) AS (VALUES
('organization.created','organization/01900000-0000-7000-8000-000000000001','{"type":"object","required":["name","slug"],"properties":{"name":{"type":"string"},"slug":{"type":"string"}},"additionalProperties":false}'::jsonb,'{"name":"Example Organization","slug":"example-organization"}'::jsonb),
('organization.retired','organization/01900000-0000-7000-8000-000000000001','{"type":"object","required":["application_count"],"properties":{"application_count":{"type":"integer","minimum":0}},"additionalProperties":false}'::jsonb,'{"application_count":2}'::jsonb),
('organization.restored','organization/01900000-0000-7000-8000-000000000001','{"type":"object","required":["descendants_restored"],"properties":{"descendants_restored":{"type":"boolean"}},"additionalProperties":false}'::jsonb,'{"descendants_restored":false}'::jsonb),
('application.created','application/01900000-0000-7000-8000-000000000002','{"type":"object","required":["name","slug"],"properties":{"name":{"type":"string"},"slug":{"type":"string"}},"additionalProperties":false}'::jsonb,'{"name":"Production","slug":"production"}'::jsonb),
('application.retired','application/01900000-0000-7000-8000-000000000002','{"type":"object","required":["organization_id","reason"],"properties":{"organization_id":{"type":"string","format":"uuid"},"reason":{"type":"string"}},"additionalProperties":false}'::jsonb,'{"organization_id":"01900000-0000-7000-8000-000000000001","reason":"application_retired"}'::jsonb),
('application.restored','application/01900000-0000-7000-8000-000000000002','{"type":"object","required":["organization_id","reason"],"properties":{"organization_id":{"type":"string","format":"uuid"},"reason":{"type":"string"}},"additionalProperties":false}'::jsonb,'{"organization_id":"01900000-0000-7000-8000-000000000001","reason":"application_restored"}'::jsonb),
('delegation.created','delegation/01900000-0000-7000-8000-000000000003','{"type":"object","required":["delegation_id","user_id","workspace_id","permissions","reason","expires_at"],"properties":{"delegation_id":{"type":"string","format":"uuid"},"user_id":{"type":"string","format":"uuid"},"workspace_id":{"type":["string","null"],"format":"uuid"},"permissions":{"type":"array","items":{"type":"string"}},"reason":{"type":"string"},"expires_at":{"type":"string","format":"date-time"}},"additionalProperties":false}'::jsonb,'{"delegation_id":"01900000-0000-7000-8000-000000000003","user_id":"01900000-0000-7000-8000-000000000004","workspace_id":null,"permissions":["/applications/01900000-0000-7000-8000-000000000002/users/read"],"reason":"Investigate support request","expires_at":"2026-01-01T00:15:00Z"}'::jsonb),
('delegation.exchanged','delegation/01900000-0000-7000-8000-000000000003','{"type":"object","required":["delegation_id","user_id"],"properties":{"delegation_id":{"type":"string","format":"uuid"},"user_id":{"type":"string","format":"uuid"}},"additionalProperties":false}'::jsonb,'{"delegation_id":"01900000-0000-7000-8000-000000000003","user_id":"01900000-0000-7000-8000-000000000004"}'::jsonb),
('delegation.revoked','delegation/01900000-0000-7000-8000-000000000003','{"type":"object","required":["delegation_id"],"properties":{"delegation_id":{"type":"string","format":"uuid"}},"additionalProperties":false}'::jsonb,'{"delegation_id":"01900000-0000-7000-8000-000000000003"}'::jsonb),
('entitlement.granted','entitlement/01900000-0000-7000-8000-000000000005','{"type":"object","required":["grant_id","subject_type","subject_id","reason"],"properties":{"grant_id":{"type":"string","format":"uuid"},"subject_type":{"enum":["user","workspace"]},"subject_id":{"type":"string","format":"uuid"},"reason":{"type":"string"}},"additionalProperties":false}'::jsonb,'{"grant_id":"01900000-0000-7000-8000-000000000005","subject_type":"workspace","subject_id":"01900000-0000-7000-8000-000000000006","reason":"subscription"}'::jsonb),
('local_entitlement_request.created','local_entitlement_request/01900000-0000-7000-8000-000000000007','{"type":"object","required":["request_id","subject_type","subject_id","price_id"],"properties":{"request_id":{"type":"string","format":"uuid"},"subject_type":{"enum":["user","workspace"]},"subject_id":{"type":"string","format":"uuid"},"price_id":{"type":"string","format":"uuid"}},"additionalProperties":false}'::jsonb,'{"request_id":"01900000-0000-7000-8000-000000000007","subject_type":"user","subject_id":"01900000-0000-7000-8000-000000000004","price_id":"01900000-0000-7000-8000-000000000008"}'::jsonb),
('local_entitlement_request.approved','local_entitlement_request/01900000-0000-7000-8000-000000000007','{"type":"object","required":["request_id","grant_id"],"properties":{"request_id":{"type":"string","format":"uuid"},"grant_id":{"type":"string","format":"uuid"}},"additionalProperties":false}'::jsonb,'{"request_id":"01900000-0000-7000-8000-000000000007","grant_id":"01900000-0000-7000-8000-000000000005"}'::jsonb),
('oauth.consent_revoked','oauth_consent/01900000-0000-7000-8000-000000000004/01900000-0000-7000-8000-000000000009','{"type":"object","required":["user_id","client_id","client_key"],"properties":{"user_id":{"type":"string","format":"uuid"},"client_id":{"type":"string","format":"uuid"},"client_key":{"type":"string"}},"additionalProperties":false}'::jsonb,'{"user_id":"01900000-0000-7000-8000-000000000004","client_id":"01900000-0000-7000-8000-000000000009","client_key":"web"}'::jsonb),
('platform93.webhook.test','webhook/01900000-0000-7000-8000-000000000010','{"type":"object","required":["webhook_endpoint_id","test"],"properties":{"webhook_endpoint_id":{"type":"string","format":"uuid"},"test":{"const":true}},"additionalProperties":false}'::jsonb,'{"webhook_endpoint_id":"01900000-0000-7000-8000-000000000010","test":true}'::jsonb),
('user.created','user/01900000-0000-7000-8000-000000000004','{"type":"object","required":["user_id","email_verified","is_org_verified"],"properties":{"user_id":{"type":"string","format":"uuid"},"email_verified":{"type":"boolean"},"is_org_verified":{"type":"boolean"}},"additionalProperties":false}'::jsonb,'{"user_id":"01900000-0000-7000-8000-000000000004","email_verified":false,"is_org_verified":false}'::jsonb),
('user.email_verified','user/01900000-0000-7000-8000-000000000004','{"type":"object","required":["user_id","verified","reason"],"properties":{"user_id":{"type":"string","format":"uuid"},"verified":{"const":true},"reason":{"type":"string"}},"additionalProperties":false}'::jsonb,'{"user_id":"01900000-0000-7000-8000-000000000004","verified":true,"reason":"self_service"}'::jsonb),
('user.email_unverified','user/01900000-0000-7000-8000-000000000004','{"type":"object","required":["user_id","verified","reason"],"properties":{"user_id":{"type":"string","format":"uuid"},"verified":{"const":false},"reason":{"type":"string"}},"additionalProperties":false}'::jsonb,'{"user_id":"01900000-0000-7000-8000-000000000004","verified":false,"reason":"operator_request"}'::jsonb),
('user.organization_verified','user/01900000-0000-7000-8000-000000000004','{"type":"object","required":["user_id","verified","reason"],"properties":{"user_id":{"type":"string","format":"uuid"},"verified":{"const":true},"reason":{"type":"string"}},"additionalProperties":false}'::jsonb,'{"user_id":"01900000-0000-7000-8000-000000000004","verified":true,"reason":"organization_approved"}'::jsonb),
('user.organization_unverified','user/01900000-0000-7000-8000-000000000004','{"type":"object","required":["user_id","verified","reason"],"properties":{"user_id":{"type":"string","format":"uuid"},"verified":{"const":false},"reason":{"type":"string"}},"additionalProperties":false}'::jsonb,'{"user_id":"01900000-0000-7000-8000-000000000004","verified":false,"reason":"organization_review"}'::jsonb),
('user.email_changed','user/01900000-0000-7000-8000-000000000004','{"type":"object","required":["user_id"],"properties":{"user_id":{"type":"string","format":"uuid"}},"additionalProperties":false}'::jsonb,'{"user_id":"01900000-0000-7000-8000-000000000004"}'::jsonb),
('user.password_reset','user/01900000-0000-7000-8000-000000000004','{"type":"object","required":["user_id"],"properties":{"user_id":{"type":"string","format":"uuid"}},"additionalProperties":false}'::jsonb,'{"user_id":"01900000-0000-7000-8000-000000000004"}'::jsonb),
('user.pending_deletion','user/01900000-0000-7000-8000-000000000004','{"type":"object","required":["user_id"],"properties":{"user_id":{"type":"string","format":"uuid"}},"additionalProperties":false}'::jsonb,'{"user_id":"01900000-0000-7000-8000-000000000004"}'::jsonb),
('user.anonymized','user/01900000-0000-7000-8000-000000000004','{"type":"object","required":["user_id"],"properties":{"user_id":{"type":"string","format":"uuid"}},"additionalProperties":false}'::jsonb,'{"user_id":"01900000-0000-7000-8000-000000000004"}'::jsonb),
('user.deleted','user/01900000-0000-7000-8000-000000000004','{"type":"object","required":["user_id"],"properties":{"user_id":{"type":"string","format":"uuid"}},"additionalProperties":false}'::jsonb,'{"user_id":"01900000-0000-7000-8000-000000000004"}'::jsonb),
('user.suspended','user/01900000-0000-7000-8000-000000000004','{"type":"object","required":["user_id","reason"],"properties":{"user_id":{"type":"string","format":"uuid"},"reason":{"type":"string"}},"additionalProperties":false}'::jsonb,'{"user_id":"01900000-0000-7000-8000-000000000004","reason":"operator_request"}'::jsonb),
('user.restored','user/01900000-0000-7000-8000-000000000004','{"type":"object","required":["user_id","reason"],"properties":{"user_id":{"type":"string","format":"uuid"},"reason":{"type":"string"}},"additionalProperties":false}'::jsonb,'{"user_id":"01900000-0000-7000-8000-000000000004","reason":"operator_request"}'::jsonb),
('workspace.invitation_created','workspace_invitation/01900000-0000-7000-8000-000000000011','{"type":"object","required":["invitation_id","workspace_id","role_keys"],"properties":{"invitation_id":{"type":"string","format":"uuid"},"workspace_id":{"type":"string","format":"uuid"},"role_keys":{"type":"array","items":{"type":"string"}}},"additionalProperties":false}'::jsonb,'{"invitation_id":"01900000-0000-7000-8000-000000000011","workspace_id":"01900000-0000-7000-8000-000000000006","role_keys":["workspace_member"]}'::jsonb),
('workspace.invitation_accepted','workspace_invitation/01900000-0000-7000-8000-000000000011','{"type":"object","required":["invitation_id","workspace_id","user_id"],"properties":{"invitation_id":{"type":"string","format":"uuid"},"workspace_id":{"type":"string","format":"uuid"},"user_id":{"type":"string","format":"uuid"}},"additionalProperties":false}'::jsonb,'{"invitation_id":"01900000-0000-7000-8000-000000000011","workspace_id":"01900000-0000-7000-8000-000000000006","user_id":"01900000-0000-7000-8000-000000000004"}'::jsonb),
('workspace.owner_transferred','workspace/01900000-0000-7000-8000-000000000006','{"type":"object","required":["workspace_id","previous_owner_user_id","new_owner_user_id","previous_owner_disposition"],"properties":{"workspace_id":{"type":"string","format":"uuid"},"previous_owner_user_id":{"type":"string","format":"uuid"},"new_owner_user_id":{"type":"string","format":"uuid"},"previous_owner_disposition":{"enum":["member","remove"]}},"additionalProperties":false}'::jsonb,'{"workspace_id":"01900000-0000-7000-8000-000000000006","previous_owner_user_id":"01900000-0000-7000-8000-000000000004","new_owner_user_id":"01900000-0000-7000-8000-000000000012","previous_owner_disposition":"member"}'::jsonb)
)
UPDATE event_type_definitions d SET
    schema_version='1.0', example_subject=c.example_subject,
    data_schema=c.data_schema, example_data=c.example_data, updated_at=now()
FROM contracts c WHERE d.application_id IS NULL AND d.source='platform93' AND d.name=c.name;

-- +goose Down
UPDATE webhook_endpoints SET event_filters=array_replace(event_filters,'platform93.webhook.test','platform93.webhook.test.v1')
WHERE 'platform93.webhook.test'=ANY(event_filters);
UPDATE domain_events SET event_type='platform93.webhook.test.v1'
WHERE event_type='platform93.webhook.test';
UPDATE event_type_definitions SET name='platform93.webhook.test.v1'
WHERE application_id IS NULL AND name='platform93.webhook.test';
DELETE FROM event_type_definitions WHERE application_id IS NULL AND name IN ('organization.created','organization.retired','organization.restored');
ALTER TABLE domain_events DROP COLUMN contract_source;
ALTER TABLE event_type_definitions DROP CONSTRAINT event_type_definition_contract_check;
ALTER TABLE event_type_definitions DROP COLUMN example_data, DROP COLUMN example_subject;
