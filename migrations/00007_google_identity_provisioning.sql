-- +goose Up
INSERT INTO event_type_definitions(id,application_id,name,description,schema_version,source,status,example_subject,data_schema,example_data,version)
VALUES(gen_random_uuid(),NULL,'user.identity.provisioned','An administrator provisioned a Google identity without sending a notification.','1.0','platform93','active',
'user/01900000-0000-7000-8000-000000000004',
'{"type":"object","required":["user_id","identity_id","provider","created_user"],"properties":{"user_id":{"type":"string","format":"uuid"},"identity_id":{"type":"string","format":"uuid"},"provider":{"const":"google"},"created_user":{"type":"boolean"}},"additionalProperties":false}'::jsonb,
'{"user_id":"01900000-0000-7000-8000-000000000004","identity_id":"01900000-0000-7000-8000-000000000005","provider":"google","created_user":true}'::jsonb,1);

-- +goose Down
DELETE FROM event_type_definitions WHERE application_id IS NULL AND name='user.identity.provisioned' AND schema_version='1.0' AND source='platform93';
