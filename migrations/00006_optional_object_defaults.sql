-- +goose Up
-- Earlier creation paths encoded omitted objects as JSON null, not SQL NULL.
-- Only repair that representation; preserve every supplied object and value.
UPDATE features SET metadata='{}'::jsonb WHERE metadata='null'::jsonb;
UPDATE products SET metadata='{}'::jsonb WHERE metadata='null'::jsonb;
UPDATE prices SET checkout_config='{}'::jsonb WHERE checkout_config='null'::jsonb;
UPDATE users SET custom_attributes='{}'::jsonb WHERE custom_attributes='null'::jsonb;
UPDATE notification_templates SET variable_schema='{}'::jsonb WHERE variable_schema='null'::jsonb;

-- +goose Down
-- A corrected empty object cannot be distinguished from an intentional one.
-- Keep the repaired data when rolling back rather than reintroducing nulls.
SELECT 1;
