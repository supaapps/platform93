-- +goose Up
-- Upgrade only byte-for-byte original defaults; retain all customized versions.
WITH originals AS (
  SELECT t.* FROM notification_templates t JOIN (VALUES
    ('platform93.application_sign_in','1b1360a405efffcb016394cfcbebadc2'),
    ('platform93.control_user_sign_in','8ad1d833b13926471af6e638c03f234c'),
    ('platform93.verify_email','4636a9bac5024df7d217f14b8c603c9b'),
    ('platform93.change_email','e0d9dd83ca1239b71b01e8102c5435d4'),
    ('platform93.password_reset','630f1f81e1063da7926fc8bb5b03621e')
  ) expected(key,fingerprint) ON t.key=expected.key
  WHERE t.application_id IS NULL AND t.system_managed AND t.status='published'
    AND md5(t.subject_template || t.text_template || t.html_template)=expected.fingerprint
), archived AS (
  UPDATE notification_templates t SET status='archived',updated_at=now()
  FROM originals o WHERE t.id=o.id RETURNING o.*
), versions AS (
  SELECT a.*,gen_random_uuid() AS new_id FROM archived a
)
INSERT INTO notification_templates
(id,application_id,key,locale,category,version,subject_template,text_template,html_template,variable_schema,status,system_managed)
SELECT a.new_id,NULL,a.key,a.locale,a.category,
  (SELECT max(version)+1 FROM notification_templates WHERE application_id IS NULL AND key=a.key AND locale=a.locale),
  CASE WHEN a.key='platform93.control_user_sign_in' THEN 'Your Platform93 sign-in' ELSE a.subject_template END,
  regexp_replace(
    replace(a.text_template,'Code: {{code}}','{{#if code}}Code: {{code}}{{/if}}'),
    '(Magic link|Confirmation link|Reset link|Verification link): \{\{magic_link\}\}',
    '{{#if magic_link}}\1: {{magic_link}}{{/if}}'),
  replace(replace(replace(replace(replace(
    regexp_replace(regexp_replace(a.html_template,
      '(<div[^>]*>.*?\{\{code\}\}.*?</div>)','{{#if code}}\1{{/if}}'),
      '(<a href="\{\{magic_link\}\}"[^>]*>.*?</a>)','{{#if magic_link}}\1{{/if}}'),
    'Use this one-time code or the secure link below to finish signing in.','Use the sign-in method below to continue.'),
    'Use this one-time code or secure link to access the Platform93 control panel.','Use the sign-in method below to access the Platform93 control panel.'),
    'Use this code or secure link to confirm the new email address for','Use the confirmation method below for'),
    'The code and link expire in','These credentials expire in'),
    'This confirmation expires in','These confirmation details expire in'),
  a.variable_schema || jsonb_build_object('x-platform93-delivery-source-id',a.id::text,'x-platform93-delivery-version-id',a.new_id::text),
  'published',true
FROM versions a;

-- +goose Down
-- Restore only defaults still published by this migration; never replace a
-- subsequently published customization or delete historical notification links.
WITH archived AS (
  UPDATE notification_templates SET status='archived',updated_at=now()
  WHERE application_id IS NULL AND system_managed AND status='published'
    AND variable_schema ? 'x-platform93-delivery-source-id'
    AND variable_schema->>'x-platform93-delivery-version-id'=id::text
  RETURNING variable_schema->>'x-platform93-delivery-source-id' AS source_id
)
UPDATE notification_templates t SET status='published',updated_at=now()
FROM archived a WHERE t.id::text=a.source_id AND t.status='archived';
