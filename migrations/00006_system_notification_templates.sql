-- +goose Up
ALTER TABLE notification_templates
    ALTER COLUMN application_id DROP NOT NULL,
    ADD COLUMN system_managed boolean NOT NULL DEFAULT false;
ALTER TABLE notification_templates
    DROP CONSTRAINT notification_templates_application_id_key_locale_version_key;
WITH ranked_published AS (
    SELECT id,row_number() OVER (PARTITION BY application_id,key,locale ORDER BY version DESC,updated_at DESC,id DESC) AS position
    FROM notification_templates WHERE status='published'
)
UPDATE notification_templates SET status='archived',updated_at=now()
WHERE id IN (SELECT id FROM ranked_published WHERE position>1);
CREATE UNIQUE INDEX notification_templates_installation_version
    ON notification_templates(key,locale,version) WHERE application_id IS NULL;
CREATE UNIQUE INDEX notification_templates_application_version
    ON notification_templates(application_id,key,locale,version) WHERE application_id IS NOT NULL;
CREATE UNIQUE INDEX notification_templates_installation_published
    ON notification_templates(key,locale) WHERE application_id IS NULL AND status='published';
CREATE UNIQUE INDEX notification_templates_application_published
    ON notification_templates(application_id,key,locale) WHERE application_id IS NOT NULL AND status='published';

INSERT INTO notification_templates
(application_id,key,locale,category,version,subject_template,text_template,html_template,variable_schema,status,system_managed)
VALUES
(NULL,'platform93.operator_sign_in','en','security',1,
 'Your Platform93 sign-in code',
 E'A sign-in was requested for your Platform93 operator account.\n\nCode: {{code}}\n\nMagic link: {{magic_link}}\n\nThis credential expires in {{expires_minutes}} minutes. If you did not request it, ignore this message.',
 '<h1>Sign in to Platform93</h1><p>A sign-in was requested for your operator account.</p><p><strong>Code:</strong> {{code}}</p><p><a href="{{magic_link}}">Sign in securely</a></p><p>This credential expires in {{expires_minutes}} minutes. If you did not request it, ignore this message.</p>',
 '{"properties":{"code":{"type":"string","title":"Sign-in code","example":"AB12CD34"},"magic_link":{"type":"string","title":"Magic link","example":"https://platform93.example/?operator_challenge=true"},"expires_minutes":{"type":"integer","title":"Expiry in minutes","example":10}},"required":["code","magic_link","expires_minutes"]}',
 'published',true),
(NULL,'platform93.application_sign_in','en','security',1,
 'Sign in to {{application_name}}',
 E'A sign-in was requested for {{application_name}}.\n\nCode: {{code}}\n\nMagic link: {{magic_link}}\n\nThis credential expires in {{expires_minutes}} minutes. If you did not request it, ignore this message.',
 '<h1>Sign in to {{application_name}}</h1><p>Use the code or secure link below.</p><p><strong>Code:</strong> {{code}}</p><p><a href="{{magic_link}}">Continue signing in</a></p><p>This credential expires in {{expires_minutes}} minutes. If you did not request it, ignore this message.</p>',
 '{"properties":{"code":{"type":"string","title":"Sign-in code","example":"AB12CD34"},"magic_link":{"type":"string","title":"Magic link","example":"https://app.example/auth/callback"},"expires_minutes":{"type":"integer","title":"Expiry in minutes","example":10},"intent":{"type":"string","title":"Authentication intent","example":"sign_in"}},"required":["code","magic_link","expires_minutes","intent"]}',
 'published',true),
(NULL,'platform93.verify_email','en','security',1,
 'Verify your email for {{application_name}}',
 E'Confirm your email address for {{application_name}}.\n\nCode: {{code}}\n\nVerification link: {{magic_link}}\n\nThis credential expires in {{expires_minutes}} minutes.',
 '<h1>Verify your email</h1><p>Confirm your email address for {{application_name}}.</p><p><strong>Code:</strong> {{code}}</p><p><a href="{{magic_link}}">Verify email</a></p><p>This credential expires in {{expires_minutes}} minutes.</p>',
 '{"properties":{"code":{"type":"string","title":"Verification code","example":"AB12CD34"},"magic_link":{"type":"string","title":"Verification link","example":"https://app.example/auth/callback"},"expires_minutes":{"type":"integer","title":"Expiry in minutes","example":10}},"required":["code","magic_link","expires_minutes"]}',
 'published',true),
(NULL,'platform93.change_email','en','security',1,
 'Confirm your new email for {{application_name}}',
 E'Confirm this email address for {{application_name}}.\n\nCode: {{code}}\n\nConfirmation link: {{magic_link}}\n\nThis credential expires in {{expires_minutes}} minutes.',
 '<h1>Confirm your new email</h1><p>Confirm this email address for {{application_name}}.</p><p><strong>Code:</strong> {{code}}</p><p><a href="{{magic_link}}">Confirm email</a></p><p>This credential expires in {{expires_minutes}} minutes.</p>',
 '{"properties":{"code":{"type":"string","title":"Confirmation code","example":"AB12CD34"},"magic_link":{"type":"string","title":"Confirmation link","example":"https://app.example/auth/callback"},"expires_minutes":{"type":"integer","title":"Expiry in minutes","example":10}},"required":["code","magic_link","expires_minutes"]}',
 'published',true),
(NULL,'platform93.password_reset','en','security',1,
 'Reset your {{application_name}} password',
 E'A password reset was requested for {{application_name}}.\n\nCode: {{code}}\n\nReset link: {{magic_link}}\n\nThis credential expires in {{expires_minutes}} minutes. If you did not request it, ignore this message.',
 '<h1>Reset your password</h1><p>A password reset was requested for {{application_name}}.</p><p><strong>Code:</strong> {{code}}</p><p><a href="{{magic_link}}">Reset password</a></p><p>This credential expires in {{expires_minutes}} minutes. If you did not request it, ignore this message.</p>',
 '{"properties":{"code":{"type":"string","title":"Reset code","example":"AB12CD34"},"magic_link":{"type":"string","title":"Reset link","example":"https://app.example/auth/callback"},"expires_minutes":{"type":"integer","title":"Expiry in minutes","example":10}},"required":["code","magic_link","expires_minutes"]}',
 'published',true),
(NULL,'platform93.organization_invitation','en','security',1,
 'Invitation to administer {{organization_name}}',
 E'You were invited to administer {{organization_name}} as {{role}}.\n\nAccept invitation: {{invitation_link}}\n\nOne-time invitation code: {{invitation_token}}\n\nExpires at: {{expires_at}}\n\nIf you did not expect this invitation, ignore this message.',
 '<h1>Organization invitation</h1><p>You were invited to administer <strong>{{organization_name}}</strong> as {{role}}.</p><p><a href="{{invitation_link}}">Accept invitation</a></p><p><strong>One-time invitation code:</strong> {{invitation_token}}</p><p>Expires at {{expires_at}}.</p>',
 '{"properties":{"organization_name":{"type":"string","title":"Organization name","example":"Acme GmbH"},"role":{"type":"string","title":"Organization role","example":"admin"},"invitation_link":{"type":"string","title":"Invitation link","example":"https://platform93.example/?organization_invitation=true"},"invitation_token":{"type":"string","title":"One-time invitation code","example":"p93_org_invite_example"},"expires_at":{"type":"string","title":"Expiry time","example":"2026-08-15T12:00:00Z"}},"required":["organization_name","role","invitation_link","invitation_token","expires_at"]}',
 'published',true),
(NULL,'platform93.workspace_invitation','en','security',1,
 'Invitation to {{workspace_name}} in {{application_name}}',
 E'You were invited to join {{workspace_name}} in {{application_name}}.\n\nAccept invitation: {{invitation_link}}\n\nOne-time invitation code: {{invitation_token}}\n\nRoles: {{role_keys}}\n\nExpires at: {{expires_at}}\n\nIf you did not expect this invitation, ignore this message.',
 '<h1>Workspace invitation</h1><p>You were invited to join <strong>{{workspace_name}}</strong> in {{application_name}}.</p><p><a href="{{invitation_link}}">Accept invitation</a></p><p><strong>One-time invitation code:</strong> {{invitation_token}}</p><p>Roles: {{role_keys}}<br>Expires at {{expires_at}}.</p>',
 '{"properties":{"workspace_id":{"type":"string","title":"Workspace ID","example":"01993f4e-7ae1-7000-8000-000000000093"},"workspace_name":{"type":"string","title":"Workspace name","example":"Main workspace"},"role_keys":{"type":"string","title":"Workspace roles","example":"member"},"invitation_link":{"type":"string","title":"Invitation link","example":"https://app.example/invitations/accept"},"invitation_token":{"type":"string","title":"One-time invitation code","example":"p93_invite_example"},"expires_at":{"type":"string","title":"Expiry time","example":"2026-08-15T12:00:00Z"}},"required":["workspace_id","workspace_name","role_keys","invitation_link","invitation_token","expires_at"]}',
 'published',true);

-- +goose Down
DELETE FROM notification_templates WHERE application_id IS NULL;
DROP INDEX notification_templates_application_published;
DROP INDEX notification_templates_installation_published;
DROP INDEX notification_templates_application_version;
DROP INDEX notification_templates_installation_version;
ALTER TABLE notification_templates DROP COLUMN system_managed;
ALTER TABLE notification_templates ALTER COLUMN application_id SET NOT NULL;
ALTER TABLE notification_templates ADD CONSTRAINT notification_templates_application_id_key_locale_version_key
    UNIQUE(application_id,key,locale,version);
