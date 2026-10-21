-- +goose Up
-- Invitation credentials authorize onboarding, never authenticate the recipient.
ALTER TABLE application_invitations ADD COLUMN version bigint NOT NULL DEFAULT 1;
ALTER TABLE application_invitations ADD CONSTRAINT application_invitations_application_id_id_key UNIQUE(application_id,id);
ALTER TABLE application_invitations ALTER COLUMN last_sent_at DROP NOT NULL;
ALTER TABLE external_auth_challenges ADD COLUMN invitation_version bigint;
ALTER TABLE users ADD COLUMN authentication_epoch bigint NOT NULL DEFAULT 0;
ALTER TABLE mfa_login_challenges ADD COLUMN authentication_epoch bigint NOT NULL DEFAULT 0;
-- Old invitation-only exchanges cannot be redeemed after the new proof boundary.
UPDATE invitation_authorization_codes SET expires_at=LEAST(expires_at,now()) WHERE used_at IS NULL;

CREATE TABLE invitation_email_challenges (
 id uuid PRIMARY KEY,
 application_id uuid NOT NULL REFERENCES applications(id),
 invitation_id uuid NOT NULL,
 invitation_version bigint NOT NULL,
 code_challenge text NOT NULL,
 code_digest bytea NOT NULL,
 link_digest bytea NOT NULL,
 attempts integer NOT NULL DEFAULT 0,
 expires_at timestamptz NOT NULL,
 consumed_at timestamptz,
 FOREIGN KEY(application_id,invitation_id) REFERENCES application_invitations(application_id,id) ON DELETE CASCADE
);
CREATE INDEX invitation_email_challenges_invitation_idx ON invitation_email_challenges(invitation_id);

-- +goose Down
ALTER TABLE mfa_login_challenges DROP COLUMN authentication_epoch;
ALTER TABLE users DROP COLUMN authentication_epoch;
DROP TABLE invitation_email_challenges;
ALTER TABLE application_invitations DROP CONSTRAINT application_invitations_application_id_id_key;
ALTER TABLE external_auth_challenges DROP COLUMN invitation_version;
UPDATE application_invitations SET last_sent_at=created_at WHERE last_sent_at IS NULL;
ALTER TABLE application_invitations ALTER COLUMN last_sent_at SET NOT NULL;
ALTER TABLE application_invitations DROP COLUMN version;
