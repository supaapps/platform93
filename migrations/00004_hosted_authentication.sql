-- +goose Up
ALTER TABLE clients ADD COLUMN authorization_ui text NOT NULL DEFAULT 'headless'
  CHECK (authorization_ui IN ('headless','hosted'));
ALTER TABLE clients ADD COLUMN pkce_required boolean NOT NULL DEFAULT true;
ALTER TABLE clients ADD COLUMN initiate_login_uri text NOT NULL DEFAULT '';
ALTER TABLE user_sessions ADD CONSTRAINT user_sessions_application_identity UNIQUE(application_id,id);
ALTER TABLE application_invitations ADD COLUMN hosted_client_id uuid;
ALTER TABLE application_invitations ADD COLUMN hosted_redirect_uri text;
ALTER TABLE application_invitations ADD CONSTRAINT invitations_hosted_pair CHECK ((hosted_client_id IS NULL)=(hosted_redirect_uri IS NULL));
ALTER TABLE application_invitations ADD CONSTRAINT invitations_hosted_client FOREIGN KEY(application_id,hosted_client_id) REFERENCES clients(application_id,id);
ALTER TABLE clients ADD CONSTRAINT clients_hosted_policy CHECK
  ((authorization_ui='headless' OR (client_type IN ('public','confidential') AND
    (cardinality(allowed_grants)=0 OR 'authorization_code'=ANY(allowed_grants)))) AND
   (pkce_required OR client_type='confidential'));

CREATE TABLE hosted_auth_branding (
  scope_type text NOT NULL CHECK(scope_type IN ('installation','organization','application')),
  scope_id uuid NOT NULL,
  configuration jsonb NOT NULL DEFAULT '{}' CHECK(jsonb_typeof(configuration)='object'),
  version bigint NOT NULL DEFAULT 1,
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(scope_type,scope_id)
);
CREATE TABLE hosted_auth_interactions (
  id uuid PRIMARY KEY,
  application_id uuid NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
  client_id uuid NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
  browser_digest bytea NOT NULL,
  csrf_digest bytea NOT NULL,
  authorization_parameters jsonb NOT NULL,
  pkce_required boolean NOT NULL,
  private_state_ciphertext text NOT NULL,
  session_id uuid REFERENCES user_sessions(id) ON DELETE CASCADE,
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  locked_until timestamptz,
  lock_token uuid,
  created_at timestamptz NOT NULL DEFAULT now()
  ,FOREIGN KEY(application_id,client_id) REFERENCES clients(application_id,id) ON DELETE CASCADE
  ,FOREIGN KEY(application_id,session_id) REFERENCES user_sessions(application_id,id) ON DELETE CASCADE
);
CREATE INDEX hosted_auth_interactions_expiry ON hosted_auth_interactions(expires_at);
CREATE TABLE hosted_auth_sessions (
  id uuid PRIMARY KEY,
  application_id uuid NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
  session_id uuid NOT NULL REFERENCES user_sessions(id) ON DELETE CASCADE,
  browser_digest bytea NOT NULL,
  credential_ciphertext text NOT NULL,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(application_id,browser_digest)
  ,FOREIGN KEY(application_id,session_id) REFERENCES user_sessions(application_id,id) ON DELETE CASCADE
);

CREATE INDEX hosted_auth_sessions_expiry ON hosted_auth_sessions(expires_at);

-- +goose Down
DROP TABLE hosted_auth_sessions;
DROP TABLE hosted_auth_interactions;
DROP TABLE hosted_auth_branding;
ALTER TABLE application_invitations DROP CONSTRAINT invitations_hosted_client;
ALTER TABLE application_invitations DROP CONSTRAINT invitations_hosted_pair;
ALTER TABLE application_invitations DROP COLUMN hosted_client_id;
ALTER TABLE application_invitations DROP COLUMN hosted_redirect_uri;
ALTER TABLE user_sessions DROP CONSTRAINT user_sessions_application_identity;
ALTER TABLE clients DROP COLUMN initiate_login_uri;
ALTER TABLE clients DROP CONSTRAINT clients_hosted_policy;
ALTER TABLE clients DROP COLUMN pkce_required;
ALTER TABLE clients DROP COLUMN authorization_ui;
