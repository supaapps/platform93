-- +goose Up
ALTER TABLE checkout_sessions ADD COLUMN provider_request JSONB;
ALTER TABLE checkout_sessions ADD COLUMN request_key TEXT;
ALTER TABLE checkout_sessions ADD COLUMN request_hash BYTEA;
-- Older binaries did not record a provider request before sending it. Never
-- infer that these unresolved outcomes are safe to retry as new purchases.
UPDATE checkout_sessions SET provider_request='{"legacy_unknown":true}'
WHERE status='pending' AND provider_session_id IS NULL;
CREATE TABLE billing_subject_cancellations (
 application_id UUID NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
 subject_type TEXT NOT NULL CHECK(subject_type='workspace'),
 subject_id UUID NOT NULL,
 operation_id UUID NOT NULL,
 at_period_end BOOLEAN NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 PRIMARY KEY(application_id,subject_type,subject_id),
 FOREIGN KEY(application_id,subject_id) REFERENCES workspaces(application_id,id) ON DELETE CASCADE
);
-- +goose Down
DROP TABLE billing_subject_cancellations;
ALTER TABLE checkout_sessions DROP COLUMN provider_request;
ALTER TABLE checkout_sessions DROP COLUMN request_key;
ALTER TABLE checkout_sessions DROP COLUMN request_hash;
