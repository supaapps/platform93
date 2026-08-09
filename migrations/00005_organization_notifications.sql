-- +goose Up
ALTER TABLE notifications
    ADD COLUMN organization_id uuid REFERENCES organizations(id),
    ADD CONSTRAINT notification_scope_check CHECK (application_id IS NULL OR organization_id IS NULL);
CREATE INDEX notifications_organization_queue
    ON notifications(organization_id,status,next_attempt_at) WHERE organization_id IS NOT NULL AND status IN ('queued','failed');

-- +goose Down
DROP INDEX notifications_organization_queue;
ALTER TABLE notifications DROP CONSTRAINT notification_scope_check, DROP COLUMN organization_id;
