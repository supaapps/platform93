-- +goose Up
ALTER TABLE subscriptions ADD COLUMN past_due_since TIMESTAMPTZ;
ALTER TABLE subscriptions ADD COLUMN provider_event_at TIMESTAMPTZ;
UPDATE subscriptions SET past_due_since=LEAST(COALESCE(current_period_start,updated_at),now()) WHERE status='past_due';
-- +goose Down
ALTER TABLE subscriptions DROP COLUMN past_due_since;
ALTER TABLE subscriptions DROP COLUMN provider_event_at;
