-- +goose Up
ALTER TABLE subscriptions ADD COLUMN past_due_since TIMESTAMPTZ;
UPDATE subscriptions SET past_due_since=LEAST(COALESCE(current_period_start,updated_at),now()) WHERE status='past_due';
-- +goose Down
ALTER TABLE subscriptions DROP COLUMN past_due_since;
