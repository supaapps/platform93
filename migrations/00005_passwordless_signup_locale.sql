-- +goose Up
ALTER TABLE login_challenges ADD COLUMN locale text NOT NULL DEFAULT ''
  CHECK (length(locale) <= 35);

-- +goose Down
ALTER TABLE login_challenges DROP COLUMN locale;
