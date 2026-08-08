-- +goose Up
ALTER TABLE operators ADD COLUMN password_hash text;

-- +goose Down
ALTER TABLE operators DROP COLUMN password_hash;
