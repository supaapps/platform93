-- +goose Up
ALTER TABLE users
    ADD COLUMN locale text NOT NULL DEFAULT '',
    ADD CONSTRAINT users_locale_length CHECK (length(locale) <= 35);

-- +goose Down
ALTER TABLE users
    DROP CONSTRAINT users_locale_length,
    DROP COLUMN locale;
