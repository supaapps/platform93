-- +goose Up
ALTER TABLE features DROP CONSTRAINT features_value_type_check;
ALTER TABLE features ADD COLUMN free_form_format text;
UPDATE features SET value_type = 'free_form', free_form_format = 'json' WHERE value_type = 'configuration';
ALTER TABLE features ADD CONSTRAINT features_value_type_check CHECK (value_type IN ('boolean','quantity','free_form'));
ALTER TABLE features ADD CONSTRAINT features_free_form_format_check CHECK (
    (value_type = 'free_form' AND free_form_format IN ('text','csv','json')) OR
    (value_type <> 'free_form' AND free_form_format IS NULL)
);

ALTER TABLE product_features RENAME COLUMN configuration_value TO free_form_value;
ALTER TABLE price_features RENAME COLUMN configuration_value TO free_form_value;

-- +goose Down
ALTER TABLE price_features RENAME COLUMN free_form_value TO configuration_value;
ALTER TABLE product_features RENAME COLUMN free_form_value TO configuration_value;

ALTER TABLE features DROP CONSTRAINT features_free_form_format_check;
ALTER TABLE features DROP CONSTRAINT features_value_type_check;
UPDATE features SET value_type = 'configuration' WHERE value_type = 'free_form';
ALTER TABLE features DROP COLUMN free_form_format;
ALTER TABLE features ADD CONSTRAINT features_value_type_check CHECK (value_type IN ('boolean','quantity','configuration'));
