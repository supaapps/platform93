-- +goose Up
ALTER TABLE products ADD COLUMN entitlement_config jsonb NOT NULL DEFAULT '{}';

CREATE TABLE product_features (
    product_id uuid NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    feature_id uuid NOT NULL REFERENCES features(id),
    boolean_value boolean,
    quantity_value bigint,
    configuration_value jsonb,
    PRIMARY KEY (product_id, feature_id)
);

-- +goose Down
DROP TABLE IF EXISTS product_features;
ALTER TABLE products DROP COLUMN IF EXISTS entitlement_config;
