import type { generated } from "../src/index.js";

const price: generated.Price = {
  id: "01900000-0000-7000-8000-000000000001",
  key: "monthly",
  mode: "recurring",
  currency: "EUR",
  currency_exponent: 2,
  tax_behavior: "inclusive",
  checkout_config: {},
  entitlement_config: {},
  active: true,
  features: [{ feature_id: "01900000-0000-7000-8000-000000000002", key: "projects", quantity_value: 10 }],
};
const active: boolean = price.active;
const snapshots: generated.CatalogFeatureSnapshot[] = price.features;
void [active, snapshots];
