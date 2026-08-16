# Upgrades

Platform93 uses forward-only application migrations during normal upgrades. Before an
upgrade, retain a tested PostgreSQL backup, the matching installation master key, the
current image digest, and the current Helm values.

```sh
platform93 backup /backups/pre-upgrade.dump
helm get values platform93 -n platform93 -o yaml > platform93-values.yaml
helm upgrade platform93 oci://ghcr.io/supaapps/charts/platform93 \
  --namespace platform93 --version TARGET_VERSION --reuse-values
kubectl -n platform93 wait --for=condition=complete job/platform93-migrate --timeout=5m
kubectl -n platform93 rollout status deployment/platform93-api
kubectl -n platform93 exec deployment/platform93-api -- /app/platform93 doctor
```

An application rollback is safe only when the target release supports the database
schema left by the newer release. If the release notes do not explicitly say so, restore
the pre-upgrade database backup and deploy the prior image together while all Platform93
processes are stopped.

## Alpha installations

The schemas published before `v0.1.0` are development snapshots and are not migration
targets. Recreate alpha databases, bootstrap a fresh installation, and configure the
required organizations, applications, users, providers, products, and roles again.
Platform93 does not automatically import data from older Supaapps installations and
does not adopt existing Stripe products, prices, customers, or subscriptions.

After `v0.1.0`, `migrations/00001_foundation.sql` is permanent history and must never be
edited or squashed. Every schema change requires a new numbered migration.
