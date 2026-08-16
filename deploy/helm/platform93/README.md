# Platform93 Helm Chart

The chart deploys the API, worker, dispatcher, migration job, optional backup job,
Service, Ingress, PodDisruptionBudgets, and NetworkPolicy. PostgreSQL 16 or newer is
external to the chart. No Redis, message broker, object store, or private image pull
secret is required for the public release image.

Create the required secrets before installation. The master key is the base64 text
representation of exactly 32 random bytes; it must remain unchanged for the lifetime
of the installation.

```sh
kubectl create namespace platform93
kubectl -n platform93 create secret generic platform93-database \
  --from-literal=database-url='postgres://USER:PASSWORD@HOST:5432/platform93?sslmode=require'
kubectl -n platform93 create secret generic platform93-master-key \
  --from-literal=master-key="$(openssl rand -base64 32)"
```

Install from GHCR with Traefik and a cert-manager issuer already present in the cluster:

```sh
helm install platform93 oci://ghcr.io/supaapps/charts/platform93 \
  --version 0.1.0 \
  --namespace platform93 \
  --set publicUrl=https://platform93.example.com \
  --set ingress.enabled=true \
  --set ingress.className=traefik \
  --set ingress.host=platform93.example.com \
  --set ingress.tlsSecret=platform93-tls \
  --set-string 'ingress.annotations.cert-manager\.io/cluster-issuer=letsencrypt-prod'
```

Wait for the migration job and all workloads before bootstrapping:

```sh
kubectl -n platform93 wait --for=condition=complete job/platform93-migrate --timeout=5m
kubectl -n platform93 rollout status deployment/platform93-api
kubectl -n platform93 exec deployment/platform93-api -- /app/platform93 bootstrap
```

Resource names are release-scoped. Multiple installations can share a namespace when
they use distinct Helm release names, database secrets, master-key secrets, hosts, and
databases. `nameOverride` and `fullnameOverride` are supported.

For upgrades, back up PostgreSQL and the master key, read the release notes, then run
`helm upgrade`. Never reuse a database between two active releases. See
[Backup and restore](../../../docs/backup-restore.md) and
[Upgrades](../../../docs/upgrades.md).
