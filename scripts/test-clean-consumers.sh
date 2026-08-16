#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

mkdir -p "$WORK/npm/packages" "$WORK/npm/consumer"
for package in sdk auth expo react server events; do
  pnpm --dir "$ROOT/sdk/typescript/$package" pack --pack-destination "$WORK/npm/packages"
done
cd "$WORK/npm/consumer"
npm init -y >/dev/null
npm install "$WORK"/npm/packages/*.tgz >/dev/null
node --input-type=module <<'NODE'
for (const name of [
  "@supaapps/platform93-sdk",
  "@supaapps/platform93-auth",
  "@supaapps/platform93-expo",
  "@supaapps/platform93-react",
  "@supaapps/platform93-server",
  "@supaapps/platform93-events",
]) await import(name);
NODE

mkdir -p "$WORK/python/dist"
python -m build --outdir "$WORK/python/dist" "$ROOT/sdk/python/auth"
python -m build --outdir "$WORK/python/dist" "$ROOT/sdk/python/webhooks"
python -m venv "$WORK/python/venv"
"$WORK/python/venv/bin/pip" install "$WORK"/python/dist/*.whl >/dev/null
"$WORK/python/venv/bin/python" -c 'import platform93_auth, platform93_webhooks'

mkdir -p "$WORK/composer"
cat >"$WORK/composer/composer.json" <<JSON
{"repositories":[{"type":"path","url":"$ROOT","options":{"symlink":false}}],"require":{"supaapps/platform93":"@dev"},"minimum-stability":"dev","prefer-stable":true}
JSON
cd "$WORK/composer"
composer install --no-interaction --prefer-dist >/dev/null
php -r 'require "vendor/autoload.php"; new Supaapps\Platform93\MachineClient("https://example.test", "01900000-0000-7000-8000-000000000001", "client", "secret");'

mkdir -p "$WORK/go"
cat >"$WORK/go/go.mod" <<MOD
module platform93-consumer

go 1.25

require github.com/supaapps/platform93 v0.0.0
replace github.com/supaapps/platform93 => $ROOT
MOD
cat >"$WORK/go/main.go" <<'GO'
package main

import (
	_ "github.com/supaapps/platform93/sdk/go/auth"
	_ "github.com/supaapps/platform93/sdk/go/client"
	_ "github.com/supaapps/platform93/sdk/go/storage"
	_ "github.com/supaapps/platform93/sdk/go/webhooks"
)

func main() {}
GO
cd "$WORK/go"
go mod tidy
go build ./...
