#!/usr/bin/env bash
# Serveur de DÉVELOPPEMENT natif (sans Docker), avec PostgreSQL local :
#   DATABASE_URL=postgres://postgres:motdepasse@127.0.0.1:5432/auxipak deploy/scripts/dev-server.sh
# Clés de test générées automatiquement dans .dev/keys (jamais en production).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
export AUXIPAK_ENV=development
export AUXIPAK_DATABASE_URL="${DATABASE_URL:?DATABASE_URL requis}"
export AUXIPAK_BIND="${AUXIPAK_BIND:-127.0.0.1:8080}"
export AUXIPAK_PUBLIC_URL="${AUXIPAK_PUBLIC_URL:-http://$AUXIPAK_BIND}"
export AUXIPAK_DATA_DIR="$ROOT/.dev/data"
export AUXIPAK_KEYS_DIR="$ROOT/.dev/keys"
export AUXIPAK_DEV_AUTO_KEYS=1
cd "$ROOT"
cargo build -p auxipak-server
echo "Créer un administrateur : AUXIPAK_ENV=development AUXIPAK_DATABASE_URL=… target/debug/auxipak-server create-admin --username admin"
exec target/debug/auxipak-server serve
