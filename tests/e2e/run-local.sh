#!/usr/bin/env bash
# Lance la démonstration complète contre un serveur AuxiPak neuf et éphémère :
# base PostgreSQL temporaire, données et clés de développement temporaires.
#
#   PG_ADMIN_URL=postgres://postgres:motdepasse@127.0.0.1:5432/postgres tests/e2e/run-local.sh
#
# Options : DEMO_MODE=native|files (voir demo.sh), BIN_DIR, PORT.
set -euo pipefail
# Les vérifications ci-dessous comparent les messages français du client.
export AUXIPAK_LANG=fr
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BIN_DIR="${BIN_DIR:-$ROOT/target/debug}"
PG_ADMIN_URL="${PG_ADMIN_URL:?PG_ADMIN_URL requis (connexion administrateur PostgreSQL)}"
PORT="${PORT:-18080}"
DB="auxipak_e2e_$$"
WORK="$(mktemp -d)"
DB_URL="${PG_ADMIN_URL%/*}/$DB"
SERVER_PID=""
cleanup() {
  [[ -n "$SERVER_PID" ]] && kill "$SERVER_PID" 2>/dev/null && wait "$SERVER_PID" 2>/dev/null || true
  psql "$PG_ADMIN_URL" -qc "DROP DATABASE IF EXISTS $DB" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT
psql "$PG_ADMIN_URL" -qc "CREATE DATABASE $DB"

export AUXIPAK_ENV=development
export AUXIPAK_DATABASE_URL="$DB_URL"
export AUXIPAK_BIND="127.0.0.1:$PORT"
export AUXIPAK_PUBLIC_URL="http://127.0.0.1:$PORT"
export AUXIPAK_DATA_DIR="$WORK/data"
export AUXIPAK_KEYS_DIR="$WORK/keys"
export AUXIPAK_DEV_AUTO_KEYS=1
ADMIN_PASSWORD="Demo-Admin-$RANDOM-$RANDOM"
AUXIPAK_ADMIN_PASSWORD="$ADMIN_PASSWORD" "$BIN_DIR/auxipak-server" create-admin --username admin >/dev/null
"$BIN_DIR/auxipak-server" serve >"$WORK/server.log" 2>&1 &
SERVER_PID=$!
for _ in $(seq 1 60); do
  curl -fsS "http://127.0.0.1:$PORT/api/v1/health" >/dev/null 2>&1 && break
  sleep 0.5
done
curl -fsS "http://127.0.0.1:$PORT/api/v1/health" >/dev/null || { cat "$WORK/server.log"; exit 1; }

AUXIPAK_URL="http://127.0.0.1:$PORT" ADMIN_PASSWORD="$ADMIN_PASSWORD" KEYS_DIR="$AUXIPAK_KEYS_DIR" BIN_DIR="$BIN_DIR" \
  "$ROOT/tests/e2e/demo.sh"
