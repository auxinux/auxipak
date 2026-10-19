#!/usr/bin/env bash
# Création du premier administrateur (le mot de passe est saisi sans écho).
#   ./create-admin.sh admin
set -euo pipefail
USERNAME="${1:?identifiant requis}"
COMPOSE=(docker compose -f "$(dirname "$0")/../docker-compose.yml" --env-file "${ENV_FILE:-$(dirname "$0")/../.env}")
read -r -s -p "Mot de passe (12 caractères minimum) : " PW; echo
read -r -s -p "Confirmation : " PW2; echo
[[ "$PW" == "$PW2" ]] || { echo "les mots de passe diffèrent" >&2; exit 1; }
printf '%s\n' "$PW" | "${COMPOSE[@]}" exec -T server auxipak-server create-admin --username "$USERNAME"
