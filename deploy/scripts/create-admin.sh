#!/usr/bin/env bash
# Création du premier administrateur (le mot de passe est saisi sans écho).
#   ./create-admin.sh admin
set -euo pipefail
# shellcheck source=i18n.sh
. "$(dirname "$0")/i18n.sh"
need "${1:-}" "identifiant requis" "username required"
USERNAME="$1"
COMPOSE=(docker compose -f "$(dirname "$0")/../docker-compose.yml" --env-file "${ENV_FILE:-$(dirname "$0")/../.env}")
read -r -s -p "$(t "Mot de passe (12 caractères minimum) : " "Password (at least 12 characters): ")" PW; echo
read -r -s -p "$(t "Confirmation : " "Confirm: ")" PW2; echo
[[ "$PW" == "$PW2" ]] || die "les mots de passe diffèrent" "the passwords do not match"
printf '%s\n' "$PW" | "${COMPOSE[@]}" exec -T server auxipak-server create-admin --username "$USERNAME"
