#!/usr/bin/env bash
# Mise à jour du serveur (Docker Compose) : sauvegarde, reconstruction,
# migrations (appliquées automatiquement au démarrage), vérification.
#   ./update.sh /srv/sauvegardes
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=i18n.sh
. "$HERE/i18n.sh"
need "${1:-}" "répertoire de sauvegarde requis" "backup directory required"
"$HERE/backup.sh" "$1"
COMPOSE=(docker compose -f "$HERE/../docker-compose.yml" --env-file "${ENV_FILE:-$HERE/../.env}")
git -C "$HERE/../.." pull --ff-only
"${COMPOSE[@]}" build server
"${COMPOSE[@]}" up -d server
for _ in $(seq 1 30); do
  curl -fsS http://127.0.0.1:8080/api/v1/health && { echo; msg "Mise à jour réussie." "Update successful."; exit 0; }
  sleep 2
done
die "le serveur ne répond pas : consultez « docker compose logs server »" "the server does not respond: see 'docker compose logs server'"
