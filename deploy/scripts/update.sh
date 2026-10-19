#!/usr/bin/env bash
# Mise à jour du serveur (Docker Compose) : sauvegarde, reconstruction,
# migrations (appliquées automatiquement au démarrage), vérification.
#   ./update.sh /srv/sauvegardes
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
"$HERE/backup.sh" "${1:?répertoire de sauvegarde requis}"
COMPOSE=(docker compose -f "$HERE/../docker-compose.yml" --env-file "${ENV_FILE:-$HERE/../.env}")
git -C "$HERE/../.." pull --ff-only
"${COMPOSE[@]}" build server
"${COMPOSE[@]}" up -d server
for _ in $(seq 1 30); do
  curl -fsS http://127.0.0.1:8080/api/v1/health && { echo; echo "Mise à jour réussie."; exit 0; }
  sleep 2
done
echo "Le serveur ne répond pas : consultez « docker compose logs server »" >&2
exit 1
