#!/usr/bin/env bash
# Sauvegarde d'AuxiPak Server (déploiement Docker Compose).
#   ./backup.sh /srv/sauvegardes
# Contenu : base PostgreSQL (pg_dump), données (paquets, dépôts, soumissions).
# Les clés privées ne sont PAS incluses : elles se sauvegardent séparément,
# chiffrées, selon docs/SIGNING.md.
set -euo pipefail
DEST="${1:?répertoire de destination requis}"
COMPOSE=(docker compose -f "$(dirname "$0")/../docker-compose.yml" --env-file "${ENV_FILE:-$(dirname "$0")/../.env}")
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$DEST/auxipak-$STAMP"
umask 077
mkdir -p "$OUT"
"${COMPOSE[@]}" exec -T db pg_dump -U auxipak -d auxipak --format=custom > "$OUT/database.dump"
"${COMPOSE[@]}" exec -T server tar -C /var/lib/auxipak-server -cf - . > "$OUT/data.tar"
sha256sum "$OUT"/* > "$OUT/SHA256SUMS"
echo "Sauvegarde : $OUT"
