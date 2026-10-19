#!/usr/bin/env bash
# Restauration d'AuxiPak Server à partir d'une sauvegarde produite par backup.sh.
#   ./restore.sh /srv/sauvegardes/auxipak-20261019T020000Z
# ATTENTION : remplace la base et les données actuelles.
set -euo pipefail
SRC="${1:?répertoire de sauvegarde requis}"
COMPOSE=(docker compose -f "$(dirname "$0")/../docker-compose.yml" --env-file "${ENV_FILE:-$(dirname "$0")/../.env}")
(cd "$SRC" && sha256sum -c SHA256SUMS)
read -r -p "Remplacer la base et les données actuelles ? Tapez RESTAURER : " ok
[[ "$ok" == RESTAURER ]] || { echo "abandon"; exit 1; }
"${COMPOSE[@]}" stop server
"${COMPOSE[@]}" exec -T db pg_restore -U auxipak -d auxipak --clean --if-exists < "$SRC/database.dump"
"${COMPOSE[@]}" run --rm --no-deps --entrypoint sh server -c 'find /var/lib/auxipak-server -mindepth 1 -delete && tar -C /var/lib/auxipak-server -xf -' < "$SRC/data.tar"
"${COMPOSE[@]}" start server
# Nouvelle génération signée (versions TUF croissantes, horodatage frais).
"${COMPOSE[@]}" exec -T server auxipak-server regenerate --repository official
echo "Restauration terminée."
