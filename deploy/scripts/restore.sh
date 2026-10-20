#!/usr/bin/env bash
# Restauration d'AuxiPak Server à partir d'une sauvegarde produite par backup.sh.
#   ./restore.sh /srv/sauvegardes/auxipak-20261019T020000Z
# ATTENTION : remplace la base et les données actuelles.
set -euo pipefail
# shellcheck source=i18n.sh
. "$(dirname "$0")/i18n.sh"
need "${1:-}" "répertoire de sauvegarde requis" "backup directory required"
SRC="$1"
COMPOSE=(docker compose -f "$(dirname "$0")/../docker-compose.yml" --env-file "${ENV_FILE:-$(dirname "$0")/../.env}")
(cd "$SRC" && sha256sum -c SHA256SUMS)
WORD="$(t RESTAURER RESTORE)"
read -r -p "$(t "Remplacer la base et les données actuelles ? Tapez $WORD : " "Replace the current database and data? Type $WORD: ")" ok
[[ "$ok" == "$WORD" ]] || die "abandon" "aborted"
"${COMPOSE[@]}" stop server
"${COMPOSE[@]}" exec -T db pg_restore -U auxipak -d auxipak --clean --if-exists < "$SRC/database.dump"
"${COMPOSE[@]}" run --rm --no-deps --entrypoint sh server -c 'find /var/lib/auxipak-server -mindepth 1 -delete && tar -C /var/lib/auxipak-server -xf -' < "$SRC/data.tar"
"${COMPOSE[@]}" start server
# Nouvelle génération signée (versions TUF croissantes, horodatage frais).
"${COMPOSE[@]}" exec -T server auxipak-server regenerate --repository official
msg "Restauration terminée." "Restore complete."
