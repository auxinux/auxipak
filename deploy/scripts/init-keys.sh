#!/usr/bin/env bash
# Initialisation sécurisée des clés d'un dépôt AuxiPak (cérémonie de clés).
#
# À exécuter sur un poste HORS LIGNE et de confiance, jamais sur le serveur :
#   ./init-keys.sh /media/cle-chiffree/auxipak-keys
# Produit :
#   <dir>/offline/root.pem          clé racine TUF — reste hors ligne
#   <dir>/server-keys/              à transférer sur le serveur (AUXIPAK_KEYS_DIR)
#   <dir>/client-trust/             à distribuer avec le client (root.json, package-keys.json)
set -euo pipefail
# shellcheck source=i18n.sh
. "$(dirname "$0")/i18n.sh"
need "${1:-}" "répertoire de sortie requis (support chiffré hors ligne)" "output directory required (encrypted offline medium)"
OUT="$1"
OWNER="${OWNER:-AuxiNux}"
BUILDER="${AUXIPAK_BUILDER:-auxipak-builder}"
umask 077
if [[ -e "$OUT" && -n "$(ls -A "$OUT" 2>/dev/null)" ]]; then
  die "$OUT n'est pas vide" "$OUT is not empty"
fi
"$BUILDER" keys init-repository --out "$OUT/set" --owner "$OWNER"
mkdir -p "$OUT/server-keys" "$OUT/client-trust" "$OUT/offline"
cp "$OUT/set/public/root.json" "$OUT/set/public/package-keys.json" "$OUT/server-keys/"
cp "$OUT/set/online/"*.pem "$OUT/server-keys/"
cp "$OUT/set/public/root.json" "$OUT/set/public/package-keys.json" "$OUT/client-trust/"
mv "$OUT/set/offline/root.pem" "$OUT/offline/root.pem"
rm -rf "$OUT/set"
chmod 600 "$OUT/server-keys/"*.pem "$OUT/offline/root.pem"
chmod 644 "$OUT/server-keys/"*.json "$OUT/client-trust/"*.json
echo
msg "Empreinte de root.json (à publier par un canal indépendant) :" "root.json fingerprint (publish it through an independent channel):"
sha256sum "$OUT/client-trust/root.json"
if [[ "$FR" == 1 ]]; then
cat <<MSG

Étapes suivantes :
 1. Transférer $OUT/server-keys/ vers le serveur (ex. /etc/auxipak-server/keys),
    puis : chown -R 10001:10001 (Docker) ou auxipak:auxipak (natif), fichiers .pem en 0600.
 2. Intégrer $OUT/client-trust/ au client (AUXIPAK_OFFICIAL_TRUST_DIR à la compilation
    ou /etc/auxipak/trust/official/ sur les systèmes cibles).
 3. Conserver $OUT/offline/root.pem HORS LIGNE (deux copies chiffrées, coffre).
MSG
else
cat <<MSG

Next steps:
 1. Transfer $OUT/server-keys/ to the server (e.g. /etc/auxipak-server/keys),
    then: chown -R 10001:10001 (Docker) or auxipak:auxipak (native), .pem files in 0600.
 2. Ship $OUT/client-trust/ with the client (AUXIPAK_OFFICIAL_TRUST_DIR at build time
    or /etc/auxipak/trust/official/ on target systems).
 3. Keep $OUT/offline/root.pem OFFLINE (two encrypted copies, in a safe).
MSG
fi
