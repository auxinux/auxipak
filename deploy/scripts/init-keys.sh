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
OUT="${1:?répertoire de sortie requis (support chiffré hors ligne)}"
OWNER="${OWNER:-AuxiNux}"
BUILDER="${AUXIPAK_BUILDER:-auxipak-builder}"
umask 077
if [[ -e "$OUT" && -n "$(ls -A "$OUT" 2>/dev/null)" ]]; then
  echo "erreur : $OUT n'est pas vide" >&2; exit 1
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
echo "Empreinte de root.json (à publier par un canal indépendant) :"
sha256sum "$OUT/client-trust/root.json"
cat <<MSG

Étapes suivantes :
 1. Transférer $OUT/server-keys/ vers le serveur (ex. /etc/auxipak-server/keys),
    puis : chown -R 10001:10001 (Docker) ou auxipak:auxipak (natif), fichiers .pem en 0600.
 2. Intégrer $OUT/client-trust/ au client (AUXIPAK_OFFICIAL_TRUST_DIR à la compilation
    ou /etc/auxipak/trust/official/ sur les systèmes cibles).
 3. Conserver $OUT/offline/root.pem HORS LIGNE (deux copies chiffrées, coffre).
MSG
