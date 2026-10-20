#!/usr/bin/env bash
# Démonstration fonctionnelle complète d'AuxiPak (section 19 du cahier des charges).
#
#  1. construction du paquet          8. téléchargement
#  2. validation du manifeste         9. vérification de signature
#  3. signature                      10. installation
#  4. publication locale             11. détection dans « auxipak list »
#  5. génération de l'INDEX          12. mise à niveau vers 1.1.0
#  6. synchronisation du client      13. désinstallation
#  7. recherche                      14. nettoyage
#
# Prérequis : un serveur AuxiPak en mode développement (AUXIPAK_URL), avec un
# compte administrateur ; binaires auxipak, auxipak-builder ; curl, jq, dpkg-deb.
#
# Variables :
#   AUXIPAK_URL         (défaut http://127.0.0.1:8080)
#   ADMIN_USER / ADMIN_PASSWORD   compte administrateur du serveur
#   KEYS_DIR            répertoire des clés du serveur (root.json, package-keys.json publics)
#   BIN_DIR             répertoire contenant auxipak et auxipak-builder
#   DEMO_MODE           « native » (défaut si root sur Debian/Ubuntu : installation .deb réelle via APT)
#                       ou « files » (profil AuxiNuxOS forcé : copie de fichiers, sans privilèges)
set -euo pipefail

URL="${AUXIPAK_URL:-http://127.0.0.1:8080}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:?ADMIN_PASSWORD requis}"
KEYS_DIR="${KEYS_DIR:?KEYS_DIR requis (root.json et package-keys.json du serveur)}"
BIN_DIR="${BIN_DIR:-$(cd "$(dirname "$0")/../.." && pwd)/target/debug}"
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
WORK="$(mktemp -d)"
export AUXIPAK_HOME="$WORK/client"
export AUXIPAK_BUILDER="$BIN_DIR/auxipak-builder"
AUXIPAK="$BIN_DIR/auxipak"
COOKIES="$WORK/cookies"
PASS=0
step() { echo; echo "=== $* ==="; }
ok() { echo "  ✔ $*"; PASS=$((PASS + 1)); }
fail() { echo "  ✘ $*" >&2; exit 1; }

if [[ -z "${DEMO_MODE:-}" ]]; then
  if [[ $EUID -eq 0 ]] && grep -qE '^ID(_LIKE)?=.*(debian|ubuntu)' /etc/os-release && command -v apt-get >/dev/null; then
    DEMO_MODE=native
  else
    DEMO_MODE=files
  fi
fi
if [[ "$DEMO_MODE" == files ]]; then
  # Profil AuxiNuxOS imposé : seule la détection est simulée, l'installation
  # (copie de fichiers dans AUXIPAK_HOME) est réelle.
  export AUXIPAK_PROFILE_OVERRIDE='{"os":"linux","distribution":"auxinuxos","version":"1.0","arch":"x86_64","raw_id":"auxinuxos","pretty_name":"AuxiNuxOS 1.0 (profil imposé pour la démonstration)","immutable":true}'
  [[ "$(uname -m)" == aarch64 ]] && export AUXIPAK_PROFILE_OVERRIDE="${AUXIPAK_PROFILE_OVERRIDE/x86_64/arm64}"
fi
echo "Mode de démonstration : $DEMO_MODE — répertoire de travail : $WORK"

api() { # méthode chemin [données JSON]
  local m="$1" p="$2"; shift 2
  curl -fsS -X "$m" -b "$COOKIES" -c "$COOKIES" -H "X-CSRF-Token: ${CSRF:-}" -H 'Content-Type: application/json' "$URL$p" "$@"
}

step "0. Préparation du serveur (comptes et jetons)"
LOGIN=$(curl -fsS -c "$COOKIES" -H 'Content-Type: application/json' -d "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASSWORD\"}" "$URL/api/v1/auth/login")
CSRF=$(jq -r .csrf_token <<<"$LOGIN")
PUB_USER="demo-publisher-$RANDOM"
PUB_ID=$(api POST /api/v1/admin/users -d "{\"username\":\"$PUB_USER\",\"password\":\"Publisher-Demo-$RANDOM!\",\"role\":\"publisher\"}" | jq -r .id)
AGENT_TOKEN=$(api POST /api/v1/admin/tokens -d "{\"name\":\"agent démo\",\"kind\":\"agent\",\"provider\":\"démonstration\",\"scopes\":[\"build\",\"submit\"],\"user_id\":\"$PUB_ID\",\"expires_days\":1}" | jq -r .token)
if [[ "$AGENT_TOKEN" == apk_* ]]; then ok "publieur $PUB_USER et jeton agent (build, submit) créés"; else fail "publieur $PUB_USER et jeton agent (build, submit) créés"; fi
# Un jeton agent ne peut jamais obtenir la portée review.
code=$(curl -s -o /dev/null -w '%{http_code}' -b "$COOKIES" -H "X-CSRF-Token: $CSRF" -H 'Content-Type: application/json' \
  -d "{\"name\":\"x\",\"kind\":\"agent\",\"scopes\":[\"review\"],\"user_id\":\"$PUB_ID\"}" "$URL/api/v1/admin/tokens")
if [[ "$code" == 400 ]]; then ok "refus d'un jeton agent avec la portée review (HTTP $code)"; else fail "refus d'un jeton agent avec la portée review (HTTP $code)"; fi

publish() { # version
  local v="$1"
  step "1-2. Construction et validation du paquet $v"
  local apak; aupak=$("$ROOT/examples/auxipak-demo/build.sh" "$v" "$WORK/dist" | tail -1)
  if "$AUXIPAK_BUILDER" validate "$aupak" >/dev/null; then ok "manifeste et archive valides : $(basename "$aupak")"; else fail "manifeste et archive valides : $(basename "$aupak")"; fi
  if "$AUXIPAK" verify "$aupak" >/dev/null; then ok "auxipak verify : structure conforme (aucune exécution)"; else fail "auxipak verify : structure conforme (aucune exécution)"; fi
  step "3-4. Soumission par l'agent puis approbation humaine (signature serveur)"
  local sub; sub=$("$AUXIPAK_BUILDER" --json submit "$aupak" --server "$URL" --token "$AGENT_TOKEN" --note "démonstration $v")
  local sid; sid=$(jq -r .id <<<"$sub")
  if [[ $(jq -r .status <<<"$sub") == pending ]]; then ok "demande $sid en attente (rien n'est publié)"; else fail "demande $sid en attente (rien n'est publié)"; fi
  code=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H "Authorization: Bearer $AGENT_TOKEN" "$URL/api/v1/submissions/$sid/approve")
  if [[ "$code" == 403 ]]; then ok "l'agent ne peut pas approuver sa propre demande (HTTP $code)"; else fail "l'agent ne peut pas approuver sa propre demande (HTTP $code)"; fi
  if api POST "/api/v1/submissions/$sid/approve" -d '{"note":"démonstration"}' >/dev/null; then ok "approuvée par $ADMIN_USER : paquet signé et publié"; else fail "approuvée par $ADMIN_USER : paquet signé et publié"; fi
  step "5. Génération de l'INDEX"
  if curl -fsS "$URL/index" | jq -e '.repositories[] | select(.name == "official") | .channels | length > 0' >/dev/null; then ok "/index liste les canaux du dépôt officiel"; else fail "/index liste les canaux du dépôt officiel"; fi
  if curl -fsS "$URL/repos/official/targets/apps.json" | jq -e '.apps[] | select(.id == "auxipak-demo")' >/dev/null; then ok "apps.json contient auxipak-demo"; else fail "apps.json contient auxipak-demo"; fi
}

publish 1.0.0

step "6. Configuration et synchronisation du client"
mkdir -p "$AUXIPAK_HOME/config/trust/official"
cp "$KEYS_DIR/root.json" "$KEYS_DIR/package-keys.json" "$AUXIPAK_HOME/config/trust/official/"
cat > "$AUXIPAK_HOME/config/config.toml" <<EOF
cache_ttl_seconds = 3600
language = "fr"

[[repository]]
name = "official"
url = "$URL/repos/official/"
root = "trust/official/root.json"
package_keys = "trust/official/package-keys.json"
official = true
allow_insecure_localhost = true
EOF
if "$AUXIPAK" update; then ok "index synchronisé (métadonnées TUF vérifiées)"; else fail "index synchronisé (métadonnées TUF vérifiées)"; fi

step "7. Recherche"
"$AUXIPAK" search demo | tee "$WORK/search.txt"
if grep -q "auxipak-demo" "$WORK/search.txt"; then ok "auxipak-demo trouvé"; else fail "auxipak-demo trouvé"; fi
if "$AUXIPAK" search demo --offline >/dev/null; then ok "recherche hors ligne depuis le cache validé"; else fail "recherche hors ligne depuis le cache validé"; fi
"$AUXIPAK" info auxipak-demo | grep -E "Statut|SHA-256|Signature" || true

step "8-10. Téléchargement, vérification de signature et installation"
"$AUXIPAK" install auxipak-demo | tee "$WORK/install.txt"
if grep -q "auxipak-demo 1.0.0 installé" "$WORK/install.txt"; then ok "installation 1.0.0"; else fail "installation 1.0.0"; fi
if [[ "$DEMO_MODE" == native ]]; then
  if dpkg-query -W -f='${Status} ${Version}\n' auxipak-demo | grep -q "install ok installed 1.0.0"; then ok "dpkg confirme auxipak-demo 1.0.0"; else fail "dpkg confirme auxipak-demo 1.0.0"; fi
  if /usr/bin/auxipak-demo | grep -q "1.0.0"; then ok "l'application installée s'exécute"; else fail "l'application installée s'exécute"; fi
else
  if "$AUXIPAK_HOME/bin/auxipak-demo" | grep -q "1.0.0"; then ok "l'application installée s'exécute"; else fail "l'application installée s'exécute"; fi
fi

step "11. Détection dans auxipak list"
"$AUXIPAK" list --check | tee "$WORK/list.txt"
if grep -q "auxipak-demo *1.0.0" "$WORK/list.txt"; then ok "auxipak-demo 1.0.0 listé"; else fail "auxipak-demo 1.0.0 listé"; fi

publish 1.1.0
step "12. Mise à niveau vers 1.1.0"
"$AUXIPAK" update >/dev/null
"$AUXIPAK" upgrade | tee "$WORK/upgrade.txt"
if grep -q "1.0.0 → 1.1.0" "$WORK/upgrade.txt"; then ok "mise à niveau effectuée"; else fail "mise à niveau effectuée"; fi
if [[ "$DEMO_MODE" == native ]]; then
  if /usr/bin/auxipak-demo | grep -q "1.1.0"; then ok "version 1.1.0 active"; else fail "version 1.1.0 active"; fi
else
  if "$AUXIPAK_HOME/bin/auxipak-demo" | grep -q "1.1.0"; then ok "version 1.1.0 active"; else fail "version 1.1.0 active"; fi
fi
if "$AUXIPAK" upgrade | grep -q "est à jour"; then ok "upgrade suivant : rien à faire"; else fail "upgrade suivant : rien à faire"; fi

step "Révocation (contrôle supplémentaire)"
REL=$(api GET "/api/v1/admin/releases?app_id=auxipak-demo" | jq -r '.[] | select(.version == "1.0.0") | .id')
api POST "/api/v1/admin/releases/$REL/state" -d '{"state":"revoked","reason":"démonstration de révocation"}' >/dev/null
"$AUXIPAK" update >/dev/null
if "$AUXIPAK" install auxipak-demo --version "=1.0.0" --reinstall 2>"$WORK/revoked.txt"; then fail "version révoquée installée"; fi
cat "$WORK/revoked.txt"
if grep -qi "révoqu" "$WORK/revoked.txt"; then ok "installation d'une version révoquée refusée"; else fail "installation d'une version révoquée refusée"; fi

step "13. Désinstallation"
"$AUXIPAK" remove auxipak-demo
if [[ "$DEMO_MODE" == native ]]; then
  if ! dpkg-query -W -f='${Status}\n' auxipak-demo 2>/dev/null | grep -q "install ok installed"; then ok "paquet Debian retiré"; else fail "paquet Debian retiré"; fi
else
  if [[ ! -e "$AUXIPAK_HOME/bin/auxipak-demo" ]]; then ok "fichiers retirés"; else fail "fichiers retirés"; fi
fi
if "$AUXIPAK" list | grep -q "Aucune application"; then ok "registre vide"; else fail "registre vide"; fi

step "14. Nettoyage"
"$AUXIPAK" clean --all
if [[ -z "$(ls -A "$AUXIPAK_HOME/cache/packages" 2>/dev/null)" ]]; then ok "cache des paquets vidé"; else fail "cache des paquets vidé"; fi
api POST /api/v1/auth/logout >/dev/null || true
rm -rf "$WORK"
echo
echo "DÉMONSTRATION RÉUSSIE ($PASS vérifications, mode $DEMO_MODE)"
