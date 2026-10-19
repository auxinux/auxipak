#!/usr/bin/env bash
# Prépare le paquet AuxiPak de Firefox pour macOS (dernière version publiée).
#
#   ./make.sh            # → firefox-macos/ + Firefox-<version>-fr.apak
#   LANG_FF=en-US ./make.sh
#
# Le paquet ne contient pas Firefox : il référence l'image disque officielle
# de Mozilla (mode « remote ») avec son empreinte SHA-256, publiée par Mozilla
# dans SHA256SUMS. Le client vérifie cette empreinte avant toute installation.
set -euo pipefail
LANG_FF="${LANG_FF:-fr}"
OUT="$(pwd)/firefox-macos"
die() { echo "erreur : $*" >&2; exit 1; }
command -v auxipak-builder >/dev/null || die "auxipak-builder requis (install.sh --with-builder)"

v=$(curl -fsSL https://product-details.mozilla.org/1.0/firefox_versions.json \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["LATEST_FIREFOX_VERSION"])')
[[ "$v" =~ ^[0-9][0-9A-Za-z.]*$ ]] || die "version inattendue : $v"
base="https://download-installer.cdn.mozilla.net/pub/firefox/releases/$v"
rel="mac/$LANG_FF/Firefox $v.dmg"
sha=$(curl -fsSL "$base/SHA256SUMS" | awk -v f="$rel" 'substr($0, 67) == f { print $1 }')
[[ "$sha" =~ ^[0-9a-f]{64}$ ]] || die "empreinte introuvable pour $rel"
url="$base/mac/$LANG_FF/Firefox%20$v.dmg"
size=$(curl -fsSIL "$url" | awk 'tolower($1) == "content-length:" { n = $2 } END { gsub(/\r/, "", n); print n }')
[[ "$size" =~ ^[0-9]+$ ]] || die "taille introuvable pour $url"
echo "Firefox $v ($LANG_FF) — $size octets — sha256 $sha"

rm -rf "$OUT"
mkdir -p "$OUT"
cat > "$OUT/instruction.auxipak" <<YAML
format: 1
id: firefox
name: "Firefox"
version: "$v"
publisher: "Mozilla"
summary: "Navigateur Web libre et indépendant"
description: |
  Navigateur Web de la fondation Mozilla. Image disque officielle téléchargée
  depuis les serveurs de Mozilla et vérifiée par son empreinte SHA-256.
license: "MPL-2.0"
homepage: "https://www.mozilla.org/firefox/"
languages: [${LANG_FF%%-*}]
categories: [internet]
privacy:
  telemetry: opt_out
  details: "Télémétrie activée par défaut, désactivable dans les paramètres de Firefox."
targets:
  - name: macos
    platform: macos
    os_version: ">=10.15"
    architectures: [x86_64, arm64]
    mode: remote
    install:
      method: dmg
      app: Firefox.app
      source:
        url: "$url"
        sha256: "$sha"
        size: $size
        file_name: "Firefox-$v.dmg"
    permissions: [network, user_files]
YAML

auxipak-builder validate "$OUT"
auxipak-builder build "$OUT"
apak=$(ls -t Firefox-"$v"-*.apak | head -n 1)
auxipak-builder test "$apak"
echo
echo "Paquet prêt : $apak"
echo "Soumission : auxipak-builder submit \"$apak\" --repository official --note \"Firefox $v\""
