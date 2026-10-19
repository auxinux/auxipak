#!/usr/bin/env bash
# Publie les binaires du client sur ce serveur (servis par /downloads/ et
# utilisés par install.sh / install.ps1).
#
#   ./fetch-client.sh v1.0.0          # depuis une release GitHub publiée
#   ./fetch-client.sh ~/release-dir   # depuis un dossier (archives + SHA256SUMS)
#
# Seules les archives du client (auxipak-<version>-<plateforme>.tar.gz|zip)
# sont retenues ; chaque empreinte SHA-256 est vérifiée avant publication.
set -euo pipefail
SRC="${1:?étiquette (ex. v1.0.0) ou dossier requis}"
REPO="${AUXIPAK_GITHUB_REPO:-auxinux/auxipak}"
DEST="${AUXIPAK_DOWNLOADS_HOST_DIR:-$(cd "$(dirname "$0")/.." && pwd)/downloads}"
die() { echo "erreur : $*" >&2; exit 1; }

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

if [[ -d "$SRC" ]]; then
  get() { cp "$SRC/$1" "$tmp/$1"; }
else
  [[ "$SRC" =~ ^v[0-9A-Za-z._-]+$ ]] || die "étiquette invalide : $SRC"
  base="https://github.com/$REPO/releases/download/$SRC"
  get() { curl -fsSL --retry 3 -o "$tmp/$1" "$base/$1"; }
fi

get SHA256SUMS || die "SHA256SUMS introuvable (la release est-elle publiée ?)"
awk '{ f = $2; sub(/^\*/, "", f)
       if ($1 ~ /^[0-9a-fA-F]{64}$/ && f ~ /^auxipak-[A-Za-z0-9._-]+\.(tar\.gz|zip)$/) print $1 "  " f }' \
  "$tmp/SHA256SUMS" > "$tmp/SUMS"
[[ -s "$tmp/SUMS" ]] || die "aucune archive du client dans SHA256SUMS"

while read -r _ f; do
  echo "Téléchargement de $f"
  get "$f" || die "archive introuvable : $f"
done < "$tmp/SUMS"
(cd "$tmp" && sha256sum -c --quiet SUMS) || die "empreinte SHA-256 invalide"
echo "Empreintes SHA-256 vérifiées."

if command -v gh >/dev/null 2>&1 && [[ ! -d "$SRC" ]]; then
  while read -r _ f; do
    gh attestation verify "$tmp/$f" --repo "$REPO" >/dev/null || die "attestation de provenance invalide : $f"
  done < "$tmp/SUMS"
  echo "Attestations de provenance vérifiées."
fi

mkdir -p "$DEST"
find "$DEST" -maxdepth 1 -type f \( -name 'auxipak-*' -o -name SHA256SUMS \) -delete
while read -r _ f; do install -m 0644 "$tmp/$f" "$DEST/$f"; done < "$tmp/SUMS"
install -m 0644 "$tmp/SUMS" "$DEST/SHA256SUMS"
echo "Client publié dans $DEST :"
sed 's/^/  /' "$DEST/SHA256SUMS"
