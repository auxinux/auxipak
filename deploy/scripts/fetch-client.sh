#!/usr/bin/env bash
# Publie les binaires du client sur ce serveur (servis par /downloads/ et
# utilisés par install.sh / install.ps1).
#
#   ./fetch-client.sh v1.0.0          # branche client-dist (git, clé SSH du dépôt),
#                                     # sinon release GitHub publiée
#   GITHUB_TOKEN=… ./fetch-client.sh v1.0.0   # API GitHub (dépôt privé, brouillon)
#   ./fetch-client.sh ~/release-dir   # depuis un dossier (archives + SHA256SUMS)
#   AUXIPAK_VERIFY_ATTESTATIONS=1 …   # vérifie aussi les attestations (gh requis)
#
# Seules les archives du client (auxipak-<version>-<plateforme>.tar.gz|zip)
# sont retenues ; chaque empreinte SHA-256 est vérifiée avant publication.
set -euo pipefail
# shellcheck source=i18n.sh
. "$(dirname "$0")/i18n.sh"
need "${1:-}" "étiquette (ex. v1.0.0) ou dossier requis" "tag (e.g. v1.0.0) or directory required"
SRC="$1"
REPO="${AUXIPAK_GITHUB_REPO:-auxinux/auxipak}"
DEST="${AUXIPAK_DOWNLOADS_HOST_DIR:-$(cd "$(dirname "$0")/.." && pwd)/downloads}"
REPO_DIR="$(cd "$(dirname "$0")/../.." && pwd)"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

if [[ -d "$SRC" ]]; then
  get() { cp "$SRC/$1" "$tmp/$1"; }
elif [[ -n "${GITHUB_TOKEN:-}" ]]; then
  # Dépôt privé (ou brouillon) : API GitHub avec un jeton en lecture seule
  # (jeton « fine-grained », permission Contents: Read sur le dépôt).
  [[ "$SRC" =~ ^v[0-9A-Za-z._-]+$ ]] || die "étiquette invalide : $SRC" "invalid tag: $SRC"
  auth=(-H "Authorization: Bearer $GITHUB_TOKEN" -H "X-GitHub-Api-Version: 2022-11-28")
  curl -fsSL "${auth[@]}" -H "Accept: application/vnd.github+json" \
    "https://api.github.com/repos/$REPO/releases?per_page=100" -o "$tmp/releases.json" \
    || die "API GitHub inaccessible (jeton valide ?)" "GitHub API unreachable (valid token?)"
  get() {
    local id
    id=$(python3 - "$tmp/releases.json" "$SRC" "$1" <<'PY'
import json, sys
rels, tag, name = json.load(open(sys.argv[1])), sys.argv[2], sys.argv[3]
for r in rels:
    if r.get("tag_name") == tag:
        for a in r.get("assets", []):
            if a.get("name") == name:
                print(a["id"]); sys.exit(0)
sys.exit(1)
PY
) || return 1
    curl -fsSL --retry 3 "${auth[@]}" -H "Accept: application/octet-stream" \
      -o "$tmp/$1" "https://api.github.com/repos/$REPO/releases/assets/$id"
  }
elif [[ "$SRC" =~ ^v[0-9A-Za-z._-]+$ ]] && git -C "$REPO_DIR" fetch -q --depth 1 origin client-dist 2>/dev/null; then
  # Branche client-dist, avec l'accès git déjà configuré pour ce dépôt.
  rev=$(git -C "$REPO_DIR" rev-parse FETCH_HEAD)
  msg "Binaires lus dans la branche client-dist (${rev:0:12})" "Binaries read from the client-dist branch (${rev:0:12})"
  get() { git -C "$REPO_DIR" cat-file -e "$rev:$1" 2>/dev/null && git -C "$REPO_DIR" show "$rev:$1" > "$tmp/$1"; }
else
  [[ "$SRC" =~ ^v[0-9A-Za-z._-]+$ ]] || die "étiquette invalide : $SRC" "invalid tag: $SRC"
  base="https://github.com/$REPO/releases/download/$SRC"
  get() { curl -fsSL --retry 3 -o "$tmp/$1" "$base/$1"; }
fi

get SHA256SUMS || die "SHA256SUMS introuvable (release publiée ? dépôt privé : définir GITHUB_TOKEN)" \
  "SHA256SUMS not found (release published? private repository: set GITHUB_TOKEN)"
awk '{ f = $2; sub(/^\*/, "", f)
       if ($1 ~ /^[0-9a-fA-F]{64}$/ && f ~ /^auxipak-[A-Za-z0-9._-]+\.(tar\.gz|zip)$/) print $1 "  " f }' \
  "$tmp/SHA256SUMS" > "$tmp/SUMS"
if [[ ! -d "$SRC" ]]; then
  grep -F "  auxipak-$SRC-" "$tmp/SUMS" > "$tmp/SUMS.tag" || true
  mv "$tmp/SUMS.tag" "$tmp/SUMS"
fi
[[ -s "$tmp/SUMS" ]] || die "aucune archive du client $SRC dans SHA256SUMS" "no $SRC client archive in SHA256SUMS"

while read -r _ f; do
  msg "Téléchargement de $f" "Downloading $f"
  get "$f" || die "archive introuvable : $f" "archive not found: $f"
done < "$tmp/SUMS"
(cd "$tmp" && sha256sum -c --quiet SUMS) || die "empreinte SHA-256 invalide" "invalid SHA-256 fingerprint"
msg "Empreintes SHA-256 vérifiées." "SHA-256 fingerprints verified."

if [[ "${AUXIPAK_VERIFY_ATTESTATIONS:-0}" == 1 ]]; then
  command -v gh >/dev/null 2>&1 || die "gh est requis pour AUXIPAK_VERIFY_ATTESTATIONS=1" "gh is required for AUXIPAK_VERIFY_ATTESTATIONS=1"
  while read -r _ f; do
    gh attestation verify "$tmp/$f" --repo "$REPO" >/dev/null || die "attestation de provenance invalide : $f" "invalid provenance attestation: $f"
  done < "$tmp/SUMS"
  msg "Attestations de provenance vérifiées." "Provenance attestations verified."
fi

mkdir -p "$DEST"
find "$DEST" -maxdepth 1 -type f \( -name 'auxipak-*' -o -name SHA256SUMS \) -delete
while read -r _ f; do install -m 0644 "$tmp/$f" "$DEST/$f"; done < "$tmp/SUMS"
install -m 0644 "$tmp/SUMS" "$DEST/SHA256SUMS"
msg "Client publié dans $DEST :" "Client published in $DEST:"
sed 's/^/  /' "$DEST/SHA256SUMS"
