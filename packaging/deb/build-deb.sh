#!/usr/bin/env bash
# Construit le paquet Debian du client AuxiPak (dpkg-deb, sans debhelper).
#
#   packaging/deb/build-deb.sh VERSION [--from-dir DIR] [--out DIR]
#
# Produit auxipak_VERSION_amd64.deb :
#   /usr/bin/auxipak                               client (seul ; pas le Builder)
#   /etc/auxipak/config.toml                       conffile : dépôt officiel
#                                                  + adaptateur auxi (AuxiNux OS)
#   /etc/auxipak/trust/official/root.json          ancres de confiance PUBLIQUES
#   /etc/auxipak/trust/official/package-keys.json  du dépôt officiel (conffiles)
#
# Le binaire vient :
#   - par défaut, de l'archive linux-x86_64 publiée sur le serveur
#     ($AUXIPAK_URL/downloads/, empreinte vérifiée avec SHA256SUMS) ;
#   - avec --from-dir DIR, de DIR/auxipak (target/release, artefact de CI,
#     archive extraite).
#
# Les dépendances (Depends) sont calculées sur le binaire lui-même (objdump) :
# bibliothèques NEEDED et version minimale de la glibc.
#
# Ce script ne publie rien : la mise en dépôt APT est une étape séparée.
set -euo pipefail

AUXIPAK_URL="${AUXIPAK_URL:-https://auxipak.auxinux.ca}"
# Empreinte de trust/official/root.json : celle qu'annonce install.sh
# (ROOT_SHA256) rendu par le serveur officiel, égale à
# $AUXIPAK_URL/repos/official/metadata/1.root.json.
ROOT_SHA256=1c5b557606d5786559ad52caba76f0759f842a90d3221736c75551ad867056af
MAINTAINER="AuxiNux <repo@auxinux.ca>"
HOMEPAGE="https://auxipak.auxinux.ca"
DEB_ARCH=amd64
PLATFORM=linux-x86_64

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "${HERE}/../.." && pwd)"

die() { printf 'build-deb.sh : %s\n' "$*" >&2; exit 1; }
usage() {
  sed -n '2,4p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  exit "${1:-0}"
}

VERSION=""
FROM_DIR=""
OUT_DIR="$(pwd)"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --from-dir) [[ $# -ge 2 ]] || die "--from-dir exige un répertoire"; FROM_DIR="$2"; shift 2 ;;
    --out) [[ $# -ge 2 ]] || die "--out exige un répertoire"; OUT_DIR="$2"; shift 2 ;;
    -h|--help) usage 0 ;;
    -*) die "option inconnue : $1" ;;
    *) [[ -z "${VERSION}" ]] || die "argument en trop : $1"; VERSION="$1"; shift ;;
  esac
done
[[ -n "${VERSION}" ]] || usage 64
VERSION="${VERSION#v}"
[[ "${VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+([~+][0-9A-Za-z.~+]+)?$ ]] || die "version invalide : ${VERSION}"

for tool in dpkg-deb objdump sha256sum md5sum tar; do
  command -v "${tool}" >/dev/null 2>&1 || die "outil requis introuvable : ${tool}"
done

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

# --- Binaire ----------------------------------------------------------------
if [[ -n "${FROM_DIR}" ]]; then
  BIN="${FROM_DIR}/auxipak"
  [[ -f "${BIN}" ]] || die "${BIN} introuvable"
else
  command -v curl >/dev/null 2>&1 || die "curl est requis (ou --from-dir)"
  archive="auxipak-v${VERSION}-${PLATFORM}.tar.gz"
  curl -fsSL --retry 3 -o "${WORK}/SHA256SUMS" "${AUXIPAK_URL}/downloads/SHA256SUMS" \
    || die "SHA256SUMS introuvable sur ${AUXIPAK_URL}/downloads/"
  expected="$(awk -v f="${archive}" '{ n = $2; sub(/^\*/, "", n) } n == f && length($1) == 64 { print tolower($1) }' \
    "${WORK}/SHA256SUMS" | tail -n 1)"
  [[ -n "${expected}" ]] || die "${archive} absent de ${AUXIPAK_URL}/downloads/SHA256SUMS (version non publiée ?)"
  curl -fsSL --retry 3 -o "${WORK}/${archive}" "${AUXIPAK_URL}/downloads/${archive}" \
    || die "téléchargement impossible : ${archive}"
  actual="$(sha256sum "${WORK}/${archive}" | awk '{print $1}')"
  [[ "${actual}" == "${expected}" ]] || die "empreinte invalide pour ${archive} (attendu ${expected}, obtenu ${actual})"
  echo "Empreinte SHA-256 vérifiée : ${archive}"
  mkdir "${WORK}/x"
  tar -xzf "${WORK}/${archive}" -C "${WORK}/x"
  BIN="${WORK}/x/${archive%.tar.gz}/auxipak"
  [[ -f "${BIN}" ]] || die "archive invalide : auxipak absent"
fi

# ELF x86-64 ?
objdump -f "${BIN}" 2>/dev/null | grep -q 'file format elf64-x86-64' || die "${BIN} n'est pas un binaire ELF x86-64"

# La version du binaire doit être celle du paquet (exécutable seulement sur
# un hôte x86-64).
if [[ "$(uname -m)" == x86_64 ]]; then
  got="$("${BIN}" --version 2>/dev/null || true)"
  [[ "${got}" == "auxipak ${VERSION}" ]] || die "le binaire annonce « ${got} », attendu « auxipak ${VERSION} »"
fi

# --- Dépendances réelles du binaire -------------------------------------------
depends=()
needed="$(objdump -p "${BIN}" | awk '$1 == "NEEDED" { print $2 }')"
if [[ -n "${needed}" ]]; then
  glibc="$(objdump -T "${BIN}" | grep -o 'GLIBC_[0-9][0-9.]*' | sed 's/GLIBC_//' | sort -uV | tail -n 1)"
  [[ -n "${glibc}" ]] || die "binaire dynamique sans symbole GLIBC_ : bibliothèque C inattendue"
  depends+=("libc6 (>= ${glibc})")
  for lib in ${needed}; do
    case "${lib}" in
      libc.so.6|libm.so.6|libpthread.so.0|libdl.so.2|librt.so.1|ld-linux-x86-64.so.2) ;;
      libgcc_s.so.1) depends+=("libgcc-s1") ;;
      *) die "dépendance inattendue du binaire : ${lib} (ajouter le paquet Debian correspondant)" ;;
    esac
  done
fi
DEPENDS="$(IFS=,; printf '%s' "${depends[*]}" | sed 's/,/, /g')"

# --- Arborescence -------------------------------------------------------------
R="${WORK}/root"
install -D -m 0755 "${BIN}" "${R}/usr/bin/auxipak"
install -D -m 0644 "${HERE}/config.toml" "${R}/etc/auxipak/config.toml"
for f in root.json package-keys.json; do
  install -D -m 0644 "${HERE}/trust/official/${f}" "${R}/etc/auxipak/trust/official/${f}"
done
got="$(sha256sum "${R}/etc/auxipak/trust/official/root.json" | awk '{print $1}')"
[[ "${got}" == "${ROOT_SHA256}" ]] || die "trust/official/root.json : empreinte ${got}, attendue ${ROOT_SHA256}"

doc="${R}/usr/share/doc/auxipak"
install -d -m 0755 "${doc}"
{
  echo "Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/"
  echo "Upstream-Name: AuxiPak"
  echo "Source: https://github.com/auxinux/auxipak"
  echo
  echo "Files: *"
  echo "Copyright: AuxiNux"
  echo "License: GPL-3.0"
  echo " Le texte complet de la licence suit."
  echo " ."
  sed -e 's/^$/./' -e 's/^/ /' "${REPO}/LICENSE"
} >"${doc}/copyright"
chmod 0644 "${doc}/copyright"

install -d -m 0755 "${R}/DEBIAN"
(cd "${R}" && find etc -type f | sort | sed 's|^|/|') >"${R}/DEBIAN/conffiles"

cat >"${R}/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
# Un client installé auparavant par install.sh (/usr/local/bin) passerait
# devant celui du paquet dans le PATH.
if [ "$1" = configure ] && [ -x /usr/local/bin/auxipak ]; then
  echo "AuxiPak : /usr/local/bin/auxipak (install.sh) masque /usr/bin/auxipak ;" >&2
  echo "          le retirer : sudo rm /usr/local/bin/auxipak" >&2
fi
exit 0
EOF
chmod 0755 "${R}/DEBIAN/postinst"

installed_size="$(du -sk --exclude=DEBIAN "${R}" | awk '{print $1}')"
{
  echo "Package: auxipak"
  echo "Version: ${VERSION}"
  echo "Architecture: ${DEB_ARCH}"
  echo "Maintainer: ${MAINTAINER}"
  echo "Installed-Size: ${installed_size}"
  [[ -z "${DEPENDS}" ]] || echo "Depends: ${DEPENDS}"
  echo "Recommends: auxi | apt"
  echo "Section: admin"
  echo "Priority: optional"
  echo "Homepage: ${HOMEPAGE}"
  echo "Description: AuxiPak, gestionnaire d'applications multiplateforme (client)"
  echo " Installe, met à jour et retire des applications depuis le dépôt"
  echo " officiel AuxiPak (métadonnées TUF, paquets signés). Sur AuxiNux OS,"
  echo " les paquets Debian passent par la commande auxi (APT y est bloqué)."
} >"${R}/DEBIAN/control"

(cd "${R}" && find usr -type f | sort | xargs md5sum) >"${R}/DEBIAN/md5sums"
chmod 0644 "${R}/DEBIAN/control" "${R}/DEBIAN/conffiles" "${R}/DEBIAN/md5sums"

# Dates reproductibles : celle du dernier commit, sinon maintenant.
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "${REPO}" log -1 --format=%ct 2>/dev/null || date +%s)}"
export SOURCE_DATE_EPOCH
find "${R}" -exec touch -h -d "@${SOURCE_DATE_EPOCH}" {} +

mkdir -p "${OUT_DIR}"
DEB="${OUT_DIR}/auxipak_${VERSION}_${DEB_ARCH}.deb"
dpkg-deb --root-owner-group -Zxz --build "${R}" "${DEB}" >/dev/null
echo "Paquet : ${DEB}"
echo "Depends : ${DEPENDS:-(aucune)}"
sha256sum "${DEB}"
