#!/usr/bin/env bash
# Construit le paquet de démonstration auxipak-demo pour une version donnée.
#   ./build.sh 1.0.0 [répertoire de sortie]
# Prérequis : dpkg-deb (pour la variante Debian/Ubuntu) et auxipak-builder.
set -euo pipefail
VERSION="${1:?version requise}"
OUT="${2:-$PWD/dist}"
HERE="$(cd "$(dirname "$0")" && pwd)"
BUILDER="${AUXIPAK_BUILDER:-auxipak-builder}"
[[ "$VERSION" =~ ^[0-9][A-Za-z0-9.+~-]*$ ]] || { echo "version invalide / invalid version: $VERSION" >&2; exit 1; }
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
PROJ="$WORK/project"
mkdir -p "$PROJ/payload/bin" "$PROJ/payload/windows" "$OUT"
sed "s/@VERSION@/$VERSION/g" "$HERE/instruction.auxipak.in" > "$PROJ/instruction.auxipak"
sed "s/@VERSION@/$VERSION/g" "$HERE/src/auxipak-demo.sh" > "$PROJ/payload/bin/auxipak-demo"
chmod 755 "$PROJ/payload/bin/auxipak-demo"
sed "s/@VERSION@/$VERSION/g" "$HERE/src/auxipak-demo.cmd" > "$PROJ/payload/windows/auxipak-demo.cmd"

# Paquet Debian (architecture « all »).
DEB="$WORK/deb"
mkdir -p "$DEB/DEBIAN" "$DEB/usr/bin" "$DEB/usr/share/doc/auxipak-demo"
cp "$PROJ/payload/bin/auxipak-demo" "$DEB/usr/bin/auxipak-demo"
cat > "$DEB/DEBIAN/control" <<CTRL
Package: auxipak-demo
Version: $VERSION
Section: utils
Priority: optional
Architecture: all
Maintainer: AuxiNux <contact@auxinux.ca>
Description: AuxiPak Demo
 Application de démonstration inoffensive pour valider le parcours AuxiPak.
CTRL
echo "AuxiPak Demo $VERSION — GPL-3.0-or-later" > "$DEB/usr/share/doc/auxipak-demo/copyright"
SOURCE_DATE_EPOCH=1700000000 dpkg-deb --root-owner-group --build "$DEB" "$PROJ/payload/auxipak-demo_${VERSION}_all.deb" >/dev/null

"$BUILDER" build "$PROJ" -o "$OUT/AuxiPakDemo-$VERSION-mul.aupak"
"$BUILDER" test "$OUT/AuxiPakDemo-$VERSION-mul.aupak" >/dev/null
echo "$OUT/AuxiPakDemo-$VERSION-mul.aupak"
