#!/bin/sh
# Installation du client AuxiPak (Linux, macOS) / AuxiPak client installer.
#
#   curl -fsSL @@AUXIPAK_URL@@/install.sh | sh
#   curl -fsSL @@AUXIPAK_URL@@/install.sh | sh -s -- --with-builder
#
# Installe /usr/local/bin/auxipak (et auxipak-builder avec --with-builder),
# puis configure le dépôt officiel dans /etc/auxipak (ancres de confiance
# fournies par ce serveur). Les privilèges administrateur sont demandés via
# sudo pour ces seules opérations. Messages en français ou en anglais selon
# AUXIPAK_LANG, sinon la langue du système (anglais par défaut).
set -eu

AUXIPAK_URL='@@AUXIPAK_URL@@'
ROOT_SHA256='@@ROOT_SHA256@@'
BIN_DIR=/usr/local/bin
CONF_DIR=/etc/auxipak
WITH_BUILDER=0

case "${AUXIPAK_LANG:-${LC_ALL:-${LC_MESSAGES:-${LANG:-}}}}" in fr*|FR*) FR=1 ;; *) FR=0 ;; esac
say() { printf '%s\n' "$*"; }
# msg "français" "English" : message dans la langue de l'utilisateur.
msg() { if [ "$FR" = 1 ]; then say "$1"; else say "$2"; fi; }
die() { if [ "$FR" = 1 ]; then printf 'erreur : %s\n' "$1" >&2; else printf 'error: %s\n' "$2" >&2; fi; exit 1; }

for arg in "$@"; do
  case "$arg" in
    --with-builder) WITH_BUILDER=1 ;;
    -h|--help)
      msg "Usage : install.sh [--with-builder]" "Usage: install.sh [--with-builder]"
      msg "  --with-builder  installe aussi auxipak-builder (création de paquets)" \
          "  --with-builder  also install auxipak-builder (package creation)"
      exit 0 ;;
    *) die "option inconnue : $arg" "unknown option: $arg" ;;
  esac
done

# Plateforme
case "$(uname -s)" in
  Linux) os=linux ;;
  Darwin) os=macos ;;
  *) die "système non pris en charge : $(uname -s)" "unsupported system: $(uname -s)" ;;
esac
case "$(uname -m)" in
  x86_64|amd64) arch=x86_64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) die "architecture non prise en charge : $(uname -m)" "unsupported architecture: $(uname -m)" ;;
esac
# Terminal macOS sous Rosetta : installer la version native Apple Silicon.
if [ "$os" = macos ] && [ "$arch" = x86_64 ] && [ "$(sysctl -n hw.optional.arm64 2>/dev/null || true)" = 1 ]; then
  arch=arm64
fi
platform="$os-$arch"

# Outils
if command -v curl >/dev/null 2>&1; then
  fetch() { curl -fsSL --retry 3 -o "$2" "$1"; }
elif command -v wget >/dev/null 2>&1; then
  fetch() { wget -q -O "$2" "$1"; }
else
  die "curl ou wget est requis" "curl or wget is required"
fi
if command -v sha256sum >/dev/null 2>&1; then
  sha256() { sha256sum "$1" | awk '{print $1}'; }
elif command -v shasum >/dev/null 2>&1; then
  sha256() { shasum -a 256 "$1" | awk '{print $1}'; }
else
  die "sha256sum ou shasum est requis" "sha256sum or shasum is required"
fi
command -v tar >/dev/null 2>&1 || die "tar est requis" "tar is required"

if [ "$(id -u)" -eq 0 ]; then
  SUDO=""
else
  command -v sudo >/dev/null 2>&1 || die "sudo est requis (ou exécutez ce script en root)" "sudo is required (or run this script as root)"
  SUDO="sudo"
fi

tmp=$(mktemp -d 2>/dev/null || mktemp -d -t auxipak)
trap 'rm -rf "$tmp"' EXIT INT TERM

# Choix de l'archive dans SHA256SUMS (une release publiée sur le serveur).
msg "AuxiPak : installation depuis $AUXIPAK_URL ($platform)" "AuxiPak: installing from $AUXIPAK_URL ($platform)"
fetch "$AUXIPAK_URL/downloads/SHA256SUMS" "$tmp/SHA256SUMS" \
  || die "aucun client publié sur $AUXIPAK_URL (downloads/SHA256SUMS introuvable)" \
         "no client published on $AUXIPAK_URL (downloads/SHA256SUMS not found)"
line=$(awk -v suf="-$platform.tar.gz" '
  { f = $2; sub(/^\*/, "", f)
    if ($1 ~ /^[0-9a-fA-F]+$/ && length($1) == 64 && length(f) > length(suf) &&
        substr(f, length(f) - length(suf) + 1) == suf && f ~ /^auxipak-/) print $1, f }' \
  "$tmp/SHA256SUMS" | tail -n 1)
[ -n "$line" ] || die "aucun client disponible pour $platform" "no client available for $platform"
expected=${line%% *}
file=${line#* }
case "$file" in *[!A-Za-z0-9._-]*) die "nom d'archive invalide : $file" "invalid archive name: $file" ;; esac

msg "Téléchargement de $file" "Downloading $file"
fetch "$AUXIPAK_URL/downloads/$file" "$tmp/$file" || die "téléchargement impossible : $file" "download failed: $file"
actual=$(sha256 "$tmp/$file")
[ "$(printf '%s' "$actual" | tr 'A-F' 'a-f')" = "$(printf '%s' "$expected" | tr 'A-F' 'a-f')" ] \
  || die "empreinte SHA-256 invalide pour $file (attendu $expected, obtenu $actual)" \
         "invalid SHA-256 fingerprint for $file (expected $expected, got $actual)"
msg "Empreinte SHA-256 vérifiée" "SHA-256 fingerprint verified"

mkdir "$tmp/x"
tar -xzf "$tmp/$file" -C "$tmp/x"
src="$tmp/x/${file%.tar.gz}"
[ -f "$src/auxipak" ] || die "archive invalide : auxipak absent" "invalid archive: auxipak missing"

# Binaires
$SUDO mkdir -p "$BIN_DIR"
$SUDO install -m 0755 "$src/auxipak" "$BIN_DIR/auxipak"
msg "Installé : $BIN_DIR/auxipak" "Installed: $BIN_DIR/auxipak"
if [ "$WITH_BUILDER" = 1 ]; then
  [ -f "$src/auxipak-builder" ] || die "archive invalide : auxipak-builder absent" "invalid archive: auxipak-builder missing"
  $SUDO install -m 0755 "$src/auxipak-builder" "$BIN_DIR/auxipak-builder"
  msg "Installé : $BIN_DIR/auxipak-builder" "Installed: $BIN_DIR/auxipak-builder"
fi

# Ancres de confiance du dépôt officiel (publiques).
cat > "$tmp/root.json" <<'AUXIPAK_EOF'
@@ROOT_JSON@@
AUXIPAK_EOF
cat > "$tmp/package-keys.json" <<'AUXIPAK_EOF'
@@KEYS_JSON@@
AUXIPAK_EOF
$SUDO mkdir -p "$CONF_DIR/trust/official"
$SUDO install -m 0644 "$tmp/root.json" "$CONF_DIR/trust/official/root.json"
$SUDO install -m 0644 "$tmp/package-keys.json" "$CONF_DIR/trust/official/package-keys.json"

# Configuration (conservée si elle existe déjà).
if $SUDO test -f "$CONF_DIR/config.toml"; then
  msg "Configuration existante conservée : $CONF_DIR/config.toml" "Existing configuration kept: $CONF_DIR/config.toml"
  $SUDO grep -q "$AUXIPAK_URL/repos/official/" "$CONF_DIR/config.toml" \
    || msg "ATTENTION : elle ne pointe pas vers $AUXIPAK_URL/repos/official/" \
           "WARNING: it does not point to $AUXIPAK_URL/repos/official/"
else
  insecure=""
  case "$AUXIPAK_URL" in http://*) insecure="allow_insecure_localhost = true" ;; esac
  cat > "$tmp/config.toml" <<AUXIPAK_EOF
# AuxiPak client configuration (created by install.sh).
cache_ttl_seconds = 3600

[[repository]]
name = "official"
url = "$AUXIPAK_URL/repos/official/"
root = "trust/official/root.json"
package_keys = "trust/official/package-keys.json"
official = true
$insecure
AUXIPAK_EOF
  $SUDO install -m 0644 "$tmp/config.toml" "$CONF_DIR/config.toml"
  msg "Configuration créée : $CONF_DIR/config.toml" "Configuration created: $CONF_DIR/config.toml"
fi

say ""
msg "Empreinte de la racine de confiance : $ROOT_SHA256" "Trust root fingerprint: $ROOT_SHA256"
if "$BIN_DIR/auxipak" update >/dev/null 2>&1; then
  msg "Index du dépôt officiel synchronisé." "Official repository index synchronized."
else
  msg "Synchronisation à faire : auxipak update" "Synchronization pending: auxipak update"
fi
say ""
msg "AuxiPak est installé. Exemples :" "AuxiPak is installed. Examples:"
say "  auxipak search firefox"
say "  sudo auxipak install <application>"
msg "  auxipak set lang fr      # langue : fr ou en" "  auxipak set lang fr      # language: fr or en"
msg "Désinstallation : curl -fsSL $AUXIPAK_URL/uninstall.sh | sh" "Uninstall: curl -fsSL $AUXIPAK_URL/uninstall.sh | sh"
