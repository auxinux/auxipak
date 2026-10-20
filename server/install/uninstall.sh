#!/bin/sh
# Désinstallation du client AuxiPak (Linux, macOS).
#
#   curl -fsSL @@AUXIPAK_URL@@/uninstall.sh | sh
#   curl -fsSL @@AUXIPAK_URL@@/uninstall.sh | sh -s -- --purge
#
# Retire auxipak et auxipak-builder. Avec --purge, supprime aussi la
# configuration, le registre, le cache et les journaux. Les applications
# installées par AuxiPak ne sont jamais supprimées par ce script : retirez-les
# d'abord avec « sudo auxipak remove <application> » si nécessaire. Messages
# en français ou en anglais selon AUXIPAK_LANG, sinon la langue du système.
set -eu

AUXIPAK_URL='@@AUXIPAK_URL@@'
BIN_DIR=/usr/local/bin
PURGE=0

case "${AUXIPAK_LANG:-${LC_ALL:-${LC_MESSAGES:-${LANG:-}}}}" in fr*|FR*) FR=1 ;; *) FR=0 ;; esac
say() { printf '%s\n' "$*"; }
# msg "français" "English" : message dans la langue de l'utilisateur.
msg() { if [ "$FR" = 1 ]; then say "$1"; else say "$2"; fi; }
die() { if [ "$FR" = 1 ]; then printf 'erreur : %s\n' "$1" >&2; else printf 'error: %s\n' "$2" >&2; fi; exit 1; }

for arg in "$@"; do
  case "$arg" in
    --purge) PURGE=1 ;;
    -h|--help)
      msg "Usage : uninstall.sh [--purge]" "Usage: uninstall.sh [--purge]"
      msg "  --purge  supprime aussi configuration, registre, cache et journaux" \
          "  --purge  also delete configuration, registry, cache and logs"
      exit 0 ;;
    *) die "option inconnue : $arg" "unknown option: $arg" ;;
  esac
done

if [ "$(id -u)" -eq 0 ]; then
  SUDO=""
else
  command -v sudo >/dev/null 2>&1 || die "sudo est requis (ou exécutez ce script en root)" "sudo is required (or run this script as root)"
  SUDO="sudo"
fi

if [ -f /var/lib/auxipak/registry.json ] && [ -x "$BIN_DIR/auxipak" ]; then
  msg "Applications encore enregistrées (elles resteront installées) :" \
      "Applications still registered (they will stay installed):"
  $SUDO "$BIN_DIR/auxipak" list 2>/dev/null || true
  say ""
fi

for b in auxipak auxipak-builder; do
  if [ -e "$BIN_DIR/$b" ]; then
    $SUDO rm -f "$BIN_DIR/$b"
    msg "Supprimé : $BIN_DIR/$b" "Deleted: $BIN_DIR/$b"
  fi
done

if [ "$PURGE" = 1 ]; then
  # Système : configuration, cache, journaux, état (les données des
  # applications, /var/lib/auxipak/data et /opt/auxipak/apps, sont conservées).
  $SUDO rm -rf /etc/auxipak /var/cache/auxipak /var/log/auxipak
  if [ -d /var/lib/auxipak ]; then
    $SUDO find /var/lib/auxipak -mindepth 1 -maxdepth 1 ! -name data -exec rm -rf {} +
    $SUDO rmdir /var/lib/auxipak 2>/dev/null || true
  fi
  # Utilisateur courant.
  rm -rf "${XDG_CONFIG_HOME:-$HOME/.config}/auxipak" \
         "${XDG_CACHE_HOME:-$HOME/.cache}/auxipak" \
         "${XDG_STATE_HOME:-$HOME/.local/state}/auxipak"
  msg "Configuration, registre, cache et journaux supprimés." "Configuration, registry, cache and logs deleted."
else
  msg "Configuration conservée (/etc/auxipak) : ajoutez --purge pour la supprimer." \
      "Configuration kept (/etc/auxipak): add --purge to delete it."
fi
msg "AuxiPak est désinstallé." "AuxiPak is uninstalled."
