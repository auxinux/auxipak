#!/bin/sh
# Désinstallation du client AuxiPak (Linux, macOS).
#
#   curl -fsSL @@AUXIPAK_URL@@/uninstall.sh | sh
#   curl -fsSL @@AUXIPAK_URL@@/uninstall.sh | sh -s -- --purge
#
# Retire auxipak et auxipak-builder. Avec --purge, supprime aussi la
# configuration, le registre, le cache et les journaux. Les applications
# installées par AuxiPak ne sont jamais supprimées par ce script : retirez-les
# d'abord avec « sudo auxipak remove <application> » si nécessaire.
set -eu

AUXIPAK_URL='@@AUXIPAK_URL@@'
BIN_DIR=/usr/local/bin
PURGE=0

say() { printf '%s\n' "$*"; }
die() { printf 'erreur : %s\n' "$*" >&2; exit 1; }

for arg in "$@"; do
  case "$arg" in
    --purge) PURGE=1 ;;
    -h|--help)
      say "Usage : uninstall.sh [--purge]"
      say "  --purge  supprime aussi configuration, registre, cache et journaux"
      exit 0 ;;
    *) die "option inconnue : $arg" ;;
  esac
done

if [ "$(id -u)" -eq 0 ]; then
  SUDO=""
else
  command -v sudo >/dev/null 2>&1 || die "sudo est requis (ou exécutez ce script en root)"
  SUDO="sudo"
fi

if [ -f /var/lib/auxipak/registry.json ] && [ -x "$BIN_DIR/auxipak" ]; then
  say "Applications encore enregistrées (elles resteront installées) :"
  $SUDO "$BIN_DIR/auxipak" list 2>/dev/null || true
  say ""
fi

for b in auxipak auxipak-builder; do
  if [ -e "$BIN_DIR/$b" ]; then
    $SUDO rm -f "$BIN_DIR/$b"
    say "Supprimé : $BIN_DIR/$b"
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
  say "Configuration, registre, cache et journaux supprimés."
else
  say "Configuration conservée (/etc/auxipak) : ajoutez --purge pour la supprimer."
fi
say "AuxiPak est désinstallé."
