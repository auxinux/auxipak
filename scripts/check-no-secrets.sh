#!/usr/bin/env bash
# Vérifie qu'aucune clé privée ni fichier de secrets n'est versionné.
set -euo pipefail
cd "$(dirname "$0")/.."
fail=0
# Fichiers .pem, .env et clés privées PEM dans l'arbre suivi.
while IFS= read -r f; do
  case "$f" in
    *.pem|*.key|.env|*/.env) echo "fichier sensible versionné / sensitive file committed: $f"; fail=1 ;;
  esac
done < <(git ls-files)
if git grep -nI -E -- "^-----BEGIN ([A-Z]+ )?PRIVATE KEY-----" -- ':!scripts/check-no-secrets.sh' ':!docs/**' ':!*.md'; then
  echo "clé privée détectée dans le dépôt / private key found in the repository"; fail=1
fi
[[ $fail -eq 0 ]] && echo "aucun secret détecté / no secret found"
exit $fail
