# Messages bilingues des scripts de déploiement (sourcé, non exécutable).
# Français si AUXIPAK_LANG, sinon LC_ALL / LC_MESSAGES / LANG, commence par
# « fr » ; anglais sinon.
case "${AUXIPAK_LANG:-${LC_ALL:-${LC_MESSAGES:-${LANG:-}}}}" in fr*|FR*) FR=1 ;; *) FR=0 ;; esac
# t "français" "English" : texte dans la langue de l'utilisateur.
t() { if [[ "$FR" == 1 ]]; then printf '%s' "$1"; else printf '%s' "$2"; fi; }
msg() { t "$1" "$2"; echo; }
die() { if [[ "$FR" == 1 ]]; then echo "erreur : $1" >&2; else echo "error: $2" >&2; fi; exit 1; }
# need VALEUR "français" "English" : argument obligatoire.
need() { [[ -n "$1" ]] || die "$2" "$3"; }
