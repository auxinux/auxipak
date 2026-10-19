# Historique des versions

Le format suit [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/) et
le projet applique le [versionnage sémantique](https://semver.org/lang/fr/).

## [Non publié]

### Ajouté

- Installation du client en une commande : le serveur publie `/install.sh`,
  `/uninstall.sh` (Linux, macOS) et `/install.ps1`, `/uninstall.ps1`
  (Windows), qui vérifient l'empreinte SHA-256 du client et installent les
  ancres de confiance du dépôt officiel ; binaires servis par `/downloads/`
  et publiés avec `deploy/scripts/fetch-client.sh`. Scripts testés en CI
  sur Linux, macOS et Windows (PowerShell 5.1).
- Déploiement derrière un mandataire HTTPS distant : `AUXIPAK_BIND` et
  `AUXIPAK_TRUSTED_PROXIES` dans `deploy/.env`.

## [1.0.0] — 2026-10-19

Première version d'AuxiPak.

### Ajouté

- **Bibliothèque commune `auxipak-core`** : modèle de plateformes et canaux
  (`linux/deb`, `linux/auxinuxos`, `linux/virtuaos`, `windows`, `macos` ;
  x86_64 et arm64), comparaison de versions de type dpkg, validation
  anti-injection des identifiants et chemins, manifeste
  `instruction.auxipak` format 1 (schéma JSON officiel, typage strict, règles
  sémantiques), format `.apak` v1 (7z normalisé, inspection et extraction
  sécurisées, construction déterministe), signatures Ed25519 détachées
  (`auxipak-signature/1`, `package-keys.json`), index des dépôts
  (`index.json`, `apps.json`, `channels/<canal>/<arch>.json`,
  `revocations.json`, catalogue `/index`), métadonnées TUF via `tough`,
  cérémonie de clés.
- **Client `auxipak`** : `search`, `install`, `remove`, `update`, `upgrade`,
  `list`, `info`, `verify`, `clean`, `repo list|add|remove`, `repair`,
  `doctor` ; détection du système et mémorisation du profil ; synchronisation
  TUF avec cache vérifié (TTL 3 600 s) ; téléchargements avec reprise et
  politique de redirection stricte ; installation transactionnelle avec
  retour arrière et reprise ; registre local ; dépendances ; méthodes APT,
  `.deb`, `auxi` (adaptateur configurable, syntaxe à valider), VirtuaOS
  (adaptateur à configurer), winget, MSI, EXE, pkg, dmg, Homebrew, `files`,
  scripts sur autorisation explicite ; portées système et utilisateur ;
  ancres de confiance embarquables à la compilation.
- **Constructeur `auxipak-builder`** : `init`, `validate`, `build`, `test`
  (tests statiques), `sign`, `verify-signature`, `keys generate`,
  `keys init-repository`, `keys show-root`, `submit`.
- **Serveur `auxipak-server`** : API REST `/api/v1` (OpenAPI 3.1), API
  Builder pour l'automatisation, demandes de publication avec approbation
  humaine (approbateur distinct par défaut), signature des paquets,
  génération des index et métadonnées TUF avec bascule atomique,
  rafraîchissement périodique, révocation, dépublication, classification
  « AuxiNux Vérifié / Compatible / Non évalué », rôles et portées, jetons
  `human`/`ci`/`agent`, sessions avec CSRF, journal d'audit, interface Web
  bilingue (français, anglais) à rendu serveur, sous-commandes `serve`,
  `migrate`, `create-admin`, `regenerate`, `check-config`, `healthcheck`.
- **Déploiement** : image Docker, Compose de production et de développement,
  configuration Nginx, service systemd durci, scripts d'initialisation des
  clés, de sauvegarde, de restauration, de création d'administrateur, de
  mise à jour et de serveur de développement.
- **Intégration continue** : formatage, Clippy, tests (dont PostgreSQL),
  démonstration de bout en bout, audit des dépendances, constructions Linux,
  Windows et macOS (x86_64, ARM64), image Docker ; publication des versions
  avec empreintes et attestations de provenance.
- **Application de démonstration** `auxipak-demo` et démonstration de bout en
  bout (`tests/e2e`).
- **Documentation** complète en français (`docs/`).

### Validation

- Windows, macOS, AuxiNuxOS réel et VirtuaOS : validation restante (voir
  [docs/ROADMAP.md](docs/ROADMAP.md)).

[Non publié]: https://github.com/auxinux/auxipak/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/auxinux/auxipak/releases/tag/v1.0.0
