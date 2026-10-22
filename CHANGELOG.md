# Historique des versions

Le format suit [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/) et
le projet applique le [versionnage sémantique](https://semver.org/lang/fr/).

## [Non publié]

## [1.0.10] — 2026-10-22

### Ajouté

- Paquet Debian du client : `packaging/deb/build-deb.sh VERSION
  [--from-dir DIR]` (dpkg-deb) produit `auxipak_VERSION_amd64.deb` —
  `/usr/bin/auxipak`, `/etc/auxipak/config.toml` (conffile : dépôt officiel
  et adaptateur `auxi` explicite) et les ancres de confiance publiques du
  dépôt officiel. `Depends` calculé sur le binaire (glibc minimale). Construit
  par la CI (artefact `auxipak-deb`) et installé par `apt-get`.
- AuxiNux OS = Debian 13 + `auxi` : faute de variante `auxinuxos`, la
  variante `debian` d'une application s'applique (contrainte `os_version`
  évaluée sur `VERSION_ID`) ; le client lit en plus les versions Debian du
  canal `linux/deb`. `manager: apt` et les dépendances natives passent alors
  par `auxi`, jamais par APT. Une variante propre à AuxiNux OS reste
  préférée.

### Modifié

- Détection d'AuxiNux OS par `VARIANT_ID=auxinuxos` : son `os-release` garde
  `ID=debian` (dépôts tiers), ce qui le faisait prendre pour une Debian et
  appeler `apt-get`, bloqué.
- Adaptateur `auxi` aligné sur le vrai script d'AuxiNux OS 0.3.0 et marqué
  validé : `auxi --yes install --deb <paquets>`, `auxi --yes uninstall --deb
  <paquet>` (un appel par paquet : auxi ne retire que le premier), `.deb`
  local par `auxi --yes install --deb <chemin absolu>`, état par
  `dpkg-query`. Le réglage DEB d'AuxiNux OS (`auxi set deb=true`) est
  respecté.
- Adaptateurs : une commande qui prend `{package}` (et non `{packages}`) est
  lancée une fois par paquet.
- `auxipak upgrade` ne remplace plus un client installé par le paquet
  système (`/usr/bin/auxipak`) : il se met à jour avec le système.

## [1.0.9] — 2026-10-22

### Ajouté

- Pré-évaluation automatique par une IA : portée `ai_evaluate` (jetons
  `agent` des relecteurs et administrateurs), route
  `PUT /api/v1/apps/{id}/ai-evaluation` (statut, réserves FR/EN, sources,
  modèle). Affichée — étiquetée « analyse automatique par l'IA » — sur le
  site, dans l'API, l'index et le client tant qu'aucun relecteur humain n'a
  évalué l'application ; ne remplace jamais une évaluation humaine.
- Administration : page « Évaluations IA » (à revoir / toutes, sources,
  modèle) avec « Confirmer » (adoption comme évaluation humaine) et
  « Réviser ».

## [1.0.8] — 2026-10-22

### Ajouté

- Manifeste : champ facultatif `translations` (nom, résumé et description
  dans d'autres langues). Le site, l'API (selon `Accept-Language`), l'index
  et le client (`search`, `info`) affichent les textes dans la langue de
  l'utilisateur ; la recherche porte aussi sur les traductions. Les clients
  antérieurs à 1.0.8 refusent les paquets qui utilisent ce champ.
- Windows et macOS arm64 : une variante `x86_64` est retenue quand aucune
  variante arm64 n'existe (émulation Windows 11, Rosetta 2) ; le serveur la
  publie aussi dans le canal arm64. Jamais sous Linux.

- Administration : « Approuver la sélection » dans la liste des demandes
  (cases à cocher, case d'en-tête pour tout cocher). Mêmes contrôles qu'une
  approbation unique (portée review, approbateur distinct) ; le dépôt est
  régénéré une seule fois.

### Modifié

- Installation refusée parce qu'une autre application AuxiPak occupe le même
  emplacement (Firefox et Firefox ESR, tous deux `Firefox.app`) : le message
  nomme cette application et indique de la désinstaller d'abord.

## [1.0.7] — 2026-10-22

### Ajouté

- `auxipak install`, `remove` et `upgrade` acceptent plusieurs applications
  (`auxipak install firefox vlc`). Un échec n'interrompt pas les suivantes ; un
  bilan final indique les applications en échec (code de sortie 1). À la
  désinstallation, une application requise par une autre de la liste est
  retirée après elle.

## [1.0.6] — 2026-10-22

### Ajouté

- `auxipak install firefox-fr` / `firefox-en` : un identifiant suivi d'une
  langue publiée pour lui impose cette langue.

### Modifié

- `auxipak install firefox` choisit d'abord la langue d'AuxiPak, puis la
  version la plus récente (auparavant, une version plus récente dans une autre
  langue l'emportait).
- Sous `sudo`, le client reprend la langue réglée par l'utilisateur qui a
  lancé la commande (`~/.config/auxipak/language`).

### Corrigé

- Serveur : une même version peut être publiée en plusieurs langues (un
  paquet par langue, par exemple `Firefox-158.0.1-fr.aupak` et
  `Firefox-158.0.1-en.aupak`). L'approbation n'est refusée que pour le même
  fichier ou une langue déjà publiée pour cette version.

## [1.0.5] — 2026-10-21

### Sécurité

- Mise à jour de `rustls-webpki` (0.103.16) et `webpki-root-certs` (1.0.10) :
  RUSTSEC-2026-0382 et RUSTSEC-2026-0383 (certificats intermédiaires
  révoqués de la confiance acceptés lors de la vérification TLS).

### Corrigé

- `auxipak upgrade` : la ligne « ✓ AuxiPak est à jour » est écrite sur la
  sortie d'erreur ; la sortie standard ne porte que le résultat des
  applications (un `auxipak upgrade | grep -q …` interrompait le client).
- `auxipak install` : quand toutes les versions d'une application sont
  révoquées, le message indique qu'aucune version n'est installable et
  suggère `auxipak search`.

## [1.0.4] — 2026-10-21

### Ajouté

- Page « Installation » du site : installation du client pas à pas par
  système (Linux, macOS, Windows), avec auxipak-builder, vérification,
  installation manuelle et désinstallation.

### Modifié

- `auxipak update` affiche une barre de progression par dépôt puis un résumé
  d'une ligne (« ✓ Cache à jour » ou « ✓ Cache déjà à jour », nombre
  d'applications) ; le détail précédent (génération, versions, validité des
  métadonnées) reste disponible avec `--verbose`.
- `auxipak upgrade` n'est plus muet quand il n'y a rien à faire : il confirme
  qu'AuxiPak est à jour, signale un échec de vérification de version (au lieu
  de le consigner seulement dans le journal) et indique qu'aucune application
  n'est installée.

## [1.0.3] — 2026-10-20

### Ajouté

- Bilinguisme anglais / français de tout le projet (anglais par défaut) :
  client, Builder, bibliothèque commune, serveur (API, pages, rapports de
  validation), scripts d'installation et de déploiement. Langue : choix
  explicite (`auxipak set lang fr|en`, `auxipak-builder set lang=…`, sélecteur
  du site), sinon `AUXIPAK_LANG`, sinon la langue du système ou du navigateur.

### Ajouté

- `auxipak upgrade` met d'abord à jour AuxiPak lui-même (et
  `auxipak-builder` s'il est installé à côté) à partir des binaires publiés
  par le serveur du dépôt officiel (`/downloads/`, empreinte SHA-256
  vérifiée) ; `--no-self` l'évite. `auxipak update` signale une nouvelle
  version.
- Administration : suppression des jetons révoqués ou expirés, des fichiers
  des versions révoquées (qui restent refusées par les clients) et des
  demandes terminées.
- Catalogue : filtre par système (Linux, macOS, Windows) et systèmes
  couverts affichés sur chaque fiche ; paramètre `platform` de
  `/api/v1/apps`.

### Modifié

- Extension des paquets : `.aupak` (au lieu de `.apak`, déjà utilisée par
  un autre gestionnaire de paquets). Les fichiers `.apak` existants restent
  acceptés en lecture (validation, installation locale, soumission) et les
  paquets déjà publiés ne changent pas.

## [1.0.2] — 2026-10-20

### Ajouté

- Client : barre de progression des téléchargements (pourcentage, taille,
  débit, temps restant) et indicateur d'étape avec temps écoulé pour la
  vérification d'empreinte et les installateurs (montage et copie d'un
  `.dmg`, APT, winget, Homebrew, MSI, `.pkg`…). Animation uniquement dans un
  terminal ; désactivable avec `AUXIPAK_NO_PROGRESS=1`.

### Corrigé

- Interface Web : les textes longs (URL, empreintes) ne débordent plus des
  cartes.

## [1.0.1] — 2026-10-20

### Ajouté

- `auxipak-builder set server=… token=…`, `unset` et `config` : réglages
  persistants de la soumission (fichier `builder.json`, droits 0600) ;
  `submit` n'exige plus `--server` ni `--token`.
- Binaires du client récupérables par git (branche `client-dist`) avec
  `deploy/scripts/fetch-client.sh`, sans jeton d'API ; exemple de paquet
  Firefox pour macOS (`examples/firefox-macos/make.sh`).

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
