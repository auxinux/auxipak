# Contribuer à AuxiPak

Merci de votre intérêt. Ce document décrit l'organisation du code, les
conventions, les tests et les règles de sécurité à respecter.

## 1. Organisation

```text
shared/      auxipak-core : formats, validation, cryptographie (aucune E/S réseau)
client/      auxipak : client multiplateforme
builder/     auxipak-builder : constructeur
server/      auxipak-server : API, publication, interface Web ; migrations/, openapi.yaml, tests/
web/         gabarits MiniJinja, i18n (fr, en), CSS et thème
schemas/     schéma JSON du manifeste (embarqué par auxipak-core)
deploy/      Docker, Compose, Nginx, systemd, scripts d'exploitation
examples/    application de démonstration
tests/e2e/   démonstration de bout en bout
scripts/     outils du dépôt (check-no-secrets.sh)
docs/        documentation
```

Voir [ARCHITECTURE.md](ARCHITECTURE.md) pour les responsabilités de chaque
module.

## 2. Prérequis

- Rust **1.89** ou plus récent (`rust-version` du workspace), avec `rustfmt`
  et `clippy` ;
- PostgreSQL (17 recommandé) pour les tests du serveur ;
- pour la démonstration de bout en bout : `psql`, `curl`, `jq`, `dpkg-deb`.

## 3. Construire et tester

```console
$ cargo build                                   # tous les composants (débogage)
$ cargo test --workspace                        # tests unitaires et d'intégration
$ cargo fmt --all --check                       # formatage (rustfmt.toml : max_width = 130)
$ cargo clippy --workspace --all-targets --locked -- -D warnings
$ scripts/check-no-secrets.sh                   # aucun .pem, .key, .env ni clé privée versionné
```

### Tests du serveur (PostgreSQL)

Les tests d'intégration de l'API (`server/tests/api.rs`) démarrent un
serveur réel sur un port local et créent puis suppriment chacun leur propre
base. Ils sont marqués `#[ignore]` et nécessitent une connexion
**administrateur** PostgreSQL :

```console
$ export AUXIPAK_TEST_DATABASE_URL=postgres://postgres:motdepasse@127.0.0.1:5432/postgres
$ cargo test -p auxipak-server -- --include-ignored
$ cargo test --workspace -- --include-ignored    # tout, comme l'intégration continue
```

Ils couvrent notamment : routes publiques et complétude d'`openapi.yaml`
(chaque route de `DOCUMENTED_ROUTES` doit y figurer), authentification,
CSRF et limitation des tentatives, politique de publication, classification
et révocation, parcours Builder avec un jeton agent, administration Web.

### Tests du client

`client/tests/integration.rs` construit des dépôts TUF locaux (`file://`) avec
les mêmes bibliothèques que le serveur et exécute le vrai binaire `auxipak`
avec un profil imposé (AuxiNuxOS x86_64) : TUF (expiration, falsification,
retour arrière), signatures, révocation, archives malveillantes, scripts,
privilèges, dépendances, reprise après interruption, dépôts externes,
adaptateur `auxi` simulé. Aucun installateur tiers n'est exécuté.

```console
$ cargo test -p auxipak --test integration
```

### Démonstration de bout en bout

```console
$ cargo build -p auxipak -p auxipak-builder -p auxipak-server
$ PG_ADMIN_URL=postgres://postgres:motdepasse@127.0.0.1:5432/postgres tests/e2e/run-local.sh
$ sudo -E env "PATH=$PATH" DEMO_MODE=native PG_ADMIN_URL=… tests/e2e/run-local.sh   # installation .deb réelle (Debian/Ubuntu, root)
```

`run-local.sh` crée une base et un serveur éphémères (clés de
développement), puis lance `demo.sh`. Modes : `native` (APT réel, root sur
Debian/Ubuntu) ou `files` (profil AuxiNuxOS imposé, utilisateur ordinaire).
Variables : `DEMO_MODE`, `BIN_DIR` (défaut `target/debug`), `PORT` (défaut
18080).

### Intégration continue

`.github/workflows/ci.yml` exécute : absence de secrets, longueur des
titres de commit (pull requests), validité du schéma JSON, syntaxe des
scripts shell, `cargo fmt --check`, Clippy (`-D warnings`), tous les tests
avec PostgreSQL, la démonstration de bout en bout (modes `native` et
`files`), `cargo audit`, la construction et les tests natifs sur Linux,
Windows et macOS (x86_64 et ARM64), et la construction de l'image Docker.
`.github/workflows/release.yml` produit les binaires et attestations des
versions étiquetées `v*`.

## 4. Conventions

- **Langue** : messages destinés aux utilisateurs, commentaires et
  documentation en français ; termes techniques usuels conservés
  (TUF, CSRF…). Les textes de l'interface Web passent par `web/i18n/fr.json`
  et `web/i18n/en.json` (mêmes clés dans les deux fichiers).
- **Messages de commit** en français et descriptifs (l'intégration continue
  refuse, en pull request, les titres de moins de 9 caractères).
- **Format** : `cargo fmt` ; aucun avertissement Clippy.
- **Erreurs** : `anyhow`/`thiserror` ; messages actionnables (ce qui a
  échoué, comment corriger) ; jamais de détail interne renvoyé par l'API
  (`ApiError::Internal` est journalisé, pas exposé).
- **Formats** : toute modification du manifeste touche à la fois
  `shared/src/manifest.rs`, `schemas/instruction.auxipak.schema.json`, les
  tests et [MANIFEST_SPEC.md](MANIFEST_SPEC.md). Toute nouvelle route touche
  `server/src/api/mod.rs` (router et `DOCUMENTED_ROUTES`),
  `server/openapi.yaml` et [API.md](API.md).
- **Dépendances** : n'en ajouter qu'en cas de nécessité, versions dans
  `[workspace.dependencies]`, `Cargo.lock` versionné (`--locked`).
- **Compatibilité** : une évolution incompatible du format `.aupak`, du
  manifeste ou des index incrémente la version correspondante
  (`AUPAK_FORMAT_VERSION`, `format`, `meta_version`).

## 5. Règles de sécurité

- **Jamais d'interpréteur de commandes** : programme + vecteur d'arguments
  (`executor::run`) ; outils système par chemin absolu ; environnement
  filtré.
- **Toute valeur externe** (manifeste, index, requête) qui finit dans un
  chemin ou un argument passe par `shared/src/ids.rs` (ou une validation
  équivalente) avant usage ; refuser plutôt que corriger.
- **Archives** : ne jamais utiliser l'extraction automatique d'une
  bibliothèque ; passer par `archive::inspect` / `archive::extract`.
- **Réseau** : HTTPS obligatoire (sauf boucle locale explicitement autorisée
  en développement), redirections filtrées (`netpolicy`), tailles bornées,
  empreintes vérifiées avant usage.
- **Écritures d'état** atomiques (`paths::atomic_write`) ; opérations
  système dans une transaction.
- **Serveur** : rien n'est exécuté depuis un paquet ; toute action sensible
  est autorisée par portée (`Actor::require`) et tracée (`audit::log`) ;
  requêtes SQL paramétrées uniquement.
- **Secrets** : aucune clé privée, aucun `.env`, aucun jeton dans le dépôt,
  les tests ou la documentation (sauf valeurs factices manifestes) ; les
  tests génèrent leurs clés à la volée.
- **Tests** : aucun test ne doit exécuter un installateur tiers réel hors de
  la démonstration contrôlée ; le mode simulation
  (`AUXIPAK_TEST_TOOLS_DIR`) n'est jamais présenté comme une validation.
- **Vulnérabilités** : ne pas ouvrir de ticket public ; suivre
  [SECURITY.md](../SECURITY.md).

## 6. Proposer une modification

1. Créer une branche depuis `main`.
2. Écrire ou adapter les tests ; vérifier `cargo fmt`, Clippy et
   `cargo test --workspace -- --include-ignored`.
3. Mettre à jour la documentation et `CHANGELOG.md` (section « Non publié »).
4. Ouvrir une pull request décrivant le besoin, la solution, les risques et
   l'état de validation par plateforme.
