# Architecture

Ce document décrit l'architecture retenue pour AuxiPak 1.0.0, la
justification des choix techniques et les principaux flux (publication,
synchronisation, installation). Il se termine par la marche à suivre pour
ajouter une distribution Linux.

## 1. Principes

1. **AuxiPak ne remplace pas les gestionnaires de paquets.** Il délègue aux
   mécanismes natifs autorisés de chaque système : APT sur Debian/Ubuntu, la
   commande `auxi` sur AuxiNuxOS (où APT est bloqué), un adaptateur
   configurable sur VirtuaOS, winget/MSI/EXE sur Windows, pkg/dmg/Homebrew
   sur macOS, et une méthode générique `files` (copie de fichiers).
2. **Le manifeste est déclaratif.** Aucune ligne de commande libre : chaque
   méthode a des paramètres structurés, validés, traduits par le client en
   appels de processus à vecteur d'arguments (jamais d'interpréteur de
   commandes).
3. **Séparation signature / évaluation.** Une signature atteste l'origine et
   l'intégrité d'un paquet ; le statut « AuxiNux Vérifié / Compatible / Non
   évalué » est une évaluation distincte, attribuée par un relecteur humain et
   stockée à part (table `evaluations`).
4. **Aucune publication sans humain.** Une soumission crée une demande ;
   seule l'approbation d'un relecteur humain (distinct de l'auteur par
   défaut) publie.
5. **Rien n'est exécuté côté serveur.** Le serveur inspecte, valide, signe et
   indexe ; il n'exécute jamais le contenu d'un paquet.

## 2. Vue d'ensemble

```text
                         ┌──────────────────────────── pak.auxinux.ca ─────────────────────────────┐
  Éditeur / CI / agent   │  Nginx (443, TLS) ──► auxipak-server (127.0.0.1:8080)                     │
  auxipak-builder ──────►│                        ├── API REST /api/v1 (axum)                         │
  (submit, API Builder)  │                        ├── Interface Web (MiniJinja, fr/en)                │
                         │                        ├── Publication : signature Ed25519, index, TUF     │
  Relecteur (navigateur) │                        └── /repos/<dépôt>/{metadata,targets,keys}/…        │
  ──────────────────────►│                                  │                                        │
                         │   PostgreSQL (5432, réseau interne)   Données : soumissions, paquets,     │
                         │   comptes, jetons, soumissions,        dépôts gen-N + lien « current »     │
                         │   versions, évaluations, audit         Clés en ligne (lecture seule)       │
                         └────────────────────────────────────────────────────────────────────────┘
                                                   │ HTTPS (métadonnées TUF, index, .aupak, .aupak.sig)
                                                   ▼
                    auxipak (client) ── vérifie TUF ─ vérifie signature ─ inspecte l'archive
                         │
                         └── APT · auxi · adaptateur VirtuaOS · winget · msiexec · EXE · installer (pkg)
                             · hdiutil/ditto (dmg) · brew · copie de fichiers · scripts autorisés
```

### Composants (workspace Rust)

| Répertoire | Crate / binaire | Rôle |
|---|---|---|
| `shared/` | `auxipak-core` | Bibliothèque commune : plateformes et canaux (`platform.rs`), versions (`version.rs`), identifiants anti-injection (`ids.rs`), manifeste (`manifest.rs`, `schema.rs` + `schemas/instruction.auxipak.schema.json`), archive `.aupak` (`archive.rs`), signatures (`signature.rs`), index (`index.rs`), TUF (`tuf.rs`), cérémonie de clés (`keyset.rs`), projets et tests statiques (`project.rs`), génération des index (`repogen.rs`), politique réseau (`netpolicy.rs`), empreintes (`hash.rs`) |
| `client/` | `auxipak` | Détection (`detect.rs`), chemins (`paths.rs`), configuration et adaptateurs (`config.rs`), synchronisation TUF (`repo.rs`), recherche/résolution (`catalog.rs`), téléchargements (`download.rs`), registre et transactions (`registry.rs`), orchestration (`engine.rs`), méthodes (`methods.rs`), exécution (`executor.rs`), privilèges (`privileges.rs`), ancres embarquées (`build.rs`) |
| `builder/` | `auxipak-builder` | Création de projets, validation, construction, tests statiques, signature, cérémonie de clés, soumission |
| `server/` | `auxipak-server` | Configuration (`config.rs`), authentification et autorisation (`auth.rs`), API (`api/*.rs`), publication (`publisher.rs`), analyse des soumissions (`validation.rs`), clés (`keys.rs`), interface Web (`web.rs`), audit (`audit.rs`), migrations (`migrations/0001_init.sql`), OpenAPI (`openapi.yaml`) |
| `web/` | (embarqué) | Gabarits MiniJinja, traductions `i18n/fr.json` et `i18n/en.json`, CSS (`static/style.css`, thème `static/themes/auxinux.css` par variables CSS), `static/app.js` |
| `deploy/` | — | Dockerfile, Compose (production et développement), Nginx, systemd, scripts d'exploitation |
| `examples/auxipak-demo/` | — | Application de démonstration et script de construction |
| `tests/e2e/` | — | Démonstration de bout en bout (`demo.sh`, `run-local.sh`) |

## 3. Choix techniques et justification

| Choix | Justification |
|---|---|
| **Rust pour tous les composants** | Un seul langage, une seule bibliothèque commune (`auxipak-core`) partagée par le client, le constructeur et le serveur : le manifeste, le format `.aupak`, les signatures et la génération des index sont validés par **le même code** partout. Binaires autonomes, sans environnement d'exécution à installer (important pour un client déployé sur Linux, Windows et macOS, et sur un système immuable). Sûreté mémoire pour un logiciel qui manipule des archives et des métadonnées non fiables. |
| **axum + sqlx / PostgreSQL** | axum (tokio) : serveur asynchrone éprouvé, extracteurs typés (l'acteur authentifié est un extracteur qui impose CSRF et portées). sqlx : requêtes paramétrées, migrations embarquées (`sqlx::migrate!`), pool de connexions. PostgreSQL : transactions, contraintes `CHECK` (rôles, états), verrou consultatif (`pg_advisory_lock`) pour sérialiser la régénération des dépôts entre instances. |
| **Rendu serveur MiniJinja embarqué** plutôt qu'un framework JavaScript | Aucune chaîne Node.js en production ni en compilation ; gabarits et ressources intégrés au binaire (`rust-embed`) ; échappement HTML automatique ; politique de sécurité du contenu stricte possible (`default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'`) car aucun script en ligne n'est nécessaire. Thème entièrement piloté par des variables CSS. |
| **7z via `sevenz-rust2`** | Le format `.aupak` est une archive 7z normalisée : bonne compression (LZMA2), outillage répandu pour l'inspection manuelle. La bibliothèque Rust pure évite d'appeler un binaire externe ; AuxiPak n'utilise jamais l'extraction automatique de la bibliothèque mais valide et écrit chaque entrée lui-même (voir [AUPAK_FORMAT.md](AUPAK_FORMAT.md)). |
| **TUF via `tough` (AWS)** plutôt qu'un protocole maison | The Update Framework traite les attaques classiques des dépôts (gel, rejeu, retour en arrière, mélange de métadonnées, compromission partielle de clés) ; `tough` est une implémentation maintenue et utilisée en production. Un protocole maison aurait exigé de réinventer et d'auditer ces protections. |
| **`consistent_snapshot = false` + bascule atomique** | Chaque publication écrit une génération complète `gen-N/` puis remplace atomiquement le lien symbolique `current` (création d'un lien temporaire puis `rename`). Les clients voient soit l'ancienne, soit la nouvelle génération, jamais un mélange ; les deux générations précédentes sont conservées pour les téléchargements en cours. Le client réessaie une fois si une bascule survient entre la lecture de `timestamp.json` et celle de `snapshot.json`. Cela évite la multiplication des fichiers préfixés par version/empreinte qu'impose `consistent_snapshot`. |
| **Ed25519 via `ed25519-dalek`** | Signatures courtes et rapides, clés de 32 octets, pas de paramètre à choisir ; clés privées stockées en PKCS#8 PEM. Les métadonnées TUF utilisent aussi Ed25519. |
| **Signature détachée (`.aupak.sig`)** | Le paquet n'est jamais modifié par la signature ; plusieurs signatures ou une chaîne de certificats (phase 2, `ca.auxinux.ca`) pourront être ajoutées sans changer le format `.aupak`. |
| **Séparation signature / évaluation** | Une clé compromise ne permet pas de s'attribuer « AuxiNux Vérifié » ; inversement, le statut d'évaluation n'a pas besoin de clés. Le client n'affiche un statut officiel que pour un dépôt marqué officiel **dans sa propre configuration**. |
| **Argon2 pour les mots de passe, jetons hachés (SHA-256)** | Aucun secret en clair en base ; un jeton n'est affiché qu'une fois. |

## 4. Modèle de dépôt

### Canaux

Un dépôt est découpé en **canaux** (`shared/src/platform.rs`) :

| Canal | Distributions |
|---|---|
| `linux/deb` | Debian, Ubuntu (et dérivées reconnues via `ID_LIKE`) |
| `linux/auxinuxos` | AuxiNuxOS |
| `linux/virtuaos` | VirtuaOS |
| `windows` | Windows |
| `macos` | macOS |

Chaque canal est décliné par architecture (`x86_64`, `arm64`) ; une variante
`any` figure dans les deux sous-index.

### Cibles TUF d'un dépôt

```text
metadata/                       (rôles TUF)
  N.root.json  targets.json  snapshot.json  timestamp.json
targets/
  index.json                    description du dépôt, génération, liste des sous-index
  apps.json                     métadonnées communes et statut officiel des applications
  revocations.json              paquets révoqués
  channels/<canal>/<arch>.json  versions disponibles (ex. channels/linux/deb/x86_64.json)
  packages/<id>/<version>/<Nom>-<version>-<langue>.aupak
  packages/<id>/<version>/<Nom>-<version>-<langue>.aupak.sig
keys/
  package-keys.json             clés publiques de signature (information ; non couvert par TUF)
```

Un client ne télécharge que `index.json`, `apps.json`, `revocations.json` et
**le** sous-index de son canal et de son architecture. Le document
`GET /index` liste les dépôts hébergés (découverte uniquement : l'authenticité
de chaque dépôt repose sur ses propres métadonnées TUF).

### Disposition sur le serveur

```text
$AUXIPAK_DATA_DIR/
  submissions/<uuid>.aupak            soumissions en attente
  packages/<dépôt>/<id>/<version>/   paquets publiés (immuables) + .sig
  repos/<dépôt>/gen-N/               générations signées (metadata/, targets/, keys/)
  repos/<dépôt>/current -> gen-N     lien servi par /repos/<dépôt>/…
  builder/<uuid>/project/            projets de l'API Builder
  builder/<uuid>/artifact.aupak       dernière construction
  tmp/                               fichiers temporaires
$AUXIPAK_KEYS_DIR/                   root.json, package-keys.json, targets.pem,
                                     snapshot.pem, timestamp.pem, package-signing.pem
```

Les fichiers de `targets/` sont des liens physiques vers `packages/` lorsque
c'est possible (sinon des copies).

## 5. Flux de publication

```mermaid
sequenceDiagram
    participant E as Éditeur / CI / agent
    participant S as auxipak-server
    participant DB as PostgreSQL
    participant R as Relecteur humain
    E->>S: POST /api/v1/submissions (corps .aupak) ou API Builder /submit
    S->>S: analyse statique (validation.rs) : structure, manifeste, contents, couverture
    S->>DB: submissions (status pending ou invalid) + audit
    opt Signature fournie
        E->>S: PUT /api/v1/submissions/{id}/signature (.aupak.sig)
        S->>S: vérification immédiate (clé package-signing de confiance)
    end
    R->>S: POST /api/v1/submissions/{id}/approve (portée review, humain)
    S->>S: politique : auteur ≠ approbateur ; ré-analyse ; empreinte inchangée
    S->>S: signature fournie revérifiée, sinon signature par package-signing.pem
    S->>S: copie immuable packages/<dépôt>/<id>/<version>/ + .sig
    S->>DB: apps, evaluations (unreviewed si nouvelle), releases (published), submissions (published)
    S->>S: regenerate : index (repogen) → TUF (tough) → gen-N → bascule « current »
```

La régénération est sérialisée par un mutex local et par
`pg_advisory_lock(717171)`. Elle a aussi lieu lors d'un changement d'état
d'une version (dépublication, republication, révocation), d'une évaluation,
de la création ou de la modification d'un dépôt, sur demande
(`auxipak-server regenerate`, `POST /api/v1/admin/repositories/{name}/regenerate`)
et périodiquement : une tâche vérifie toutes les 10 minutes si la dernière
publication date de plus de la moitié de la durée de vie de `timestamp.json`
(`AUXIPAK_TIMESTAMP_HOURS`, 24 h par défaut). Chaque génération incrémente la
version commune de `targets`, `snapshot` et `timestamp`.

Durées de validité : `targets.json` 30 jours, `snapshot.json` 7 jours,
`timestamp.json` `AUXIPAK_TIMESTAMP_HOURS` (1 à 168 h), `root.json` fixée à
la cérémonie (365 jours par défaut).

## 6. Flux de synchronisation (client)

```text
auxipak update / search / info / install
  │
  ├─ profil système (detect.rs) → canal + architecture ; empreinte comparée au profil mémorisé
  ├─ pour chaque dépôt actif (ordre de priorité croissante) :
  │    ├─ cache frais ?  (âge < cache_ttl_seconds [3600 s], métadonnées non expirées,
  │    │                  même empreinte de profil, même URL) → utilisé tel quel
  │    └─ sinon synchronisation :
  │         ├─ tough RepositoryLoader(root.json local) : chaîne de racines, seuils,
  │         │   versions (anti-retour), expirations (ExpirationEnforcement::Safe)
  │         ├─ lecture vérifiée de index.json, apps.json, revocations.json,
  │         │   channels/<canal>/<arch>.json (≤ 64 Mio chacun)
  │         └─ écriture atomique dans <cache>/repos/<dépôt>/verified/ puis state.json
  └─ règles : recherche/consultation → un cache périmé est toléré si le réseau échoue
             (avec avertissement) ; installation/mise à niveau → cache frais obligatoire
```

Le cache ne contient que des fichiers déjà vérifiés ; l'état (`state.json`)
est écrit en dernier, atomiquement.

## 7. Flux d'installation (client)

```text
auxipak install <app>
 1. verrou exclusif (<état>/auxipak.lock) ; avertissement si transactions interrompues
 2. synchronisation exigeant des index frais
 3. résolution (catalog.rs) : nom de fichier exact, puis identifiant, puis nom ;
    filtres --version / --lang / --repo ; versions révoquées exclues ;
    préférence : version la plus élevée, puis langue, puis priorité du dépôt
 4. plan des dépendances AuxiPak (dépendances d'abord, cycles refusés)
 5. pour chaque élément :
    a. téléchargement (reprise Range, taille/empreinte de l'index authentifié)
    b. signature détachée : obligatoire pour un dépôt officiel ou require_signatures ;
       clé package-signing de confiance ; id/version cohérents avec l'index
    c. inspection complète de l'archive ; manifeste = index (id, version)
    d. sélection de la variante pour le profil ; privilèges ; politique des scripts
    e. application déjà présente hors AuxiPak ? → refus, sauf --adopt
    f. transaction : Started → Verified → Extracted → Installing → Installed → Registered
       extraction sécurisée dans un répertoire de travail privé ; dépendances natives ;
       pre_install ; méthode ; post_install ; détection de contrôle
    g. registre (registry.json, écriture atomique + registry.json.bak)
 6. en cas d'échec : retour arrière précis pour la méthode files ; sinon état « partial »
    enregistré ; « auxipak repair » reprend les transactions interrompues
```

Les outils système sont appelés par chemin absolu (`/usr/bin/apt-get`,
`%SystemRoot%\System32\msiexec.exe`…), avec un environnement filtré (liste
blanche), sans entrée standard et avec un délai maximal.

## 8. Sécurité transversale

Voir [SECURITY.md](../SECURITY.md) pour la liste détaillée des contrôles.

## 9. Ajouter une nouvelle distribution Linux

Exemple : ajout d'une distribution `exempleos` avec son propre gestionnaire
`exm`. Les étapes suivent l'ordre des dépendances du code.

1. **Plateforme** (`shared/src/platform.rs`)
   - ajouter la variante à `Distribution` et compléter `as_str()`,
     `FromStr`, `os()` (Linux par défaut) et, si elle appartient à une
     famille existante, `family()` ;
   - reconnaître l'`os-release` dans `distribution_from_os_release()` (`ID`
     exact, puis candidats `ID_LIKE` — placer la nouvelle distribution
     **avant** `debian`/`ubuntu` si elle en dérive mais ne doit pas utiliser
     APT, comme AuxiNuxOS) ;
   - si elle a besoin de son propre canal : ajouter la variante à `Channel`
     avec son nom sérialisé (`#[serde(rename = "linux/exempleos")]`), l'ajouter
     à `Channel::ALL` (taille du tableau), `as_str()`,
     `for_distribution()` et `distributions()` ; sinon la rattacher à un canal
     existant dans `for_distribution()` ;
   - système immuable : l'ajouter au calcul de `immutable` de
     `linux_profile_from_os_release()` ; le cas échéant, un marqueur dans
     `client/src/detect.rs` (`detect_linux`).
2. **Manifeste** (`shared/src/manifest.rs`)
   - nouveau gestionnaire : variante de `Manager`, `as_str()`, `allowed_on()`
     (distributions autorisées) ; ajuster `Target::effective_privileges()` si
     le gestionnaire n'exige pas l'administration ;
   - mettre à jour le **schéma** `schemas/instruction.auxipak.schema.json` :
     énumération `distributions` de `$defs/target` et `$defs/manager`.
3. **Client**
   - `client/src/executor.rs` : variante de `Tool` avec `name()` et chemins
     absolus dans `candidates()` (jamais de recherche dans le `PATH`) ;
   - `client/src/methods.rs` : `manager_install()`, `manager_remove()`,
     `detect()` (branche `Detect::PackageManager`) et `native_manager()`
     (dépendances natives) ; si la syntaxe doit rester configurable, suivre le
     modèle des adaptateurs `auxi`/VirtuaOS (`AdapterConfig`, `Adapters`,
     `adapter_for()` dans `client/src/config.rs`) ;
   - `Install::Deb` : décider si les `.deb` y sont permis (aujourd'hui, sur
     AuxiNuxOS/VirtuaOS, ils passent par `install_local_deb` de l'adaptateur).
4. **Génération des index** : `shared/src/repogen.rs` utilise
   `Channel::for_distribution()` ; rien d'autre à modifier si l'étape 1 est
   complète.
5. **Profils de référence** : ajouter un ou plusieurs profils dans
   `reference_profiles()` de `shared/src/project.rs` (utilisés par
   `auxipak-builder test` et `POST …/test`).
6. **Tests**
   - `platform.rs` : `os-release` réel de la distribution et d'une dérivée,
     canal attendu, immuabilité ;
   - `manifest.rs` : gestionnaire refusé sur les autres distributions, et
     inversement ;
   - `client/tests/integration.rs` : profil imposé par
     `AUXIPAK_PROFILE_OVERRIDE` et outil simulé dans `AUXIPAK_TEST_TOOLS_DIR`
     (sur le modèle de `auxi_adapter_passes_structured_arguments_simulated`) ;
   - test `channel_roundtrip` (sérialisation des canaux).
7. **Interface et documentation** : libellés éventuels dans `web/i18n/*.json`,
   [INSTALLATION.md](INSTALLATION.md), [MANIFEST_SPEC.md](MANIFEST_SPEC.md),
   [CLI_REFERENCE.md](CLI_REFERENCE.md).
8. **Validation** sur le système réel avant d'annoncer la prise en charge.
