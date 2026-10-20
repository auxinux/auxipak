# Construire et publier une application

AuxiPak propose deux façons équivalentes de produire un paquet `.aupak` :

- le **Builder CLI** `auxipak-builder`, sur le poste de l'éditeur ou en CI ;
- l'**API Builder** du serveur (`/api/v1/builder/…`), pilotable par un
  outil d'automatisation ou un agent IA, sans outil local.

Dans les deux cas, **construire ne publie jamais** : la publication exige
une demande de publication puis l'approbation d'un relecteur humain.

```text
projet ─► validate ─► build ─► test ─► (sign) ─► submit ─► demande « pending »
                                                              │  relecteur humain (review)
                                                              ▼
                                         approve ─► signature serveur si besoin ─► index + TUF
                                                              │
                                                              ▼
                                         auxipak update / install sur les clients
```

## 1. Parcours complet avec le Builder CLI

### 1.1 Créer le projet

```console
$ auxipak-builder init mon-outil --id mon-outil --name "Mon outil" \
    --version 1.0.0 --publisher "Exemple inc." --language fr --license MIT
```

Arborescence produite :

```text
mon-outil/
  instruction.auxipak        manifeste (modèle : variante Linux « files »)
  payload/bin/mon-outil      script d'exemple (à remplacer)
  scripts/                   scripts éventuels
```

### 1.2 Ajouter les fichiers et écrire le manifeste

Placez les fichiers distribués sous `payload/` (et les scripts sous
`scripts/`), puis complétez `instruction.auxipak` selon
[MANIFEST_SPEC.md](MANIFEST_SPEC.md). Ne renseignez pas `contents` : il est
calculé à la construction. Les fichiers cachés sont ignorés ; un lien
symbolique fait échouer la construction.

### 1.3 Valider, construire, tester

```console
$ auxipak-builder validate mon-outil
$ auxipak-builder build mon-outil                # → ./Monoutil-1.0.0-fr.aupak
$ auxipak-builder test Monoutil-1.0.0-fr.aupak
$ auxipak verify Monoutil-1.0.0-fr.aupak          # contrôle côté client, sans exécution
```

- `validate` sur un répertoire construit le paquet dans un emplacement
  temporaire (validation complète avec les fichiers réels).
- `build` produit une archive **déterministe** (mêmes entrées → même
  SHA-256), ce qui permet de reconstruire et comparer un paquet.
- `test` affiche, pour 12 profils de référence (Debian 12/13, Ubuntu
  22.04/24.04, AuxiNuxOS, VirtuaOS, Windows 10/11, macOS 13/14, x86_64 et
  arm64), la variante retenue ; vérifie le nom du paquet `.deb`
  (`dpkg-deb --field`) et la syntaxe des scripts `.sh` (`bash -n`) si ces
  outils sont présents. Rien n'est installé ni exécuté.

### 1.4 Signer (facultatif)

Le serveur signe à l'approbation avec sa clé `package-signing`. Un éditeur
dont la clé `package-signing` figure dans le `package-keys.json` **du
serveur** peut signer lui-même :

```console
$ auxipak-builder sign Monoutil-1.0.0-fr.aupak --key secrets/cle-paquets.pem
$ auxipak-builder verify-signature Monoutil-1.0.0-fr.aupak --keys package-keys.json
```

Voir [SIGNING.md](SIGNING.md#7-ajouter-une-signature-à-un-paquet).

### 1.5 Soumettre

Un jeton portant la portée `submit` est nécessaire (créé par un humain dans
l'interface `/admin/tokens` ou via `POST /api/v1/tokens`).

Enregistrez une fois le serveur et le jeton (fichier
`~/.config/auxipak/builder.json`, droits 0600 ; `%APPDATA%\AuxiPak\builder.json`
sous Windows) :

```console
$ auxipak-builder set server=https://auxipak.auxinux.ca
$ auxipak-builder set token             # demande le jeton (hors de l'historique du shell)
$ auxipak-builder config                # affiche les réglages, jeton masqué
```

`auxipak-builder set token=apk_…` fonctionne aussi ; `auxipak-builder unset
token` l'efface. Les variables `AUXIPAK_SERVER` / `AUXIPAK_TOKEN` et les
options `--server` / `--token` restent prioritaires (CI, agents).

```console
$ auxipak-builder submit Monoutil-1.0.0-fr.aupak --note "Version 1.0.0"
Demande de publication créée : 7c1e… (statut : pending). Elle doit être approuvée par un relecteur.
```

`submit` envoie l'archive, joint `Monoutil-1.0.0-fr.aupak.sig` s'il existe,
et affiche l'identifiant de la demande. Le serveur analyse le paquet sans
l'exécuter ; une analyse en échec donne le statut `invalid` (détails dans
`GET /api/v1/submissions/{id}`).

### 1.6 Approbation

Un relecteur (rôle `reviewer` ou `admin`, **autre personne que l'auteur**
par défaut) ouvre `https://auxipak.auxinux.ca/admin/submissions`, examine le
rapport (contrôles, avertissements, points d'attention : scripts,
téléchargements distants, installateurs `exe`, permissions étendues,
absence de déclaration de vie privée, télémétrie obligatoire) et approuve ou
rejette avec un motif. L'approbation :

1. ré-analyse le paquet et vérifie qu'il n'a pas changé ;
2. vérifie la signature jointe ou signe avec la clé du serveur ;
3. copie le paquet et sa signature dans le stockage immuable ;
4. enregistre la version (`published`) et, pour une nouvelle application, le
   statut « Non évalué » ;
5. régénère les index et les métadonnées TUF et bascule le dépôt servi.

L'évaluation « AuxiNux Vérifié / Compatible » est une décision distincte,
prise ensuite par un relecteur (`/admin/apps` ou
`PUT /api/v1/admin/apps/{id}/evaluation`).

### 1.7 Vérifier côté client

```console
$ auxipak update
$ auxipak info mon-outil
$ auxipak install mon-outil
```

## 2. Parcours avec l'API Builder

Les mêmes étapes (créer le projet, modifier le manifeste par fusion JSON,
importer les fichiers, valider, construire, tester, soumettre) sont
détaillées avec des exemples `curl` dans
[API.md](API.md#5-construire-un-paquet-avec-lapi-builder-jeton-agent).
Côté serveur, les tests sont purement statiques : aucun outil externe
(`dpkg-deb`, `bash`) n'est invoqué.

## 3. Intégration GitHub Actions

Le projet ne fournit pas de flux tout prêt ; l'exemple suivant, à placer
dans le dépôt de l'**application** (`.github/workflows/auxipak.yml`), utilise
uniquement les commandes documentées. Créez au préalable un jeton de type
`ci` (portées `build`, `submit`, expiration courte) et enregistrez-le comme
secret `AUXIPAK_TOKEN`.

```yaml
name: Paquet AuxiPak
on:
  push:
    tags: ["v*"]
jobs:
  aupak:
    runs-on: ubuntu-24.04
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - name: Installer auxipak-builder
        run: cargo install --locked --git https://github.com/auxinux/auxipak auxipak-builder
      - name: Construire et tester
        run: |
          mkdir -p dist
          auxipak-builder validate packaging/
          auxipak-builder --json build packaging/ -o dist/MonOutil.aupak | tee build.json
          auxipak-builder test dist/MonOutil.aupak
      - name: Soumettre (demande de publication)
        env:
          AUXIPAK_SERVER: https://auxipak.auxinux.ca
          AUXIPAK_TOKEN: ${{ secrets.AUXIPAK_TOKEN }}
        run: auxipak-builder --json submit dist/MonOutil.aupak --note "CI ${GITHUB_REF_NAME} ${GITHUB_SHA}"
```

Bonnes pratiques :

- la CI **soumet** ; elle ne peut ni approuver ni classer (les portées
  `review`, `evaluate`, `admin` sont interdites aux jetons `ci`) ;
- ne placez pas de clé de signature de production dans les secrets de CI ;
  laissez le serveur signer à l'approbation ;
- la construction étant déterministe, conservez `build.json` (SHA-256) pour
  comparer avec le paquet publié ;
- pour tester l'installation, utilisez une machine virtuelle ou un conteneur
  jetable (section 5).

## 4. Claude Code et autres agents d'automatisation

Un agent (Claude Code, ou tout autre fournisseur) peut préparer un paquet de
bout en bout, avec le Builder CLI ou l'API Builder, à l'aide d'un jeton de
type **`agent`**.

### 4.1 Créer le jeton (humain)

Dans `/admin/tokens` ou par l'API (session humaine) :

```json
{"name": "claude-code mon-outil", "kind": "agent", "provider": "claude-code",
 "scopes": ["build", "submit"], "expires_days": 7}
```

Un administrateur peut créer le jeton pour un compte `publisher` dédié
(`POST /api/v1/admin/tokens` avec `user_id`), afin que l'agent n'agisse
qu'avec les droits de ce compte.

### 4.2 Ce qu'un jeton agent peut et ne peut pas faire

| Peut | Ne peut pas |
|---|---|
| créer, modifier, construire, tester, supprimer **ses** projets Builder (`build`) | approuver ou rejeter une demande |
| soumettre des demandes et joindre une signature (`submit`) | publier, dépublier ou révoquer une version |
| lire ses propres demandes | classer une application (statut AuxiNux) |
| lire dépôts et versions (`read`, si accordée) | gérer comptes, jetons, dépôts ou clés |
| | créer d'autres jetons |

Ces limites sont appliquées par le serveur quelle que soit la portée
demandée (`review`, `evaluate`, `admin` réservées aux humains). Chaque
action est tracée avec le type d'acteur (`agent`) et le fournisseur.

### 4.3 Consignes à donner à l'agent

- utiliser le jeton via la variable `AUXIPAK_TOKEN`, ne jamais l'écrire dans
  un fichier du dépôt ni l'afficher ;
- n'écrire que des manifestes déclaratifs : pas de scripts sauf nécessité,
  méthodes natives (`package_manager`) de préférence, sources distantes
  HTTPS avec `sha256` et `size` ;
- enchaîner `validate` → `build` → `test`, corriger jusqu'à `ok: true`, puis
  `submit` avec une note expliquant le paquet ;
- s'arrêter à la demande `pending` : la suite appartient au relecteur.

### 4.4 Limites et hygiène

- expiration courte (1 à 366 jours ; quelques jours pour une tâche
  ponctuelle) ; révocation immédiate après usage
  (`DELETE /api/v1/tokens/{id}`) ;
- un jeton par agent et par tâche, nom explicite, `provider` renseigné ;
- revue régulière du journal d'audit (`/admin/audit`).

## 5. Isolation des tests

- Le **serveur** n'exécute jamais le contenu d'un paquet : inspection,
  validation, empreintes, signatures et tests statiques uniquement.
- `auxipak-builder test` n'exécute ni installateur ni script ; il peut
  appeler `dpkg-deb --field` (lecture du fichier `control`) et `bash -n`
  (analyse syntaxique sans exécution).
- Les **tests d'installation réels** se font dans un environnement jetable
  (machine virtuelle, conteneur, runner éphémère) **sans secret** (ni jeton
  de soumission, ni clé) :

  ```console
  $ export AUXIPAK_HOME=$(mktemp -d)       # configuration, état et racines isolés
  $ mkdir -p "$AUXIPAK_HOME/config/trust/official"
  $ cp root.json package-keys.json "$AUXIPAK_HOME/config/trust/official/"
  $ auxipak update && auxipak install mon-outil && auxipak list --check && auxipak remove mon-outil
  ```

- Pour vérifier une variante `files` d'un autre système sans privilèges,
  `AUXIPAK_PROFILE_OVERRIDE` impose un profil (outil de test et de
  diagnostic, voir [CLI_REFERENCE.md](CLI_REFERENCE.md#variables-denvironnement)).
- Le mode simulation (`AUXIPAK_TEST_TOOLS_DIR`) remplace les outils système
  par des outils factices : il teste la mécanique d'AuxiPak, pas
  l'installateur ; les installations sont marquées `simulated` et ne valent
  jamais validation.
- Un paquet de test ne doit jamais être soumis au dépôt `official` : créez
  un dépôt dédié (`POST /api/v1/admin/repositories`) ou utilisez un serveur
  de développement ([DEPLOYMENT.md](DEPLOYMENT.md#6-environnement-de-développement-immédiat)).
