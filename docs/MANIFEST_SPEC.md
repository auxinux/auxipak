# Manifeste `instruction.auxipak` — spécification (format 1)

Le manifeste décrit une application et, pour chaque plateforme, **comment**
l'installer, la détecter et la désinstaller. Il est entièrement
**déclaratif** : aucune ligne de commande libre n'est acceptée ; chaque
méthode a des paramètres structurés que le client traduit en appels de
processus à vecteur d'arguments, sans interpréteur de commandes.

- Fichier : `instruction.auxipak`, à la racine de l'archive `.aupak`, YAML
  UTF-8, 256 Kio au plus.
- Schéma JSON officiel : `schemas/instruction.auxipak.schema.json`
  (`$id` : `https://auxipak.auxinux.ca/schemas/instruction.auxipak/1.json`),
  embarqué dans tous les binaires.
- Implémentation : `shared/src/manifest.rs`.

## 1. Validation

La validation se fait en trois étapes ; la première erreur bloquante arrête
le traitement :

1. **schéma JSON** (types, champs obligatoires, énumérations, motifs) ;
2. **typage strict** : tout champ inconnu est refusé (`deny_unknown_fields`) ;
3. **règles sémantiques** : cohérence mode/méthode/plateforme, chemins,
   présence des fichiers dans `contents`, noms de paquets natifs, etc.

Les règles sémantiques produisent des **erreurs** (bloquantes) et des
**avertissements** (affichés par `auxipak-builder validate`, `auxipak
verify`, et dans le rapport de soumission).

> Les chaînes qui ressemblent à des nombres doivent être entre guillemets en
> YAML : `version: "1.0"` (et non `version: 1.0`, interprété comme un nombre
> et refusé par le schéma).

Pour valider un manifeste source **avant** construction, validez le
répertoire du projet (`auxipak-builder validate <projet>`) : la liste
`contents` y est calculée à partir des fichiers réels. Un fichier manifeste
isolé n'est valide que si `contents` est déjà renseigné.

## 2. Champs de premier niveau

| Champ | Type | Oblig. | Règles |
|---|---|---|---|
| `format` | entier | oui | `1` |
| `id` | chaîne | oui | identifiant stable : `^[a-z0-9][a-z0-9.+-]{1,63}$`, sans `..` (ex. `firefox`, `org.mozilla.firefox`) |
| `name` | chaîne | oui | nom affiché, 1–128 caractères, sans caractère de contrôle |
| `version` | chaîne | oui | commence par un chiffre ; alphanumériques et `. + - ~ _` ; ≤ 64 caractères |
| `publisher` | chaîne | oui | éditeur, 1–128 caractères |
| `summary` | chaîne | oui | description d'une ligne, 1–200 caractères |
| `description` | chaîne | non | texte long (≤ 20 000) |
| `license` | chaîne | oui | identifiant SPDX recommandé (`MPL-2.0`, `GPL-3.0-or-later`) ou `Proprietary` |
| `homepage` | chaîne (URI) | non | avertissement si elle n'est pas en HTTPS |
| `languages` | liste | oui | ≥ 1, sans doublon ; BCP 47 simplifié (`fr`, `en`, `fr-CA`, `zh-Hant`) ou `mul` (multilingue) |
| `categories` | liste | non | ≤ 10 ; `^[a-z0-9-]{1,32}$` |
| `translations` | objet | non | textes dans d'autres langues (section 2.4) |
| `privacy` | objet | non | déclaration de l'éditeur (section 2.1) |
| `dependencies` | liste | non | autres applications AuxiPak (section 2.2) |
| `contents` | liste | selon cas | fichiers de l'archive (section 2.3) ; calculée par le constructeur |
| `targets` | liste | oui | ≥ 1 variante par plateforme (section 3) |

### 2.1 `privacy`

| Champ | Valeurs |
|---|---|
| `telemetry` (oblig.) | `none`, `opt_in`, `opt_out`, `mandatory` |
| `details` | texte (≤ 4000) |
| `data_collected` | liste de chaînes (≤ 200 caractères chacune) |

Cette déclaration est **informative** : la classification officielle
(« AuxiNux Vérifié », « AuxiNux Compatible », « Non évalué ») est attribuée
par un relecteur sur le serveur et ne peut pas être fixée par le manifeste.
L'absence de déclaration ou une télémétrie `mandatory` sont signalées au
relecteur.

### 2.2 `dependencies`

```yaml
dependencies:
  - id: bibliotheque-commune
    version: ">=2.0, <3.0"
```

- `id` : identifiant d'une autre application AuxiPak ; une application ne
  peut pas dépendre d'elle-même ; pas de doublon.
- `version` : contrainte (défaut `*`). Syntaxe : clauses séparées par des
  virgules, chacune `=`, `>=`, `>`, `<=`, `<` suivie d'une version (une
  version seule vaut `=`). Les versions se comparent comme `dpkg
  --compare-versions` (sans époque ni révision) : segments numériques
  comparés numériquement, `~` trié avant tout (`1.0~rc1 < 1.0`).

Le client installe les dépendances d'abord, refuse les cycles, n'installe
pas une dépendance déjà présente dans une version compatible et empêche de
désinstaller une application requise (sauf `--force`). Les dépendances
natives (paquets système) se déclarent par variante avec
`native_dependencies`.

### 2.3 `contents`

```yaml
contents:
  - path: payload/bin/mon-outil
    sha256: "64 caractères hexadécimaux minuscules"
    size: 18432
    executable: true
```

Liste exhaustive des fichiers de l'archive hors manifeste, sous `payload/`
ou `scripts/`, avec SHA-256 et taille ; chemins sûrs et uniques. Le
constructeur la calcule ; elle est vérifiée à l'inspection et à l'extraction
(voir [AUPAK_FORMAT.md](AUPAK_FORMAT.md)). Un paquet sans fichier (mode
`native` uniquement) n'a pas de `contents`.

### 2.4 `translations`

```yaml
summary: "Lecteur multimédia libre"          # langue de base
translations:
  en:
    name: "VLC media player"                 # facultatif
    summary: "Free multimedia player"        # obligatoire
    description: |                           # facultatif
      Plays most multimedia files…
```

- Clé : code de langue (`en`, `fr`, `fr-CA`… ; pas `mul`) ; au plus 50.
- `summary` (1–200 caractères) obligatoire ; `name` (≤ 128) et
  `description` (≤ 20 000) facultatifs, repris de la langue de base s'ils
  sont absents.
- Le site, l'API (`Accept-Language`) et le client (`search`, `info`)
  affichent la traduction correspondant à la langue de l'utilisateur
  (correspondance exacte, puis langue de base : `fr-CA` → `fr`), sinon les
  champs de premier niveau. La recherche porte aussi sur les traductions.
- Champ reconnu à partir d'AuxiPak 1.0.8 : les clients antérieurs refusent
  un paquet qui le contient (« auxipak upgrade » met d'abord AuxiPak à jour).

## 3. Variantes (`targets`)

| Champ | Type | Oblig. | Règles |
|---|---|---|---|
| `name` | chaîne | oui | unique dans le manifeste ; `^[a-z0-9][a-z0-9_-]{0,31}$` |
| `platform` | `linux` \| `windows` \| `macos` | oui | |
| `distributions` | liste | Linux : oui | Linux : `debian`, `ubuntu`, `auxinuxos`, `virtuaos` ; Windows/macOS : facultatif (`windows` / `macos`) |
| `os_version` | contrainte | non | sur la version du système : `>=12` (Debian), `>=22.04` (Ubuntu), `>=10.0.19041` (Windows), `>=13` (macOS) |
| `architectures` | liste | oui | `x86_64`, `arm64` ou `any` seul |
| `mode` | `native` \| `remote` \| `embedded` | oui | section 4 |
| `privileges` | `user` \| `admin` | non | déduits de la méthode si absents (section 8) |
| `install` | objet | oui | méthode d'installation (section 5) |
| `remove` | objet | selon cas | désinstallation ; déduite si possible (section 6) |
| `detect` | objet | non | détection d'une installation ; déduite si possible (section 7) |
| `upgrade.strategy` | `in_place` \| `remove_then_install` | non | défaut `in_place` |
| `reboot` | `none` \| `recommended` \| `required` | non | défaut `none` ; affiché après l'opération |
| `success_codes` | liste d'entiers | non | défaut `[0]` ; ≥ 1 élément |
| `reboot_codes` | liste d'entiers | non | codes signifiant « succès, redémarrage requis » |
| `scripts` | objet | non | `pre_install`, `post_install`, `pre_remove`, `post_remove` (section 9) |
| `permissions` | liste | non | informatif : `network`, `system_files`, `user_files`, `services`, `autostart`, `drivers`, `firewall` |
| `native_dependencies` | liste | non | Linux uniquement : paquets système installés au préalable par le gestionnaire natif (APT, `auxi`, adaptateur VirtuaOS) |
| `timeout_seconds` | entier | non | 1–86 400 ; défaut 3 600 |

Les permissions `drivers` et `services` sont signalées au relecteur.

## 4. Modes

| Mode | Méthodes admises | Source | Règles |
|---|---|---|---|
| `native` | `package_manager` uniquement | dépôts du gestionnaire natif | le gestionnaire doit être autorisé sur **chaque** distribution visée |
| `remote` | `deb`, `msi`, `exe`, `pkg`, `dmg` | `source.url` + `source.sha256` | URL HTTPS obligatoire (section 4.1) ; `file` interdit |
| `embedded` | `deb`, `msi`, `exe`, `pkg`, `dmg`, `files`, `script` | fichiers de l'archive (`payload/`, `scripts/`) | `source.file` obligatoire pour les installateurs ; `url`, `sha256`, `allowed_hosts`, `file_name` interdits |

Réciproquement, `package_manager` exige `native`, `files` et `script`
exigent `embedded`.

### 4.1 `source`

| Champ | Mode | Description |
|---|---|---|
| `file` | `embedded` | chemin dans l'archive, sous `payload/`, présent dans `contents`, avec l'extension de la méthode |
| `url` | `remote` | URL HTTPS : nom d'hôte DNS (pas d'adresse IP littérale), sans identifiants intégrés ni fragment |
| `sha256` | `remote` | empreinte attendue (obligatoire) |
| `size` | `remote` | taille attendue en octets (recommandée ; sans elle : avertissement et limite `max_download_bytes` du client) |
| `allowed_hosts` | `remote` | hôtes supplémentaires autorisés lors des redirections ; l'hôte de `url` l'est toujours |
| `file_name` | `remote` | nom du fichier téléchargé (défaut : dernier segment de l'URL) ; doit porter l'extension de la méthode |

Téléchargement distant par le client : redirections limitées à 5, chacune
en HTTPS vers un hôte autorisé ; reprise par `Range` ; taille et SHA-256
vérifiés avant usage, fichier supprimé en cas d'écart.

## 5. Méthodes d'installation (`install`)

Le champ `method` sélectionne la méthode ; les autres champs sont ses
paramètres. Les noms de paquets natifs doivent respecter
`^[A-Za-z0-9][A-Za-z0-9.+_:@/-]{0,127}$` (pas d'espace, pas de
métacaractère, pas de `-` initial, pas de `..`).

### `package_manager` (mode `native`)

```yaml
install: { method: package_manager, manager: apt, packages: [firefox-esr] }
```

| Paramètre | Description |
|---|---|
| `manager` | `apt`, `auxi`, `virtuaos`, `winget`, `brew` |
| `packages` | ≥ 1 nom de paquet natif |

| Gestionnaire | Autorisé sur | Appel effectué par le client |
|---|---|---|
| `apt` | Debian, Ubuntu (jamais AuxiNuxOS/VirtuaOS) | `/usr/bin/apt-get install -y --no-install-recommends <paquets>` avec `DEBIAN_FRONTEND=noninteractive` |
| `auxi` | AuxiNuxOS | adaptateur `auxi` : `auxi --yes install --deb <paquets>` (voir [CLI_REFERENCE.md](CLI_REFERENCE.md#adaptateur-auxi-auxinuxos)). Sur AuxiNux OS, une variante `debian` avec `manager: apt` passe aussi par `auxi` |
| `virtuaos` | VirtuaOS | adaptateur VirtuaOS (non configuré par défaut) |
| `winget` | Windows | pour chaque paquet : `winget install --id <id> --exact --silent --accept-package-agreements --accept-source-agreements --disable-interactivity` |
| `brew` | macOS | `brew install <paquets>` ; refusé si `allow_brew = false` ou si le client tourne en administrateur |

### `deb`

```yaml
install:
  method: deb
  package: auxipak-demo          # champ Package du fichier control
  source: { file: payload/auxipak-demo_1.0.0_all.deb }
```

Linux uniquement ; extension `.deb`. Debian/Ubuntu :
`apt-get install -y --no-install-recommends /chemin/absolu/fichier.deb`
(APT résout les dépendances). AuxiNuxOS/VirtuaOS : délégation à la commande
`install_local_deb` de l'adaptateur, **vide par défaut** (l'installation
échoue tant qu'elle n'est pas configurée et validée). `auxipak-builder test`
compare `package` au champ `Package` du `.deb` (via `dpkg-deb --field`) si
l'outil est présent.

### `msi` (Windows)

```yaml
install:
  method: msi
  product_code: "{12345678-1234-1234-1234-1234567890AB}"
  scope: machine                 # ou user
  properties: { INSTALLDESKTOPSHORTCUT: "0" }
  source: { url: …, sha256: …, size: … }
```

| Paramètre | Description |
|---|---|
| `source` | `.msi` intégré ou distant |
| `product_code` | GUID entre accolades ; permet la détection et la désinstallation automatiques (sans lui : avertissement, `remove` explicite requis) |
| `properties` | propriétés publiques : nom `^[A-Z][A-Z0-9_]{0,63}$`, valeur sans guillemets ni métacaractères |
| `scope` | `machine` (défaut, privilèges admin) ou `user` (ajoute `ALLUSERS=2 MSIINSTALLPERUSER=1`) |

Appel : `msiexec /i <fichier> /qn /norestart [ALLUSERS=2 MSIINSTALLPERUSER=1] [PROP=valeur…]`.
Les codes `3010` et `1641` sont toujours interprétés comme « succès,
redémarrage requis ».

### `exe` (Windows)

```yaml
install: { method: exe, source: { file: payload/setup.exe }, args: ["/S"] }
```

`args` : arguments silencieux, chacun ≤ 256 caractères, sans guillemets ni
`` ` $ ; | & < > % ^ `` ni caractère de contrôle. Avertissement si
`privileges` n'est pas déclaré (admin supposé). Aucune détection ni
désinstallation n'est déductible : déclarer `remove` (méthode `exe`) et de
préférence `detect`. L'installateur exe est signalé au relecteur
(comportement opaque).

### `pkg` (macOS)

```yaml
install: { method: pkg, package_id: org.exemple.outil, source: { file: payload/Outil.pkg } }
```

`package_id` : identifiant de reçu en notation DNS inversée
(`pkgutil --pkgs`). Appel : `/usr/sbin/installer -pkg <fichier> -target /`.
Détection déduite : `pkgutil --pkg-info <id>`. La désinstallation doit être
déclarée (`remove: {method: pkg, …}`).

### `dmg` (macOS)

```yaml
install: { method: dmg, app: Outil.app, source: { url: …, sha256: … } }
```

Monte l'image en lecture seule (`hdiutil attach -nobrowse -readonly
-noautoopen -mountpoint …`), copie le bundle avec `ditto` vers
`/Applications` (administrateur) ou `~/Applications` (utilisateur), puis
démonte. Refuse d'écraser un bundle non géré par AuxiPak. Désinstallation et
détection déduites (méthode `app`).

### `files` (mode `embedded`, toutes plateformes)

```yaml
install:
  method: files
  files:
    - source: payload/bin/mon-outil        # fichier ou répertoire de l'archive
      destination: "{bin}/mon-outil"
      executable: true
```

| Paramètre | Description |
|---|---|
| `source` | sous `payload/`, présent dans `contents` (un répertoire est copié récursivement) |
| `destination` | `{app}`, `{bin}` ou `{data}` suivi éventuellement d'un chemin relatif sûr (section 10) |
| `executable` | droits `0755` sous Unix (sinon `0644`, ou `0755` si le fichier extrait est exécutable) |

Le client n'écrase **jamais** un fichier qui n'appartient pas à
l'application (ni lien symbolique, ni répertoire) ; chaque fichier est écrit
par fichier temporaire puis renommage, et enregistré dans la transaction pour
un retour arrière précis. Désinstallation (`files`) et détection (présence
des destinations) déduites.

### `script` (mode `embedded`)

```yaml
install: { method: script, script: scripts/install.sh, args: ["--prefix-auxipak"] }
remove:  { method: script, script: scripts/remove.sh }
```

Exige une désinstallation **explicite** et l'autorisation des scripts
(section 9).

## 6. Désinstallation (`remove`)

| Méthode | Paramètres | Action du client |
|---|---|---|
| `package_manager` | `manager`, `packages` | `apt-get remove -y` · adaptateur `remove` · `winget uninstall --id <id> --exact --silent --disable-interactivity` · `brew uninstall` |
| `deb` | `package` | gestionnaire natif de la distribution (`apt`, ou adaptateur sur AuxiNuxOS/VirtuaOS) |
| `msi` | `product_code` | `msiexec /x <code> /qn /norestart` |
| `exe` | `path`, `args` | exécute le désinstallateur ; `path` sous `{program_files}`, `{program_files_x86}`, `{local_app_data}` ou `{app}`, extension `.exe` |
| `pkg` | `package_id`, `paths` | supprime les `paths` (sous `/Applications/` uniquement) puis `pkgutil --forget <id>` |
| `app` | `app` | supprime le bundle `.app` enregistré à l'installation |
| `files` | — | supprime les fichiers enregistrés puis les répertoires devenus vides (seulement pour une installation `files`) |
| `script` | `script`, `args` | exécute le script (autorisation requise) |

Déduction lorsque `remove` est absent : `package_manager` → même
gestionnaire et mêmes paquets ; `deb` → `deb` ; `msi` avec `product_code` →
`msi` ; `dmg` → `app` ; `files` → `files`. Sinon (`exe`, `pkg`, `script`,
`msi` sans code) `remove` est **obligatoire**. Pour une installation `files`,
les fichiers enregistrés sont toujours supprimés, même si une autre méthode
de désinstallation est déclarée.

## 7. Détection (`detect`)

| Méthode | Paramètres | Contrôle |
|---|---|---|
| `package_manager` | `manager`, `package` | `apt` : `dpkg-query -W -f=${Status} <paquet>` contient `install ok installed` · `auxi`/`virtuaos` : commande `query` de l'adaptateur, code 0 (inconnu si non configurée) · `winget list --id <id> --exact` code 0 · `brew list --versions <paquet>` |
| `msi` | `product_code` | clé `Uninstall\<code>` dans `HKLM` (64 et 32 bits) ou `HKCU` (`reg query`) |
| `pkg` | `package_id` | `pkgutil --pkg-info <id>` |
| `app` | `app` | `/Applications/<app>` ou `~/Applications/<app>` |
| `files` | `paths` | tous les chemins (`{app}`, `{bin}`, `{data}`) existent |

Déduction : `package_manager` → premier paquet ; `deb` → `apt`/`dpkg-query`
sur `package` ; `msi` avec `product_code` ; `pkg` ; `dmg` → `app` ; `files`
→ destinations. La détection sert à refuser de revendiquer une application
installée hors AuxiPak (sauf `--adopt`), à contrôler le résultat d'une
installation et à `auxipak list --check` / `auxipak repair`.

## 8. Privilèges

Si `privileges` est absent :

| Méthode | Privilèges déduits |
|---|---|
| `package_manager` avec `winget` ou `brew` | `user` |
| `package_manager` avec `apt`, `auxi`, `virtuaos` | `admin` |
| `msi` avec `scope: user` | `user` |
| `files`, `dmg` | `user` |
| `deb`, `msi` (`machine`), `exe`, `pkg`, `script` | `admin` |

Le client ne s'élève jamais lui-même : une variante `admin` exige d'être
lancé avec `sudo` (Linux/macOS) ou depuis un terminal administrateur
(Windows), sinon l'opération est refusée avant toute modification. En
portée système, les racines `{app}`, `{bin}`, `{data}` sont des répertoires
système (voir [INSTALLATION.md](INSTALLATION.md#5-emplacements-des-fichiers)).

## 9. Scripts personnalisés

```yaml
scripts:
  pre_install: scripts/pre-install.sh
  post_install: scripts/post-install.sh
  pre_remove: scripts/pre-remove.sh
  post_remove: scripts/post-remove.sh
```

Règles de validation :

- chemin sous `scripts/`, présent dans `contents` ;
- extension `.sh` pour Linux et macOS, `.ps1` pour Windows ;
- un avertissement signale toute variante qui utilise des scripts
  (crochets, méthode `script`, désinstallation `script`) ; le serveur les
  signale au relecteur.

Politique du client : un script ne s'exécute que si l'utilisateur passe
`--allow-scripts` **ou** si le dépôt a `allow_scripts = true` dans la
configuration locale, **et** si le paquet est signé (ou que le dépôt n'exige
pas de signature). Sinon l'installation est refusée avant toute modification,
avec la liste des scripts concernés.

Exécution :

- `.sh` : `/bin/bash --noprofile --norc <script> [args]` ;
  `.ps1` : `powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File <script> [args]` ;
- répertoire courant : racine du paquet extrait (à la désinstallation : copie
  conservée du manifeste et des scripts dans `<état>/apps/<id>/`) ;
- environnement filtré + variables `AUXIPAK_ACTION` (`pre_install`,
  `install`, `post_install`, `pre_remove`, `remove`, `post_remove`),
  `AUXIPAK_APP_ID`, `AUXIPAK_VERSION`, `AUXIPAK_PAYLOAD_DIR`,
  `AUXIPAK_APP_DIR`, `AUXIPAK_BIN_DIR`, `AUXIPAK_DATA_DIR` ;
- ordre : dépendances natives → `pre_install` → méthode → `post_install` ;
  `pre_remove` → méthode → `post_remove` ;
- code de retour interprété selon `success_codes` / `reboot_codes`.

À la désinstallation, `payload/` n'est pas conservé : `AUXIPAK_PAYLOAD_DIR`
est alors vide, et un script de désinstallation ne doit pas en dépendre.

## 10. Racines de chemins

| Racine | Usage | Résolution |
|---|---|---|
| `{app}` | `files`, `detect.files`, `remove.exe` | `<apps>/<id>` (ex. `/opt/auxipak/apps/<id>`, `~/.local/share/auxipak/apps/<id>`) |
| `{bin}` | `files`, `detect.files` | répertoire des exécutables (`/usr/local/bin`, `~/.local/bin`…) |
| `{data}` | `files`, `detect.files` | `<data>/<id>` |
| `{program_files}` | `remove.exe` | `%ProgramFiles%` |
| `{program_files_x86}` | `remove.exe` | `%ProgramFiles(x86)%` |
| `{local_app_data}` | `remove.exe` | `%LOCALAPPDATA%` |

Un chemin est soit la racine seule, soit `racine/chemin/relatif` avec un
chemin relatif sûr (pas de `..`, etc.). Le tableau complet des emplacements
par portée figure dans [INSTALLATION.md](INSTALLATION.md#5-emplacements-des-fichiers).
Le répertoire `{data}/<id>` et le répertoire `{app}/<id>` (s'il est vide)
sont supprimés à la désinstallation.

## 11. Sélection de la variante

Pour le profil du système (plateforme, distribution, version, architecture),
une variante convient si :

1. `platform` correspond ;
2. sous Linux, la distribution figure dans `distributions` ;
3. l'architecture figure dans `architectures`, ou la variante est `any`, ou —
   sous Windows et macOS arm64 uniquement — la variante est `x86_64`
   (émulation par Windows 11 ou Rosetta 2) ;
4. la version du système satisfait `os_version` (si présent).

Entre plusieurs variantes compatibles, on préfère : une exécution native à
l'émulation, puis une architecture exacte à `any`, puis une variante dont la version est contrainte, puis l'ordre de
déclaration. Sans variante compatible, l'installation est refusée avec la
raison de chaque rejet. `auxipak-builder test` affiche la variante choisie
pour 12 profils de référence (Debian 12/13, Ubuntu 22.04/24.04, AuxiNuxOS,
VirtuaOS, Windows 10/11, macOS 13/14, en x86_64 et arm64).

## 12. Exemples complets

### 12.1 Firefox natif : Debian, AuxiNuxOS, Windows (winget)

```yaml
format: 1
id: firefox
name: "Firefox"
version: "150.1"
publisher: "Mozilla"
summary: "Navigateur Web libre"
description: |
  Navigateur Web développé par la fondation Mozilla. AuxiPak délègue
  l'installation au gestionnaire natif autorisé de chaque système.
license: "MPL-2.0"
homepage: "https://www.mozilla.org/firefox/"
languages: [mul]
categories: [internet]
privacy:
  telemetry: opt_out
  details: "Télémétrie activée par défaut, désactivable dans les paramètres."
targets:
  # Debian : paquet firefox-esr des dépôts Debian, installé par APT.
  - name: debian
    platform: linux
    distributions: [debian]
    os_version: ">=12"
    architectures: [x86_64, arm64]
    mode: native
    install:
      method: package_manager
      manager: apt
      packages: [firefox-esr]
    permissions: [network, user_files]
  # AuxiNuxOS : APT est bloqué ; installation par la commande système auxi.
  - name: auxinuxos
    platform: linux
    distributions: [auxinuxos]
    architectures: [x86_64, arm64]
    mode: native
    install:
      method: package_manager
      manager: auxi
      packages: [firefox]
    permissions: [network, user_files]
  # Windows : Windows Package Manager (identifiant winget exact).
  - name: windows
    platform: windows
    os_version: ">=10.0.19041"
    architectures: [x86_64, arm64]
    mode: native
    install:
      method: package_manager
      manager: winget
      packages: [Mozilla.Firefox]
    permissions: [network, user_files]
```

Paquet sans fichier : l'archive ne contient que le manifeste. Désinstallation
et détection sont déduites. La variante `debian` exige `sudo` ; la variante
`windows` s'exécute en utilisateur (winget).

### 12.2 MSI distant avec empreinte

```yaml
format: 1
id: exemple-outil
name: "Exemple Outil"
version: "3.2.1"
publisher: "Exemple inc."
summary: "Outil de démonstration distribué en MSI depuis le site de l'éditeur"
license: "Proprietary"
homepage: "https://www.example.org/outil"
languages: [fr-CA]
privacy:
  telemetry: none
targets:
  - name: windows-x64
    platform: windows
    os_version: ">=10.0.19041"
    architectures: [x86_64]
    mode: remote
    privileges: admin
    install:
      method: msi
      product_code: "{6F1C2E3A-4B5D-4E6F-8A9B-0C1D2E3F4A5B}"
      scope: machine
      properties:
        ALLUSERS: "1"
        INSTALLDESKTOPSHORTCUT: "0"
      source:
        url: "https://downloads.example.org/outil/3.2.1/ExempleOutil-3.2.1-x64.msi"
        sha256: "3b4f2c9e8d7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c"
        size: 48211968
        allowed_hosts: [cdn.example.org]
    reboot: recommended
    success_codes: [0]
    reboot_codes: [3010]
    timeout_seconds: 1800
    permissions: [system_files, services]
```

Le client télécharge l'installateur depuis `downloads.example.org` (avec
redirection éventuelle vers `cdn.example.org` seulement), vérifie taille et
SHA-256, puis exécute `msiexec /i … /qn /norestart ALLUSERS=1
INSTALLDESKTOPSHORTCUT=0`. Le relecteur voit l'URL distante et la permission
`services` dans le rapport de soumission.

### 12.3 Application de démonstration (`examples/auxipak-demo`)

Le manifeste source `examples/auxipak-demo/instruction.auxipak.in` (la
version y est substituée par `build.sh`) illustre :

- une variante `debian` (Debian/Ubuntu ≥ 12, `deb` intégré installé par APT) ;
- une variante `immutable` (AuxiNuxOS et VirtuaOS, copie `files` vers
  `{bin}`, sans privilèges) ;
- des variantes `macos` et `windows` en `files` ;
- une déclaration `privacy` (`telemetry: none`).

```yaml
targets:
  - name: debian
    platform: linux
    distributions: [debian, ubuntu]
    os_version: ">=12"
    architectures: [any]
    mode: embedded
    install:
      method: deb
      package: auxipak-demo
      source:
        file: payload/auxipak-demo_1.0.0_all.deb
  - name: immutable
    platform: linux
    distributions: [auxinuxos, virtuaos]
    architectures: [any]
    mode: embedded
    install:
      method: files
      files:
        - source: payload/bin/auxipak-demo
          destination: "{bin}/auxipak-demo"
          executable: true
```

Construction : `examples/auxipak-demo/build.sh 1.0.0 dist/` (requiert
`dpkg-deb` et `auxipak-builder`).
