# Référence des commandes

- [Client `auxipak`](#client-auxipak)
- [Configuration (config.toml)](#configuration-configtoml)
- [Adaptateur auxi (AuxiNuxOS)](#adaptateur-auxi-auxinuxos)
- [Adaptateur VirtuaOS](#adaptateur-virtuaos)
- [Constructeur `auxipak-builder`](#constructeur-auxipak-builder)

---

## Client `auxipak`

```text
auxipak [--json] <commande> [options]
auxipak --version | --help
```

| Option globale | Effet |
|---|---|
| `--json` | sortie JSON pour les commandes de consultation (`search`, `list`, `info`, `verify`, `repo list`) |
| `-h`, `--help` | aide |
| `-V`, `--version` | version (au niveau principal uniquement) |

Les commandes qui modifient l'état (`install`, `remove`, `upgrade`, `clean`,
`repair`) prennent un **verrou exclusif** (`<état>/auxipak.lock`) : une
seconde instance échoue immédiatement. Si des opérations interrompues
existent, un avertissement invite à lancer `auxipak repair`.

### `search [QUERY] [--offline]`

Recherche dans les index du canal du système (identifiant, nom, résumé ;
insensible à la casse et aux accents usuels). Une ligne par application et
par dépôt (meilleure version) ; les versions révoquées sont exclues ; sans
terme, liste tout.

- Les index sont synchronisés s'ils ne sont plus frais (TTL, 3 600 s par
  défaut). En cas d'échec réseau, le dernier index validé est utilisé avec un
  avertissement indiquant son âge.
- `--offline` : n'utilise que le cache, sans réseau.
- Colonnes : `ID`, `NOM`, `VERSION`, `LANGUE`, `STATUT` (`vérifié`,
  `compatible`, `non évalué`, ou `externe` pour un dépôt non officiel),
  `PLATEF.`, `DESCRIPTION` (suivie de `[dépôt]` pour un dépôt externe).
- JSON : `id`, `name`, `version`, `languages`, `status`, `platform`,
  `repository`, `summary`.

### `install PACKAGE [options]`

Installe une application et ses dépendances AuxiPak.

| Option | Effet |
|---|---|
| `PACKAGE` | identifiant (`firefox`), nom de fichier sans extension (`Firefox-150.1-fr`) ou nom affiché |
| `--version <CONTRAINTE>` | contrainte de version (`=150.1`, `>=150, <151`) |
| `--lang <LANGUE>` | langue exigée (`fr`, `fr-CA`, `en`…) ; les paquets `mul` conviennent |
| `--repo <NOM>` | limiter la résolution à un dépôt |
| `--allow-scripts` | autoriser explicitement les scripts personnalisés du paquet |
| `--adopt` | faire suivre par AuxiPak une application déjà installée par un autre moyen, sans la réinstaller (état `adopted`) |
| `--reinstall` | réinstaller la même version |

Déroulement : index frais exigés → résolution (révoqués refusés) →
dépendances → téléchargement avec reprise → vérification de l'empreinte
(index TUF) et de la signature → inspection de l'archive → variante →
privilèges → politique des scripts → installation transactionnelle →
contrôle de détection → registre. Détails : [ARCHITECTURE.md](ARCHITECTURE.md#7-flux-dinstallation-client).

Une application détectée comme déjà présente (installée hors AuxiPak) n'est
jamais revendiquée implicitement : l'installation est refusée sans
`--adopt`.

### `remove PACKAGE [options]`

Désinstalle une application **gérée par AuxiPak** (présente dans le
registre), selon la procédure du manifeste conservé à l'installation.

| Option | Effet |
|---|---|
| `--force` | désinstaller même si d'autres applications en dépendent |
| `--autoremove` | désinstaller aussi les dépendances installées automatiquement devenues inutiles |
| `--allow-scripts` | autoriser les scripts de désinstallation |

Les répertoires `{data}/<id>` et `{app}/<id>` (s'il est vide) sont supprimés.
Les dépendances natives installées par APT restent gérées par APT
(`apt autoremove`). Une application adoptée est désinstallée via son
gestionnaire d'origine.

### `update`

Force la synchronisation des index de tous les dépôts actifs (vérification
TUF complète) ; **ne met pas à jour les applications**. Affiche, par dépôt,
la génération, le nombre de versions pour le canal du système et la date
d'expiration des métadonnées. Code de sortie 1 si au moins un dépôt échoue.

### `upgrade [PACKAGE] [--allow-scripts]`

Met à niveau toutes les applications gérées, ou celle indiquée, vers la
meilleure version non révoquée **du même dépôt**, en privilégiant la langue
installée. Les applications adoptées sont laissées à leur gestionnaire
d'origine. Exige des index frais. Stratégie selon `upgrade.strategy` du
manifeste (`in_place` ou `remove_then_install`). Les fichiers d'une
installation `files` qui ne font plus partie de la nouvelle version sont
supprimés. En cas d'erreurs, les autres mises à niveau sont tout de même
tentées, puis la commande échoue en listant les erreurs.

### `list [--check]`

Liste les applications du registre : `ID`, `VERSION`, `DÉPÔT`, `MÉTHODE`,
`GEST.` (gestionnaire), `ÉTAT` (`installed`, `adopted`, `partial`,
`recovered`), date d'installation, mention `(dépendance)`. Un astérisque
signale une installation réalisée en mode simulation.

- `--check` : vérifie la présence réelle de chaque application (détection) ;
  ajoute `(absente!)` ou `(?)` si indéterminable.
- `--json` : registre complet.

### `info PACKAGE [--offline]`

Métadonnées (éditeur, licence, site), **statut AuxiNux** (et réserves),
versions disponibles (révoquées signalées), langues, plateforme, dépôt
(officiel/externe), mode et privilèges, dépendances, informations de
sécurité (fichier, taille, SHA-256, clé de signature, scripts, révocation,
date de publication), installation locale éventuelle. Pour une application
installée absente des index, affiche l'entrée du registre.

### `verify FILE [--signature SIG]`

Vérifie un `.apak` local **sans rien exécuter** : extension, structure,
manifeste (schéma et règles), correspondance avec `contents`, empreinte,
variantes, présence de scripts, avertissements. La signature
(`<fichier>.sig` par défaut, ou `--signature`) est vérifiée contre les clés
`package-signing` de chaque dépôt configuré. Code de sortie 1 si le paquet
ou la signature est invalide. Une absence de signature n'est pas une erreur
pour cette commande.

### `clean [--all]`

Supprime les paquets téléchargés (`<cache>/packages`) et, s'il n'y a pas
d'opération interrompue, les répertoires de travail (`<cache>/work`).
`--all` supprime aussi les index en cache (une synchronisation sera
nécessaire).

### `repo list | add | remove`

```text
auxipak repo list
auxipak repo add <URL> [--name NOM] (--root root.json --keys package-keys.json | --trust-on-first-use) [--allow-scripts]
auxipak repo remove <NOM>
```

- `repo list` : nom, `officiel`/`EXTERNE`, `actif`/`inactif`, URL, scripts
  autorisés.
- `repo add` : ajoute un dépôt **externe** (jamais officiel : il ne peut pas
  afficher les statuts AuxiNux). URL en HTTPS (ou `file://` pour un miroir
  local) ; nom par défaut : premier label du nom d'hôte ; nom
  `^[a-z0-9][a-z0-9_-]{0,31}$`. Les ancres sont copiées dans
  `<config>/trust/<nom>/`, l'empreinte de `root.json` et les clés sont
  affichées. Le dépôt exige des signatures (`require_signatures = true`) et
  reçoit la priorité 10.
  - `--root`, `--keys` : ancres obtenues par un canal sûr (recommandé) ;
  - `--trust-on-first-use` : télécharge `metadata/1.root.json` et
    `keys/package-keys.json` depuis le dépôt lui-même (moins sûr ; vérifiez
    les empreintes affichées auprès de l'éditeur) ;
  - `--allow-scripts` : autorise les scripts de ce dépôt (déconseillé).
- `repo remove` : retire le dépôt, son cache et ses ancres ; les applications
  installées restent dans le registre.

### `repair`

Reprend ou nettoie les transactions interrompues (`<état>/transactions/`) :

- interrompue avant toute modification du système → nettoyée ;
- désinstallation interrompue → registre mis à jour si l'application n'est
  plus détectée ;
- installation interrompue après lancement de l'installateur → enregistrée
  comme `recovered` si l'application est détectée, sinon fichiers copiés
  supprimés et, si l'état est indéterminé, enregistrée comme `partial`.

### `doctor`

Diagnostic : système détecté, canal, immuabilité, portée (système ou
utilisateur) et droits, emplacements (configuration, état, cache, journal),
TTL, mode simulation, pour chaque dépôt la source de confiance et l'état du
cache, nombre d'opérations interrompues, et un avertissement si l'adaptateur
`auxi` n'est pas validé sur AuxiNuxOS.

### Codes de sortie

| Code | Signification |
|---|---|
| 0 | succès |
| 1 | erreur (message `erreur : …` sur la sortie d'erreur, détail dans le journal) |
| 2 | erreur d'utilisation (option ou argument invalide, analyse de la ligne de commande) |

### Fichiers

| Fichier | Rôle |
|---|---|
| `<config>/config.toml` | configuration (section suivante) |
| `<config>/trust/<dépôt>/root.json`, `package-keys.json` | ancres de confiance |
| `<état>/profile.json` | profil système mémorisé |
| `<état>/registry.json` (+ `.bak`) | registre des installations (écriture atomique, sauvegarde de la version précédente lisible) |
| `<état>/transactions/<uuid>.json` | journal d'une opération en cours (`.corrupt` si illisible) |
| `<état>/apps/<id>/` | copie du manifeste et des scripts d'une application installée |
| `<état>/auxipak.lock` | verrou |
| `<cache>/repos/<dépôt>/` | métadonnées TUF (`tuf/`), index vérifiés (`verified/`), `state.json` |
| `<cache>/packages/<dépôt>/<sha256>.apak` | paquets téléchargés |
| `<cache>/work/` | répertoires de travail privés |
| `<journal>/auxipak.log` | journal (niveau `AUXIPAK_LOG`, `info` par défaut) |

Emplacements de `<config>`, `<état>`, `<cache>`, `<journal>` :
[INSTALLATION.md](INSTALLATION.md#5-emplacements-des-fichiers).

### Variables d'environnement

| Variable | Effet |
|---|---|
| `AUXIPAK_HOME` | place configuration, état, cache, journal et racines sous un répertoire unique |
| `AUXIPAK_LOG` | filtre de journalisation (`error`, `warn`, `info`, `debug`, syntaxe `tracing`) |
| `XDG_CONFIG_HOME`, `XDG_STATE_HOME`, `XDG_CACHE_HOME`, `XDG_DATA_HOME` | emplacements utilisateur (Linux/macOS) |
| `AUXIPAK_PROFILE_OVERRIDE` | **tests et diagnostic** : profil système imposé (JSON `{"os","distribution","version","arch","raw_id","pretty_name","immutable"}`) |
| `AUXIPAK_ASSUME_ELEVATED` | **tests** : `1` fait considérer le processus comme administrateur (n'accorde aucun droit réel) |
| `AUXIPAK_TEST_TOOLS_DIR` | **tests** : mode simulation ; les outils système sont cherchés dans ce répertoire ; les installations sont marquées `simulated` et ne valent jamais validation réelle |
| `AUXIPAK_TEST_LOG` | **tests** : transmise aux outils simulés |
| `AUXIPAK_TEST_CRASH_AT` | **tests**, binaires de débogage uniquement : interruption simulée (`after_extract`, `after_install`) |
| `AUXIPAK_OFFICIAL_TRUST_DIR` | **à la compilation** : répertoire de `root.json` et `package-keys.json` à intégrer au binaire |

Les outils lancés par AuxiPak ne reçoivent qu'une liste blanche de
variables (`PATH`, `HOME`, `USER`, `LOGNAME`, `LANG`, `LC_ALL`,
`LC_MESSAGES`, `TMPDIR`, `TERM`, variables système Windows usuelles,
`AUXIPAK_TEST_TOOLS_DIR`, `AUXIPAK_TEST_LOG`) plus celles propres à
l'opération (`DEBIAN_FRONTEND=noninteractive`, variables `AUXIPAK_*` des
scripts).

---

## Configuration (config.toml)

Sans fichier, la configuration par défaut équivaut à :

```toml
cache_ttl_seconds = 3600        # 1 à 604800
language = "fr"                 # langue préférée pour le choix des paquets

[[repository]]
name = "official"
url = "https://pak.auxinux.ca/repos/official/"
root = "trust/official/root.json"               # relatif à <config>, ou absolu
package_keys = "trust/official/package-keys.json"
official = true                 # seul un dépôt officiel localement affiche les statuts AuxiNux
enabled = true
allow_scripts = false           # autorise les scripts de ce dépôt sans --allow-scripts
require_signatures = true       # toujours exigé pour un dépôt officiel
allow_insecure_localhost = false   # développement : HTTP vers localhost/127.0.0.1/[::1]
priority = 0                    # plus petit = prioritaire à version égale

[adapters.auxi]
program = "auxi"
install = ["install", "{packages}"]
remove = ["remove", "{packages}"]
query = []
install_local_deb = []
validated = false

[adapters.virtuaos]
program = ""                    # non configuré

[policy]
allow_brew = true
max_download_bytes = 34359738368   # 32 Gio
```

- Tout champ inconnu est refusé. Si `config.toml` est absent dans la portée
  utilisateur, le client lit `/etc/auxipak/config.toml` (ou
  `%ProgramData%\AuxiPak\config\config.toml`) s'il existe.
- `url` : HTTPS, `file://` (miroir local, toujours vérifié par TUF), ou HTTP
  vers la boucle locale si `allow_insecure_localhost = true` ; jamais
  d'identifiants dans l'URL.
- Dans une section `[adapters.<nom>]`, `program` est obligatoire.

---

## Adaptateur auxi (AuxiNuxOS)

Sur AuxiNuxOS, APT est bloqué : AuxiPak n'utilise **jamais** `apt` (le
manifeste qui le tenterait est refusé : `apt` n'est autorisé que sur Debian et
Ubuntu). Les installations natives passent par la commande système `auxi`,
via un **adaptateur configurable**.

### Valeurs par défaut (supposées)

Les valeurs par défaut reposent sur la syntaxe annoncée (`auxi install
firefox`). Elles **n'ont pas été validées sur un AuxiNuxOS réel** :

| Opération | Commande par défaut | État |
|---|---|---|
| installation | `auxi install <paquets>` | supposée |
| désinstallation | `auxi remove <paquets>` | supposée |
| détection (`query`) | **vide** : la présence n'est pas vérifiable (résultat « inconnu ») | à définir |
| installation d'un `.deb` local (`install_local_deb`) | **vide** : les variantes `deb` échouent sur AuxiNuxOS | à définir |
| `validated` | `false` | |

Tant que `validated = false`, chaque appel est journalisé comme « syntaxe non
validée » et `auxipak doctor` l'indique sur AuxiNuxOS. Conséquences de la
détection vide : AuxiPak ne peut pas repérer une application déjà installée
par `auxi` (pas de refus ni d'adoption), ni confirmer une installation ;
`list --check` affiche `(?)`.

### Syntaxe des commandes

Chaque commande est un **vecteur d'arguments** (aucun interpréteur de
commandes). Paramètres substitués :

| Paramètre | Remplacé par |
|---|---|
| `{packages}` | la liste des paquets (chacun un argument, noms validés) |
| `{package}` | le premier paquet |
| `{file}` | chemin absolu d'un fichier local (`.deb`) |

Tout autre `{…}` est refusé ; les arguments littéraux ne doivent contenir ni
guillemets ni métacaractères (`` ` $ ; | & < > % ^ ``). `program` est un
chemin absolu ou un nom cherché **uniquement** dans `/usr/bin`, `/usr/sbin`,
`/bin`, `/sbin`, `/usr/local/bin`. Le code de retour est interprété avec
`success_codes` / `reboot_codes` de la variante ; l'entrée standard est
fermée (aucune interaction possible) ; délai `timeout_seconds` (3 600 s par
défaut).

### Liste des points à valider sur AuxiNuxOS réel

1. **Installation** : `auxi install <p1> <p2>` est-elle la syntaxe exacte ?
   Accepte-t-elle plusieurs paquets en un appel ? Faut-il une option non
   interactive (confirmation automatique), sachant que l'entrée standard est
   fermée ?
2. **Désinstallation** : sous-commande exacte (`remove`, `uninstall`…) et
   comportement des dépendances.
3. **Détection** : existe-t-il une commande dont le code de retour vaut 0 si
   et seulement si un paquet est installé ? Renseigner
   `query = ["<sous-commande>", "{package}"]`.
4. **Paquets `.deb` locaux** : `auxi` permet-il d'installer un fichier
   `.deb` local ? Si oui, renseigner `install_local_deb = ["…", "{file}"]` ;
   sinon, les éditeurs doivent utiliser `package_manager` (`auxi`) ou `files`.
5. **Codes de retour** : succès, « déjà installé », « paquet introuvable »,
   et surtout « redémarrage nécessaire » (système immuable : la modification
   peut ne prendre effet qu'au redémarrage → `reboot_codes` / `reboot`).
6. **Privilèges** : `auxi` exige-t-il root ? (AuxiPak déduit `admin` pour
   `auxi` et exige `sudo auxipak …`.) Fonctionne-t-il via `sudo` avec
   l'environnement filtré (`PATH`, `HOME`, `LANG`…) ?
7. **Emplacement** du programme (`/usr/bin/auxi` ?).
8. **Noms de paquets** : correspondance avec les noms Debian ; caractères
   utilisés (doivent respecter `^[A-Za-z0-9][A-Za-z0-9.+_:@/-]{0,127}$`).
9. **Système immuable** : où AuxiPak peut-il écrire en portée système
   (`/usr/local/bin`, `/opt/auxipak`, `/var/lib/auxipak`) ? Les marqueurs
   d'immuabilité (`/run/ostree-booted`, `/etc/auxinuxos-immutable`) sont-ils
   pertinents ?
10. **Détection du système** : `ID=auxinuxos` (ou `ID_LIKE` contenant
    `auxinuxos`) dans `/etc/os-release`.

Une fois validé, déployer la configuration (par exemple dans
`/etc/auxipak/config.toml`) :

```toml
[adapters.auxi]
program = "/usr/bin/auxi"
install = ["install", "{packages}"]
remove = ["remove", "{packages}"]
query = ["<sous-commande-validée>", "{package}"]
install_local_deb = []
validated = true
```

Puis vérifier avec `auxipak doctor` et une installation de test (par exemple
l'application de démonstration). Pour tester la mécanique sans système réel,
le mode simulation (`AUXIPAK_TEST_TOOLS_DIR`, outil factice `auxi`) est
utilisé par les tests d'intégration ; il ne vaut pas validation.

## Adaptateur VirtuaOS

VirtuaOS (détecté par `ID=virtuaos` ou `ID_LIKE` contenant `virtuaos`) est
traité comme un système immuable avec son propre canal (`linux/virtuaos`).
Son adaptateur **n'est pas configuré par défaut** (`program` vide) : toute
variante `package_manager` avec `manager: virtuaos` ou `deb` échoue avec le
message « l'adaptateur n'est pas configuré ». Les variantes `files` (et
`script`, si autorisées) fonctionnent sans adaptateur.

Après validation du mécanisme système de VirtuaOS (mêmes questions que pour
`auxi`), le configurer :

```toml
[adapters.virtuaos]
program = "/usr/bin/<outil-virtuaos>"
install = ["<sous-commande>", "{packages}"]
remove = ["<sous-commande>", "{packages}"]
query = ["<sous-commande>", "{package}"]
install_local_deb = []
validated = true
```

État : **validation restante** (détection, adaptateur, emplacements).

---

## Constructeur `auxipak-builder`

```text
auxipak-builder [--json] <commande> [options]
```

`--json` produit une sortie JSON pour `build`, `validate`, `test` et `submit`
(automatisation : CI, agents). Codes de sortie : 0 succès, 1 erreur, 2 erreur
d'utilisation.

| Commande | Description |
|---|---|
| `init <DIR> --id <ID> --name <NOM> [--version 1.0.0] [--publisher "Éditeur inconnu"] [--language fr] [--license GPL-3.0-or-later]` | crée un projet : `instruction.auxipak` (modèle `files` Linux), `payload/bin/<id>` (script d'exemple exécutable), `scripts/` ; refuse un répertoire contenant déjà un manifeste |
| `validate <CHEMIN>` | valide un **projet** (répertoire : construction complète dans un emplacement temporaire), une **archive** `.apak` ou un **manifeste** isolé (qui doit alors contenir `contents`) ; affiche les avertissements |
| `build <DIR> [-o, --output <FICHIER.apak>]` | construit une archive normalisée et déterministe ; nom par défaut `<Nom>-<version>-<langue>.apak` dans le répertoire courant ; ne publie rien |
| `test <FICHIER.apak>` | tests statiques : structure et manifeste, extraction et empreintes, variante choisie pour 12 profils de référence, couverture ; pour les variantes `deb` : `dpkg-deb --field <deb> Package` comparé au manifeste (si `dpkg-deb` est présent) ; pour les scripts `.sh` : `bash -n` (analyse sans exécution). Aucun installateur ni script n'est exécuté. Code 1 si un test échoue |
| `sign <FICHIER.apak> --key <CLÉ.pem>` | écrit `<FICHIER.apak>.sig` (clé Ed25519 PKCS#8 PEM ; variable `AUXIPAK_SIGNING_KEY`) |
| `verify-signature <FICHIER.apak> --keys <package-keys.json>` | vérifie `<FICHIER.apak>.sig` (usages `package-signing` et `developer-signing` admis) |
| `keys generate --out <CLÉ.pem> --public <package-keys.json> [--owner AuxiNux]` | crée une clé de signature de paquets (`0600`, jamais d'écrasement) et ajoute la clé publique au fichier (créé s'il n'existe pas) |
| `keys init-repository --out <DIR> [--owner AuxiNux] [--root-days 365] [--dev]` | cérémonie : racine TUF, clés en ligne, clé de paquets (voir [SIGNING.md](SIGNING.md)) ; `--dev` omet le rappel de procédure de production |
| `keys show-root <root.json>` | version, expiration, clés et seuils de chaque rôle |
| `submit <FICHIER.apak> --server <URL> --token <JETON> [--repository official] [--note ""]` | crée une **demande de publication** (`POST /api/v1/submissions`) puis joint `<FICHIER.apak>.sig` s'il existe (`PUT …/signature`) ; HTTPS obligatoire (HTTP seulement vers `localhost`/`127.0.0.1`) ; variables `AUXIPAK_SERVER` et `AUXIPAK_TOKEN` |

Exemples :

```console
$ auxipak-builder init mon-outil --id mon-outil --name "Mon outil" --publisher "Exemple inc." --license MIT
$ auxipak-builder validate mon-outil
$ auxipak-builder --json build mon-outil -o Monoutil-1.0.0-fr.apak
$ auxipak-builder test Monoutil-1.0.0-fr.apak
$ AUXIPAK_SERVER=https://pak.auxinux.ca AUXIPAK_TOKEN=apk_… auxipak-builder submit Monoutil-1.0.0-fr.apak --note "version 1.0.0"
```

Pour `keys generate`, indiquez un chemin `--out` situé dans un
sous-répertoire dédié (par exemple `secrets/cle-paquets.pem`) : le
répertoire parent est créé avec les droits `0700`.
