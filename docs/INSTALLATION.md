# Installation

Ce document couvre l'installation du **client** `auxipak` et la compilation
depuis les sources. Le **serveur** se déploie selon [DEPLOYMENT.md](DEPLOYMENT.md).

## 1. Plateformes prises en charge

Le client détecte le système au premier lancement et choisit le canal d'index
correspondant (voir [ARCHITECTURE.md](ARCHITECTURE.md#canaux)) :

| Système | Détection | Canal | Mécanismes d'installation | État |
|---|---|---|---|---|
| Debian (12, 13) | `/etc/os-release` (`ID=debian`) | `linux/deb` | APT (`apt-get`), paquets `.deb`, `files`, scripts | démonstration `tests/e2e` prévue pour Debian/Ubuntu ; validation sur Debian réel à consigner |
| Ubuntu (22.04, 24.04) et dérivées (`ID_LIKE=ubuntu`) | `os-release` | `linux/deb` | idem Debian | démonstration de bout en bout (installation `.deb` réelle) intégrée à la CI sur Ubuntu 24.04 |
| AuxiNux OS (Debian 13) | `VARIANT_ID=auxinuxos` (son `ID` reste `debian`), sinon `ID=auxinuxos` ou `ID_LIKE` contenant `auxinuxos` | `linux/auxinuxos`, complété par les versions Debian de `linux/deb` | commande `auxi` (APT n'est **jamais** utilisé ; variantes Debian par `auxi --deb`), `files`, scripts | syntaxe `auxi` vérifiée contre le script réel ; installation réelle en VM à consigner |
| VirtuaOS | `ID=virtuaos` ou `ID_LIKE` contenant `virtuaos` | `linux/virtuaos` | adaptateur configurable (non configuré par défaut), `files`, scripts | **validation restante** |
| Windows 10/11 (x86_64, ARM64) | API système (`os_info`) | `windows` | winget, MSI (`msiexec`), EXE, `files`, PowerShell | **validation restante** |
| macOS 13+ (Intel, Apple Silicon) | `os_info`, Rosetta détectée | `macos` | `pkg` (`installer`), `dmg`, Homebrew, `files`, scripts | **validation restante** |

Architectures : `x86_64` et `arm64`. Une distribution Linux non reconnue
(Fedora, Arch…) est signalée comme non prise en charge : aucun canal ne lui
correspond. AuxiPak ne met jamais à jour le système d'exploitation lui-même.

## 2. Binaires publiés

Les binaires sont produits par le flux GitHub Actions
`.github/workflows/release.yml` à chaque étiquette `v*` (par exemple
`v1.0.0`), puis publiés, après relecture humaine du brouillon, sur
<https://github.com/auxinux/auxipak/releases>.

| Archive | Contenu |
|---|---|
| `auxipak-<version>-linux-x86_64.tar.gz`, `auxipak-<version>-linux-arm64.tar.gz` | `auxipak`, `auxipak-builder`, `auxipak-server` |
| `auxipak-<version>-windows-x86_64.zip`, `auxipak-<version>-windows-arm64.zip` | `auxipak.exe`, `auxipak-builder.exe` |
| `auxipak-<version>-macos-arm64.tar.gz`, `auxipak-<version>-macos-x86_64.tar.gz` | `auxipak`, `auxipak-builder` |
| `SHA256SUMS` | empreintes SHA-256 de toutes les archives |

Chaque archive contient aussi `LICENSE`, `README.md` et `CHANGELOG.md`, et
fait l'objet d'une **attestation de provenance** signée (Sigstore). Avant
toute installation :

```console
$ sha256sum -c --ignore-missing SHA256SUMS                     # macOS : shasum -a 256 -c
$ gh attestation verify auxipak-v1.0.0-linux-x86_64.tar.gz --repo auxinux/auxipak
```

Sous Windows : `Get-FileHash -Algorithm SHA256 <archive>` et comparaison avec
`SHA256SUMS`.

Le flux de publication intègre les ancres de confiance du dépôt officiel au
client si le dépôt source contient `trust/official/root.json` (variable
`AUXIPAK_OFFICIAL_TRUST_DIR`, voir section 7 et
[SIGNING.md](SIGNING.md#4-distribution-de-la-racine-avec-le-client)) ; sinon
il émet un avertissement et le client est publié sans ancre embarquée. Dans
ce cas, installez `root.json` et `package-keys.json` (section 4).

Les binaires Windows et macOS sont construits et leurs tests automatisés
exécutés nativement par l'intégration continue ; l'installation réelle
d'applications sur ces systèmes reste à valider.

## 3. Installation du client

### 3.0 Installation en une commande (recommandée)

Le serveur publie des scripts d'installation qui téléchargent le client
correspondant à la plateforme, vérifient son empreinte SHA-256, installent les
ancres de confiance du dépôt officiel et créent la configuration :

| Système | Installation | Désinstallation |
|---|---|---|
| Linux, macOS | `curl -fsSL https://auxipak.auxinux.ca/install.sh \| sh` | `curl -fsSL https://auxipak.auxinux.ca/uninstall.sh \| sh` |
| Windows (PowerShell) | `irm https://auxipak.auxinux.ca/install.ps1 \| iex` | `irm https://auxipak.auxinux.ca/uninstall.ps1 \| iex` |

Options :

- Linux/macOS : `… | sh -s -- --with-builder` installe aussi
  `auxipak-builder` ; `uninstall.sh` accepte `--purge` (configuration,
  registre, cache et journaux).
- Windows : `$env:AUXIPAK_WITH_BUILDER = "1"` avant l'installation ;
  `$env:AUXIPAK_PURGE = "1"` avant la désinstallation.

Emplacements : `/usr/local/bin` et `/etc/auxipak` (Linux, macOS, via `sudo`) ;
sous Windows, `C:\Program Files\AuxiPak\bin` et
`C:\ProgramData\AuxiPak\config` depuis une console administrateur, sinon
`%LOCALAPPDATA%\AuxiPak` pour l'utilisateur courant (PATH mis à jour).
Les applications installées par AuxiPak ne sont jamais supprimées par les
scripts de désinstallation.

Le script affiche l'empreinte de `root.json` : comparez-la à celle publiée par
AuxiNux par un autre canal. Côté serveur, les binaires proviennent d'une
release (`deploy/scripts/fetch-client.sh`, voir
[DEPLOYMENT.md](DEPLOYMENT.md#38-binaires-du-client-et-scripts-dinstallation)).

Les sections suivantes décrivent l'installation manuelle.

### 3.1 Linux (Debian, Ubuntu, AuxiNuxOS, VirtuaOS)

```console
# install -m 0755 auxipak /usr/local/bin/auxipak
# install -m 0755 auxipak-builder /usr/local/bin/auxipak-builder   # facultatif (éditeurs)
$ auxipak --version
```

Sur AuxiNux OS, le client est fourni en paquet `.deb` (ci-dessous) ;
l'adaptateur `auxi` est configuré par défaut
([CLI_REFERENCE.md](CLI_REFERENCE.md#adaptateur-auxi-auxinuxos)).

#### Paquet Debian (`auxipak_VERSION_amd64.deb`)

```console
$ packaging/deb/build-deb.sh 1.0.10                       # binaire publié sur le serveur (SHA256SUMS vérifié)
$ packaging/deb/build-deb.sh 1.0.10 --from-dir target/release --out dist
```

Contenu : `/usr/bin/auxipak` (le client seul), `/etc/auxipak/config.toml`
(conffile : dépôt officiel et section `[adapters.auxi]` explicite) et
`/etc/auxipak/trust/official/{root.json,package-keys.json}` (ancres
publiques ; l'empreinte de `root.json` est vérifiée par le script).
`Depends` est calculé sur le binaire (`libc6 (>= <glibc minimale>)`,
`libgcc-s1`) ; `Recommends: auxi | apt`. Installé ainsi, AuxiPak se met à
jour avec le système, pas par `auxipak upgrade`. La CI construit le paquet
(artefact `auxipak-deb`) et l'installe avec `apt-get`.

### 3.2 Windows (validation restante)

1. Copier `auxipak.exe` dans `C:\Program Files\AuxiPak\` (terminal administrateur).
2. Ajouter ce répertoire au `PATH` du système.
3. Installer les ancres de confiance dans
   `C:\ProgramData\AuxiPak\config\trust\official\` (section 4).

Les installations qui exigent des droits d'administration (MSI `machine`, EXE)
doivent être lancées depuis un terminal « Exécuter en tant
qu'administrateur » : AuxiPak ne s'élève jamais lui-même. winget doit être
présent (`%LOCALAPPDATA%\Microsoft\WindowsApps\winget.exe`).

### 3.3 macOS (validation restante)

```console
# install -m 0755 auxipak /usr/local/bin/auxipak
```

Si le binaire n'est pas notarié, macOS peut le bloquer au premier lancement
(Gatekeeper) ; vérifiez l'empreinte avant d'autoriser son exécution. Homebrew
est utilisé uniquement s'il est présent (`/opt/homebrew/bin/brew` ou
`/usr/local/bin/brew`), autorisé par la politique locale (`allow_brew`) et
jamais en tant qu'administrateur.

## 4. Installation des ancres de confiance

Le client n'accorde sa confiance à un dépôt qu'à partir de deux fichiers
publics produits par la cérémonie de clés ([SIGNING.md](SIGNING.md)) :

- `root.json` : racine TUF (authenticité, fraîcheur et non-régression des index) ;
- `package-keys.json` : clés publiques de signature des paquets.

Pour le dépôt officiel, la configuration par défaut les cherche dans
`trust/official/`, relativement au répertoire de configuration :

| Portée | Emplacement |
|---|---|
| Système Linux/macOS | `/etc/auxipak/trust/official/root.json` et `package-keys.json` |
| Système Windows | `%ProgramData%\AuxiPak\config\trust\official\` |
| Utilisateur Linux/macOS | `~/.config/auxipak/trust/official/`, **sinon** `/etc/auxipak/trust/official/` |
| Utilisateur Windows | `%LOCALAPPDATA%\AuxiPak\config\trust\official\`, sinon `%ProgramData%\AuxiPak\config\trust\official\` |

Ordre de résolution : chemin absolu → répertoire de configuration de la
portée courante → configuration système → ancre embarquée dans le binaire
(dépôt nommé `official` et marqué officiel uniquement).

Installation système (Linux/macOS) :

```console
# install -d -m 0755 /etc/auxipak/trust/official
# install -m 0644 root.json package-keys.json /etc/auxipak/trust/official/
$ sha256sum /etc/auxipak/trust/official/root.json   # comparer à l'empreinte publiée
```

Obtenez ces fichiers par un canal sûr (paquet du client, support remis en
main propre, empreinte publiée sur un canal indépendant). Les télécharger
depuis le serveur lui-même revient à une « confiance au premier usage ».

## 5. Emplacements des fichiers

Le client choisit la portée au lancement : **système** si le processus a les
droits d'administration (root, administrateur Windows), **utilisateur**
sinon. La variable `AUXIPAK_HOME` place tout sous un répertoire unique
(tests, installation portable).

| Rôle | Système Linux/macOS | Utilisateur Linux/macOS | Système Windows | Utilisateur Windows | `AUXIPAK_HOME` |
|---|---|---|---|---|---|
| Configuration (`config.toml`, `trust/`) | `/etc/auxipak` | `$XDG_CONFIG_HOME/auxipak` (`~/.config/auxipak`) | `%ProgramData%\AuxiPak\config` | `%LOCALAPPDATA%\AuxiPak\config` | `<home>/config` |
| État (registre, transactions, profil) | `/var/lib/auxipak` | `$XDG_STATE_HOME/auxipak` (`~/.local/state/auxipak`) | `%ProgramData%\AuxiPak\state` | `%LOCALAPPDATA%\AuxiPak\state` | `<home>/state` |
| Cache (index vérifiés, paquets) | `/var/cache/auxipak` | `$XDG_CACHE_HOME/auxipak` (`~/.cache/auxipak`) | `%ProgramData%\AuxiPak\cache` | `%LOCALAPPDATA%\AuxiPak\cache` | `<home>/cache` |
| Journal (`auxipak.log`) | `/var/log/auxipak` | `~/.local/state/auxipak/log` | `%ProgramData%\AuxiPak\log` | `%LOCALAPPDATA%\AuxiPak\log` | `<home>/log` |
| Racine `{app}` | `/opt/auxipak/apps/<id>` | `~/.local/share/auxipak/apps/<id>` | `%ProgramFiles%\AuxiPak\apps\<id>` | `%LOCALAPPDATA%\AuxiPak\apps\<id>` | `<home>/apps/<id>` |
| Racine `{bin}` | `/usr/local/bin` | `~/.local/bin` | `%ProgramFiles%\AuxiPak\bin` | `%LOCALAPPDATA%\AuxiPak\bin` | `<home>/bin` |
| Racine `{data}` | `/var/lib/auxipak/data/<id>` | `~/.local/share/auxipak/data/<id>` | `%ProgramData%\AuxiPak\data\<id>` | `%LOCALAPPDATA%\AuxiPak\data\<id>` | `<home>/data/<id>` |

Le répertoire d'état est restreint au propriétaire (droits `0700` sous Unix).
Pour une installation utilisateur, ajoutez `~/.local/bin` (ou
`%LOCALAPPDATA%\AuxiPak\bin`) au `PATH`.

## 6. Premier lancement

```console
$ auxipak doctor      # profil détecté, canal, portée, dépôts, confiance
$ auxipak update      # synchronisation des index (vérification TUF complète)
$ auxipak search firefox
```

Au premier lancement, le profil système est enregistré
(`<état>/profile.json`). Un changement important (système, distribution,
version majeure, architecture) est détecté automatiquement et provoque une
resynchronisation des index.

Sans fichier `config.toml`, la configuration par défaut contient uniquement
le dépôt officiel `https://auxipak.auxinux.ca/repos/official/`. Le format complet
de `config.toml` est décrit dans [CLI_REFERENCE.md](CLI_REFERENCE.md#configuration-configtoml).

## 7. Compilation depuis les sources

Prérequis : Rust **1.89** ou plus récent (`rust-version` du workspace),
`cargo`, un compilateur C (dépendances cryptographiques), Git.

```console
$ git clone https://github.com/auxinux/auxipak.git
$ cd auxipak
$ cargo build --release --locked -p auxipak -p auxipak-builder
$ ls target/release/auxipak target/release/auxipak-builder
```

### Intégrer les ancres du dépôt officiel au binaire

Si `AUXIPAK_OFFICIAL_TRUST_DIR` désigne, **à la compilation**, un répertoire
contenant `root.json` et `package-keys.json`, ces fichiers sont intégrés au
binaire du client (`client/build.rs`). La compilation échoue si l'un des deux
manque.

```console
$ AUXIPAK_OFFICIAL_TRUST_DIR=/chemin/vers/client-trust \
    cargo build --release --locked -p auxipak
```

L'ancre embarquée n'est utilisée qu'en dernier recours, lorsque aucun fichier
n'est trouvé sur disque pour le dépôt `official` (section 4). Ne placez dans
ce répertoire que les fichiers **publics** produits par
`deploy/scripts/init-keys.sh` (`client-trust/`).

### Composants

| Paquet Cargo | Binaire | Rôle |
|---|---|---|
| `auxipak-core` (`shared/`) | — | bibliothèque commune |
| `auxipak` (`client/`) | `auxipak` | client |
| `auxipak-builder` (`builder/`) | `auxipak-builder` | constructeur de paquets |
| `auxipak-server` (`server/`) | `auxipak-server` | serveur (voir [DEPLOYMENT.md](DEPLOYMENT.md)) |

Windows et macOS : la compilation native sur la plateforme cible est la voie
recommandée (`cargo build --release --locked -p auxipak`). Le serveur, lui,
exige un système Unix (bascule de lien symbolique lors de la publication).

## 8. Désinstallation du client

1. Désinstaller les applications gérées si souhaité (`auxipak list`, puis
   `auxipak remove <id>`).
2. Supprimer le binaire, puis les répertoires de configuration, d'état, de
   cache et de journal listés en section 5.

Les applications installées par un gestionnaire natif (APT, `auxi`, winget,
MSI, pkg) restent gérables par ce gestionnaire après la suppression d'AuxiPak.
