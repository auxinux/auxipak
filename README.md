# AuxiPak

**AuxiPak** est le service de distribution d'applications multiplateforme de
l'écosystème AuxiNux : <https://auxipak.auxinux.ca>.

Il permet de rechercher, installer, mettre à niveau et désinstaller des
applications sur Debian, Ubuntu, AuxiNuxOS, VirtuaOS, Windows et macOS, à
partir de paquets `.aupak` signés et d'index authentifiés par TUF.

## Philosophie

- **AuxiPak ne remplace pas les gestionnaires de paquets.** Il utilise les
  mécanismes natifs autorisés de chaque système : APT sur Debian/Ubuntu, la
  commande `auxi` sur AuxiNuxOS (où APT est bloqué), un adaptateur
  configurable sur VirtuaOS, winget/MSI/EXE sur Windows, pkg/dmg/Homebrew
  sur macOS, et une méthode `files` de copie de fichiers.
- **AuxiPak ne met jamais à jour le système d'exploitation.**
- **Déclaratif et vérifiable.** Le manifeste `instruction.auxipak` ne contient
  aucune commande libre ; tout est validé avant exécution, sans interpréteur
  de commandes ; les scripts exigent une autorisation explicite.
- **Confiance explicite.** Index protégés par TUF (authenticité, fraîcheur,
  anti-retour en arrière), paquets signés en Ed25519, archives inspectées
  avant extraction.
- **Humain dans la boucle.** Une soumission (y compris par une CI ou un agent
  IA) n'est publiée qu'après l'approbation d'un relecteur humain.

### Statuts AuxiNux

Chaque application du dépôt officiel porte un statut, attribué par un
relecteur et **distinct de la signature** (qui n'atteste que l'origine et
l'intégrité) :

| Statut | Signification |
|---|---|
| **AuxiNux Vérifié** | application évaluée et conforme aux critères AuxiNux |
| **AuxiNux Compatible** | application acceptable, avec des réserves documentées |
| **Non évalué** | application publiée, pas encore évaluée |

Les dépôts ajoutés par l'utilisateur sont toujours affichés comme
« externes » : ils ne peuvent pas se prévaloir d'un statut AuxiNux.

## Composants

| Composant | Rôle |
|---|---|
| `auxipak` (`client/`) | client en ligne de commande : `search`, `install`, `remove`, `update`, `upgrade`, `list`, `info`, `verify`, `clean`, `repo`, `repair`, `doctor` |
| `auxipak-builder` (`builder/`) | création, validation, construction, tests statiques, signature et soumission de paquets ; cérémonie de clés |
| `auxipak-server` (`server/`) | API REST, interface Web bilingue (fr/en), relecture et publication, signature, génération des index et métadonnées TUF |
| `auxipak-core` (`shared/`) | bibliothèque commune : manifeste, format `.aupak`, signatures, index, TUF |
| `web/` | gabarits, traductions et thème de l'interface Web |
| `deploy/` | Docker, Compose, Nginx, systemd, scripts d'exploitation |
| `examples/auxipak-demo/` | application de démonstration |

Tout est écrit en Rust : binaires autonomes, une seule bibliothèque de
validation partagée par le client, le constructeur et le serveur.

## Installation du client

```sh
curl -fsSL https://auxipak.auxinux.ca/install.sh | sh      # Linux, macOS
```

```powershell
irm https://auxipak.auxinux.ca/install.ps1 | iex           # Windows
```

Détails et désinstallation : [docs/INSTALLATION.md](docs/INSTALLATION.md).

## Démarrage rapide (développement)

Prérequis : Rust ≥ 1.89, Docker (ou PostgreSQL local).

```console
$ git clone https://github.com/auxinux/auxipak.git && cd auxipak
$ cargo build                                   # auxipak, auxipak-builder, auxipak-server

# Serveur de développement (clés de TEST générées automatiquement)
$ docker compose -f deploy/docker-compose.dev.yml up --build -d
$ docker compose -f deploy/docker-compose.dev.yml exec server auxipak-server create-admin --username admin
$ curl -fsS http://127.0.0.1:8080/api/v1/health

# Construire le paquet de démonstration
$ AUXIPAK_BUILDER=$PWD/target/debug/auxipak-builder examples/auxipak-demo/build.sh 1.0.0 dist/
$ target/debug/auxipak verify dist/AuxiPakDemo-1.0.0-mul.aupak

# Démonstration complète de bout en bout (serveur et base éphémères)
$ PG_ADMIN_URL=postgres://postgres:motdepasse@127.0.0.1:5432/postgres tests/e2e/run-local.sh
```

Interface Web : <http://127.0.0.1:8080> (administration : `/admin`).

## Documentation

| | |
|---|---|
| [Installation](docs/INSTALLATION.md) | client (Linux, Windows, macOS), ancres de confiance, compilation |
| [Référence des commandes](docs/CLI_REFERENCE.md) | `auxipak`, `auxipak-builder`, configuration, adaptateurs `auxi` et VirtuaOS |
| [Construire et publier](docs/BUILDER.md) | Builder CLI et API, GitHub Actions, agents IA |
| [Manifeste](docs/MANIFEST_SPEC.md) | spécification de `instruction.auxipak` |
| [Format .aupak](docs/AUPAK_FORMAT.md) | archive et signature détachée |
| [API](docs/API.md) | API REST du serveur |
| [Déploiement](docs/DEPLOYMENT.md) | Debian 13, Docker Compose, Nginx, sauvegardes |
| [Signatures et clés](docs/SIGNING.md) | TUF, cérémonie de clés, rotation, révocation |
| [Architecture](docs/ARCHITECTURE.md) | conception et choix techniques |
| [Contribuer](docs/CONTRIBUTING.md) · [Feuille de route](docs/ROADMAP.md) · [Traductions](docs/i18n.md) | |
| [Sécurité](SECURITY.md) · [Historique](CHANGELOG.md) | |

## État de validation

Une fonctionnalité implémentée n'est pas une fonctionnalité validée. État au
19 octobre 2026 (V1.0.0) :

| Élément | État | Détail |
|---|---|---|
| Bibliothèque commune, client, Builder, serveur | **testés** | 102 tests automatiques (unitaires et d'intégration, dont 5 contre PostgreSQL réel) |
| Parcours complet de démonstration (section 19) | **validé réellement sur Ubuntu 24.04 x86_64** | `tests/e2e/run-local.sh` : construction, signature, soumission par jeton agent, approbation humaine, INDEX, synchronisation TUF, recherche, installation du `.deb` via APT, `list`, mise à niveau 1.0.0 → 1.1.0, révocation, désinstallation, nettoyage (30 vérifications) |
| Méthode `files` (profil AuxiNuxOS imposé) | validée sur Ubuntu | installation réelle de fichiers ; seule la *détection* du système est simulée |
| Image Docker du serveur (Debian 13) | validée | construction, démarrage en mode production, conteneur en lecture seule, sonde de santé |
| Debian 13 réel | **à valider** | détection testée par analyse d'`os-release` ; parcours APT identique à Ubuntu |
| AuxiNuxOS 1.0 réel | **à valider** | syntaxe de la commande `auxi` supposée (`auxi install/remove`) : voir [CLI_REFERENCE.md](docs/CLI_REFERENCE.md) ; adaptateur testé uniquement en simulation |
| VirtuaOS | **à valider** | adaptateur système non configuré ; méthode `files` disponible |
| Windows x64/ARM64, macOS Apple Silicon, Linux ARM64 | **partiellement validés (CI GitHub Actions)** | compilation et tests natifs du client et de la bibliothèque réussis (TUF, signatures, extraction, méthode `files`, registre, reprise après interruption, refus de privilèges) |
| macOS Intel | construit en CI | binaire compilé par compilation croisée ; aucun test exécuté |
| Méthodes MSI, EXE, winget, pkg, dmg, Homebrew | **à valider** | arguments construits et vérifiés par revue ; jamais exécutées sur un système réel |
| Clés de production | **non créées** | cérémonie à réaliser ([SIGNING.md](docs/SIGNING.md)) ; aucune clé privée n'est versionnée |

## Licence

GPL-3.0-or-later — voir [LICENSE](LICENSE).
