# Documentation d'AuxiPak

AuxiPak est le service de distribution d'applications de l'écosystème AuxiNux
(<https://auxipak.auxinux.ca>). Cette documentation décrit la version 1.0.0.

## Pour commencer

| Document | Contenu |
|---|---|
| [INSTALLATION.md](INSTALLATION.md) | Installer le client `auxipak` (Linux, Windows, macOS), installer les ancres de confiance, compiler depuis les sources |
| [CLI_REFERENCE.md](CLI_REFERENCE.md) | Référence complète des commandes `auxipak` et `auxipak-builder`, codes de sortie, fichiers, variables d'environnement, adaptateurs `auxi` et VirtuaOS |

## Publier des applications

| Document | Contenu |
|---|---|
| [BUILDER.md](BUILDER.md) | Construire, tester, signer et soumettre un paquet (CLI et API), intégration GitHub Actions et agents d'automatisation |
| [MANIFEST_SPEC.md](MANIFEST_SPEC.md) | Spécification complète du manifeste `instruction.auxipak` |
| [AUPAK_FORMAT.md](AUPAK_FORMAT.md) | Spécification du format d'archive `.aupak` v1 et de la signature détachée `.aupak.sig` |
| [API.md](API.md) | API REST du serveur : routes, authentification, portées, politique d'approbation, exemples `curl` |

## Exploiter le service

| Document | Contenu |
|---|---|
| [DEPLOYMENT.md](DEPLOYMENT.md) | Déploiement sur Debian 13 (Docker Compose ou systemd), Nginx, sauvegardes, mises à jour, liste de contrôle de mise en production |
| [SIGNING.md](SIGNING.md) | Racine de confiance TUF, cérémonie de clés, distribution, rotation, révocation, signatures de paquets |
| [../SECURITY.md](../SECURITY.md) | Modèle de menaces, contrôles implémentés, signalement des vulnérabilités |

## Comprendre et faire évoluer le projet

| Document | Contenu |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | Architecture, justification des choix techniques, flux de publication, de synchronisation et d'installation, ajout d'une distribution |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Conventions, tests, style, règles de sécurité |
| [ROADMAP.md](ROADMAP.md) | Phase 2 et limites connues de la V1 |
| [i18n.md](i18n.md) | Traduire la documentation et l'interface Web |
| [../CHANGELOG.md](../CHANGELOG.md) | Historique des versions |

## Conventions de cette documentation

- Les commandes précédées de `$` s'exécutent en utilisateur ordinaire, celles
  précédées de `#` avec les droits d'administration (`sudo`).
- Les valeurs entre chevrons (`<id>`, `<jeton>`) sont à remplacer.
- Les mentions « validation restante » signalent un comportement implémenté
  mais pas encore éprouvé sur la plateforme réelle (Windows, macOS,
  AuxiNuxOS réel, VirtuaOS). L'état de validation à jour est tenu par le
  mainteneur dans le [README](../README.md#état-de-validation).
