# Feuille de route

## 1. Phase 2

| Chantier | Objectif | Points d'appui existants en V1 |
|---|---|---|
| **Autorité de certification `ca.auxinux.ca`** | Émettre des certificats aux développeurs et vérifier des chaînes de certificats | champ `certificate_chain` du `.aupak.sig` (vide, non signé), signature détachée |
| **Certificats développeurs** | Permettre la publication de paquets signés par leur éditeur, avec une identité vérifiée | usage de clé `developer-signing`, accepté par `auxipak-builder verify-signature` ; refusé pour la publication en V1 |
| **Révocation centralisée** | Révoquer clés et certificats et diffuser la révocation de façon authentifiée (via TUF), sans mise à jour manuelle des clients | `revoked`, `not_before`, `not_after` dans `package-keys.json` ; `revocations.json` (paquets) |
| **Rotation des clés** | Commande de rotation de la racine TUF (N+1 signée par l'ancienne et la nouvelle racine), conservation de toutes les versions `N.root.json`, seuils multi-clés, diffusion des clés de paquets par TUF | `auxipak-core::tuf::create_root` (version, plusieurs clés, seuil) |
| **Dépôts externes avancés** | Fédération de dépôts tiers, découverte via `/index`, épinglage et politiques par dépôt (scripts, priorités, statuts) | `auxipak repo add`, statut « externe » forcé, `priority`, `allow_scripts`, `require_signatures` |
| **Soumission tierce** | Éditeurs externes autonomes : inscription, espaces de publication, quotas, file de relecture | comptes `publisher`, jetons `ci`/`agent`, demandes de publication, approbateur distinct |
| **Évaluation** | Grille d'évaluation structurée (vie privée, télémétrie, sécurité, licence…), historique consultable, réévaluation périodique | table `evaluations` (`criteria` JSON), `evaluation_history`, statut `compatible` avec réserves obligatoires |
| **IA avancée** | Assistance à la relecture (analyse des manifestes, détection d'anomalies) et à la création de paquets, toujours sous décision humaine | API Builder, jetons `agent` limités, rapport `review_flags` |
| **Tableau de bord de conformité** | Vue d'ensemble : statuts, signatures, versions révoquées, expirations de clés et de métadonnées, couverture des plateformes | journal d'audit, `/admin`, données en base |
| **Miroirs** | Miroirs publics ou d'entreprise, vérifiés par TUF de bout en bout | les clients vérifient tout par TUF ; `file://` accepté pour un miroir local |
| **Mises à jour incrémentales** | Téléchargement différentiel des paquets et des index | index découpés par canal et architecture |
| **Délégations TUF / « hashed bins »** | Limiter la taille de `targets.json` et déléguer des espaces de noms (éditeurs, dépôts) | génération centralisée dans `repogen.rs` / `tuf.rs` |

## 2. Limites connues de la V1

### Validation des plateformes

- **Windows, macOS, AuxiNuxOS réel et VirtuaOS : validation restante.** Les
  méthodes (winget, MSI, EXE, PowerShell, pkg, dmg, Homebrew, `auxi`) sont
  implémentées et leurs tests automatisés s'exécutent, mais aucune
  installation réelle d'application n'a été validée sur ces systèmes.
- **Adaptateur `auxi`** : syntaxe vérifiée contre le script `auxi`
  d'AuxiNux OS 0.3.0 (1.0.10) ; installation réelle de bout en bout en VM
  restant à consigner. Voir
  [CLI_REFERENCE.md](CLI_REFERENCE.md#adaptateur-auxi-auxinuxos).
- **VirtuaOS** : adaptateur non configuré ; seules les variantes `files` (et
  `script`, si autorisées) fonctionnent.
- Variantes `deb` sur AuxiNuxOS/VirtuaOS : échouent tant que
  `install_local_deb` n'est pas configuré (la validation du manifeste émet un
  avertissement) ; leur détection passe par la commande `query` de
  l'adaptateur système, jamais par APT.

### Confiance et clés

- Pas de commande de **rotation** de la racine TUF dans `auxipak-builder`
  (utiliser `tuftool` hors ligne) ; les racines antérieures placées dans
  `root-history/` sont publiées, ce qui permet aux clients de suivre toute la
  chaîne. Voir [SIGNING.md](SIGNING.md#5-rotation-des-clés).
- La cérémonie standard produit une seule clé racine (seuil 1).
- Les clés de signature de paquets (`package-keys.json`) sont lues dans la
  configuration locale du client et **ne sont pas distribuées par TUF** :
  rotation et révocation exigent de mettre à jour les clients.

### Dépôts et publication

- Chaque publication régénère et re-signe l'ensemble du dépôt (`targets`,
  `snapshot`, `timestamp`), y compris lors du rafraîchissement périodique.
- `consistent_snapshot = false` : seules les deux générations précédentes
  sont conservées ; un téléchargement plus long que deux publications
  successives peut échouer et doit être relancé.
- La publication de dépôts exige un serveur Unix (lien symbolique `current`).
- Une version dépubliée ne peut pas être republiée par une nouvelle
  soumission du même fichier (utiliser le changement d'état
  `published`).
- Les numéros de version TUF sont dérivés de l'horloge (minutes depuis 1970)
  pour rester croissants après une restauration
  ([DEPLOYMENT.md](DEPLOYMENT.md#44-restauration)).

### Client

- Une application installée dans une version ensuite révoquée n'est ni
  signalée par `auxipak list` ni désinstallée automatiquement.
- Installateurs `exe` : pas de détection ni de désinstallation déduites
  (à déclarer dans le manifeste).
- À la désinstallation, `payload/` n'est pas conservé : les scripts de
  désinstallation n'y ont pas accès.
- Avec `upgrade.strategy: remove_then_install`, l'ancienne version est
  désinstallée avant l'installation de la nouvelle ; un échec entre les deux
  laisse l'application désinstallée.
- Pas de mises à jour différentielles ; pas de miroirs configurables autres
  que l'URL de dépôt.
- Homebrew n'est jamais utilisé en tant qu'administrateur.

### Serveur

- Limitation des tentatives de connexion en mémoire, par processus (en plus
  de la limitation Nginx).
- Tests côté serveur uniquement statiques ; les tests d'installation sont à
  la charge d'environnements isolés (CI, machines virtuelles).
- Langues de l'interface Web limitées à `fr` et `en` (liste fixée dans
  `server/src/web.rs`).
