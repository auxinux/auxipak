# Signatures, racine de confiance et gestion des clés

AuxiPak utilise deux mécanismes cryptographiques complémentaires, tous deux
en Ed25519 :

1. **TUF** (The Update Framework, bibliothèque `tough`) protège les **index
   des dépôts** : authenticité, fraîcheur, protection contre le gel, le rejeu
   et le retour à une version antérieure.
2. Les **signatures détachées de paquets** (`.apak.sig`) attestent l'origine
   et l'intégrité de chaque archive `.apak`.

> **Signature ≠ « AuxiNux Vérifié ».** Une signature dit *qui* a publié un
> paquet et qu'il n'a pas été modifié. Le statut « AuxiNux Vérifié »,
> « AuxiNux Compatible » ou « Non évalué » est une **évaluation** de
> conformité aux valeurs AuxiNux, attribuée par un relecteur humain (portée
> `evaluate`), stockée séparément (table `evaluations`) et publiée dans
> `apps.json`. Aucune clé ne permet de s'attribuer un statut, et un client
> n'affiche les statuts officiels que pour un dépôt marqué officiel dans **sa
> propre** configuration.

## 1. Racine de confiance et rôles TUF

| Rôle | Fichier | Clé | Emplacement de la clé privée | Validité |
|---|---|---|---|---|
| `root` | `N.root.json` | `root.pem` | **hors ligne** (support chiffré, coffre) | `--root-days` (365 jours par défaut) |
| `targets` | `targets.json` | `targets.pem` | serveur (en ligne) | 30 jours |
| `snapshot` | `snapshot.json` | `snapshot.pem` | serveur (en ligne) | 7 jours |
| `timestamp` | `timestamp.json` | `timestamp.pem` | serveur (en ligne) | `AUXIPAK_TIMESTAMP_HOURS` (24 h par défaut, 1–168) |
| signature des paquets | `.apak.sig` | `package-signing.pem` | serveur (en ligne, facultative) | `not_before`/`not_after` facultatifs |

- `root.json` désigne les clés et seuils des autres rôles ; il est signé par
  la clé racine. La cérémonie standard crée **une** clé racine avec un seuil
  de 1, et une clé par rôle en ligne.
- Le client démarre toujours de **son** `root.json` local (jamais de celui du
  serveur) ; `tough` suit ensuite la chaîne des racines publiées
  (`metadata/N.root.json`), vérifie seuils, versions et expirations
  (`ExpirationEnforcement::Safe`).
- Le serveur régénère et re-signe `targets`, `snapshot` et `timestamp` à
  chaque publication et au moins toutes les `AUXIPAK_TIMESTAMP_HOURS / 2`
  heures. Un serveur arrêté plus longtemps que la validité de
  `timestamp.json` rend ses index refusés par les clients (protection contre
  le gel), jusqu'à son redémarrage.
- La clé `package-signing` n'est **pas** un rôle TUF. Les clients la trouvent
  dans leur `package-keys.json` local (le dépôt publie une copie dans
  `keys/package-keys.json`, utilisée seulement par `repo add
  --trust-on-first-use`).

## 2. Clés en ligne et hors ligne

| Fichier | Nature | Où | Droits |
|---|---|---|---|
| `root.json` | public | serveur, clients, archives | `0644` |
| `package-keys.json` | public | serveur, clients | `0644` |
| `targets.pem`, `snapshot.pem`, `timestamp.pem` | **secret** en ligne | `AUXIPAK_KEYS_DIR` du serveur | `0600`, propriétaire du service |
| `package-signing.pem` | **secret** en ligne | `AUXIPAK_KEYS_DIR` du serveur | `0600` |
| `root.pem` | **secret** hors ligne | jamais sur le serveur | `0600`, support chiffré |

Contrôles au démarrage du serveur (`server/src/keys.rs`) :

- `root.json`, `package-keys.json` et les trois clés TUF en ligne doivent
  être présents ; chaque clé TUF doit correspondre au rôle déclaré dans
  `root.json` ;
- les fichiers `.pem` ne doivent être lisibles par personne d'autre que leur
  propriétaire (sinon : « chmod 600 ») ;
- `package-signing.pem`, s'il est présent, doit figurer dans
  `package-keys.json` ; absent, seuls les paquets déjà signés par une clé de
  confiance peuvent être publiés ;
- en production, la présence de `root.pem` dans le répertoire des clés est
  refusée, `AUXIPAK_KEYS_DIR` ne doit pas se trouver dans
  `AUXIPAK_DATA_DIR`, et `AUXIPAK_DEV_AUTO_KEYS` est interdit.

## 3. Procédure sécurisée d'initialisation (cérémonie de clés)

À réaliser **une fois** par dépôt, sur un **poste hors ligne** de confiance,
jamais sur le serveur.

### Préparation

- Poste sans réseau (câble débranché, Wi-Fi désactivé), système à jour avant
  déconnexion, disque chiffré.
- Binaire `auxipak-builder` vérifié (empreinte) ou compilé depuis une
  révision étiquetée.
- Deux supports amovibles chiffrés (copie principale et copie de secours de
  la clé racine) ; un support de transfert pour les fichiers du serveur.
- Deux personnes présentes ; procès-verbal daté (empreintes, numéros de
  support, participants).

### Exécution

```console
$ AUXIPAK_BUILDER=/chemin/auxipak-builder OWNER=AuxiNux \
    deploy/scripts/init-keys.sh /media/support-chiffre/auxipak-keys
```

Le script exécute `auxipak-builder keys init-repository --out <dir>/set
--owner <OWNER>` (racine valable 365 jours ; pour une autre durée, lancer
directement la commande avec `--root-days`), puis répartit les fichiers :

```text
<dir>/offline/root.pem         clé racine TUF — reste hors ligne
<dir>/server-keys/             root.json, package-keys.json, targets.pem,
                               snapshot.pem, timestamp.pem, package-signing.pem
<dir>/client-trust/            root.json, package-keys.json (publics)
```

Il refuse un répertoire de sortie non vide, applique `umask 077`, met les
`.pem` en `0600` et affiche l'empreinte SHA-256 de `root.json`. La commande
sous-jacente n'écrase jamais une clé existante.

### Après la cérémonie

1. **Publier l'empreinte** de `root.json` sur un canal indépendant (site,
   annonce signée, documentation imprimée).
2. **Serveur** : transférer `server-keys/` vers `/etc/auxipak-server/keys`
   (voir [DEPLOYMENT.md](DEPLOYMENT.md)) ; propriétaire `10001:10001`
   (Docker) ou `auxipak:auxipak` (natif) ; `.pem` en `0600`.
3. **Clients** : intégrer `client-trust/` au client (section 4).
4. **Clé racine** : copier `offline/root.pem` sur le second support chiffré,
   ranger les deux supports dans des lieux distincts, effacer toute autre
   copie ; vérifier `auxipak-builder keys show-root root.json`.
5. Planifier la **ré-signature de `root.json` avant son expiration**
   (section 5) : une racine expirée bloque tous les clients.

### Environnement de développement

`AUXIPAK_DEV_AUTO_KEYS=1` (mode `development` uniquement) génère des clés de
**test** dans `AUXIPAK_KEYS_DIR` au premier démarrage, y compris
`dev-root.pem`. Ces clés ne doivent jamais servir en production.

## 4. Distribution de la racine avec le client

Trois moyens, par ordre de résolution pour le dépôt `official` :

1. **Fichiers de configuration** `trust/official/root.json` et
   `trust/official/package-keys.json` relatifs au répertoire de
   configuration de la portée courante (`~/.config/auxipak`, `/etc/auxipak`,
   `%LOCALAPPDATA%\AuxiPak\config`, `%ProgramData%\AuxiPak\config`) ;
2. **Configuration système** consultée par un utilisateur ordinaire :
   `/etc/auxipak/trust/official/` (Linux/macOS) ou
   `%ProgramData%\AuxiPak\config\trust\official\` (Windows) ;
3. **Ancre embarquée** dans le binaire, si le client a été compilé avec
   `AUXIPAK_OFFICIAL_TRUST_DIR=<dir>/client-trust` (fichiers intégrés par
   `client/build.rs`) ; utilisée seulement si aucun fichier n'est trouvé,
   pour un dépôt nommé `official` et marqué officiel.

Recommandation : paquets du client (`.deb`, MSI…) livrant
`/etc/auxipak/trust/official/` et binaires compilés avec l'ancre embarquée.
`auxipak doctor` indique la source de confiance utilisée pour chaque dépôt.

## 5. Rotation des clés

### Principe TUF

Une nouvelle racine `root.json` de version **N+1** doit être signée à la fois
par le seuil des clés racine de la version N **et** par celui des clés de la
version N+1. Le serveur publie `metadata/N.root.json` ; un client qui
possède la version N télécharge `N+1.root.json`, la vérifie, puis continue
avec `N+2`, etc. Chaque version intermédiaire doit donc **rester publiée**.

### Cas d'usage

| Situation | Action |
|---|---|
| `root.json` proche de l'expiration | nouvelle version N+1 avec les mêmes clés, nouvelle date d'expiration |
| clé en ligne (`targets`, `snapshot`, `timestamp`) compromise ou à renouveler | nouvelle racine N+1 désignant la nouvelle clé ; remplacer le `.pem` sur le serveur |
| clé racine à renouveler | racine N+1 signée par l'ancienne **et** la nouvelle clé racine |

### Procédure

1. Sur le poste hors ligne, produire `N+1.root.json` (version incrémentée,
   nouvelle expiration, nouvelles clés publiques le cas échéant) signé par
   les clés racine requises.
2. Contrôler : `auxipak-builder keys show-root root.json` (version, rôles,
   seuils).
3. Sur le serveur : copier **chaque** racine antérieure dans
   `AUXIPAK_KEYS_DIR/root-history/` sous son nom versionné (`1.root.json`,
   `2.root.json`…), remplacer
   `AUXIPAK_KEYS_DIR/root.json` par la nouvelle, remplacer les `.pem` en
   ligne concernés, redémarrer (`check-config` vérifie la correspondance
   clés/rôles) ; la régénération publie `metadata/N+1.root.json`.
4. Mettre à jour `client-trust/root.json` pour les **nouvelles** installations
   du client (les clients existants suivent la chaîne).

> Le serveur publie, à chaque génération, la racine courante **et** toutes
> les racines présentes dans `AUXIPAK_KEYS_DIR/root-history/` : un client
> resté à n'importe quelle version antérieure suit toute la chaîne
> (`1.root.json` → … → `N.root.json`), et `repo add --trust-on-first-use`
> (qui part de `1.root.json`) continue de fonctionner après rotation.
>
> **Limite de la V1** : `auxipak-builder` ne fournit pas encore de commande
> de rotation (signature d'une racine N+1 par l'ancienne et la nouvelle clé
> racine). Utiliser l'outil de référence `tuftool` (projet `tough`, même
> bibliothèque que AuxiPak) sur le poste hors ligne, puis contrôler le
> résultat avec `auxipak-builder keys show-root`. Voir [ROADMAP.md](ROADMAP.md).

### Clé de signature des paquets

Le client vérifie les signatures avec son `package-keys.json` **local** :

1. générer une nouvelle clé (`auxipak-builder keys generate --out
   secrets/package-signing-2027.pem --public package-keys.json --owner
   AuxiNux`) ;
2. distribuer le nouveau `package-keys.json` (contenant l'ancienne et la
   nouvelle clé) aux clients **avant** la bascule ;
3. sur le serveur, remplacer `package-signing.pem` et `package-keys.json`,
   redémarrer ;
4. borner l'ancienne clé (`not_after`) ou la marquer `"revoked": true` quand
   tous les paquets utiles ont été re-signés.

## 6. Révocation

| Objet | Moyen | Effet |
|---|---|---|
| Version d'un paquet | `POST /api/v1/admin/releases/{id}/state` `{"state":"revoked","reason":"…"}` (portée `review`) ou interface `/admin/releases` | inscrite dans `revocations.json` (signé par TUF) ; le client refuse de l'installer ou de la proposer en mise à niveau, même par nom de fichier ; état définitif |
| Clé de signature de paquets | `"revoked": true` (ou `not_after`) dans `package-keys.json` côté client et serveur | toute signature de cette clé est refusée |
| Clé TUF en ligne | rotation de la racine (section 5) | les métadonnées signées par l'ancienne clé ne sont plus acceptées |
| Jeton d'API | `DELETE /api/v1/tokens/{id}` ou `/api/v1/admin/tokens/{id}` | refus immédiat |

Une application déjà installée dans une version révoquée n'est pas
désinstallée automatiquement : la liste des versions de `auxipak info` la
signale « (révoquée) » et `auxipak upgrade` propose la meilleure version non
révoquée.

## 7. Ajouter une signature à un paquet

Par défaut, le serveur signe le paquet avec `package-signing.pem` au moment
de l'approbation. Un paquet peut aussi être signé **avant** la soumission par
une clé `package-signing` listée dans le `package-keys.json` du serveur :

```console
$ auxipak-builder sign MonOutil-1.0.0-fr.apak --key secrets/cle-paquets.pem
$ auxipak-builder verify-signature MonOutil-1.0.0-fr.apak --keys package-keys.json
$ auxipak-builder submit MonOutil-1.0.0-fr.apak --server https://pak.auxinux.ca --token "$AUXIPAK_TOKEN"
```

`submit` joint automatiquement `MonOutil-1.0.0-fr.apak.sig`. Pour une
demande existante :

```console
$ curl -fsS -X PUT -H "Authorization: Bearer $AUXIPAK_TOKEN" \
    --data-binary @MonOutil-1.0.0-fr.apak.sig \
    https://pak.auxinux.ca/api/v1/submissions/<id>/signature
```

La signature est vérifiée immédiatement (clé connue, non révoquée, usage
`package-signing`, période de validité, empreinte et taille, identifiant et
version), puis de nouveau à l'approbation. Les signatures `developer-signing`
ne sont pas acceptées pour la publication en V1. Format exact :
[APAK_FORMAT.md](APAK_FORMAT.md#6-signature-détachée-apaksig).

## 8. Préparation de la phase 2 (`ca.auxinux.ca`)

Les éléments suivants sont déjà présents pour accueillir une autorité de
certification AuxiNux sans changer les formats :

- champ `certificate_chain` du document `.apak.sig` (vide en V1, non signé) ;
- usage de clé `developer-signing` (`KeyPurpose::DeveloperSigning`), admis
  par `auxipak-builder verify-signature` ;
- période de validité (`not_before`, `not_after`) et révocation par clé dans
  `package-keys.json` ;
- signature détachée : plusieurs signatures (éditeur + AuxiNux) pourront
  coexister sans modifier l'archive.

Restent à concevoir : l'émission des certificats développeurs, la
vérification de chaîne, la révocation centralisée (voir
[ROADMAP.md](ROADMAP.md)).

## 9. Règles impératives

- **Aucune clé privée de production** dans Git, dans une image Docker, dans
  un dépôt publié, dans une sauvegarde non chiffrée ni dans un journal.
  `.gitignore` exclut `*.pem` ; le Dockerfile ne copie que les binaires dans
  l'image finale et les clés sont montées en lecture seule à l'exécution ;
  `backup.sh` n'inclut pas les clés.
- La clé racine ne se trouve **jamais** sur le serveur ; elle n'est utilisée
  que hors ligne, pour la cérémonie et les rotations.
- Les clés en ligne : `0600`, propriétaire du service, répertoire hors des
  données, monté en lecture seule (Docker : `:ro` ; systemd :
  `ReadOnlyPaths=/etc/auxipak-server`).
- Toute signature, approbation, révocation et évaluation est tracée dans le
  journal d'audit.
- Une clé compromise se traite immédiatement : révocation, rotation,
  re-signature, annonce.
