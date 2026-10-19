# Sécurité d'AuxiPak

## Signaler une vulnérabilité

Ne publiez pas de ticket public. Utilisez le **signalement privé de
vulnérabilités** de GitHub (onglet « Security » → « Report a vulnerability »)
du dépôt <https://github.com/auxinux/auxipak>, ou écrivez à
`contact@auxinux.ca` en indiquant « Sécurité AuxiPak » dans l'objet.

Merci de fournir : version concernée, composant (client, constructeur,
serveur, format), plateforme, étapes de reproduction, impact estimé. Nous
accusons réception, évaluons, corrigeons, puis publions un avis et, si
nécessaire, révoquons les paquets ou clés concernés. Merci de nous laisser
le temps de corriger avant toute divulgation.

Versions prises en charge : la dernière version publiée (1.0.x).

## Modèle de menaces

### Biens à protéger

- l'intégrité des systèmes des utilisateurs (aucun code non voulu exécuté,
  aucun fichier écrasé hors du périmètre d'une application) ;
- l'authenticité et la fraîcheur des index et des paquets ;
- les clés (racine TUF hors ligne, clés en ligne, clé de signature des
  paquets) ;
- la crédibilité des statuts « AuxiNux Vérifié / Compatible » ;
- les comptes, jetons et le journal d'audit du serveur.

### Adversaires et scénarios

| Adversaire | Scénarios considérés |
|---|---|
| Attaquant réseau (MITM, DNS, Wi-Fi) | modifier un index ou un paquet, servir un index ancien (rejeu, gel), rediriger un téléchargement distant |
| Miroir ou serveur de fichiers compromis | servir des métadonnées falsifiées, mélangées ou périmées, des paquets modifiés |
| Éditeur malveillant ou négligent | paquet avec commandes cachées, traversée de répertoires, liens symboliques, bombe de décompression, scripts, écrasement de fichiers système, téléchargement depuis un hôte non prévu, télémétrie non déclarée |
| Jeton d'automatisation compromis (CI, agent IA) | publier sans relecture, s'auto-approuver, s'attribuer un statut, créer d'autres jetons, élever ses droits |
| Compte humain compromis | publication malveillante, approbation de sa propre soumission |
| Navigateur d'un administrateur | CSRF, XSS, détournement de session, cadrage (clickjacking) |
| Utilisateur local non privilégié | profiter d'AuxiPak pour obtenir des droits, altérer le registre ou le cache |
| Compromission partielle du serveur | vol des clés en ligne (sans la clé racine) |

### Hors périmètre de la V1

- compromission de la clé racine hors ligne ;
- logiciel malveillant **intentionnellement** fourni par un éditeur et
  approuvé par un relecteur (la relecture et l'évaluation réduisent ce
  risque sans l'éliminer) ;
- sécurité des gestionnaires natifs eux-mêmes (APT, `auxi`, winget, MSI…) et
  de leurs dépôts ;
- attaques nécessitant déjà les droits administrateur sur le poste client.

## Contrôles implémentés

### Index et transport

- Métadonnées de dépôt **TUF** (`tough`) : rôles `root` (hors ligne),
  `targets`, `snapshot`, `timestamp` ; vérification des signatures, des
  seuils, des versions (anti-retour en arrière) et des expirations
  (`ExpirationEnforcement::Safe`) à chaque synchronisation, à partir du
  `root.json` **local** du client.
- `timestamp.json` de 24 h (configurable 1–168 h), rafraîchi
  automatiquement ; un index gelé est refusé.
- Cache d'index : uniquement des fichiers vérifiés, écrits atomiquement ;
  invalidé si l'URL ou le profil système change ; installation et mise à
  niveau exigent un index frais (TTL 3 600 s, métadonnées non expirées).
- `revocations.json` signé par TUF : versions révoquées refusées, y compris
  par nom de fichier exact.
- HTTPS obligatoire pour les dépôts et téléchargements (HTTP uniquement vers
  la boucle locale avec option explicite de développement) ; pas
  d'identifiants dans les URL ; pas d'adresse IP littérale ni de fragment
  pour les sources distantes ; redirections limitées à 5, en HTTPS, vers
  l'hôte d'origine ou `allowed_hosts`.
- Téléchargements : taille annoncée par l'index authentifié ou le manifeste,
  limite globale, reprise contrôlée, SHA-256 vérifié avant tout usage,
  fichier supprimé en cas d'écart ; contrôle de l'espace disque.

### Paquets

- Signature **Ed25519** détachée obligatoire pour un dépôt officiel (et pour
  tout dépôt avec `require_signatures`) ; clé connue, non révoquée, d'usage
  `package-signing`, dans sa période de validité ; empreinte, taille,
  identifiant et version cohérents avec l'index.
- Archive inspectée **avant** toute extraction : chemins sûrs (traversée,
  chemins absolus, lettres de lecteur, noms réservés Windows), doublons
  insensibles à la casse, liens symboliques/points d'analyse/fichiers
  spéciaux/anti-items refusés, emplacements autorisés (`instruction.auxipak`,
  `payload/`, `scripts/`), méthodes de compression LZMA2/LZMA/COPY
  seulement, limites (20 000 entrées, 32 Gio, 16 Gio par entrée, rapport
  1 000:1 au-delà de 64 Mio, manifeste 256 Kio), correspondance exacte avec
  `contents`.
- Extraction maison : répertoire privé vide, `create_new` + `O_NOFOLLOW`,
  droits `0600`/`0700`, SHA-256 et taille vérifiés au fil de l'écriture.
- Manifeste **déclaratif** : schéma JSON + typage strict (champs inconnus
  refusés) + règles sémantiques ; aucune commande libre ; noms de paquets
  natifs, arguments d'installateurs, propriétés MSI, codes produits,
  identifiants de reçus et chemins validés par liste blanche ; gestionnaire
  autorisé seulement sur ses distributions (jamais APT sur AuxiNuxOS).

### Exécution sur le client

- Aucun interpréteur de commandes : programme + vecteur d'arguments ; outils
  système par chemin absolu ; programme d'adaptateur limité aux répertoires
  système ; environnement réduit à une liste blanche ; entrée standard
  fermée ; délai maximal ; codes de retour interprétés.
- Aucune élévation automatique : une variante `admin` exige un lancement
  explicite avec `sudo` / terminal administrateur ; Homebrew refusé en
  administrateur.
- Scripts personnalisés refusés par défaut : `--allow-scripts` (ou
  autorisation explicite du dépôt) **et** paquet signé requis.
- Méthode `files` : n'écrase jamais un fichier non géré par l'application,
  refuse liens et répertoires en destination, écriture atomique ; dmg :
  refuse d'écraser un bundle non géré.
- Applications installées hors AuxiPak jamais revendiquées implicitement
  (`--adopt` explicite).
- Transactions journalisées, retour arrière, `auxipak repair` ; registre
  écrit atomiquement avec sauvegarde ; verrou exclusif ; répertoire d'état en
  `0700`.
- Statuts officiels affichés uniquement pour un dépôt marqué officiel dans
  la configuration **locale** ; un dépôt ajouté par l'utilisateur est
  toujours « externe ».
- Mode simulation de test signalé à l'écran et dans le registre
  (`simulated`) ; points d'interruption de test absents des binaires de
  production.

### Serveur

- Rien n'est exécuté à partir d'un paquet ; tests côté serveur statiques.
- Publication uniquement par approbation d'un **humain** portant la portée
  `review`, distinct de l'auteur par défaut ; ré-analyse et contrôle
  d'empreinte à l'approbation ; stockage immuable des paquets publiés.
- Rôles (`publisher`, `reviewer`, `admin`) et portées (`read`, `build`,
  `submit`, `review`, `evaluate`, `admin`) ; `review`, `evaluate`, `admin`
  interdites aux jetons `ci` et `agent` ; un jeton ne peut émettre de jetons
  que s'il est humain et porte `admin`, et seulement avec ses propres
  portées ; changement de rôle → révocation des jetons ; projets Builder
  cloisonnés par propriétaire.
- Mots de passe Argon2 (≥ 12 caractères, plusieurs types) ; jetons et
  sessions stockés hachés (SHA-256), jetons expirants (≤ 366 jours) ;
  comparaison en temps constant ; réponse homogène pour un compte inexistant ;
  limitation des tentatives (5 par 15 min et par IP+identifiant, plus
  Nginx).
- Sessions : cookie `HttpOnly`, `SameSite=Strict`, `Secure` en production,
  12 h ; jeton **CSRF** obligatoire pour toute requête non sûre.
- En-têtes : CSP stricte (`default-src 'self'`, aucun script en ligne,
  `frame-ancestors 'none'`), `X-Frame-Options: DENY`, `nosniff`,
  `Referrer-Policy: same-origin` ; HSTS côté Nginx ; échappement HTML
  automatique (MiniJinja).
- `X-Forwarded-For` pris en compte uniquement depuis les mandataires de
  confiance.
- Requêtes SQL paramétrées ; contraintes `CHECK` en base ; erreurs internes
  jamais détaillées au client.
- Journal d'audit des opérations sensibles (acteur, type d'acteur, fournisseur
  du jeton, IP).
- Clés : contrôle de correspondance avec `root.json`, droits `0600` exigés,
  clé racine refusée sur le serveur en production, répertoire des clés hors
  des données, montage en lecture seule ; mode production strict (HTTPS,
  cookies sécurisés, clés de développement interdites).
- Déploiement : conteneur non root, système de fichiers en lecture seule,
  capacités retirées, `no-new-privileges` ; PostgreSQL non exposé ; service
  systemd durci ; aucune clé dans l'image ni dans Git (`scripts/check-no-secrets.sh`
  en intégration continue).

## Ce qui reste à valider

- Comportement réel sur **Windows, macOS, AuxiNuxOS et VirtuaOS**
  (installateurs, détection, privilèges, emplacements) : validation restante.
- Syntaxe et codes de retour de la commande **`auxi`** ; configuration de
  l'adaptateur VirtuaOS.
- **Rotation** de la racine TUF (outillage, conservation des versions
  `N.root.json`) et distribution authentifiée des clés de paquets.
- Audit externe du code (en particulier archive, TUF, authentification) et
  test d'intrusion du serveur déployé.
- Exercice de la procédure de compromission de clé (révocation, rotation,
  communication) et de restauration de sauvegarde.

Voir aussi [docs/SIGNING.md](docs/SIGNING.md) et
[docs/ROADMAP.md](docs/ROADMAP.md).
