# Déploiement du serveur (Debian 13)

Ce document décrit le déploiement d'`auxipak-server` pour
`pak.auxinux.ca` sur **Debian 13 « trixie »** : Docker Compose (recommandé)
ou service systemd natif, derrière Nginx avec un certificat Let's Encrypt.

## 1. Vue d'ensemble

```text
Internet ──► 80/443 Nginx (TLS, HSTS, limitation des connexions)
                 │  proxy_pass http://127.0.0.1:8080
                 ▼
          auxipak-server  (127.0.0.1:8080 publié par Docker ; conteneur non root, uid 10001,
                 │         système de fichiers en lecture seule, capacités retirées)
                 ├── volume server-data → /var/lib/auxipak-server (données)
                 ├── /etc/auxipak-server/keys (lecture seule, clés du serveur)
                 ▼
          PostgreSQL 17 (5432, réseau Docker interne uniquement, volume db-data)
```

| Port | Service | Exposition |
|---|---|---|
| 80 | Nginx (redirection HTTPS, défi ACME) | public |
| 443 | Nginx (HTTPS) | public |
| 8080 | auxipak-server | boucle locale de l'hôte uniquement (`127.0.0.1:8080`) |
| 5432 | PostgreSQL | réseau Docker interne `backend` (non publié) ; en natif : `127.0.0.1` |

## 2. Prérequis

- Debian 13 à jour, accès root, nom DNS `pak.auxinux.ca` pointant vers le
  serveur (A/AAAA).
- Docker Engine et le greffon Compose v2 (commande `docker compose`), par
  exemple depuis le dépôt officiel Docker pour Debian.
- `git`, `curl`, `jq`, `nginx`, `certbot`, `python3-certbot-nginx`.
- Pare-feu n'autorisant en entrée que 22 (administration), 80 et 443.
- Les clés du dépôt, produites hors ligne selon [SIGNING.md](SIGNING.md)
  (`server-keys/`).
- Espace disque : paquets publiés + soumissions + trois générations de
  dépôt + sauvegardes.

```console
# apt update && apt install -y git curl jq nginx certbot python3-certbot-nginx
```

## 3. Déploiement avec Docker Compose (production)

### 3.1 Code source

```console
# git clone https://github.com/auxinux/auxipak.git /opt/auxipak
# cd /opt/auxipak/deploy
```

### 3.2 Clés du serveur

Transférer `server-keys/` (support de la cérémonie) vers l'hôte :

```console
# install -d -m 0700 -o 10001 -g 10001 /etc/auxipak-server/keys
# cp /media/transfert/server-keys/* /etc/auxipak-server/keys/
# chown 10001:10001 /etc/auxipak-server/keys/*
# chmod 0600 /etc/auxipak-server/keys/*.pem
# chmod 0644 /etc/auxipak-server/keys/*.json
# ls -l /etc/auxipak-server/keys
```

Le répertoire doit contenir `root.json`, `package-keys.json`,
`targets.pem`, `snapshot.pem`, `timestamp.pem` et (recommandé)
`package-signing.pem` ; **jamais** `root.pem`. Il est monté en lecture seule
dans le conteneur (`/etc/auxipak-server/keys:ro`).

### 3.3 Fichier d'environnement

```console
# cp .env.example .env
# chmod 600 .env
# openssl rand -hex 32        # mot de passe PostgreSQL
# $EDITOR .env
```

| Variable (`.env`) | Valeur |
|---|---|
| `AUXIPAK_PUBLIC_URL` | `https://pak.auxinux.ca` |
| `POSTGRES_PASSWORD` | valeur aléatoire ; **préférer une valeur hexadécimale** (`openssl rand -hex 32`) : elle est insérée telle quelle dans l'URL de connexion `postgres://auxipak:<mot de passe>@db:5432/auxipak`, où `/`, `+` ou `=` (sortie base64) poseraient problème |
| `AUXIPAK_KEYS_HOST_DIR` | `/etc/auxipak-server/keys` |
| `AUXIPAK_REQUIRE_DISTINCT_APPROVER` | `true` |
| `AUXIPAK_MAX_UPLOAD_BYTES` | `8589934592` (8 Gio) |
| `AUXIPAK_LOG` | `info` |

> `.env` contient un secret : il ne doit jamais être versionné. Le
> `.gitignore` racine n'exclut que `/.env` ; ajoutez `deploy/.env` à vos
> exclusions locales (`.git/info/exclude`) ou placez le fichier hors du dépôt
> et indiquez-le aux scripts avec `ENV_FILE=/chemin/.env`.

Le fichier `docker-compose.yml` fixe en outre `AUXIPAK_ENV=production`,
`AUXIPAK_COOKIE_SECURE=true` et `AUXIPAK_TRUSTED_PROXIES=172.30.0.1`
(passerelle du réseau `backend`, par laquelle arrivent les connexions
relayées par Nginx).

### 3.4 Démarrage

```console
# docker compose --env-file .env up -d --build
# docker compose ps
# curl -fsS http://127.0.0.1:8080/api/v1/health
# docker compose exec server auxipak-server check-config
```

Au démarrage, le serveur applique les migrations, charge et contrôle les
clés, puis publie une première génération du dépôt `official` (créé par la
migration initiale) s'il n'a jamais été publié. `check-config` affiche le
mode, l'état de la base, la version et l'expiration de la racine TUF, la clé
de signature des paquets et avertit s'il n'existe aucun administrateur.

### 3.5 Premier administrateur

```console
# /opt/auxipak/deploy/scripts/create-admin.sh admin
```

Le script demande le mot de passe deux fois sans écho (12 caractères
minimum, plusieurs types de caractères) et exécute `auxipak-server
create-admin --username admin` dans le conteneur. Créez ensuite, depuis
`https://pak.auxinux.ca/admin`, au moins un second compte `reviewer` : avec
`AUXIPAK_REQUIRE_DISTINCT_APPROVER=true`, l'auteur d'une soumission ne peut
pas l'approuver lui-même.

### 3.6 Nginx et certificat

```console
# cp /opt/auxipak/deploy/nginx/auxipak-limits.conf /etc/nginx/conf.d/
# install -d /etc/nginx/snippets /var/www/letsencrypt
# cp /opt/auxipak/deploy/nginx/auxipak-proxy.conf /etc/nginx/snippets/
# certbot certonly --nginx -d pak.auxinux.ca          # avant d'activer le site
# cp /opt/auxipak/deploy/nginx/pak.auxinux.ca.conf /etc/nginx/sites-available/
# ln -s /etc/nginx/sites-available/pak.auxinux.ca.conf /etc/nginx/sites-enabled/
# nginx -t && systemctl reload nginx
# systemctl list-timers | grep certbot                # renouvellement automatique
```

Le certificat doit exister avant l'activation du site (le bloc 443 y fait
référence). La configuration fournie : redirection HTTP→HTTPS, TLS 1.2/1.3,
HSTS (2 ans), corps jusqu'à 8 Gio sans mise en tampon (paquets), délais de
3 600 s, limitation de `/api/v1/auth/login` et `/admin/login`
(10 requêtes/minute, rafale 5), `X-Forwarded-For` réduit à l'adresse vue par
Nginx. Les en-têtes de sécurité applicatifs (CSP, `X-Frame-Options`,
`nosniff`, `Referrer-Policy`) sont posés par le serveur.

Vérification depuis l'extérieur :

```console
$ curl -fsS https://pak.auxinux.ca/api/v1/health
$ curl -fsS https://pak.auxinux.ca/index | jq .
$ curl -fsSI https://pak.auxinux.ca/repos/official/metadata/timestamp.json
```

### 3.7 Mandataire HTTPS sur une autre machine (panneau d'hébergement)

Si le HTTPS est assuré par un panneau ou un Nginx situé sur **une autre
machine**, le serveur doit être joignable depuis celle-ci, et uniquement
depuis celle-ci. Dans `deploy/.env` :

```ini
AUXIPAK_BIND=0.0.0.0
AUXIPAK_TRUSTED_PROXIES=172.30.0.1,<IP du mandataire>
```

Docker contourne `ufw` : le filtrage se fait dans la chaîne `DOCKER-USER`,
rétablie à chaque démarrage par une unité systemd
(`/etc/systemd/system/auxipak-fw.service`) :

```ini
[Unit]
Description=AuxiPak : port 8080 réservé au mandataire HTTPS
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/iptables -I DOCKER-USER -p tcp --dport 8080 ! -s <IP du mandataire> -j DROP
ExecStop=/usr/sbin/iptables -D DOCKER-USER -p tcp --dport 8080 ! -s <IP du mandataire> -j DROP

[Install]
WantedBy=multi-user.target
```

Côté mandataire : protocole HTTP, port 8080, délai de réponse 3 600 s et
taille de corps 8 Gio (envoi des paquets).

### 3.8 Binaires du client et scripts d'installation

Le serveur publie `/install.sh`, `/uninstall.sh`, `/install.ps1` et
`/uninstall.ps1` (générés avec `AUXIPAK_PUBLIC_URL` et les ancres publiques du
dépôt officiel) ainsi que `/downloads/` : les archives du client d'une
release, lues dans `deploy/downloads/` (monté en lecture seule).

1. Créer une release : pousser une étiquette `v1.0.0` ; le workflow
   « Release » prépare un brouillon (archives, `SHA256SUMS`, attestations) ;
   le relire puis le publier sur GitHub.
2. Sur le serveur :

   ```console
   $ cd ~/auxipak/deploy
   $ ./scripts/fetch-client.sh v1.0.0      # ou un dossier : ./scripts/fetch-client.sh ~/release
   $ curl -fsS https://auxipak.auxinux.ca/downloads/SHA256SUMS
   ```

Le script vérifie chaque empreinte (et les attestations de provenance si
`gh` est installé) puis remplace les binaires publiés. Aucun redémarrage
n'est nécessaire. Installation native (systemd) : déposer les fichiers dans
`AUXIPAK_DOWNLOADS_DIR` (par défaut `$AUXIPAK_DATA_DIR/downloads`).

## 4. Exploitation

### 4.1 Healthcheck

`GET /api/v1/health` renvoie `200` et
`{"status":"ok","database":true,"version":"1.0.0","package_signing_key":"<id ou null>"}`,
ou `503` (`"degraded"`) si PostgreSQL ne répond pas. L'image définit un
`HEALTHCHECK` Docker (toutes les 30 s, délai 5 s, 3 essais) qui exécute
`auxipak-server healthcheck` : cette sous-commande interroge
`/api/v1/health` sur l'adresse `AUXIPAK_BIND` (`127.0.0.1` si l'adresse
d'écoute est `0.0.0.0`) et réussit seulement sur une réponse `200` ; aucun
outil supplémentaire (curl) n'est installé dans l'image. PostgreSQL a sa
propre sonde (`pg_isready`).

### 4.2 Journaux

```console
# docker compose logs -f server            # journal applicatif (AUXIPAK_LOG)
# docker compose logs -f db
# journalctl -u nginx ; tail -f /var/log/nginx/access.log
```

Le **journal d'audit** (connexions, échecs, jetons, soumissions,
approbations, rejets, signatures, révocations, évaluations, comptes, dépôts,
régénérations) est en base : interface `/admin/audit` ou
`GET /api/v1/admin/audit`.

### 4.3 Sauvegarde

```console
# /opt/auxipak/deploy/scripts/backup.sh /srv/sauvegardes
```

Produit `/srv/sauvegardes/auxipak-<horodatage>/` : `database.dump`
(`pg_dump` au format personnalisé), `data.tar` (paquets, dépôts,
soumissions, projets) et `SHA256SUMS`. **Les clés ne sont pas incluses** :
sauvegardez `/etc/auxipak-server/keys` séparément, chiffré, et la clé racine
uniquement hors ligne. Planifiez la sauvegarde (timer systemd ou cron) et
copiez-la hors de l'hôte.

### 4.4 Restauration

```console
# /opt/auxipak/deploy/scripts/restore.sh /srv/sauvegardes/auxipak-20261019T020000Z
```

Le script vérifie les empreintes, demande de taper `RESTAURER`, arrête le
serveur, restaure la base (`pg_restore --clean --if-exists`) et les données,
redémarre, puis régénère le dépôt `official` (nouvelle génération signée).

> Les clients refusent toute métadonnée TUF dont la version est inférieure à
> celle qu'ils ont déjà vue. Pour qu'une restauration ne fasse jamais reculer
> cette version, le numéro de génération est au moins égal au nombre de
> minutes écoulées depuis le 1er janvier 1970 : une régénération après
> restauration produit donc une version supérieure à toutes celles déjà
> publiées (sauf si plus d'une régénération par minute avait été effectuée
> en continu, cas dans lequel il suffit d'attendre quelques minutes). Les
> autres dépôts éventuels se régénèrent de la même façon
> (`auxipak-server regenerate --repository NOM`).

### 4.5 Mise à jour

```console
# /opt/auxipak/deploy/scripts/update.sh /srv/sauvegardes
```

Le script sauvegarde, met à jour le code (`git pull --ff-only`), reconstruit
l'image, redémarre le service et attend que `/api/v1/health` réponde (60 s
au plus). Les migrations de base sont appliquées automatiquement au
démarrage. En cas d'échec : `docker compose logs server`, puis retour à la
révision précédente (`git checkout <révision>`, reconstruction) et, si
nécessaire, restauration.

### 4.6 Commandes du serveur

```text
auxipak-server [serve]                          démarre le serveur (par défaut)
auxipak-server migrate                          applique les migrations puis quitte
auxipak-server create-admin --username <id> [--display-name <nom>]
                                                mot de passe lu sur l'entrée standard ou dans AUXIPAK_ADMIN_PASSWORD
auxipak-server regenerate [--repository official]
                                                régénère index et métadonnées TUF
auxipak-server check-config                     vérifie configuration, base et clés
auxipak-server healthcheck                      sonde de santé locale (code 0 si /api/v1/health répond 200)
```

Avec Docker : `docker compose exec server auxipak-server <commande>`.

### 4.7 Variables d'environnement du serveur

| Variable | Défaut | Description |
|---|---|---|
| `AUXIPAK_ENV` | `production` | `production` ou `development` |
| `AUXIPAK_DATABASE_URL` | — (obligatoire) | URL PostgreSQL |
| `AUXIPAK_BIND` | `127.0.0.1:8080` (image Docker : `0.0.0.0:8080`) | adresse d'écoute |
| `AUXIPAK_PUBLIC_URL` | obligatoire en production (HTTPS) ; `http://127.0.0.1:8080` en développement | URL publique |
| `AUXIPAK_DATA_DIR` | `/var/lib/auxipak-server` | données |
| `AUXIPAK_KEYS_DIR` | `/etc/auxipak-server/keys` | clés (hors de `AUXIPAK_DATA_DIR` en production) |
| `AUXIPAK_COOKIE_SECURE` | `true` en production (non désactivable), `false` en développement | attribut `Secure` du cookie |
| `AUXIPAK_REQUIRE_DISTINCT_APPROVER` | `true` | approbateur ≠ auteur |
| `AUXIPAK_MAX_UPLOAD_BYTES` | `8589934592` | taille maximale d'une soumission |
| `AUXIPAK_DEV_AUTO_KEYS` | `false` | développement : génère des clés de test si absentes (interdit en production) |
| `AUXIPAK_TIMESTAMP_HOURS` | `24` | validité de `timestamp.json` (1–168) |
| `AUXIPAK_TRUSTED_PROXIES` | `127.0.0.1,::1` | mandataires dont `X-Forwarded-For` est pris en compte |
| `AUXIPAK_LOG` | `info,tower_http=info,sqlx=warn` | filtre de journalisation |
| `AUXIPAK_ADMIN_PASSWORD` | — | mot de passe pour `create-admin` (sinon entrée standard) |

Valeurs booléennes acceptées : `1/true/yes/on`, `0/false/no/off`.

## 5. Déploiement natif (systemd, sans Docker)

```console
# apt install -y postgresql build-essential pkg-config
# useradd --system --home-dir /var/lib/auxipak-server --shell /usr/sbin/nologin auxipak
# install -d -o auxipak -g auxipak -m 0750 /var/lib/auxipak-server
# install -d -o root -g auxipak -m 0750 /etc/auxipak-server
# install -d -o auxipak -g auxipak -m 0700 /etc/auxipak-server/keys
```

1. **Binaire** (Rust ≥ 1.89, compilé par un utilisateur ordinaire puis
   installé) :

   ```console
   $ cargo build --release --locked -p auxipak-server -p auxipak-builder
   # install -m 0755 target/release/auxipak-server target/release/auxipak-builder /usr/local/bin/
   ```

2. **PostgreSQL** :

   ```console
   # sudo -u postgres createuser --pwprompt auxipak
   # sudo -u postgres createdb --owner auxipak auxipak
   ```

3. **Clés** : copier `server-keys/` dans `/etc/auxipak-server/keys`,
   `chown auxipak:auxipak`, `.pem` en `0600`.
4. **Environnement** : copier `deploy/systemd/server.env.example` vers
   `/etc/auxipak-server/server.env` (propriétaire `root:auxipak`, droits
   `0640`) et renseigner le mot de passe dans `AUXIPAK_DATABASE_URL`.
5. **Service** :

   ```console
   # cp deploy/systemd/auxipak-server.service /etc/systemd/system/
   # systemctl daemon-reload
   # systemctl enable --now auxipak-server
   # systemctl status auxipak-server ; journalctl -u auxipak-server -f
   # sudo -u auxipak sh -c 'set -a; . /etc/auxipak-server/server.env; exec auxipak-server create-admin --username admin'
   ```

   L'unité exécute `auxipak-server migrate` avant le démarrage, en
   utilisateur `auxipak`, avec un durcissement systemd (`ProtectSystem=strict`,
   `ReadWritePaths=/var/lib/auxipak-server`,
   `ReadOnlyPaths=/etc/auxipak-server`, `NoNewPrivileges`, aucune capacité,
   `MemoryDenyWriteExecute`, `UMask=0077`…).
6. **Nginx** : identique à la section 3.6 (`AUXIPAK_TRUSTED_PROXIES=127.0.0.1,::1`).
7. **Sauvegardes** : les scripts `backup.sh`/`restore.sh` visent Docker
   Compose ; en natif, utiliser `pg_dump -Fc auxipak` et une archive de
   `/var/lib/auxipak-server`, selon les mêmes principes (clés à part).

## 6. Environnement de développement immédiat

### 6.1 Docker Compose

```console
$ docker compose -f deploy/docker-compose.dev.yml up --build
$ docker compose -f deploy/docker-compose.dev.yml exec server auxipak-server create-admin --username admin
```

- Serveur sur `http://127.0.0.1:8080`, mode `development`, clés de **test**
  générées automatiquement dans le conteneur
  (`/var/lib/auxipak-server/dev-keys`), approbateur distinct non exigé.
- Aucun volume : les données et les clés disparaissent avec le conteneur.
- Pour un client de test : récupérer les ancres publiques avec
  `docker compose -f deploy/docker-compose.dev.yml cp server:/var/lib/auxipak-server/dev-keys/root.json .`
  (idem `package-keys.json`), ou utiliser `auxipak repo add
  http://127.0.0.1:8080/repos/official/ --name dev --trust-on-first-use
  --allow-insecure-localhost` (option de développement masquée).

### 6.2 Serveur natif

```console
$ DATABASE_URL=postgres://postgres:motdepasse@127.0.0.1:5432/auxipak deploy/scripts/dev-server.sh
```

Compile `auxipak-server` (débogage), place données et clés de test dans
`.dev/` (ignoré par Git) et démarre sur `127.0.0.1:8080` (modifiable par
`AUXIPAK_BIND`). La base doit exister.

### 6.3 Démonstration de bout en bout

```console
$ cargo build
$ PG_ADMIN_URL=postgres://postgres:motdepasse@127.0.0.1:5432/postgres tests/e2e/run-local.sh
```

Crée une base et un serveur éphémères, puis exécute `tests/e2e/demo.sh`
(construction, validation, soumission par un jeton agent, refus de
l'auto-approbation, approbation humaine, index, synchronisation, recherche,
installation, `list`, mise à niveau, révocation, désinstallation,
nettoyage). Prérequis : `psql`, `curl`, `jq`, `dpkg-deb`. Voir
[CONTRIBUTING.md](CONTRIBUTING.md).

## 7. Liste de contrôle « passage en production »

- [ ] Cérémonie de clés réalisée hors ligne ; procès-verbal ; empreinte de
      `root.json` publiée sur un canal indépendant.
- [ ] `root.pem` absent du serveur ; deux copies chiffrées hors ligne.
- [ ] `/etc/auxipak-server/keys` : propriétaire du service, `.pem` en `0600`,
      monté en lecture seule, hors de `AUXIPAK_DATA_DIR`.
- [ ] `auxipak-server check-config` sans avertissement ; clé de signature des
      paquets présente.
- [ ] `AUXIPAK_ENV=production`, `AUXIPAK_PUBLIC_URL` en HTTPS,
      `AUXIPAK_COOKIE_SECURE=true`, `AUXIPAK_DEV_AUTO_KEYS` absent.
- [ ] `AUXIPAK_REQUIRE_DISTINCT_APPROVER=true` et au moins deux relecteurs
      humains.
- [ ] `.env` / `server.env` en `0600`/`0640`, non versionnés ; mot de passe
      PostgreSQL aléatoire.
- [ ] Ports : seuls 80 et 443 (et l'administration) ouverts ; 8080 sur la
      boucle locale ; 5432 non publié.
- [ ] Nginx : certificat valide, renouvellement automatique testé
      (`certbot renew --dry-run`), HSTS actif, limitation des connexions.
- [ ] `AUXIPAK_TRUSTED_PROXIES` limité au seul mandataire réel.
- [ ] Healthcheck surveillé ; alerte si `timestamp.json` n'est plus
      rafraîchi (serveur arrêté > `AUXIPAK_TIMESTAMP_HOURS`).
- [ ] Sauvegardes planifiées, copiées hors site, restauration testée.
- [ ] Date d'expiration de `root.json` notée et ré-signature planifiée.
- [ ] Clients distribués avec `root.json` et `package-keys.json` officiels.
- [ ] Jetons `agent`/`ci` à portées minimales et expiration courte ; revue
      périodique de `/admin/tokens` et du journal d'audit.
- [ ] Démonstration de bout en bout passée sur l'environnement de
      préproduction.
