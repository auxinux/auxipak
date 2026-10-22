# API REST du serveur AuxiPak

La description OpenAPI 3.1 fait référence : `server/openapi.yaml`, servie par
`GET /api/v1/openapi.yaml`. La liste des routes est définie dans
`server/src/api/mod.rs` ; un test d'intégration vérifie que chaque route est
documentée dans le fichier OpenAPI.

- URL de base : `https://auxipak.auxinux.ca` (développement : `http://127.0.0.1:8080`).
- Corps et réponses JSON (UTF-8), sauf mention contraire.
- Erreurs : `{"error": "<code>", "message": "<texte>"}` avec les codes
  `bad_request` (400), `unauthorized` (401), `forbidden` (403), `not_found`
  (404), `conflict` (409), `too_large` (413), `too_many_requests` (429),
  `internal` (500, détail journalisé côté serveur uniquement).
- Taille des corps JSON et texte : 2 Mio. Les corps binaires (paquets,
  fichiers de projet) sont lus en flux, limités par `AUXIPAK_MAX_UPLOAD_BYTES`
  (8 Gio par défaut) et, pour un fichier de projet Builder, 4 Gio.

Dans les exemples : `URL=https://auxipak.auxinux.ca`, `TOKEN=apk_…`.

## 1. Authentification

### Jetons d'API (Bearer)

```http
Authorization: Bearer apk_XXXXXXXX…
```

- Format : préfixe `apk_` + 32 octets aléatoires en base64url ; seul le
  SHA-256 est stocké ; le jeton n'est affiché qu'à sa création.
- Expiration : 1 à 366 jours (90 par défaut). Un jeton est refusé s'il est
  expiré, révoqué ou si son propriétaire est désactivé. Changer le rôle d'un
  utilisateur révoque tous ses jetons.
- Les requêtes Bearer ne sont pas soumises au contrôle CSRF.

### Session (interface Web)

- `POST /api/v1/auth/login` crée une session de 12 heures : cookie
  `auxipak_session` (`HttpOnly`, `SameSite=Strict`, `Secure` en production) et
  renvoie un `csrf_token`.
- Toute requête non sûre (autre que `GET`, `HEAD`, `OPTIONS`) authentifiée
  par session doit porter l'en-tête `X-CSRF-Token: <csrf_token>` ; sinon
  `403 forbidden`. Les formulaires de l'interface Web incluent ce jeton.
- Limitation : 5 échecs par couple (adresse IP, identifiant) sur 15 minutes,
  puis `429`. Nginx limite en plus `/api/v1/auth/login` et `/admin/login` à
  10 requêtes/minute par adresse (rafale de 5).
- L'adresse IP n'est lue dans `X-Forwarded-For` (dernière valeur) que si la
  connexion provient d'un mandataire listé dans `AUXIPAK_TRUSTED_PROXIES`.

### Rôles, portées et types de jetons

| Rôle | Portées accessibles |
|---|---|
| `publisher` | `read`, `build`, `submit` |
| `reviewer` | `read`, `build`, `submit`, `review`, `evaluate`, `ai_evaluate` |
| `admin` | `read`, `build`, `submit`, `review`, `evaluate`, `ai_evaluate`, `admin` |

| Portée | Autorise |
|---|---|
| `read` | lecture des dépôts et versions côté administration |
| `build` | API Builder (projets de l'utilisateur) |
| `submit` | soumissions (création, lecture des siennes, signature) |
| `review` | approuver/rejeter, voir toutes les soumissions, dépublier, republier, révoquer |
| `evaluate` | attribuer le statut AuxiNux (Vérifié, Compatible, Non évalué) |
| `ai_evaluate` | enregistrer une **pré-évaluation automatique** (IA), indicative et étiquetée comme telle ; jamais le statut officiel |
| `admin` | comptes, jetons d'autrui, dépôts, régénération, journal d'audit |

| Type de jeton (`kind`) | Usage | Portées possibles |
|---|---|---|
| `human` | outil personnel d'une personne | toutes celles de son rôle |
| `ci` | intégration continue | `read`, `build`, `submit` |
| `agent` | agent d'automatisation (IA de tout fournisseur) | `read`, `build`, `submit`, `ai_evaluate` |

Règles :

- une session a toutes les portées de son rôle ; un jeton a l'**intersection**
  de ses portées et de celles du rôle de son propriétaire ;
- `review`, `evaluate` et `admin` sont **réservées aux humains** : refusées à
  la création d'un jeton `ci`/`agent` (`400`) et ignorées à l'usage ;
- seul un humain peut créer des jetons : par une **session**, ou par un
  jeton `human` qui porte lui-même la portée `admin` ; dans ce second cas,
  le nouveau jeton ne peut recevoir que des portées que le jeton émetteur
  détient (un jeton ne sert jamais à obtenir davantage de droits) ;
- le champ facultatif `provider` (≤ 64 caractères) identifie l'outil
  (ex. `mon-agent`, `github-actions`) et apparaît dans le journal d'audit.

## 2. Politique d'approbation et de publication

- Une soumission ne publie jamais : elle crée une demande `pending` (analyse
  réussie) ou `invalid` (analyse échouée).
- Approuver exige la portée `review` (donc un humain). Avec
  `AUXIPAK_REQUIRE_DISTINCT_APPROVER=true` (défaut), l'approbateur doit être
  une autre personne que l'auteur (`403` sinon).
- À l'approbation, le paquet est ré-analysé et son empreinte comparée à celle
  de la soumission ; une version `id`+`version` déjà publiée (ou révoquée)
  dans le même dépôt est refusée (`409`).
- Signature : la signature jointe (`PUT …/signature`) est revérifiée ; à
  défaut, le serveur signe avec `package-signing.pem`. Sans l'une ni l'autre,
  l'approbation échoue (`400`).
- Rejet : portée `review`, motif obligatoire ; possible pour une demande
  `pending` ou `invalid` ; le fichier soumis est supprimé.
- Une nouvelle application est toujours « non évaluée » ; le manifeste ne peut
  pas fixer la classification. Le statut `compatible` exige une note
  documentant les réserves.
- États d'une version : `published`, `unpublished` (retirée des index),
  `revoked` (inscrite dans `revocations.json`, motif obligatoire, définitive).
- Toute opération sensible est inscrite au journal d'audit.

### Pré-évaluation automatique (IA)

Un agent muni de la portée `ai_evaluate` (jeton `agent` d'un relecteur ou d'un
administrateur) peut enregistrer une **pré-évaluation** issue d'une recherche
automatique : statut proposé, réserves en plusieurs langues, sources.

- Elle est publiée — site, API (`status_source: "ai"`), index (`ai_evaluation`)
  et client (« AuxiNux Compatible (analyse automatique par l'IA) ») —
  **seulement tant qu'aucun relecteur humain n'a évalué l'application**.
- Elle ne modifie jamais l'évaluation humaine (table distincte) ; dans
  `apps.json`, `status` reste `unreviewed` pour les clients antérieurs à 1.0.9.
- Les relecteurs la retrouvent dans **Administration → Évaluations IA** :
  « Confirmer » l'adopte telle quelle comme évaluation humaine, « Réviser »
  ouvre le formulaire d'évaluation.

## 3. Routes

### Public (sans authentification)

| Méthode | Chemin | Description |
|---|---|---|
| GET | `/index` | Catalogue des dépôts hébergés (`ServerCatalog` : `meta_version`, `server`, `generated_at`, `repositories[]` avec `name`, `title`, `description`, `official`, `url`, `channels`) |
| GET | `/repos/{repo}/{path}` | Fichiers du dépôt publié : `metadata/…`, `targets/…`, `keys/…` ; `Range: bytes=N-` pris en charge (`206`, `416`) ; `Cache-Control: no-cache` pour `metadata/` |
| GET | `/api/v1/health` | État : `{"status":"ok","database":true,"version":"1.0.0","package_signing_key":"<id>"}` ; `503` si la base est indisponible |
| GET | `/api/v1/openapi.yaml` | Description OpenAPI |
| GET | `/api/v1/repositories` | Dépôts actifs (`name`, `title`, `description`, `official`, `generation`, `published_at`) |
| GET | `/api/v1/apps` | Applications publiées ; paramètres `q`, `repository`, `status` (`verified`, `compatible`, `unreviewed`) ; 500 résultats au plus |
| GET | `/api/v1/apps/{id}` | Fiche : `app` (métadonnées, statut, note, date d'évaluation) et `releases` publiées ou révoquées (empreinte, clé de signature, manifeste…) |

### Authentification et jetons personnels

| Méthode | Chemin | Portée | Corps / réponse |
|---|---|---|---|
| POST | `/api/v1/auth/login` | — | `{"username","password"}` → cookie + `{"user","role","csrf_token"}` |
| POST | `/api/v1/auth/logout` | authentifié | supprime la session |
| GET | `/api/v1/auth/me` | authentifié | `{"user","role","kind","scopes","csrf_token"}` |
| GET | `/api/v1/tokens` | authentifié | jetons de l'utilisateur (sans les secrets) |
| POST | `/api/v1/tokens` | session, ou jeton `human` avec `admin` | `{"name","kind","scopes":[…],"provider"?,"expires_days"?}` → `{"id","token","warning"}` |
| DELETE | `/api/v1/tokens/{id}` | authentifié | révoque un de ses jetons |

### Soumissions

| Méthode | Chemin | Portée | Description |
|---|---|---|---|
| GET | `/api/v1/submissions` | `submit` (les siennes) ou `review` (toutes) | paramètre `status` (`invalid`, `pending`, `rejected`, `published`) |
| POST | `/api/v1/submissions` | `submit` | corps : octets du `.aupak` (`Content-Type: application/octet-stream`) ; paramètres `repository` (défaut `official`), `file_name` (nom `.aupak` sûr, sinon nom normalisé), `note` (≤ 2000) → `Submission` |
| GET | `/api/v1/submissions/{id}` | auteur ou `review` | détail, rapport d'analyse (`validation` : `checks`, `warnings`, `review_flags`, `targets`, `uses_scripts`) |
| PUT | `/api/v1/submissions/{id}/signature` | auteur ou `review` | corps : document `.aupak.sig` ; vérifié immédiatement ; demande `pending` uniquement |
| POST | `/api/v1/submissions/{id}/approve` | `review` (humain) | corps facultatif `{"note"}` → `{"status":"published","releases":[…]}` |
| POST | `/api/v1/submissions/{id}/reject` | `review` (humain) | `{"note"}` obligatoire → `{"status":"rejected"}` |

### API Builder

Les projets appartiennent à l'utilisateur propriétaire du jeton ou de la
session ; un administrateur peut accéder à tous. Toutes ces routes exigent la
portée `build` ; `submit` exige en plus `submit`.

| Méthode | Chemin | Description |
|---|---|---|
| GET | `/api/v1/builder/projects` | projets de l'utilisateur |
| POST | `/api/v1/builder/projects` | `{"name", "manifest"?}` ou `{"name","id","version"?,"publisher"?,"language"?,"license"?}` (modèle généré) |
| GET | `/api/v1/builder/projects/{id}` | projet, manifeste YAML, dernière construction, fichiers (chemin, taille, SHA-256) |
| DELETE | `/api/v1/builder/projects/{id}` | supprime le projet et ses fichiers |
| PUT | `/api/v1/builder/projects/{id}/manifest` | remplace le manifeste (corps : YAML, ≤ 256 Kio, doit être analysable) |
| PATCH | `/api/v1/builder/projects/{id}/manifest` | fusion JSON RFC 7386 (`Content-Type: application/merge-patch+json` ou `application/json`) |
| PUT | `/api/v1/builder/projects/{id}/files/{path}` | importe un fichier (corps brut) sous `payload/…` ou `scripts/…` |
| DELETE | `/api/v1/builder/projects/{id}/files/{path}` | supprime un fichier |
| POST | `/api/v1/builder/projects/{id}/validate` | `{"valid":true,"id","version","warnings"}` ou `{"valid":false,"errors":[…]}` |
| POST | `/api/v1/builder/projects/{id}/build` | `{"ok":true,"id","version","file_name","sha256","size","entries","built_at"}` ou `{"ok":false,"errors"}` |
| POST | `/api/v1/builder/projects/{id}/test` | tests statiques : `{"ok","checks":[{"check","ok","detail"}],"note"}` |
| GET | `/api/v1/builder/projects/{id}/artifact` | télécharge la dernière construction |
| POST | `/api/v1/builder/projects/{id}/submit` | `{"repository"?:"official","note"?}` → `Submission` |

### Administration

| Méthode | Chemin | Portée | Description |
|---|---|---|---|
| GET | `/api/v1/admin/users` | `admin` | comptes |
| POST | `/api/v1/admin/users` | `admin` | `{"username","display_name"?,"password","role"}` ; identifiant `[a-z0-9][a-z0-9._-]{1,31}`, mot de passe ≥ 12 caractères mêlant plusieurs types |
| PATCH | `/api/v1/admin/users/{id}` | `admin` | `{"role"?,"active"?,"password"?,"display_name"?}` ; un administrateur ne peut ni se désactiver ni se rétrograder |
| GET | `/api/v1/admin/tokens` | `admin` | tous les jetons |
| POST | `/api/v1/admin/tokens` | `admin` | comme `/api/v1/tokens`, avec `user_id` (propriétaire) |
| DELETE | `/api/v1/admin/tokens/{id}` | `admin` | révoque un jeton |
| GET | `/api/v1/admin/repositories` | `read` | dépôts (y compris désactivés) |
| POST | `/api/v1/admin/repositories` | `admin` | `{"name","title","description"?,"official"?}` puis première génération |
| PATCH | `/api/v1/admin/repositories/{name}` | `admin` | `{"title"?,"description"?,"official"?,"enabled"?}` puis régénération |
| POST | `/api/v1/admin/repositories/{name}/regenerate` | `admin` | → `{"generation": N}` |
| GET | `/api/v1/admin/releases` | `read` | paramètres `repository`, `app_id` (1000 au plus) |
| POST | `/api/v1/admin/releases/{id}/state` | `review` | `{"state":"published"\|"unpublished"\|"revoked","reason"}` (motif obligatoire pour `revoked`) |
| PUT | `/api/v1/admin/apps/{id}/evaluation` | `evaluate` | `{"status":"verified"\|"compatible"\|"unreviewed","note"?,"criteria"?}` |
| PUT | `/api/v1/apps/{id}/ai-evaluation` | `ai_evaluate` | pré-évaluation IA : `{"status":"verified"\|"compatible","notes":{"fr":…,"en":…},"sources":["https://…"],"model"?,"criteria"?}` (réserves obligatoires pour `compatible`, 1 à 20 sources HTTPS) |
| GET | `/api/v1/admin/audit` | `admin` | paramètres `limit` (1–1000, défaut 200), `before_id` (pagination) |

## 4. Exemples `curl`

### Connexion et création d'un jeton « agent »

```bash
URL=https://auxipak.auxinux.ca
# 1. Session (humain)
CSRF=$(curl -fsS -c cookies.txt -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"<mot de passe>"}' \
  "$URL/api/v1/auth/login" | jq -r .csrf_token)

# 2. Jeton agent limité à build + submit, valable 30 jours
curl -fsS -b cookies.txt -H "X-CSRF-Token: $CSRF" -H 'Content-Type: application/json' \
  -d '{"name":"agent mon-outil","kind":"agent","provider":"mon-agent","scopes":["build","submit"],"expires_days":30}' \
  "$URL/api/v1/tokens"
# → {"id":"…","token":"apk_…","warning":"ce jeton ne sera plus affiché"}

# 3. Déconnexion
curl -fsS -X POST -b cookies.txt -H "X-CSRF-Token: $CSRF" "$URL/api/v1/auth/logout"
```

### Consultation publique

```bash
curl -fsS "$URL/api/v1/health"
curl -fsS "$URL/index" | jq '.repositories[] | {name, url, channels: [.channels[].target]}'
curl -fsS "$URL/api/v1/apps?q=firefox&status=verified"
curl -fsS "$URL/repos/official/targets/channels/linux/deb/x86_64.json" | jq '.releases[] | {id, version}'
```

Les fichiers de `/repos/…` ne doivent être considérés comme authentiques
qu'après vérification TUF (ce que fait le client).

### Soumettre un paquet construit localement

```bash
curl -fsS -X POST -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/octet-stream' --data-binary @MonOutil-1.0.0-fr.aupak \
  "$URL/api/v1/submissions?repository=official&file_name=MonOutil-1.0.0-fr.aupak&note=premi%C3%A8re%20version"
# Signature détachée facultative :
curl -fsS -X PUT -H "Authorization: Bearer $TOKEN" --data-binary @MonOutil-1.0.0-fr.aupak.sig \
  "$URL/api/v1/submissions/<id>/signature"
```

`auxipak-builder submit` effectue ces deux appels (voir [BUILDER.md](BUILDER.md)).

### Relecture (humain, portée `review`)

```bash
curl -fsS -H "Authorization: Bearer $REVIEW_TOKEN" "$URL/api/v1/submissions?status=pending" \
  | jq '.[] | {id, app_id, version, submitter, submitter_kind, review_flags: .validation.review_flags}'
curl -fsS -X POST -H "Authorization: Bearer $REVIEW_TOKEN" -H 'Content-Type: application/json' \
  -d '{"note":"relu : aucun script, source HTTPS"}' "$URL/api/v1/submissions/<id>/approve"
curl -fsS -X POST -H "Authorization: Bearer $REVIEW_TOKEN" -H 'Content-Type: application/json' \
  -d '{"note":"télémétrie obligatoire non déclarée"}' "$URL/api/v1/submissions/<id>/reject"
```

`$REVIEW_TOKEN` est un jeton `human` d'un relecteur portant la portée
`review` (ou utilisez une session avec `X-CSRF-Token`).

### Classification et révocation

```bash
curl -fsS -X PUT -H "Authorization: Bearer $REVIEW_TOKEN" -H 'Content-Type: application/json' \
  -d '{"status":"compatible","note":"Télémétrie activée par défaut (désactivable)."}' \
  "$URL/api/v1/admin/apps/firefox/evaluation"
REL=$(curl -fsS -H "Authorization: Bearer $REVIEW_TOKEN" "$URL/api/v1/admin/releases?app_id=firefox" \
  | jq -r '.[] | select(.version=="150.1") | .id')
curl -fsS -X POST -H "Authorization: Bearer $REVIEW_TOKEN" -H 'Content-Type: application/json' \
  -d '{"state":"revoked","reason":"faille critique CVE-XXXX-YYYY"}' "$URL/api/v1/admin/releases/$REL/state"
```

## 5. Construire un paquet avec l'API Builder (jeton agent)

Scénario : un agent d'automatisation dispose d'un jeton `agent`
(`build`, `submit`) et construit le paquet `mon-outil`. Il ne peut ni
approuver ni publier.

```bash
URL=https://auxipak.auxinux.ca
AUTH="Authorization: Bearer $AUXIPAK_TOKEN"
```

**1. Créer le projet** (manifeste généré à partir d'un modèle : une variante
Linux `files` qui copie `payload/bin/<id>` vers `{bin}/<id>`) :

```bash
P=$(curl -fsS -H "$AUTH" -H 'Content-Type: application/json' \
  -d '{"name":"Mon outil","id":"mon-outil","version":"1.0.0","publisher":"Exemple inc.","language":"fr","license":"MIT"}' \
  "$URL/api/v1/builder/projects" | jq -r .id)
```

On peut aussi fournir directement `"manifest": "<YAML complet>"`.

**2. Modifier le manifeste par fusion JSON (RFC 7386).** Les objets sont
fusionnés, une valeur `null` supprime une clé et **un tableau remplace
entièrement le précédent** (`targets` doit donc être fourni en entier) :

```bash
curl -fsS -X PATCH -H "$AUTH" -H 'Content-Type: application/merge-patch+json' \
  "$URL/api/v1/builder/projects/$P/manifest" -d '{
  "summary": "Outil en ligne de commande de démonstration",
  "homepage": "https://www.example.org/mon-outil",
  "privacy": {"telemetry": "none"},
  "targets": [
    {"name": "linux", "platform": "linux",
     "distributions": ["debian", "ubuntu", "auxinuxos", "virtuaos"],
     "architectures": ["any"], "mode": "embedded",
     "install": {"method": "files", "files": [
       {"source": "payload/bin/mon-outil", "destination": "{bin}/mon-outil", "executable": true}]}},
    {"name": "windows", "platform": "windows", "architectures": ["x86_64", "arm64"], "mode": "embedded",
     "install": {"method": "files", "files": [
       {"source": "payload/windows/mon-outil.exe", "destination": "{bin}/mon-outil.exe"}]}}
  ]}'
```

Le manifeste résultant est réécrit en YAML ; il doit seulement être
analysable à ce stade, la validation complète a lieu à l'étape 4.

**3. Importer les fichiers** (le chemin suit `files/`) :

```bash
curl -fsS -X PUT -H "$AUTH" --data-binary @dist/mon-outil \
  "$URL/api/v1/builder/projects/$P/files/payload/bin/mon-outil"
curl -fsS -X PUT -H "$AUTH" --data-binary @dist/mon-outil.exe \
  "$URL/api/v1/builder/projects/$P/files/payload/windows/mon-outil.exe"
# → {"path":"payload/bin/mon-outil","size":…,"sha256":"…"}
```

Les droits d'exécution ne sont pas transmis : ils proviennent du manifeste
(`executable: true` d'une copie `files` ou d'une entrée `contents`) ou de
l'extension `.sh`.

**4. Valider** (la liste `contents` est recalculée à partir des fichiers) :

```bash
curl -fsS -X POST -H "$AUTH" "$URL/api/v1/builder/projects/$P/validate"
# → {"valid":true,"id":"mon-outil","version":"1.0.0","warnings":[…]}
```

**5. Construire** :

```bash
curl -fsS -X POST -H "$AUTH" "$URL/api/v1/builder/projects/$P/build"
# → {"ok":true,"file_name":"Monoutil-1.0.0-fr.aupak","sha256":"…","size":…,"entries":3,…}
```

**6. Tester** (statique : structure, extraction, empreintes, sélection de
variante pour 12 profils de référence ; aucun outil externe ni script n'est
exécuté côté serveur) :

```bash
curl -fsS -X POST -H "$AUTH" "$URL/api/v1/builder/projects/$P/test" | jq '.ok, .checks[] | select(.ok == false)'
curl -fsS -H "$AUTH" -o Monoutil-1.0.0-fr.aupak "$URL/api/v1/builder/projects/$P/artifact"   # facultatif
```

**7. Soumettre** (crée une demande `pending`, rien n'est publié) :

```bash
curl -fsS -X POST -H "$AUTH" -H 'Content-Type: application/json' \
  -d '{"repository":"official","note":"construit par un agent"}' \
  "$URL/api/v1/builder/projects/$P/submit" | jq '{id, status, validation: .validation.ok}'
```

**8. Approbation humaine** : un relecteur examine la demande dans
l'interface (`/admin/submissions`) ou via l'API, puis l'approuve. Le serveur
signe le paquet (si aucune signature n'a été jointe), régénère les index et
les métadonnées TUF. Toute tentative d'approbation avec le jeton agent
renvoie `403`.
