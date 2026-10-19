# Format `.apak` — spécification version 1

| | |
|---|---|
| Version du format | 1 (`APAK_FORMAT_VERSION`, `shared/src/archive.rs`) |
| Extension | `.apak` (obligatoire) |
| Signature détachée | `<fichier>.apak.sig`, format `auxipak-signature/1` |
| Implémentation de référence | `auxipak-core` : `archive.rs`, `signature.rs`, `ids.rs`, `manifest.rs` |

Les mots **DOIT**, **NE DOIT PAS**, **DEVRAIT** ont le sens habituel des
spécifications normatives. Ce qui est décrit comme « vérifié » est appliqué
par le lecteur de référence (client, constructeur, serveur).

## 1. Conteneur

Un `.apak` est une archive **7z** normalisée.

- Méthodes de compression admises à la lecture : **LZMA2**, LZMA, **COPY**
  (stockage). Toute autre méthode ou filtre (dont le chiffrement AES) est
  refusé. Vérifié.
- L'archive NE DOIT PAS être chiffrée (ni contenu ni en-tête). Le lecteur
  ouvre l'archive sans mot de passe.
- Le producteur de référence (`auxipak-builder`) écrit en LZMA2, une entrée
  par fichier (archive **non solide**), en-tête non chiffré. Un producteur
  DEVRAIT faire de même ; la version 1 du lecteur ne refuse pas explicitement
  une archive solide.

## 2. Entrées

### 2.1 Entrées autorisées

| Entrée | Règle |
|---|---|
| `instruction.auxipak` | Fichier à la racine, **obligatoire**, ≤ 256 Kio, manifeste YAML ([MANIFEST_SPEC.md](MANIFEST_SPEC.md)) |
| `payload/**` | Fichiers de l'application (installateurs, binaires, ressources) |
| `scripts/**` | Scripts déclarés par le manifeste (`.sh` ou `.ps1`) |
| répertoires | Uniquement `payload`, `scripts` et leurs sous-répertoires |

Tout autre fichier à la racine, ou tout fichier directement nommé `payload`
ou `scripts`, est refusé. Vérifié.

### 2.2 Chemins

Chaque nom d'entrée DOIT être un chemin relatif sûr (`ids::is_safe_relative_path`) :

- séparateur `/` uniquement (pas de `\`), pas de `/` initial, pas de lettre
  de lecteur (`C:`), pas d'octet nul ;
- aucun composant vide, `.` ou `..` ;
- longueur totale ≤ 512 octets, composant ≤ 255 octets ;
- aucun caractère de contrôle ni `< > : " | ? *` ;
- aucun composant terminé par une espace ou un point ;
- aucun nom réservé Windows (`CON`, `PRN`, `AUX`, `NUL`, `COM0`–`COM9`,
  `LPT0`–`LPT9`, avec ou sans extension).

Deux entrées dont les chemins ne diffèrent que par la casse sont refusées
(« entrée dupliquée »), afin qu'un fichier vérifié ne puisse pas être écrasé
sur un système de fichiers insensible à la casse.

### 2.3 Types d'entrées interdits

- **Liens symboliques et points d'analyse** : attribut Windows
  `FILE_ATTRIBUTE_REPARSE_POINT` (`0x400`) refusé ; si l'extension d'attributs
  Unix est présente (`0x8000`), le type de fichier (16 bits de poids fort,
  masque `S_IFMT`) DOIT être « fichier ordinaire » pour un fichier ou
  « répertoire » pour un répertoire (ou absent). Liens, périphériques, tubes
  et sockets sont refusés.
- **Anti-items 7z** (marqueurs de suppression) : refusés.

### 2.4 Correspondance avec `contents`

Le manifeste DOIT lister dans `contents` **chaque** fichier de l'archive
(hors `instruction.auxipak` et hors répertoires), avec son chemin, sa taille
en octets et son SHA-256 (64 caractères hexadécimaux minuscules), et
réciproquement :

- un fichier présent mais non déclaré → refus ;
- un fichier déclaré mais absent → refus ;
- une taille déclarée différente de la taille de l'entrée → refus
  (vérifié dès l'inspection) ;
- une empreinte différente → refus (vérifié à l'extraction, au fil de
  l'écriture).

L'attribut `executable: true` d'une entrée `contents` fixe les droits
d'exécution à l'extraction sous Unix.

## 3. Limites

| Limite | Valeur (défaut de `Limits`) |
|---|---|
| Nombre d'entrées | 20 000 |
| Taille décompressée totale | 32 Gio |
| Taille d'une entrée | 16 Gio |
| Rapport décompressé / taille de l'archive | 1 000:1 au plus, appliqué au-delà de 64 Mio décompressés (bombe de décompression) |
| Manifeste | 256 Kio |
| Document de signature | 64 Kio |
| Téléchargement par le client | `policy.max_download_bytes` (32 Gio par défaut) et taille exacte annoncée par l'index |
| Soumission au serveur | `AUXIPAK_MAX_UPLOAD_BYTES` (8 Gio par défaut) |

## 4. Inspection et extraction

L'inspection (`archive::inspect`) n'extrait ni n'exécute rien :

1. calcul du SHA-256 et de la taille de l'archive ;
2. lecture de la table des entrées ; contrôle du nombre d'entrées ;
3. pour chaque entrée : anti-item, chemin, attributs, emplacement autorisé,
   doublons (insensibles à la casse), taille maximale ;
4. taille totale et rapport de compression ;
5. méthodes de compression de chaque fichier ;
6. présence et taille du manifeste, puis validation complète (schéma JSON,
   typage strict, règles sémantiques) ;
7. correspondance exacte fichiers ↔ `contents` (chemins et tailles).

L'extraction (`archive::extract`) n'utilise **jamais** la fonction
d'extraction automatique de la bibliothèque 7z :

1. inspection complète (ci-dessus) ;
2. la destination DOIT exister et être vide ;
3. chaque entrée est revalidée puis jointe à la destination composant par
   composant ; le répertoire parent, une fois créé, doit rester dans la
   destination (chemin canonique) ;
4. chaque fichier est créé avec `create_new` (jamais d'écrasement), droits
   `0600` et `O_NOFOLLOW` sous Unix ;
5. le contenu est haché au fil de l'écriture, avec une limite égale à la
   taille déclarée ; taille et SHA-256 sont comparés à `contents` (au
   manifeste lu pour `instruction.auxipak`) ;
6. droits finaux sous Unix : `0700` si `executable`, sinon `0600` ;
7. contrôle final : tous les fichiers de `contents` ont été extraits.

Le client extrait toujours dans un répertoire de travail privé
(`<cache>/work/<transaction>/pkg`, droits `0700`).

## 5. Normalisation et reproductibilité

Le constructeur de référence produit une archive **déterministe** : mêmes
fichiers et même manifeste → même archive octet pour octet.

- `contents` est recalculé à partir des fichiers réels (chemin, taille,
  SHA-256, bit exécutable) ;
- le manifeste est réécrit en YAML canonique, puis revalidé ;
- entrées triées par chemin, `instruction.auxipak` en premier ;
- aucune date ni attribut de lien ; répertoires non stockés ;
- les fichiers cachés (nom commençant par `.`) d'un projet sont ignorés ; un
  lien symbolique dans un projet fait échouer la construction ;
- un fichier est marqué exécutable s'il l'est sur disque (Unix), s'il se
  termine par `.sh`, s'il est déclaré `executable` dans `contents` ou dans
  une copie `files`.

Nom de fichier normalisé : `<Nom>-<version>-<langue>.apak`, où `<Nom>` est
le champ `name` réduit aux caractères ASCII alphanumériques, `-` et `_`
(l'identifiant s'il devient vide) et `<langue>` la langue unique du
manifeste, ou `mul` s'il y en a plusieurs. Exemple : `Firefox-150.1-fr.apak`.

## 6. Signature détachée (`.apak.sig`)

### 6.1 Format

Document JSON (≤ 64 Kio) :

```json
{
  "format": "auxipak-signature/1",
  "algorithm": "ed25519",
  "key_id": "1c7795bd5be5909f93ab83ea8e3fcf44",
  "package": {
    "id": "mon-outil",
    "version": "1.0.0",
    "file_name": "Monoutil-1.0.0-fr.apak",
    "sha256": "ba792359f31d5cbb43d2b82d6177c7ca1083f8f7a4f8d16a05201404a25e0f57",
    "size": 651
  },
  "signed_at": "2026-10-19T02:47:41Z",
  "certificate_chain": [],
  "signature": "GsIgApDZihaAO0RZlfwWpoMU1YgrYOWLomJEEof1XJ1G0O7yiL3a7F+N2r7DnO9cMJOtAat+eQBnUwBQ+4+VAA=="
}
```

| Champ | Description |
|---|---|
| `format` | `auxipak-signature/1` |
| `algorithm` | `ed25519` |
| `key_id` | 32 premiers caractères hexadécimaux du SHA-256 de la clé publique brute (32 octets) |
| `package.id`, `package.version` | identifiant et version du manifeste |
| `package.file_name` | nom du fichier au moment de la signature (informatif, non vérifié) |
| `package.sha256`, `package.size` | empreinte et taille **de l'archive `.apak` complète** |
| `signed_at` | date RFC 3339 à la seconde, en UTC (`Z`) |
| `certificate_chain` | réservé à la phase 2 (chaîne `ca.auxinux.ca`) ; vide en V1 |
| `signature` | signature Ed25519 (64 octets) en base64 standard |

### 6.2 Message signé

```text
message = "AUXIPAK-SIGNATURE-V1\n" || JSON(payload)
```

où `payload` est l'objet composé, **dans cet ordre**, des champs `format`,
`algorithm`, `key_id`, `package` (lui-même dans l'ordre `id`, `version`,
`file_name`, `sha256`, `size`) et `signed_at`, sérialisé en JSON compact
(aucune espace, séparateurs `,` et `:`), UTF-8. Les champs
`certificate_chain` et `signature` ne sont pas signés.

Vérification indépendante (Python, bibliothèque `cryptography`) :

```python
import base64, hashlib, json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

sig = json.load(open("Monoutil-1.0.0-fr.apak.sig"))
key = next(k for k in json.load(open("package-keys.json"))["keys"] if k["key_id"] == sig["key_id"])
raw = base64.b64decode(key["public_key"])
assert hashlib.sha256(raw).hexdigest()[:32] == sig["key_id"]
data = open("Monoutil-1.0.0-fr.apak", "rb").read()
assert hashlib.sha256(data).hexdigest() == sig["package"]["sha256"] and len(data) == sig["package"]["size"]
payload = {k: sig[k] for k in ("format", "algorithm", "key_id", "package", "signed_at")}
msg = b"AUXIPAK-SIGNATURE-V1\n" + json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode()
Ed25519PublicKey.from_public_bytes(raw).verify(base64.b64decode(sig["signature"]), msg)
print("signature valide")
```

### 6.3 Règles de vérification

Une signature est acceptée si et seulement si :

1. `format` = `auxipak-signature/1` et `algorithm` = `ed25519` ;
2. `key_id` figure dans l'ensemble de clés de confiance (`package-keys.json`)
   et la clé publique correspond à cet identifiant ;
3. la clé n'est pas `revoked` ;
4. l'usage (`purpose`) de la clé est admis : `package-signing` pour le
   client et le serveur ; `auxipak-builder verify-signature` admet aussi
   `developer-signing` ;
5. `signed_at` est compris entre `not_before` et `not_after` de la clé
   (s'ils sont définis) ;
6. `package.sha256` et `package.size` correspondent à l'archive réelle ;
7. la signature Ed25519 du message est valide.

Le client et le serveur vérifient en outre que `package.id` et
`package.version` correspondent au paquet (index ou manifeste).

### 6.4 Ensemble de clés de confiance (`package-keys.json`)

```json
{
  "format": "auxipak-trusted-keys/1",
  "keys": [
    {
      "key_id": "1c7795bd5be5909f93ab83ea8e3fcf44",
      "algorithm": "ed25519",
      "public_key": "rTtgSyNtWl3kDU+ChgrNaqCT6DP6JC8fsRQq5TIajnI=",
      "purpose": "package-signing",
      "owner": "AuxiNux",
      "not_before": "2026-10-19T00:00:00Z",
      "not_after": "2028-10-19T00:00:00Z",
      "revoked": false
    }
  ]
}
```

`purpose` : `package-signing` ou `developer-signing` ; `not_before` et
`not_after` sont facultatifs ; `public_key` est la clé brute de 32 octets en
base64. Les clés privées sont stockées en PKCS#8 PEM
(`-----BEGIN PRIVATE KEY-----`).

## 7. Créer un `.apak`

### 7.1 Avec `auxipak-builder` (recommandé)

```console
$ auxipak-builder init mon-outil --id mon-outil --name "Mon outil" --publisher "Exemple inc." --license MIT
$ cp dist/mon-outil mon-outil/payload/bin/mon-outil
$ $EDITOR mon-outil/instruction.auxipak
$ auxipak-builder validate mon-outil
$ auxipak-builder build mon-outil -o Monoutil-1.0.0-fr.apak
$ auxipak-builder test Monoutil-1.0.0-fr.apak
$ auxipak-builder sign Monoutil-1.0.0-fr.apak --key cle-paquets.pem   # facultatif
```

### 7.2 Manuellement (outil 7-Zip)

La création manuelle est possible mais non normalisée (dates, ordre) : le
résultat est valide s'il respecte cette spécification, sans être
reproductible octet pour octet.

1. Préparer l'arborescence (aucun lien symbolique, aucun fichier caché) :

   ```text
   paquet/
     instruction.auxipak
     payload/bin/mon-outil
   ```

2. Calculer taille et empreinte de chaque fichier :

   ```console
   $ cd paquet
   $ find payload scripts -type f 2>/dev/null | sort | while read -r f; do
       printf '  - path: %s\n    sha256: "%s"\n    size: %s\n' \
         "$f" "$(sha256sum "$f" | cut -d' ' -f1)" "$(stat -c %s "$f")"
     done
   ```

3. Coller le résultat sous une clé `contents:` du manifeste (ajouter
   `executable: true` aux fichiers exécutables).
4. Créer l'archive en LZMA2, non solide, sans chiffrement ; selon la version
   de 7-Zip, les options suivantes désactivent aussi le stockage des dates :

   ```console
   $ 7z a -t7z -m0=LZMA2 -ms=off -mhe=off -mtm=off -mtc=off -mta=off \
       ../MonOutil-1.0.0-fr.apak instruction.auxipak payload
   ```

5. Contrôler le résultat avec les outils de référence :

   ```console
   $ auxipak verify ../MonOutil-1.0.0-fr.apak
   $ auxipak-builder validate ../MonOutil-1.0.0-fr.apak
   ```

## 8. Évolution du format

Toute modification incompatible incrémentera `APAK_FORMAT_VERSION` et, pour
le manifeste, le champ `format`. Les ajouts compatibles prévus (chaîne de
certificats, signatures multiples) passent par le document de signature
détaché, sans toucher à l'archive.
