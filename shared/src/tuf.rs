//! Métadonnées de dépôt TUF (The Update Framework) via la bibliothèque
//! éprouvée `tough` (AWS).
//!
//! Rôles :
//! - `root`      : clés hors ligne, désigne les clés des autres rôles ;
//! - `targets`   : signe la liste des fichiers (index, paquets, signatures) ;
//! - `snapshot`  : fige la version de `targets` (cohérence) ;
//! - `timestamp` : courte durée de vie, garantit la fraîcheur (anti-rejeu,
//!   anti-gel).
//!
//! Le serveur détient uniquement les clés `targets`, `snapshot` et
//! `timestamp` (fichiers PEM montés en secrets). La clé `root` reste hors
//! ligne et n'est utilisée que lors de la cérémonie d'initialisation ou de
//! rotation.

use anyhow::{anyhow, bail, Context, Result};
use aws_lc_rs::rand::SystemRandom;
use ed25519_dalek::pkcs8::EncodePrivateKey;
use ed25519_dalek::SigningKey;
use std::collections::HashMap;
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};
use tough::editor::signed::SignedRole;
use tough::editor::RepositoryEditor;
use tough::key_source::KeySource;
use tough::schema::{KeyHolder, Role, RoleKeys, RoleType, Root, Target};
use tough::sign::{parse_keypair, Sign};

/// Rôles TUF de premier niveau.
pub const ROLES: [&str; 4] = ["root", "targets", "snapshot", "timestamp"];

/// Durées de validité par défaut.
pub mod expiry {
    pub const ROOT_DAYS: i64 = 365;
    pub const TARGETS_DAYS: i64 = 30;
    pub const SNAPSHOT_DAYS: i64 = 7;
    pub const TIMESTAMP_HOURS: i64 = 24;
}

/// Génère une clé Ed25519 au format PKCS#8 PEM.
pub fn generate_key_pem() -> String {
    let k = SigningKey::generate(&mut rand::rngs::OsRng);
    k.to_pkcs8_pem(Default::default()).expect("PKCS#8").to_string()
}

fn pem_to_der(pem_text: &[u8]) -> Result<Vec<u8>> {
    let p = pem::parse(pem_text).map_err(|e| anyhow!("PEM invalide : {e}"))?;
    if p.tag() != "PRIVATE KEY" {
        bail!("étiquette PEM inattendue : {}", p.tag());
    }
    Ok(p.contents().to_vec())
}

/// Source de clé `tough` lisant une clé PKCS#8 PEM sur disque.
#[derive(Debug, Clone)]
pub struct PemKeySource {
    pub path: PathBuf,
}

#[tough::async_trait]
impl KeySource for PemKeySource {
    async fn as_sign(&self) -> std::result::Result<Box<dyn Sign>, Box<dyn std::error::Error + Send + Sync + 'static>> {
        let data = tokio::fs::read(&self.path).await?;
        let der = pem_to_der(&data).map_err(|e| e.to_string())?;
        Ok(Box::new(parse_keypair(&der)?))
    }

    async fn write(
        &self,
        _value: &str,
        _key_id_hex: &str,
    ) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        Err("écriture de clé non prise en charge".into())
    }
}

/// Source de clé en mémoire (tests et cérémonie d'initialisation).
#[derive(Clone)]
pub struct MemKeySource {
    pub pem: String,
}

impl std::fmt::Debug for MemKeySource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MemKeySource(<secret>)")
    }
}

#[tough::async_trait]
impl KeySource for MemKeySource {
    async fn as_sign(&self) -> std::result::Result<Box<dyn Sign>, Box<dyn std::error::Error + Send + Sync + 'static>> {
        let der = pem_to_der(self.pem.as_bytes()).map_err(|e| e.to_string())?;
        Ok(Box::new(parse_keypair(&der)?))
    }

    async fn write(
        &self,
        _value: &str,
        _key_id_hex: &str,
    ) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        Err("écriture de clé non prise en charge".into())
    }
}

/// Clé publique TUF (et son identifiant) correspondant à une clé privée PEM.
pub fn public_tuf_key(pem_text: &str) -> Result<(String, tough::schema::key::Key)> {
    let der = pem_to_der(pem_text.as_bytes())?;
    let kp = parse_keypair(&der).map_err(|e| anyhow!("clé refusée : {e}"))?;
    let key = kp.tuf_key();
    let id = key.key_id().map_err(|e| anyhow!("{e}"))?;
    Ok((hex::encode(id.as_ref()), key))
}

/// Description de la racine de confiance à créer.
pub struct RootSpec {
    /// Clés privées PEM du rôle root (utilisées pour signer root.json).
    pub root_keys: Vec<String>,
    pub root_threshold: u64,
    /// Clés publiques (via leur clé privée PEM ou leur clé publique TUF) des autres rôles.
    pub targets_keys: Vec<tough::schema::key::Key>,
    pub snapshot_keys: Vec<tough::schema::key::Key>,
    pub timestamp_keys: Vec<tough::schema::key::Key>,
    pub version: u64,
    pub expires: chrono::DateTime<chrono::Utc>,
}

fn to_jiff(t: chrono::DateTime<chrono::Utc>) -> Result<jiff::Timestamp> {
    jiff::Timestamp::from_second(t.timestamp()).map_err(|e| anyhow!("{e}"))
}

/// Crée et signe un `root.json`. Retourne le JSON sérialisé.
pub async fn create_root(spec: RootSpec) -> Result<Vec<u8>> {
    let mut root = Root {
        spec_version: "1.0.0".into(),
        consistent_snapshot: false,
        version: NonZeroU64::new(spec.version).context("version > 0")?,
        expires: to_jiff(spec.expires)?,
        keys: HashMap::new(),
        roles: HashMap::new(),
        _extra: HashMap::new(),
    };
    let mut add_role = |role: RoleType, keys: Vec<tough::schema::key::Key>, threshold: u64| -> Result<()> {
        if keys.is_empty() {
            bail!("aucune clé pour le rôle {role}");
        }
        let mut ids = Vec::new();
        for k in keys {
            let id = k.key_id().map_err(|e| anyhow!("{e}"))?;
            root.keys.insert(id.clone(), k);
            if !ids.contains(&id) {
                ids.push(id);
            }
        }
        if threshold == 0 || threshold > ids.len() as u64 {
            bail!("seuil invalide pour le rôle {role}");
        }
        root.roles.insert(
            role,
            RoleKeys {
                keyids: ids,
                threshold: NonZeroU64::new(threshold).unwrap(),
                _extra: HashMap::new(),
            },
        );
        Ok(())
    };
    let root_pub = spec
        .root_keys
        .iter()
        .map(|p| public_tuf_key(p).map(|(_, k)| k))
        .collect::<Result<Vec<_>>>()?;
    add_role(RoleType::Root, root_pub, spec.root_threshold)?;
    add_role(RoleType::Targets, spec.targets_keys, 1)?;
    add_role(RoleType::Snapshot, spec.snapshot_keys, 1)?;
    add_role(RoleType::Timestamp, spec.timestamp_keys, 1)?;

    let sources: Vec<Box<dyn KeySource>> = spec
        .root_keys
        .iter()
        .map(|p| Box::new(MemKeySource { pem: p.clone() }) as Box<dyn KeySource>)
        .collect();
    let signed = SignedRole::new(root.clone(), &KeyHolder::Root(root), &sources, &SystemRandom::new())
        .await
        .map_err(|e| anyhow!("signature de root.json : {e}"))?;
    if (signed.signed().signatures.len() as u64) < spec.root_threshold {
        bail!("nombre de signatures root insuffisant");
    }
    Ok(signed.buffer().clone())
}

/// Résumé d'une racine de confiance (affichage, vérifications).
#[derive(Debug, Clone, serde::Serialize)]
pub struct RootSummary {
    pub version: u64,
    pub expires: String,
    pub roles: Vec<(String, Vec<String>, u64)>,
}

pub fn summarize_root(bytes: &[u8]) -> Result<RootSummary> {
    let signed: tough::schema::Signed<Root> = serde_json::from_slice(bytes).context("root.json invalide")?;
    let r = signed.signed;
    let mut roles: Vec<_> = r
        .roles
        .iter()
        .map(|(t, k)| {
            (
                t.to_string(),
                k.keyids.iter().map(|id| hex::encode(id.as_ref())).collect(),
                k.threshold.get(),
            )
        })
        .collect();
    roles.sort();
    Ok(RootSummary {
        version: r.version.get(),
        expires: r.expires.to_string(),
        roles,
    })
}

/// Paramètres de publication d'un dépôt TUF.
pub struct PublishSpec {
    pub root_path: PathBuf,
    pub keys: Vec<Box<dyn KeySource>>,
    /// (nom de cible, fichier source).
    pub targets: Vec<(String, PathBuf)>,
    /// Version commune targets/snapshot/timestamp (doit croître à chaque publication).
    pub version: u64,
    pub targets_expires: chrono::DateTime<chrono::Utc>,
    pub snapshot_expires: chrono::DateTime<chrono::Utc>,
    pub timestamp_expires: chrono::DateTime<chrono::Utc>,
    /// Répertoire de sortie (doit être vide) : `metadata/` et `targets/` y sont créés.
    pub out_dir: PathBuf,
}

/// Signe et écrit un dépôt TUF complet.
pub async fn publish(spec: PublishSpec) -> Result<()> {
    let meta_dir = spec.out_dir.join("metadata");
    let targets_dir = spec.out_dir.join("targets");
    tokio::fs::create_dir_all(&meta_dir).await?;
    tokio::fs::create_dir_all(&targets_dir).await?;
    let mut editor = RepositoryEditor::new(&spec.root_path)
        .await
        .map_err(|e| anyhow!("lecture de root.json : {e}"))?;
    let v = NonZeroU64::new(spec.version).context("version > 0")?;
    for (name, path) in &spec.targets {
        if !crate::ids::is_safe_relative_path(name) {
            bail!("nom de cible dangereux : {name}");
        }
        let t = Target::from_path(path).await.map_err(|e| anyhow!("cible {name} : {e}"))?;
        editor
            .add_target(name.as_str(), t)
            .map_err(|e| anyhow!("cible {name} : {e}"))?;
    }
    editor
        .targets_version(v)
        .map_err(|e| anyhow!("{e}"))?
        .targets_expires(to_jiff(spec.targets_expires)?)
        .map_err(|e| anyhow!("{e}"))?
        .snapshot_version(v)
        .snapshot_expires(to_jiff(spec.snapshot_expires)?)
        .timestamp_version(v)
        .timestamp_expires(to_jiff(spec.timestamp_expires)?);
    let signed = editor.sign(&spec.keys).await.map_err(|e| anyhow!("signature TUF : {e}"))?;
    signed
        .write(&meta_dir)
        .await
        .map_err(|e| anyhow!("écriture des métadonnées : {e}"))?;
    // Copie des racines successives pour permettre la rotation côté client.
    for (name, path) in &spec.targets {
        let dest = targets_dir.join(name);
        if let Some(p) = dest.parent() {
            tokio::fs::create_dir_all(p).await?;
        }
        if tokio::fs::hard_link(path, &dest).await.is_err() {
            tokio::fs::copy(path, &dest).await?;
        }
    }
    Ok(())
}

/// Version et expiration d'un fichier de métadonnées signé (lecture seule,
/// sans vérification : à n'utiliser que pour l'affichage).
pub fn peek_role(bytes: &[u8]) -> Option<(u64, String)> {
    let v: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    let s = v.get("signed")?;
    Some((s.get("version")?.as_u64()?, s.get("expires")?.as_str()?.to_string()))
}

/// Vérifie qu'un fichier root.json peut être lu par `tough`.
pub fn check_root_file(path: &Path) -> Result<RootSummary> {
    let bytes = std::fs::read(path).with_context(|| format!("lecture de {}", path.display()))?;
    let s = summarize_root(&bytes)?;
    for r in ["root", "targets", "snapshot", "timestamp"] {
        if !s.roles.iter().any(|(n, _, _)| n == r) {
            bail!("rôle {r} absent de root.json");
        }
    }
    Ok(s)
}

// Rend `Role` utilisé (version/expiration) pour éviter un avertissement si
// l'API évolue.
#[allow(dead_code)]
fn _role_version<R: Role>(r: &R) -> u64 {
    r.version().get()
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use tough::{ExpirationEnforcement, FilesystemTransport, RepositoryLoader, TargetName};

    /// Jeu de clés de test (jamais utilisé en production).
    pub struct TestKeys {
        pub root: String,
        pub targets: String,
        pub snapshot: String,
        pub timestamp: String,
    }

    impl TestKeys {
        pub fn generate() -> Self {
            TestKeys {
                root: generate_key_pem(),
                targets: generate_key_pem(),
                snapshot: generate_key_pem(),
                timestamp: generate_key_pem(),
            }
        }

        pub fn online_sources(&self) -> Vec<Box<dyn KeySource>> {
            [&self.targets, &self.snapshot, &self.timestamp]
                .into_iter()
                .map(|p| Box::new(MemKeySource { pem: p.clone() }) as Box<dyn KeySource>)
                .collect()
        }

        pub async fn root_json(&self) -> Vec<u8> {
            create_root(RootSpec {
                root_keys: vec![self.root.clone()],
                root_threshold: 1,
                targets_keys: vec![public_tuf_key(&self.targets).unwrap().1],
                snapshot_keys: vec![public_tuf_key(&self.snapshot).unwrap().1],
                timestamp_keys: vec![public_tuf_key(&self.timestamp).unwrap().1],
                version: 1,
                expires: Utc::now() + Duration::days(365),
            })
            .await
            .unwrap()
        }
    }

    async fn publish_simple(
        dir: &Path,
        keys: &TestKeys,
        root_path: &Path,
        version: u64,
        content: &[u8],
        ts_expires: chrono::DateTime<Utc>,
    ) -> PathBuf {
        let src = dir.join(format!("src-{version}"));
        std::fs::create_dir_all(&src).unwrap();
        let f = src.join("index.json");
        std::fs::write(&f, content).unwrap();
        let out = dir.join(format!("repo-{version}"));
        publish(PublishSpec {
            root_path: root_path.to_path_buf(),
            keys: keys.online_sources(),
            targets: vec![("index.json".into(), f)],
            version,
            targets_expires: Utc::now() + Duration::days(30),
            snapshot_expires: Utc::now() + Duration::days(7),
            timestamp_expires: ts_expires,
            out_dir: out.clone(),
        })
        .await
        .unwrap();
        out
    }

    async fn load(repo: &Path, root: &[u8], datastore: &Path) -> tough::error::Result<tough::Repository> {
        let meta = url::Url::from_directory_path(repo.join("metadata")).unwrap();
        let targets = url::Url::from_directory_path(repo.join("targets")).unwrap();
        RepositoryLoader::new(&root, meta, targets)
            .transport(FilesystemTransport)
            .datastore(datastore)
            .expiration_enforcement(ExpirationEnforcement::Safe)
            .load()
            .await
    }

    async fn read(repo: &tough::Repository, name: &str) -> Vec<u8> {
        use futures::StreamExt;
        let mut s = repo.read_target(&TargetName::new(name).unwrap()).await.unwrap().unwrap();
        let mut out = Vec::new();
        while let Some(chunk) = s.next().await {
            out.extend_from_slice(&chunk.unwrap());
        }
        out
    }

    #[tokio::test]
    async fn publish_and_verify_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let keys = TestKeys::generate();
        let root = keys.root_json().await;
        let root_path = dir.path().join("root.json");
        std::fs::write(&root_path, &root).unwrap();
        let repo = publish_simple(
            dir.path(),
            &keys,
            &root_path,
            1,
            b"{\"v\":1}",
            Utc::now() + Duration::hours(24),
        )
        .await;
        let ds = dir.path().join("ds");
        std::fs::create_dir(&ds).unwrap();
        let r = load(&repo, &root, &ds).await.unwrap();
        assert_eq!(read(&r, "index.json").await, b"{\"v\":1}");
        let summary = check_root_file(&root_path).unwrap();
        assert_eq!(summary.roles.len(), 4);
    }

    #[tokio::test]
    async fn rejects_expired_timestamp() {
        let dir = tempfile::tempdir().unwrap();
        let keys = TestKeys::generate();
        let root = keys.root_json().await;
        let root_path = dir.path().join("root.json");
        std::fs::write(&root_path, &root).unwrap();
        let repo = publish_simple(dir.path(), &keys, &root_path, 1, b"{}", Utc::now() - Duration::hours(1)).await;
        let ds = dir.path().join("ds");
        std::fs::create_dir(&ds).unwrap();
        let err = load(&repo, &root, &ds).await.unwrap_err();
        assert!(err.to_string().to_lowercase().contains("expired"), "{err}");
    }

    #[tokio::test]
    async fn rejects_tampered_target_and_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let keys = TestKeys::generate();
        let root = keys.root_json().await;
        let root_path = dir.path().join("root.json");
        std::fs::write(&root_path, &root).unwrap();
        let repo = publish_simple(
            dir.path(),
            &keys,
            &root_path,
            1,
            b"{\"v\":1}",
            Utc::now() + Duration::hours(24),
        )
        .await;
        // Cible falsifiée : le contenu ne correspond plus à l'empreinte signée.
        let target = repo.join("targets/index.json");
        std::fs::remove_file(&target).unwrap();
        std::fs::write(&target, b"{\"v\":2}").unwrap();
        let ds = dir.path().join("ds");
        std::fs::create_dir(&ds).unwrap();
        let r = load(&repo, &root, &ds).await.unwrap();
        use futures::StreamExt;
        let mut s = r.read_target(&TargetName::new("index.json").unwrap()).await.unwrap().unwrap();
        let mut failed = false;
        while let Some(c) = s.next().await {
            if c.is_err() {
                failed = true;
                break;
            }
        }
        assert!(failed, "une cible falsifiée doit être rejetée");
        // Métadonnées falsifiées : la signature de targets.json ne correspond plus.
        let tj = repo.join("metadata/targets.json");
        let text = std::fs::read_to_string(&tj).unwrap();
        std::fs::write(
            &tj,
            text.replacen("\"version\": 1", "\"version\": 1 ", 1)
                .replace("\"length\": 7", "\"length\": 8"),
        )
        .unwrap();
        let ds2 = dir.path().join("ds2");
        std::fs::create_dir(&ds2).unwrap();
        assert!(load(&repo, &root, &ds2).await.is_err());
    }

    #[tokio::test]
    async fn rejects_rollback_to_older_repository() {
        let dir = tempfile::tempdir().unwrap();
        let keys = TestKeys::generate();
        let root = keys.root_json().await;
        let root_path = dir.path().join("root.json");
        std::fs::write(&root_path, &root).unwrap();
        let old = publish_simple(dir.path(), &keys, &root_path, 1, b"old", Utc::now() + Duration::hours(24)).await;
        let new = publish_simple(dir.path(), &keys, &root_path, 2, b"new", Utc::now() + Duration::hours(24)).await;
        let ds = dir.path().join("ds");
        std::fs::create_dir(&ds).unwrap();
        let r = load(&new, &root, &ds).await.unwrap();
        assert_eq!(read(&r, "index.json").await, b"new");
        // Un attaquant sert l'ancien dépôt (signé, non expiré) : refusé.
        let err = load(&old, &root, &ds).await.unwrap_err();
        assert!(err.to_string().to_lowercase().contains("version"), "{err}");
    }

    #[tokio::test]
    async fn rejects_untrusted_signer() {
        let dir = tempfile::tempdir().unwrap();
        let keys = TestKeys::generate();
        let attacker = TestKeys::generate();
        let root = keys.root_json().await;
        let attacker_root = attacker.root_json().await;
        let root_path = dir.path().join("root.json");
        std::fs::write(&root_path, &attacker_root).unwrap();
        // Dépôt signé par des clés non désignées par la racine de confiance du client.
        let repo = publish_simple(
            dir.path(),
            &attacker,
            &root_path,
            1,
            b"evil",
            Utc::now() + Duration::hours(24),
        )
        .await;
        std::fs::copy(dir.path().join("root.json"), repo.join("metadata/1.root.json")).unwrap();
        let ds = dir.path().join("ds");
        std::fs::create_dir(&ds).unwrap();
        assert!(load(&repo, &root, &ds).await.is_err());
    }
}
