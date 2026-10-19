//! Jeu de clés d'un dépôt AuxiPak : racine TUF, clés en ligne et clé de
//! signature des paquets.
//!
//! Disposition produite :
//! ```text
//! public/root.json            racine de confiance TUF (publique)
//! public/package-keys.json    clés publiques de signature des paquets
//! online/targets.pem          secrets du serveur
//! online/snapshot.pem
//! online/timestamp.pem
//! online/package-signing.pem
//! offline/root.pem            clé racine : à conserver hors ligne
//! ```

use crate::signature::{KeyPurpose, PackageSigner, TrustedKeys};
use crate::tuf;
use anyhow::{bail, Result};
use std::path::Path;

pub struct KeysetSummary {
    pub root_sha256: String,
    pub package_key_id: String,
}

/// Écrit un fichier secret (0600), sans jamais écraser un fichier existant.
pub fn write_secret(path: &Path, data: &str) -> Result<()> {
    if path.exists() {
        bail!("{} existe déjà : refus d'écraser une clé", path.display());
    }
    if let Some(p) = path.parent() {
        std::fs::create_dir_all(p)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700))?;
        }
    }
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    use std::io::Write;
    o.open(path)?.write_all(data.as_bytes())?;
    Ok(())
}

/// Génère un jeu de clés complet dans `out` (répertoire vide ou inexistant).
pub async fn generate(out: &Path, owner: &str, root_days: i64) -> Result<KeysetSummary> {
    if out.exists() && std::fs::read_dir(out)?.next().is_some() {
        bail!("{} n'est pas vide", out.display());
    }
    let root_pem = tuf::generate_key_pem();
    let targets = tuf::generate_key_pem();
    let snapshot = tuf::generate_key_pem();
    let timestamp = tuf::generate_key_pem();
    let root_json = tuf::create_root(tuf::RootSpec {
        root_keys: vec![root_pem.clone()],
        root_threshold: 1,
        targets_keys: vec![tuf::public_tuf_key(&targets)?.1],
        snapshot_keys: vec![tuf::public_tuf_key(&snapshot)?.1],
        timestamp_keys: vec![tuf::public_tuf_key(&timestamp)?.1],
        version: 1,
        expires: chrono::Utc::now() + chrono::Duration::days(root_days),
    })
    .await?;
    let pkg = PackageSigner::generate();
    std::fs::create_dir_all(out.join("public"))?;
    std::fs::write(out.join("public/root.json"), &root_json)?;
    let trust = TrustedKeys::new(vec![pkg.public_info(owner, KeyPurpose::PackageSigning)]);
    std::fs::write(out.join("public/package-keys.json"), serde_json::to_string_pretty(&trust)?)?;
    write_secret(&out.join("online/targets.pem"), &targets)?;
    write_secret(&out.join("online/snapshot.pem"), &snapshot)?;
    write_secret(&out.join("online/timestamp.pem"), &timestamp)?;
    write_secret(&out.join("online/package-signing.pem"), &pkg.to_pem())?;
    write_secret(&out.join("offline/root.pem"), &root_pem)?;
    Ok(KeysetSummary { root_sha256: crate::hash::sha256_hex(&root_json), package_key_id: pkg.key_id().to_string() })
}
