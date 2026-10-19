//! Chargement des clés du serveur.
//!
//! `AUXIPAK_KEYS_DIR` contient (disposition à plat) :
//! - `root.json`, `package-keys.json` : publics ;
//! - `targets.pem`, `snapshot.pem`, `timestamp.pem` : clés TUF en ligne ;
//! - `package-signing.pem` : clé de signature des paquets (facultative : sans
//!   elle, seuls les paquets déjà signés par une clé de confiance peuvent être
//!   publiés).
//!
//! La clé racine TUF n'est jamais présente sur le serveur.

use crate::config::{Config, Mode};
use anyhow::{bail, Context, Result};
use auxipak_core::signature::{PackageSigner, TrustedKeys};
use auxipak_core::tuf::PemKeySource;
use std::path::PathBuf;
use tough::key_source::KeySource;

pub struct Keys {
    pub root_path: PathBuf,
    pub root_json: Vec<u8>,
    pub package_keys: TrustedKeys,
    pub package_keys_json: Vec<u8>,
    pub signer: Option<PackageSigner>,
    tuf: Vec<PathBuf>,
}

impl Keys {
    pub fn tuf_sources(&self) -> Vec<Box<dyn KeySource>> {
        self.tuf
            .iter()
            .map(|p| Box::new(PemKeySource { path: p.clone() }) as Box<dyn KeySource>)
            .collect()
    }

    pub async fn load(cfg: &Config) -> Result<Keys> {
        let dir = &cfg.keys_dir;
        if !dir.join("root.json").exists() {
            if cfg.dev_auto_keys && cfg.mode == Mode::Development {
                generate_dev_keys(cfg).await?;
            } else {
                bail!(
                    "clés absentes de {} : initialisez-les (docs/SIGNING.md) ou, en développement uniquement, \
                     définissez AUXIPAK_DEV_AUTO_KEYS=1",
                    dir.display()
                );
            }
        }
        let root_path = dir.join("root.json");
        let root_json = std::fs::read(&root_path)?;
        auxipak_core::tuf::check_root_file(&root_path)?;
        let package_keys_json = std::fs::read(dir.join("package-keys.json")).context("package-keys.json absent")?;
        let package_keys: TrustedKeys = serde_json::from_slice(&package_keys_json).context("package-keys.json invalide")?;
        let mut tuf = Vec::new();
        for role in ["targets", "snapshot", "timestamp"] {
            let p = dir.join(format!("{role}.pem"));
            if !p.exists() {
                bail!("clé TUF en ligne absente : {}", p.display());
            }
            check_secret_permissions(&p)?;
            tuf.push(p);
        }
        // Les clés TUF doivent correspondre à celles désignées par root.json.
        let summary = auxipak_core::tuf::summarize_root(&root_json)?;
        for (role, path) in ["targets", "snapshot", "timestamp"].iter().zip(&tuf) {
            let (id, _) = auxipak_core::tuf::public_tuf_key(&std::fs::read_to_string(path)?)?;
            let ok = summary.roles.iter().any(|(r, ids, _)| r == role && ids.contains(&id));
            if !ok {
                bail!("la clé {} ne correspond pas au rôle {role} de root.json", path.display());
            }
        }
        if dir.join("root.pem").exists() && cfg.mode == Mode::Production {
            bail!(
                "la clé racine TUF ne doit jamais se trouver sur le serveur ({})",
                dir.join("root.pem").display()
            );
        }
        let sp = dir.join("package-signing.pem");
        let signer = if sp.exists() {
            check_secret_permissions(&sp)?;
            let s = PackageSigner::load(&sp)?;
            if package_keys.find(s.key_id()).is_none() {
                bail!(
                    "la clé package-signing.pem ({}) n'est pas listée dans package-keys.json",
                    s.key_id()
                );
            }
            Some(s)
        } else {
            tracing::warn!("aucune clé de signature de paquets : seuls les paquets déjà signés pourront être publiés");
            None
        };
        Ok(Keys {
            root_path,
            root_json,
            package_keys,
            package_keys_json,
            signer,
            tuf,
        })
    }
}

fn check_secret_permissions(p: &std::path::Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(p)?.permissions().mode();
        if mode & 0o077 != 0 {
            bail!(
                "{} est lisible par d'autres utilisateurs (droits {:o}) : chmod 600",
                p.display(),
                mode & 0o777
            );
        }
    }
    let _ = p;
    Ok(())
}

async fn generate_dev_keys(cfg: &Config) -> Result<()> {
    tracing::warn!(
        "MODE DÉVELOPPEMENT : génération de clés de TEST dans {}",
        cfg.keys_dir.display()
    );
    eprintln!(
        "ATTENTION : clés de développement générées dans {} — ne jamais les utiliser en production",
        cfg.keys_dir.display()
    );
    let tmp = tempfile::tempdir()?;
    let set = tmp.path().join("set");
    auxipak_core::keyset::generate(&set, "AuxiNux (développement)", 365).await?;
    std::fs::create_dir_all(&cfg.keys_dir)?;
    for f in ["root.json", "package-keys.json"] {
        std::fs::copy(set.join("public").join(f), cfg.keys_dir.join(f))?;
    }
    for f in ["targets.pem", "snapshot.pem", "timestamp.pem", "package-signing.pem"] {
        auxipak_core::keyset::write_secret(&cfg.keys_dir.join(f), &std::fs::read_to_string(set.join("online").join(f))?)?;
    }
    auxipak_core::keyset::write_secret(
        &cfg.keys_dir.join("dev-root.pem"),
        &std::fs::read_to_string(set.join("offline/root.pem"))?,
    )?;
    Ok(())
}
