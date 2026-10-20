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
use auxipak_core::tr;
use auxipak_core::tuf::PemKeySource;
use std::path::PathBuf;
use tough::key_source::KeySource;

pub struct Keys {
    pub root_path: PathBuf,
    pub root_json: Vec<u8>,
    pub package_keys: TrustedKeys,
    pub package_keys_json: Vec<u8>,
    pub signer: Option<PackageSigner>,
    /// Racines antérieures (`root-history/N.root.json`) publiées pour la rotation.
    pub previous_roots: Vec<(String, Vec<u8>)>,
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
                bail!(tr!(
                    "clés absentes de {} : initialisez-les (docs/SIGNING.md) ou, en développement uniquement, \
                     définissez AUXIPAK_DEV_AUTO_KEYS=1",
                    "no keys in {}: initialize them (docs/SIGNING.md) or, in development only, \
                     set AUXIPAK_DEV_AUTO_KEYS=1",
                    dir.display()
                ));
            }
        }
        let root_path = dir.join("root.json");
        let root_json = std::fs::read(&root_path)?;
        auxipak_core::tuf::check_root_file(&root_path)?;
        let package_keys_json =
            std::fs::read(dir.join("package-keys.json")).context(tr!("package-keys.json absent", "package-keys.json missing"))?;
        let package_keys: TrustedKeys =
            serde_json::from_slice(&package_keys_json).context(tr!("package-keys.json invalide", "invalid package-keys.json"))?;
        let mut tuf = Vec::new();
        for role in ["targets", "snapshot", "timestamp"] {
            let p = dir.join(format!("{role}.pem"));
            if !p.exists() {
                bail!(tr!(
                    "clé TUF en ligne absente : {}",
                    "online TUF key missing: {}",
                    p.display()
                ));
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
                bail!(tr!(
                    "la clé {} ne correspond pas au rôle {role} de root.json",
                    "key {} does not match the {role} role of root.json",
                    path.display()
                ));
            }
        }
        if dir.join("root.pem").exists() && cfg.mode == Mode::Production {
            bail!(tr!(
                "la clé racine TUF ne doit jamais se trouver sur le serveur ({})",
                "the TUF root key must never be on the server ({})",
                dir.join("root.pem").display()
            ));
        }
        let sp = dir.join("package-signing.pem");
        let signer = if sp.exists() {
            check_secret_permissions(&sp)?;
            let s = PackageSigner::load(&sp)?;
            if package_keys.find(s.key_id()).is_none() {
                bail!(tr!(
                    "la clé package-signing.pem ({}) n'est pas listée dans package-keys.json",
                    "the package-signing.pem key ({}) is not listed in package-keys.json",
                    s.key_id()
                ));
            }
            Some(s)
        } else {
            tracing::warn!(
                "{}",
                tr!(
                    "aucune clé de signature de paquets : seuls les paquets déjà signés pourront être publiés",
                    "no package signing key: only pre-signed packages can be published"
                )
            );
            None
        };
        let mut previous_roots = Vec::new();
        if let Ok(rd) = std::fs::read_dir(dir.join("root-history")) {
            for e in rd.flatten() {
                let name = e.file_name().to_string_lossy().into_owned();
                if name.ends_with(".root.json") {
                    previous_roots.push((name, std::fs::read(e.path())?));
                }
            }
        }
        Ok(Keys {
            root_path,
            root_json,
            package_keys,
            package_keys_json,
            signer,
            previous_roots,
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
            bail!(tr!(
                "{} est lisible par d'autres utilisateurs (droits {:o}) : chmod 600",
                "{} is readable by other users (mode {:o}): chmod 600",
                p.display(),
                mode & 0o777
            ));
        }
    }
    let _ = p;
    Ok(())
}

async fn generate_dev_keys(cfg: &Config) -> Result<()> {
    tracing::warn!(
        "{}",
        tr!(
            "MODE DÉVELOPPEMENT : génération de clés de TEST dans {}",
            "DEVELOPMENT MODE: generating TEST keys in {}",
            cfg.keys_dir.display()
        )
    );
    eprintln!(
        "{}",
        tr!(
            "ATTENTION : clés de développement générées dans {} — ne jamais les utiliser en production",
            "WARNING: development keys generated in {} — never use them in production",
            cfg.keys_dir.display()
        )
    );
    let tmp = tempfile::tempdir()?;
    let set = tmp.path().join("set");
    auxipak_core::keyset::generate(&set, "AuxiNux (development)", 365).await?;
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
