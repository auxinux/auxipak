//! Configuration du serveur (variables d'environnement).
//!
//! En production (`AUXIPAK_ENV=production`), le démarrage échoue si la
//! configuration de sécurité est incomplète : URL publique HTTPS, cookies
//! sécurisés, clés de signature présentes hors du répertoire de données.

use anyhow::{bail, Context, Result};
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Production,
    Development,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub mode: Mode,
    pub database_url: String,
    pub bind: SocketAddr,
    /// URL publique (`https://pak.auxinux.ca`).
    pub public_url: url::Url,
    /// Données : soumissions, paquets publiés, dépôts générés.
    pub data_dir: PathBuf,
    /// Clés : `root.json`, `package-keys.json` (publics), `targets.pem`,
    /// `snapshot.pem`, `timestamp.pem`, `package-signing.pem` (secrets).
    pub keys_dir: PathBuf,
    pub cookie_secure: bool,
    /// L'approbateur d'une demande doit être différent du soumissionnaire.
    pub require_distinct_approver: bool,
    pub max_upload_bytes: u64,
    /// Développement : génère des clés de test si absentes.
    pub dev_auto_keys: bool,
    /// Durée de validité de timestamp.json (heures).
    pub timestamp_hours: i64,
    /// Adresses IP de mandataires inverses de confiance (en-tête X-Forwarded-For).
    pub trusted_proxies: Vec<String>,
}

fn var(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.trim().is_empty())
}

fn flag(name: &str, default: bool) -> Result<bool> {
    match var(name).as_deref() {
        None => Ok(default),
        Some("1" | "true" | "yes" | "on") => Ok(true),
        Some("0" | "false" | "no" | "off") => Ok(false),
        Some(v) => bail!("{name} : valeur booléenne invalide « {v} »"),
    }
}

impl Config {
    pub fn from_env() -> Result<Config> {
        let mode = match var("AUXIPAK_ENV").as_deref() {
            Some("production") | None => Mode::Production,
            Some("development") => Mode::Development,
            Some(o) => bail!("AUXIPAK_ENV invalide : {o} (production | development)"),
        };
        let dev = mode == Mode::Development;
        let database_url = var("AUXIPAK_DATABASE_URL").context("AUXIPAK_DATABASE_URL est obligatoire")?;
        let bind = var("AUXIPAK_BIND")
            .unwrap_or_else(|| "127.0.0.1:8080".into())
            .parse()
            .context("AUXIPAK_BIND invalide")?;
        let public_url = url::Url::parse(&var("AUXIPAK_PUBLIC_URL").unwrap_or_else(|| {
            if dev {
                "http://127.0.0.1:8080".into()
            } else {
                String::new()
            }
        }))
        .context("AUXIPAK_PUBLIC_URL est obligatoire en production (ex. https://pak.auxinux.ca)")?;
        let data_dir = PathBuf::from(var("AUXIPAK_DATA_DIR").unwrap_or_else(|| "/var/lib/auxipak-server".into()));
        let keys_dir = PathBuf::from(var("AUXIPAK_KEYS_DIR").unwrap_or_else(|| "/etc/auxipak-server/keys".into()));
        let cfg = Config {
            mode,
            database_url,
            bind,
            cookie_secure: flag("AUXIPAK_COOKIE_SECURE", !dev)?,
            require_distinct_approver: flag("AUXIPAK_REQUIRE_DISTINCT_APPROVER", true)?,
            max_upload_bytes: var("AUXIPAK_MAX_UPLOAD_BYTES")
                .map(|v| v.parse())
                .transpose()?
                .unwrap_or(8 * 1024 * 1024 * 1024),
            dev_auto_keys: flag("AUXIPAK_DEV_AUTO_KEYS", false)?,
            timestamp_hours: var("AUXIPAK_TIMESTAMP_HOURS").map(|v| v.parse()).transpose()?.unwrap_or(24),
            trusted_proxies: var("AUXIPAK_TRUSTED_PROXIES")
                .map(|v| v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect())
                .unwrap_or_else(|| vec!["127.0.0.1".into(), "::1".into()]),
            public_url,
            data_dir,
            keys_dir,
        };
        cfg.check()?;
        Ok(cfg)
    }

    /// Contrôles de cohérence ; stricts en production.
    pub fn check(&self) -> Result<()> {
        if self.timestamp_hours < 1 || self.timestamp_hours > 24 * 7 {
            bail!("AUXIPAK_TIMESTAMP_HOURS doit être compris entre 1 et 168");
        }
        if self.mode == Mode::Production {
            if self.public_url.scheme() != "https" {
                bail!("production : AUXIPAK_PUBLIC_URL doit utiliser HTTPS");
            }
            if !self.cookie_secure {
                bail!("production : AUXIPAK_COOKIE_SECURE ne peut pas être désactivé");
            }
            if self.dev_auto_keys {
                bail!("production : AUXIPAK_DEV_AUTO_KEYS est interdit (initialisez les clés selon docs/SIGNING.md)");
            }
            let data = self.data_dir.canonicalize().unwrap_or(self.data_dir.clone());
            let keys = self.keys_dir.canonicalize().unwrap_or(self.keys_dir.clone());
            if keys.starts_with(&data) {
                bail!("production : AUXIPAK_KEYS_DIR ne doit pas se trouver dans AUXIPAK_DATA_DIR");
            }
        }
        Ok(())
    }

    pub fn key_path(&self, name: &str) -> PathBuf {
        self.keys_dir.join(name)
    }

    pub fn submissions_dir(&self) -> PathBuf {
        self.data_dir.join("submissions")
    }
    pub fn packages_dir(&self) -> PathBuf {
        self.data_dir.join("packages")
    }
    pub fn repos_dir(&self) -> PathBuf {
        self.data_dir.join("repos")
    }
    pub fn builder_dir(&self) -> PathBuf {
        self.data_dir.join("builder")
    }
    pub fn tmp_dir(&self) -> PathBuf {
        self.data_dir.join("tmp")
    }

    /// Configuration pour les tests d'intégration.
    pub fn for_tests(database_url: &str, data_dir: PathBuf, keys_dir: PathBuf) -> Config {
        Config {
            mode: Mode::Development,
            database_url: database_url.into(),
            bind: "127.0.0.1:0".parse().unwrap(),
            public_url: url::Url::parse("http://127.0.0.1").unwrap(),
            data_dir,
            keys_dir,
            cookie_secure: false,
            require_distinct_approver: true,
            max_upload_bytes: 256 * 1024 * 1024,
            dev_auto_keys: true,
            timestamp_hours: 24,
            trusted_proxies: vec![],
        }
    }
}
