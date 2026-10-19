//! Emplacements des fichiers du client.
//!
//! Trois portées :
//! - `AUXIPAK_HOME` défini : tout est placé sous ce répertoire (tests,
//!   installations portables) ;
//! - système (root/administrateur) : `/etc/auxipak`, `/var/lib/auxipak`,
//!   `/var/cache/auxipak`, `/var/log/auxipak` (Linux/macOS) ou
//!   `%ProgramData%\AuxiPak` (Windows) ;
//! - utilisateur : répertoires XDG / `%LOCALAPPDATA%\AuxiPak`.

use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    System,
    User,
}

#[derive(Debug, Clone)]
pub struct Paths {
    pub scope: Scope,
    /// Configuration (`config.toml`, ancres de confiance).
    pub config_dir: PathBuf,
    /// État persistant (registre, transactions, profil).
    pub state_dir: PathBuf,
    /// Cache (index vérifiés, paquets téléchargés).
    pub cache_dir: PathBuf,
    pub log_dir: PathBuf,
    /// Racine `{app}` : une sous-arborescence par application.
    pub apps_dir: PathBuf,
    /// Racine `{bin}`.
    pub bin_dir: PathBuf,
    /// Racine `{data}`.
    pub data_dir: PathBuf,
    /// Configuration système en lecture seule consultée en plus (ancres de
    /// confiance installées avec le client).
    pub system_config_dir: Option<PathBuf>,
}

impl Paths {
    pub fn detect() -> Paths {
        if let Some(home) = std::env::var_os("AUXIPAK_HOME").filter(|h| !h.is_empty()) {
            return Paths::under(Path::new(&home), crate::privileges::is_elevated());
        }
        if crate::privileges::is_elevated() {
            Paths::system()
        } else {
            Paths::user()
        }
    }

    /// Toutes les données sous une racine unique.
    pub fn under(root: &Path, elevated: bool) -> Paths {
        Paths {
            scope: if elevated { Scope::System } else { Scope::User },
            config_dir: root.join("config"),
            state_dir: root.join("state"),
            cache_dir: root.join("cache"),
            log_dir: root.join("log"),
            apps_dir: root.join("apps"),
            bin_dir: root.join("bin"),
            data_dir: root.join("data"),
            system_config_dir: None,
        }
    }

    #[cfg(not(windows))]
    fn system() -> Paths {
        Paths {
            scope: Scope::System,
            config_dir: "/etc/auxipak".into(),
            state_dir: "/var/lib/auxipak".into(),
            cache_dir: "/var/cache/auxipak".into(),
            log_dir: "/var/log/auxipak".into(),
            apps_dir: "/opt/auxipak/apps".into(),
            bin_dir: "/usr/local/bin".into(),
            data_dir: "/var/lib/auxipak/data".into(),
            system_config_dir: None,
        }
    }

    #[cfg(windows)]
    fn system() -> Paths {
        let pd = std::env::var_os("ProgramData")
            .map(PathBuf::from)
            .unwrap_or_else(|| "C:\\ProgramData".into());
        let pf = std::env::var_os("ProgramFiles")
            .map(PathBuf::from)
            .unwrap_or_else(|| "C:\\Program Files".into());
        let root = pd.join("AuxiPak");
        Paths {
            scope: Scope::System,
            config_dir: root.join("config"),
            state_dir: root.join("state"),
            cache_dir: root.join("cache"),
            log_dir: root.join("log"),
            apps_dir: pf.join("AuxiPak").join("apps"),
            bin_dir: pf.join("AuxiPak").join("bin"),
            data_dir: root.join("data"),
            system_config_dir: None,
        }
    }

    fn user() -> Paths {
        #[cfg(windows)]
        {
            let la = std::env::var_os("LOCALAPPDATA")
                .map(PathBuf::from)
                .unwrap_or_else(|| ".".into());
            let mut p = Paths::under(&la.join("AuxiPak"), false);
            p.system_config_dir = std::env::var_os("ProgramData").map(|d| PathBuf::from(d).join("AuxiPak").join("config"));
            p
        }
        #[cfg(not(windows))]
        {
            let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| ".".into());
            let xdg = |var: &str, default: &str| {
                std::env::var_os(var)
                    .filter(|v| !v.is_empty())
                    .map(PathBuf::from)
                    .unwrap_or_else(|| home.join(default))
            };
            let data = xdg("XDG_DATA_HOME", ".local/share").join("auxipak");
            let state = xdg("XDG_STATE_HOME", ".local/state").join("auxipak");
            Paths {
                scope: Scope::User,
                config_dir: xdg("XDG_CONFIG_HOME", ".config").join("auxipak"),
                state_dir: state.clone(),
                cache_dir: xdg("XDG_CACHE_HOME", ".cache").join("auxipak"),
                log_dir: state.join("log"),
                apps_dir: data.join("apps"),
                bin_dir: home.join(".local/bin"),
                data_dir: data.join("data"),
                system_config_dir: Some("/etc/auxipak".into()),
            }
        }
    }

    pub fn ensure(&self) -> std::io::Result<()> {
        for d in [&self.config_dir, &self.state_dir, &self.cache_dir, &self.log_dir] {
            std::fs::create_dir_all(d)?;
        }
        std::fs::create_dir_all(self.transactions_dir())?;
        restrict_dir(&self.state_dir)?;
        Ok(())
    }

    pub fn config_file(&self) -> PathBuf {
        self.config_dir.join("config.toml")
    }
    pub fn registry_file(&self) -> PathBuf {
        self.state_dir.join("registry.json")
    }
    pub fn profile_file(&self) -> PathBuf {
        self.state_dir.join("profile.json")
    }
    pub fn lock_file(&self) -> PathBuf {
        self.state_dir.join("auxipak.lock")
    }
    pub fn transactions_dir(&self) -> PathBuf {
        self.state_dir.join("transactions")
    }
    /// Copie conservée du manifeste et des scripts d'une application installée.
    pub fn app_state_dir(&self, id: &str) -> PathBuf {
        self.state_dir.join("apps").join(id)
    }
    pub fn repo_cache_dir(&self, repo: &str) -> PathBuf {
        self.cache_dir.join("repos").join(repo)
    }
    pub fn package_cache_dir(&self) -> PathBuf {
        self.cache_dir.join("packages")
    }
    pub fn work_dir(&self) -> PathBuf {
        self.cache_dir.join("work")
    }
    pub fn log_file(&self) -> PathBuf {
        self.log_dir.join("auxipak.log")
    }
}

/// Restreint les droits d'un répertoire au seul propriétaire (Unix).
pub fn restrict_dir(p: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700))?;
    }
    #[cfg(not(unix))]
    let _ = p;
    Ok(())
}

/// Écriture atomique : fichier temporaire dans le même répertoire, `fsync`,
/// puis renommage. Une interruption laisse soit l'ancien, soit le nouveau
/// contenu, jamais un fichier tronqué.
pub fn atomic_write(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let dir = path.parent().unwrap_or(Path::new("."));
    std::fs::create_dir_all(dir)?;
    let mut tmp = tempfile::Builder::new().prefix(".tmp-").tempfile_in(dir)?;
    tmp.write_all(data)?;
    tmp.as_file().sync_all()?;
    tmp.persist(path).map_err(|e| e.error)?;
    #[cfg(unix)]
    if let Ok(d) = std::fs::File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}
