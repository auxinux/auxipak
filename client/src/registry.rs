//! Registre local des installations et journal de transactions.
//!
//! - `registry.json` est réécrit atomiquement (fichier temporaire + `fsync` +
//!   renommage) ; la version précédente est conservée dans `registry.json.bak`
//!   et utilisée si le fichier principal est illisible.
//! - Chaque opération modifiant le système ouvre une transaction
//!   (`transactions/<uuid>.json`) mise à jour à chaque étape et supprimée à la
//!   fin. Une transaction restante signale une interruption : `auxipak repair`
//!   la reprend ou nettoie ce qui a été partiellement installé.
//! - Un verrou exclusif empêche deux instances de modifier l'état en même temps.

use crate::paths::{atomic_write, Paths};
use anyhow::{bail, Context, Result};
use auxipak_core::tr;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::File;
use std::path::{Path, PathBuf};

pub const REGISTRY_FORMAT: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallState {
    /// Installée et vérifiée par AuxiPak.
    Installed,
    /// Déjà présente via le gestionnaire natif, prise en charge explicitement (`--adopt`).
    Adopted,
    /// Installation incomplète (interruption, échec partiel).
    Partial,
    /// Récupérée par `auxipak repair` après interruption.
    Recovered,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub at: DateTime<Utc>,
    pub action: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
    pub result: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstalledApp {
    pub id: String,
    pub name: String,
    pub version: String,
    pub repo: String,
    /// URL du paquet téléchargé.
    pub source: String,
    pub package_sha256: String,
    pub file_name: String,
    pub target: String,
    pub mode: String,
    pub method: String,
    /// Gestionnaire utilisé (`apt`, `auxi`, `msiexec`, `files`…).
    pub manager: String,
    pub languages: Vec<String>,
    pub installed_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub state: InstallState,
    /// Installée automatiquement en tant que dépendance.
    #[serde(default)]
    pub auto_installed: bool,
    /// Dépendances AuxiPak de cette application.
    #[serde(default)]
    pub dependencies: Vec<String>,
    /// Fichiers installés lorsqu'ils sont connus (méthode `files`).
    #[serde(default)]
    pub files: Vec<PathBuf>,
    /// Redémarrage demandé par l'installateur.
    #[serde(default)]
    pub reboot_required: bool,
    /// Installation réalisée avec des outils simulés (tests uniquement).
    #[serde(default)]
    pub simulated: bool,
    #[serde(default)]
    pub history: Vec<HistoryEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Registry {
    pub format: u32,
    pub apps: BTreeMap<String, InstalledApp>,
}

impl Default for Registry {
    fn default() -> Self {
        Registry {
            format: REGISTRY_FORMAT,
            apps: BTreeMap::new(),
        }
    }
}

impl Registry {
    pub fn load(paths: &Paths) -> Result<Registry> {
        let main = paths.registry_file();
        let bak = backup_path(&main);
        match read_registry(&main) {
            Ok(Some(r)) => Ok(r),
            Ok(None) => match read_registry(&bak) {
                Ok(Some(r)) => Ok(r),
                _ => Ok(Registry::default()),
            },
            Err(e) => {
                tracing::error!(error = %e, "{}", tr!("registre illisible, utilisation de la sauvegarde", "unreadable registry, using the backup"));
                match read_registry(&bak)? {
                    Some(r) => {
                        eprintln!(
                            "{}",
                            tr!(
                                "avertissement : registre principal corrompu, restauration depuis la sauvegarde",
                                "warning: main registry corrupted, restoring from the backup"
                            )
                        );
                        Ok(r)
                    }
                    None => bail!(tr!(
                        "registre corrompu et aucune sauvegarde : {e:#}",
                        "corrupted registry and no backup: {e:#}"
                    )),
                }
            }
        }
    }

    pub fn save(&self, paths: &Paths) -> Result<()> {
        let main = paths.registry_file();
        if main.exists() {
            // La sauvegarde n'est mise à jour que si le registre actuel est lisible.
            if read_registry(&main).map(|r| r.is_some()).unwrap_or(false) {
                std::fs::copy(&main, backup_path(&main))?;
            }
        }
        atomic_write(&main, &serde_json::to_vec_pretty(self)?)?;
        Ok(())
    }

    pub fn get(&self, id: &str) -> Option<&InstalledApp> {
        self.apps.get(id)
    }

    /// Applications installées qui dépendent de `id`.
    pub fn dependents(&self, id: &str) -> Vec<&InstalledApp> {
        self.apps
            .values()
            .filter(|a| a.id != id && a.dependencies.iter().any(|d| d == id))
            .collect()
    }

    /// Dépendances installées automatiquement et plus requises par personne.
    pub fn orphans(&self) -> Vec<&InstalledApp> {
        self.apps
            .values()
            .filter(|a| a.auto_installed && self.dependents(&a.id).is_empty())
            .collect()
    }
}

fn backup_path(main: &Path) -> PathBuf {
    main.with_extension("json.bak")
}

fn read_registry(p: &Path) -> Result<Option<Registry>> {
    match std::fs::read(p) {
        Ok(b) => {
            let r: Registry = serde_json::from_slice(&b).with_context(|| tr!("{} invalide", "invalid {}", p.display()))?;
            if r.format != REGISTRY_FORMAT {
                bail!(tr!(
                    "format de registre non pris en charge : {}",
                    "unsupported registry format: {}",
                    r.format
                ));
            }
            Ok(Some(r))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Verrou exclusif sur l'état local.
pub struct StateLock {
    _file: File,
}

impl StateLock {
    pub fn acquire(paths: &Paths) -> Result<StateLock> {
        let f = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(paths.lock_file())?;
        match f.try_lock() {
            Ok(()) => Ok(StateLock { _file: f }),
            Err(std::fs::TryLockError::WouldBlock) => {
                bail!(tr!(
                    "une autre instance d'auxipak est en cours d'exécution (verrou {})",
                    "another auxipak instance is running (lock {})",
                    paths.lock_file().display()
                ))
            }
            Err(std::fs::TryLockError::Error(e)) => Err(e.into()),
        }
    }
}

/// Étape d'une transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Started,
    Downloaded,
    Verified,
    Extracted,
    /// L'installateur natif a été lancé : le système peut avoir été modifié.
    Installing,
    Installed,
    Registered,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    pub id: String,
    /// `install`, `upgrade`, `remove`.
    pub action: String,
    pub app_id: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_version: Option<String>,
    pub phase: Phase,
    pub started_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// Répertoire de travail temporaire à nettoyer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub work_dir: Option<PathBuf>,
    /// Fichiers déjà copiés (méthode `files`) : permet un retour arrière précis.
    #[serde(default)]
    pub files_written: Vec<PathBuf>,
    /// Données nécessaires à l'enregistrement final (application prête à être inscrite).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_record: Option<InstalledApp>,
    #[serde(skip)]
    path: PathBuf,
}

impl Transaction {
    pub fn begin(paths: &Paths, action: &str, app_id: &str, version: &str, previous: Option<String>) -> Result<Transaction> {
        let id = uuid::Uuid::new_v4().to_string();
        let t = Transaction {
            path: paths.transactions_dir().join(format!("{id}.json")),
            id,
            action: action.into(),
            app_id: app_id.into(),
            version: version.into(),
            previous_version: previous,
            phase: Phase::Started,
            started_at: Utc::now(),
            updated_at: Utc::now(),
            work_dir: None,
            files_written: Vec::new(),
            pending_record: None,
        };
        t.persist()?;
        Ok(t)
    }

    pub fn set_phase(&mut self, phase: Phase) -> Result<()> {
        self.phase = phase;
        self.updated_at = Utc::now();
        self.persist()
    }

    pub fn persist(&self) -> Result<()> {
        atomic_write(&self.path, &serde_json::to_vec_pretty(self)?)?;
        Ok(())
    }

    pub fn record_file(&mut self, p: PathBuf) -> Result<()> {
        self.files_written.push(p);
        self.persist()
    }

    /// Clôture : supprime le journal et le répertoire de travail.
    pub fn finish(self) -> Result<()> {
        if let Some(w) = &self.work_dir {
            let _ = std::fs::remove_dir_all(w);
        }
        match std::fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    pub fn pending(paths: &Paths) -> Result<Vec<Transaction>> {
        let mut v = Vec::new();
        let dir = paths.transactions_dir();
        if !dir.exists() {
            return Ok(v);
        }
        for e in std::fs::read_dir(dir)? {
            let p = e?.path();
            if p.extension().and_then(|x| x.to_str()) != Some("json") {
                continue;
            }
            match std::fs::read(&p)
                .ok()
                .and_then(|b| serde_json::from_slice::<Transaction>(&b).ok())
            {
                Some(mut t) => {
                    t.path = p;
                    v.push(t);
                }
                None => {
                    // Journal illisible (écriture interrompue avant le renommage atomique : impossible
                    // en principe) : on le met de côté pour analyse.
                    let _ = std::fs::rename(&p, p.with_extension("corrupt"));
                }
            }
        }
        v.sort_by_key(|t| t.started_at);
        Ok(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app(id: &str, deps: &[&str], auto: bool) -> InstalledApp {
        InstalledApp {
            id: id.into(),
            name: id.into(),
            version: "1.0".into(),
            repo: "official".into(),
            source: "x".into(),
            package_sha256: "0".repeat(64),
            file_name: "x.aupak".into(),
            target: "t".into(),
            mode: "embedded".into(),
            method: "files".into(),
            manager: "files".into(),
            languages: vec!["fr".into()],
            installed_at: Utc::now(),
            updated_at: Utc::now(),
            state: InstallState::Installed,
            auto_installed: auto,
            dependencies: deps.iter().map(|s| s.to_string()).collect(),
            files: vec![],
            reboot_required: false,
            simulated: false,
            history: vec![],
        }
    }

    #[test]
    fn save_load_and_recover_from_corruption() {
        let d = tempfile::tempdir().unwrap();
        let p = Paths::under(d.path(), false);
        p.ensure().unwrap();
        let mut r = Registry::default();
        r.apps.insert("a".into(), app("a", &[], false));
        r.save(&p).unwrap();
        r.apps.insert("b".into(), app("b", &[], false));
        r.save(&p).unwrap();
        assert_eq!(Registry::load(&p).unwrap().apps.len(), 2);
        // Écriture incomplète simulée du fichier principal.
        std::fs::write(p.registry_file(), b"{\"format\":1,\"apps\":{\"a\":").unwrap();
        let rec = Registry::load(&p).unwrap();
        assert_eq!(rec.apps.len(), 1, "restauration de la dernière version cohérente");
    }

    #[test]
    fn dependency_tracking() {
        let mut r = Registry::default();
        r.apps.insert("lib".into(), app("lib", &[], true));
        r.apps.insert("app1".into(), app("app1", &["lib"], false));
        r.apps.insert("app2".into(), app("app2", &["lib"], false));
        assert_eq!(r.dependents("lib").len(), 2);
        assert!(r.orphans().is_empty());
        r.apps.remove("app1");
        r.apps.remove("app2");
        assert_eq!(r.orphans().len(), 1);
    }

    #[test]
    fn transactions_survive_and_are_listed() {
        let d = tempfile::tempdir().unwrap();
        let p = Paths::under(d.path(), false);
        p.ensure().unwrap();
        let mut t = Transaction::begin(&p, "install", "a", "1.0", None).unwrap();
        t.set_phase(Phase::Installing).unwrap();
        let pending = Transaction::pending(&p).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].phase, Phase::Installing);
        pending.into_iter().next().unwrap().finish().unwrap();
        assert!(Transaction::pending(&p).unwrap().is_empty());
    }

    #[test]
    fn lock_is_exclusive() {
        let d = tempfile::tempdir().unwrap();
        let p = Paths::under(d.path(), false);
        p.ensure().unwrap();
        let l = StateLock::acquire(&p).unwrap();
        assert!(StateLock::acquire(&p).is_err());
        drop(l);
        assert!(StateLock::acquire(&p).is_ok());
    }
}
