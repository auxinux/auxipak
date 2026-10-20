//! Détection du système et mémorisation du profil.

use crate::paths::{atomic_write, Paths};
use anyhow::{Context, Result};
use auxipak_core::platform::{self, Arch, Distribution, Os, SystemProfile};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredProfile {
    pub profile: SystemProfile,
    pub detected_at: DateTime<Utc>,
}

/// Détecte le système courant.
pub fn detect() -> Result<SystemProfile> {
    if let Ok(over) = std::env::var("AUXIPAK_PROFILE_OVERRIDE") {
        // Tests et diagnostic : profil fourni en JSON.
        return serde_json::from_str(&over).context(auxipak_core::tr!(
            "AUXIPAK_PROFILE_OVERRIDE invalide",
            "invalid AUXIPAK_PROFILE_OVERRIDE"
        ));
    }
    let arch = detect_arch().context(auxipak_core::tr!(
        "architecture non prise en charge",
        "unsupported architecture"
    ))?;
    match Os::current() {
        Some(Os::Linux) => detect_linux(Path::new("/"), arch),
        Some(Os::Windows) => Ok(detect_windows(arch)),
        Some(Os::Macos) => Ok(detect_macos(arch)),
        None => anyhow::bail!(auxipak_core::tr!(
            "système d'exploitation non pris en charge : {}",
            "unsupported operating system: {}",
            std::env::consts::OS
        )),
    }
}

fn detect_arch() -> Option<Arch> {
    #[cfg(windows)]
    {
        // Sous émulation x64 sur ARM64, PROCESSOR_ARCHITEW6432 révèle l'architecture native.
        for var in ["PROCESSOR_ARCHITEW6432", "PROCESSOR_ARCHITECTURE"] {
            if let Ok(v) = std::env::var(var) {
                match v.to_ascii_uppercase().as_str() {
                    "ARM64" => return Some(Arch::Arm64),
                    "AMD64" => return Some(Arch::X86_64),
                    _ => {}
                }
            }
        }
    }
    #[cfg(target_os = "macos")]
    {
        // Rosetta 2 : un binaire x86_64 sur Apple Silicon.
        if let Ok(out) = std::process::Command::new("/usr/sbin/sysctl")
            .args(["-in", "sysctl.proc_translated"])
            .output()
        {
            if String::from_utf8_lossy(&out.stdout).trim() == "1" {
                return Some(Arch::Arm64);
            }
        }
    }
    Arch::current()
}

/// Détection Linux à partir d'une racine (testable sur une arborescence factice).
pub fn detect_linux(root: &Path, arch: Arch) -> Result<SystemProfile> {
    let osr = ["etc/os-release", "usr/lib/os-release"]
        .iter()
        .map(|p| root.join(p))
        .find(|p| p.exists())
        .context(auxipak_core::tr!("os-release introuvable", "os-release not found"))?;
    let content = std::fs::read_to_string(&osr)?;
    let parsed = platform::parse_os_release(&content);
    // Indices d'un système immuable : marqueur AuxiNuxOS, OSTree, racine en lecture seule.
    let immutable = root.join("run/ostree-booted").exists() || root.join("etc/auxinuxos-immutable").exists();
    Ok(platform::linux_profile_from_os_release(&parsed, arch, immutable))
}

fn detect_windows(arch: Arch) -> SystemProfile {
    let info = os_info::get();
    SystemProfile {
        os: Os::Windows,
        distribution: Distribution::Windows,
        version: info.version().to_string(),
        arch,
        raw_id: "windows".into(),
        pretty_name: format!("{} {}", info.os_type(), info.edition().unwrap_or(""))
            .trim()
            .to_string(),
        immutable: false,
    }
}

fn detect_macos(arch: Arch) -> SystemProfile {
    let info = os_info::get();
    SystemProfile {
        os: Os::Macos,
        distribution: Distribution::Macos,
        version: info.version().to_string(),
        arch,
        raw_id: "macos".into(),
        pretty_name: format!("macOS {}", info.version()),
        immutable: false,
    }
}

/// Résultat du chargement du profil.
pub struct ProfileStatus {
    pub profile: SystemProfile,
    /// Le système a changé de manière significative depuis la dernière exécution.
    pub changed: bool,
    pub first_run: bool,
}

/// Détecte le système, compare au profil mémorisé et l'enregistre.
pub fn load_or_detect(paths: &Paths) -> Result<ProfileStatus> {
    let current = detect()?;
    let file = paths.profile_file();
    let stored: Option<StoredProfile> = std::fs::read(&file).ok().and_then(|b| serde_json::from_slice(&b).ok());
    let (changed, first_run) = match &stored {
        None => (false, true),
        Some(s) => (s.profile.fingerprint() != current.fingerprint(), false),
    };
    if stored.as_ref().map(|s| s.profile != current).unwrap_or(true) {
        let sp = StoredProfile {
            profile: current.clone(),
            detected_at: Utc::now(),
        };
        atomic_write(&file, &serde_json::to_vec_pretty(&sp)?)?;
    }
    Ok(ProfileStatus {
        profile: current,
        changed,
        first_run,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_from_fake_root() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("etc")).unwrap();
        std::fs::write(
            d.path().join("etc/os-release"),
            "ID=auxinuxos\nVERSION_ID=1.0\nID_LIKE=debian\n",
        )
        .unwrap();
        let p = detect_linux(d.path(), Arch::X86_64).unwrap();
        assert_eq!(p.distribution, Distribution::Auxinuxos);
        assert!(p.immutable);
        std::fs::remove_file(d.path().join("etc/os-release")).unwrap();
        std::fs::create_dir_all(d.path().join("usr/lib")).unwrap();
        std::fs::write(d.path().join("usr/lib/os-release"), "ID=debian\nVERSION_ID=13\n").unwrap();
        let p = detect_linux(d.path(), Arch::Arm64).unwrap();
        assert_eq!(p.distribution, Distribution::Debian);
        assert!(!p.immutable);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn detects_real_host() {
        // Validation réelle sur l'hôte d'exécution des tests.
        let p = detect_linux(Path::new("/"), Arch::current().unwrap()).unwrap();
        assert_eq!(p.os, Os::Linux);
        assert!(!p.version.is_empty());
    }
}
