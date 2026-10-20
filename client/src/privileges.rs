//! Détection des privilèges du processus courant.
//!
//! AuxiPak ne s'élève jamais lui-même : si une installation exige des droits
//! d'administration, l'utilisateur doit relancer la commande avec `sudo`
//! (Linux/macOS) ou depuis un terminal administrateur (Windows). Cela garde
//! l'élévation visible et explicite.

/// Le processus dispose-t-il des droits d'administration ?
pub fn is_elevated() -> bool {
    if let Ok(v) = std::env::var("AUXIPAK_ASSUME_ELEVATED") {
        // Réservé aux tests automatisés ; n'accorde aucun droit réel.
        return v == "1";
    }
    imp()
}

#[cfg(unix)]
fn imp() -> bool {
    // SAFETY: geteuid n'a pas de précondition.
    unsafe { libc::geteuid() == 0 }
}

#[cfg(windows)]
fn imp() -> bool {
    // SAFETY: IsUserAnAdmin n'a pas de précondition.
    unsafe { windows_sys::Win32::UI::Shell::IsUserAnAdmin() != 0 }
}

#[cfg(not(any(unix, windows)))]
fn imp() -> bool {
    false
}

/// Message expliquant comment obtenir les privilèges requis.
pub fn elevation_hint() -> String {
    if cfg!(windows) {
        auxipak_core::tr!(
            "relancez la commande depuis un terminal « Exécuter en tant qu'administrateur »",
            "run the command again from a terminal opened with \"Run as administrator\""
        )
    } else {
        auxipak_core::tr!("relancez la commande avec sudo", "run the command again with sudo")
    }
}
