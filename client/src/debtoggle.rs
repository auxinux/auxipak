//! Activation temporaire de l'installation DEB d'AuxiNux OS.
//!
//! Sur AuxiNux OS, `auxi install --deb` refuse tout paquet nouveau tant que
//! le réglage DEB est désactivé (`/etc/auxinux/apps.conf` sans la ligne
//! exacte `DEB_APPS=1`, règle de `deb_apps_enabled` dans le script `auxi`).
//! Décision d'aporler (2026-10-22) : AuxiPak l'active le temps de
//! l'opération (`auxi set deb=true`), puis le remet à désactivé
//! (`auxi set deb=false`), succès ou échec. S'il était déjà actif, rien
//! n'est touché, ni avant ni après.
//!
//! - Une seule activation par lancement d'AuxiPak (tout un lot
//!   `auxipak install a b c`) : [`ensure_enabled`] est idempotent, la remise
//!   à désactivé a lieu à la fin de la commande ([`Session`], par `Drop`).
//! - Ctrl-C / SIGTERM pendant la fenêtre : remise à désactivé, puis sortie.
//! - Témoin persistant `<état>/deb-temporaire` (`/var/lib/auxipak`), écrit
//!   AVANT l'activation et supprimé APRÈS la remise à désactivé : après un
//!   plantage ou une coupure, le lancement suivant ([`recover`]) remet le
//!   réglage à désactivé.
//!
//! Seules l'installation et l'installation d'un `.deb` local par `auxi`
//! l'utilisent ; jamais la désinstallation ni la détection.

use crate::paths::Paths;
use anyhow::{bail, Result};
use auxipak_core::tr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;

/// Réglage DEB d'AuxiNux OS.
const APPS_CONF: &str = "/etc/auxinux/apps.conf";
/// Nom du témoin dans le répertoire d'état.
pub const MARKER: &str = "deb-temporaire";

/// Fenêtre ouverte : programme `auxi` résolu et témoin à supprimer.
struct Window {
    program: PathBuf,
    marker: PathBuf,
}

static WINDOW: Mutex<Option<Window>> = Mutex::new(None);

/// Fichier de réglage lu (remplaçable uniquement en mode simulation, tests).
fn apps_conf() -> PathBuf {
    if crate::executor::is_simulation() {
        if let Some(p) = std::env::var_os("AUXIPAK_TEST_APPS_CONF").filter(|p| !p.is_empty()) {
            return PathBuf::from(p);
        }
    }
    PathBuf::from(APPS_CONF)
}

/// Le réglage DEB est-il actif ? Une ligne exacte `DEB_APPS=1` (comme
/// `grep -Eq '^DEB_APPS=1$'` dans `auxi`) ; fichier absent = désactivé.
pub fn deb_enabled(conf: &Path) -> bool {
    std::fs::read_to_string(conf)
        .map(|s| s.lines().any(|l| l == "DEB_APPS=1"))
        .unwrap_or(false)
}

/// `auxi set deb=<valeur>` ; la sortie (verbeuse) est captée, pas affichée.
fn set_deb(program: &Path, value: bool) -> Result<()> {
    let arg = if value { "deb=true" } else { "deb=false" };
    let out = Command::new(program).args(["set", arg]).stdin(Stdio::null()).output()?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        bail!("{} set {arg} : {} {}", program.display(), out.status, err.trim());
    }
    Ok(())
}

/// Active le réglage DEB si nécessaire, une seule fois par lancement.
/// `program` : programme de l'adaptateur `auxi` (déjà résolu).
pub fn ensure_enabled(paths: &Paths, program: &Path) -> Result<()> {
    let mut w = WINDOW.lock().unwrap_or_else(|e| e.into_inner());
    if w.is_some() || deb_enabled(&apps_conf()) {
        return Ok(());
    }
    let marker = paths.state_dir.join(MARKER);
    // Témoin AVANT l'activation : un plantage entre les deux laisse au pire
    // un témoin sans activation, dont la remise à false est sans effet.
    crate::paths::atomic_write(&marker, program.as_os_str().as_encoded_bytes())?;
    if let Err(e) = set_deb(program, true) {
        let _ = std::fs::remove_file(&marker);
        bail!(tr!(
            "impossible d'activer l'installation DEB d'AuxiNux OS : {e:#}",
            "cannot enable AuxiNux OS DEB installation: {e:#}"
        ));
    }
    eprintln!(
        "{}",
        tr!(
            "Installation DEB d'AuxiNux OS activée le temps de l'opération",
            "AuxiNux OS DEB installation enabled for the duration of the operation"
        )
    );
    *w = Some(Window {
        program: program.to_path_buf(),
        marker,
    });
    drop(w);
    watch_signals();
    Ok(())
}

/// Remet le réglage à désactivé si AuxiPak l'a activé (sans effet sinon).
pub fn restore() {
    let Some(w) = WINDOW.lock().unwrap_or_else(|e| e.into_inner()).take() else {
        return;
    };
    match set_deb(&w.program, false) {
        Ok(()) => {
            let _ = std::fs::remove_file(&w.marker);
            eprintln!(
                "{}",
                tr!(
                    "Installation DEB d'AuxiNux OS remise à désactivée",
                    "AuxiNux OS DEB installation set back to disabled"
                )
            );
        }
        // Le témoin reste : le prochain lancement réessaiera.
        Err(e) => eprintln!(
            "{}",
            tr!(
                "avertissement : installation DEB d'AuxiNux OS NON remise à désactivée ({e:#}) ; exécutez : sudo auxi set deb=false",
                "warning: AuxiNux OS DEB installation NOT set back to disabled ({e:#}); run: sudo auxi set deb=false"
            )
        ),
    }
}

/// Ctrl-C / SIGTERM pendant la fenêtre : remise à désactivé, puis sortie.
fn watch_signals() {
    if tokio::runtime::Handle::try_current().is_err() {
        return;
    }
    tokio::spawn(async {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            let (Ok(mut int), Ok(mut term)) = (signal(SignalKind::interrupt()), signal(SignalKind::terminate())) else {
                return;
            };
            let code = tokio::select! {
                _ = int.recv() => 130,
                _ = term.recv() => 143,
            };
            restore();
            std::process::exit(code);
        }
        #[cfg(not(unix))]
        {
            if tokio::signal::ctrl_c().await.is_ok() {
                restore();
                std::process::exit(130);
            }
        }
    });
}

/// Garde de commande : remet le réglage à désactivé à la fin (retour,
/// erreur ou panique).
pub struct Session;

impl Drop for Session {
    fn drop(&mut self) {
        restore();
    }
}

/// Au lancement : un témoin résiduel (plantage, coupure de courant pendant la
/// fenêtre) fait remettre le réglage à désactivé.
pub fn recover(paths: &Paths) {
    let marker = paths.state_dir.join(MARKER);
    let Ok(content) = std::fs::read(&marker) else {
        return;
    };
    // Une autre instance en cours (verrou d'état pris) a peut-être ouvert la
    // fenêtre elle-même : ne pas la refermer sous elle.
    let Ok(_lock) = crate::registry::StateLock::acquire(paths) else {
        return;
    };
    if !crate::privileges::is_elevated() {
        eprintln!(
            "{}",
            tr!(
                "avertissement : une opération AuxiPak interrompue a laissé l'installation DEB d'AuxiNux OS activée ; relancez AuxiPak avec sudo pour la remettre à désactivée",
                "warning: an interrupted AuxiPak operation left AuxiNux OS DEB installation enabled; run AuxiPak with sudo to set it back to disabled"
            )
        );
        return;
    }
    // Programme noté dans le témoin s'il est plausible, sinon l'adaptateur.
    let noted = PathBuf::from(String::from_utf8_lossy(&content).trim());
    let program = if noted.is_absolute() && noted.is_file() {
        noted
    } else {
        match crate::executor::resolve_program("auxi") {
            Ok(p) => p,
            Err(_) => return,
        }
    };
    eprintln!(
        "{}",
        tr!(
            "Une opération AuxiPak interrompue avait activé l'installation DEB d'AuxiNux OS : remise à désactivée",
            "An interrupted AuxiPak operation had enabled AuxiNux OS DEB installation: setting it back to disabled"
        )
    );
    match set_deb(&program, false) {
        Ok(()) => {
            let _ = std::fs::remove_file(&marker);
        }
        Err(e) => eprintln!(
            "{}",
            tr!(
                "avertissement : échec de « auxi set deb=false » ({e:#}) ; exécutez : sudo auxi set deb=false",
                "warning: \"auxi set deb=false\" failed ({e:#}); run: sudo auxi set deb=false"
            )
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deb_enabled_follows_auxi_rule() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("apps.conf");
        assert!(!deb_enabled(&f), "fichier absent = désactivé");
        for (content, on) in [
            ("DEB_APPS=1\n", true),
            ("# x\nDEB_APPS=1\n", true),
            ("DEB_APPS=0\n", false),
            ("DEB_APPS=1 \n", false),
            (" DEB_APPS=1\n", false),
            ("DEB_APPS=10\n", false),
            ("", false),
        ] {
            std::fs::write(&f, content).unwrap();
            assert_eq!(deb_enabled(&f), on, "{content:?}");
        }
    }
}
