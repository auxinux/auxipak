//! Langue des messages (anglais / français ; anglais par défaut).
//!
//! Ordre de résolution :
//! 1. langue de la requête en cours (serveur : `Accept-Language` ou cookie,
//!    portée par [`scope`]) ;
//! 2. langue fixée par le programme ([`set`]) : variable `AUXIPAK_LANG`,
//!    réglage `lang` du client ou du Builder ;
//! 3. langue du système (`LC_ALL`, `LC_MESSAGES`, `LANG` ; langue d'affichage
//!    sous Windows) ;
//! 4. anglais.
//!
//! Les messages s'écrivent avec la macro [`tr!`](crate::tr) :
//! `tr!("fichier {f} introuvable", "file {f} not found")`.

use std::sync::atomic::{AtomicU8, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Lang {
    En,
    Fr,
}

impl Lang {
    /// `fr`, `fr-CA`, `fr_CA.UTF-8`, `FR` → français ; `en…` → anglais.
    pub fn parse(s: &str) -> Option<Lang> {
        let s = s.trim().to_ascii_lowercase();
        let base = s.split(['-', '_', '.', '@']).next().unwrap_or("");
        match base {
            "fr" => Some(Lang::Fr),
            "en" => Some(Lang::En),
            _ => None,
        }
    }

    pub fn code(self) -> &'static str {
        match self {
            Lang::En => "en",
            Lang::Fr => "fr",
        }
    }

    /// Première langue reconnue d'un en-tête `Accept-Language` (ordre de
    /// préférence par poids `q`).
    pub fn from_accept_language(h: &str) -> Option<Lang> {
        let mut best: Option<(f32, Lang)> = None;
        for part in h.split(',') {
            let mut it = part.split(';');
            let tag = it.next().unwrap_or("").trim();
            let q = it
                .find_map(|p| p.trim().strip_prefix("q="))
                .and_then(|q| q.parse::<f32>().ok())
                .unwrap_or(1.0);
            if let Some(l) = Lang::parse(tag) {
                if best.map(|(bq, _)| q > bq).unwrap_or(true) {
                    best = Some((q, l));
                }
            }
        }
        best.map(|(_, l)| l)
    }
}

// 0 : non fixée ; 1 : anglais ; 2 : français.
static FIXED: AtomicU8 = AtomicU8::new(0);

tokio::task_local! {
    static REQUEST: Lang;
}

/// Fixe la langue du programme (prioritaire sur celle du système).
pub fn set(l: Lang) {
    FIXED.store(
        match l {
            Lang::En => 1,
            Lang::Fr => 2,
        },
        Ordering::Relaxed,
    );
}

/// Exécute `fut` avec la langue `l` (requête du serveur).
pub async fn scope<F: std::future::Future>(l: Lang, fut: F) -> F::Output {
    REQUEST.scope(l, fut).await
}

/// Langue du système, si elle est reconnue (sinon : anglais, par l'appelant).
pub fn system() -> Option<Lang> {
    // macOS : langue de l'interface choisie dans Réglages (AppleLanguages),
    // prioritaire sur la variable LANG du terminal.
    #[cfg(target_os = "macos")]
    if let Some(l) = macos_ui_language() {
        return Some(l);
    }
    // GNU : LANGUAGE (liste « fr:en ») sauf si la locale est C/POSIX.
    let posix = |v: &str| matches!(v.split('.').next(), Some("C" | "POSIX"));
    let lc = ["LC_ALL", "LC_MESSAGES", "LANG"]
        .iter()
        .find_map(|v| std::env::var(v).ok().filter(|s| !s.is_empty()));
    if !lc.as_deref().map(posix).unwrap_or(false) {
        if let Some(l) = std::env::var("LANGUAGE")
            .ok()
            .and_then(|v| v.split(':').find_map(Lang::parse))
        {
            return Some(l);
        }
    }
    if let Some(val) = lc {
        // « C » / « POSIX » ou langue non prise en charge : anglais.
        return Lang::parse(&val);
    }
    #[cfg(windows)]
    {
        // LANGID : langue principale sur les 10 bits de poids faible.
        let id = unsafe { windows_sys::Win32::Globalization::GetUserDefaultUILanguage() };
        return Some(if id & 0x3ff == 0x0c { Lang::Fr } else { Lang::En });
    }
    #[allow(unreachable_code)]
    None
}

/// macOS : première langue préférée de l'utilisateur (`defaults read -g
/// AppleLanguages`) ; sous `sudo`, celle de l'utilisateur qui a lancé la
/// commande. Une première langue non prise en charge donne l'anglais ;
/// `None` seulement si le réglage est illisible.
#[cfg(target_os = "macos")]
fn macos_ui_language() -> Option<Lang> {
    let mut cmd = std::process::Command::new("/usr/bin/defaults");
    match std::env::var("SUDO_USER")
        .ok()
        .filter(|u| !u.is_empty() && u != "root" && !u.contains('/'))
    {
        Some(u) => cmd.args([
            "read",
            &format!("/Users/{u}/Library/Preferences/.GlobalPreferences"),
            "AppleLanguages",
        ]),
        None => cmd.args(["read", "-g", "AppleLanguages"]),
    };
    let out = cmd.stderr(std::process::Stdio::null()).output().ok()?;
    if !out.status.success() {
        return None;
    }
    // Sortie : ( "fr-CA", "en-CA" )
    let text = String::from_utf8_lossy(&out.stdout);
    let first = text
        .split(|c: char| c == '"' || c == ',' || c == '(' || c == ')' || c.is_whitespace())
        .find(|t| !t.is_empty())?;
    Some(Lang::parse(first).unwrap_or(Lang::En))
}

/// Langue effective.
pub fn current() -> Lang {
    if let Ok(l) = REQUEST.try_with(|l| *l) {
        return l;
    }
    match FIXED.load(Ordering::Relaxed) {
        1 => Lang::En,
        2 => Lang::Fr,
        _ => {
            let l = std::env::var("AUXIPAK_LANG")
                .ok()
                .and_then(|v| Lang::parse(&v))
                .or_else(system)
                .unwrap_or(Lang::En);
            set(l);
            l
        }
    }
}

pub fn is_fr() -> bool {
    current() == Lang::Fr
}

/// Message bilingue : `tr!("français {x}", "English {x}")`, arguments de
/// `format!` acceptés après les deux gabarits.
#[macro_export]
macro_rules! tr {
    ($fr:literal, $en:literal $(, $arg:expr)* $(,)?) => {
        if $crate::i18n::is_fr() {
            format!($fr $(, $arg)*)
        } else {
            format!($en $(, $arg)*)
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn analyse() {
        assert_eq!(Lang::parse("fr_CA.UTF-8"), Some(Lang::Fr));
        assert_eq!(Lang::parse("FR"), Some(Lang::Fr));
        assert_eq!(Lang::parse("en-US"), Some(Lang::En));
        assert_eq!(Lang::parse("C.UTF-8"), None);
        assert_eq!(Lang::from_accept_language("fr-CA,fr;q=0.9,en;q=0.8"), Some(Lang::Fr));
        assert_eq!(Lang::from_accept_language("en-CA,en;q=0.9,fr-CA;q=0.8"), Some(Lang::En));
        assert_eq!(Lang::from_accept_language("de;q=1, fr;q=0.3"), Some(Lang::Fr));
        assert_eq!(Lang::from_accept_language("de"), None);
    }

    #[tokio::test]
    async fn portee_de_requete() {
        set(Lang::En);
        let x = 3;
        assert_eq!(tr!("{x} fichiers", "{x} files"), "3 files");
        let fr = scope(Lang::Fr, async { tr!("{} fichiers", "{} files", x) }).await;
        assert_eq!(fr, "3 fichiers");
        assert_eq!(current(), Lang::En);
    }
}
