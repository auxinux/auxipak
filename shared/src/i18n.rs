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

/// Langue du système, si elle est reconnue.
pub fn system() -> Option<Lang> {
    for v in ["LC_ALL", "LC_MESSAGES", "LANG"] {
        if let Some(val) = std::env::var(v).ok().filter(|s| !s.is_empty()) {
            // « C » / « POSIX » : pas de préférence, on continue (puis anglais).
            return Lang::parse(&val);
        }
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
