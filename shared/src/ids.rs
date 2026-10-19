//! Validation des identifiants et des valeurs utilisées dans les noms de
//! fichiers, chemins de dépôt ou arguments de commandes natives.
//!
//! Toute valeur provenant d'un manifeste qui finit dans un argument de
//! processus ou un chemin passe par l'une de ces fonctions : elles constituent
//! la première barrière contre l'injection de commandes et la traversée de
//! répertoires.

use regex::Regex;
use std::sync::OnceLock;

fn re(cell: &'static OnceLock<Regex>, pat: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pat).expect("regex valide"))
}

/// Identifiant stable d'application : minuscules, chiffres, `.`, `-`, `+`
/// (2 à 64 caractères, commence par une lettre ou un chiffre).
pub fn is_valid_app_id(s: &str) -> bool {
    static R: OnceLock<Regex> = OnceLock::new();
    re(&R, r"^[a-z0-9][a-z0-9.+-]{1,63}$").is_match(s) && !s.contains("..")
}

/// Code de langue : BCP 47 simplifié (`fr`, `en`, `fr-CA`, `pt-BR`) ou `mul`
/// (multilingue).
pub fn is_valid_language(s: &str) -> bool {
    static R: OnceLock<Regex> = OnceLock::new();
    re(&R, r"^([a-z]{2,3})(-[A-Z]{2}|-[A-Za-z]{4})?$").is_match(s)
}

/// Nom de paquet natif (apt/auxi, winget, Homebrew…). Volontairement
/// restrictif : aucun espace, aucun métacaractère de shell, ne commence pas
/// par `-` (pas d'injection d'option).
pub fn is_valid_native_package(s: &str) -> bool {
    static R: OnceLock<Regex> = OnceLock::new();
    re(&R, r"^[A-Za-z0-9][A-Za-z0-9.+_:@/-]{0,127}$").is_match(s) && !s.contains("..")
}

/// Identifiant de produit MSI (GUID entre accolades).
pub fn is_valid_msi_product_code(s: &str) -> bool {
    static R: OnceLock<Regex> = OnceLock::new();
    re(
        &R,
        r"^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$",
    )
    .is_match(s)
}

/// Identifiant de reçu macOS (`com.example.app`).
pub fn is_valid_reverse_dns(s: &str) -> bool {
    static R: OnceLock<Regex> = OnceLock::new();
    re(&R, r"^[A-Za-z0-9][A-Za-z0-9-]*(\.[A-Za-z0-9][A-Za-z0-9-]*)+$").is_match(s) && s.len() <= 255
}

/// Nom de propriété MSI publique (MAJUSCULES).
pub fn is_valid_msi_property(s: &str) -> bool {
    static R: OnceLock<Regex> = OnceLock::new();
    re(&R, r"^[A-Z][A-Z0-9_]{0,63}$").is_match(s)
}

/// Argument transmis à un installateur (`/S`, `--silent`, `/norestart`,
/// `INSTALLDIR=...` interdit ici). Les arguments sont toujours transmis tels
/// quels via un vecteur d'arguments, jamais à un interpréteur de commandes ;
/// on refuse néanmoins les caractères de contrôle, les guillemets et les
/// métacaractères usuels pour qu'un argument reste lisible et auditable.
pub fn is_valid_installer_arg(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 256
        && !s.chars().any(|c| {
            c.is_control() || matches!(c, '"' | '\'' | '`' | '$' | ';' | '|' | '&' | '<' | '>' | '%' | '^')
        })
}

/// Chemin relatif sûr à l'intérieur d'une archive `.apak` :
/// séparateur `/`, pas de composant vide, `.` ou `..`, pas de chemin absolu,
/// pas de lettre de lecteur, pas de caractères interdits sous Windows,
/// longueur bornée.
pub fn is_safe_relative_path(p: &str) -> bool {
    if p.is_empty() || p.len() > 512 || p.starts_with('/') || p.contains('\\') || p.contains('\0') {
        return false;
    }
    if p.len() >= 2 && p.as_bytes()[1] == b':' {
        return false;
    }
    p.split('/').all(|c| {
        !c.is_empty()
            && c != "."
            && c != ".."
            && c.len() <= 255
            && !c.chars().any(|ch| ch.is_control() || matches!(ch, '<' | '>' | ':' | '"' | '|' | '?' | '*'))
            && !c.ends_with(' ')
            && !c.ends_with('.')
            && !is_windows_reserved(c)
    })
}

fn is_windows_reserved(component: &str) -> bool {
    let stem = component.split('.').next().unwrap_or("").to_ascii_uppercase();
    matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || ((stem.starts_with("COM") || stem.starts_with("LPT"))
            && stem.len() == 4
            && stem.as_bytes()[3].is_ascii_digit())
}

/// Nom de fichier simple (sans répertoire).
pub fn is_safe_file_name(s: &str) -> bool {
    is_safe_relative_path(s) && !s.contains('/')
}

/// Nom de dépôt configuré côté client ou serveur.
pub fn is_valid_repo_name(s: &str) -> bool {
    static R: OnceLock<Regex> = OnceLock::new();
    re(&R, r"^[a-z0-9][a-z0-9_-]{0,31}$").is_match(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_ids() {
        assert!(is_valid_app_id("firefox"));
        assert!(is_valid_app_id("auxipak-demo"));
        assert!(is_valid_app_id("org.mozilla.firefox"));
        assert!(!is_valid_app_id("Firefox"));
        assert!(!is_valid_app_id("a"));
        assert!(!is_valid_app_id("../etc"));
        assert!(!is_valid_app_id("foo bar"));
        assert!(!is_valid_app_id("-rf"));
    }

    #[test]
    fn languages() {
        for ok in ["fr", "en", "fr-CA", "mul", "zh-Hant"] {
            assert!(is_valid_language(ok), "{ok}");
        }
        for bad in ["FR", "francais", "fr_CA", ""] {
            assert!(!is_valid_language(bad), "{bad}");
        }
    }

    #[test]
    fn native_packages_reject_injection() {
        assert!(is_valid_native_package("firefox-esr"));
        assert!(is_valid_native_package("Mozilla.Firefox"));
        assert!(is_valid_native_package("libc6:amd64"));
        for bad in ["-y", "foo;rm", "a b", "$(x)", "a|b", "../x", "`x`"] {
            assert!(!is_valid_native_package(bad), "{bad}");
        }
    }

    #[test]
    fn relative_paths() {
        assert!(is_safe_relative_path("payload/app.deb"));
        assert!(is_safe_relative_path("instruction.auxipak"));
        for bad in [
            "/etc/passwd",
            "../x",
            "payload/../../x",
            "payload//x",
            "C:/x",
            "c:x",
            "payload\\x",
            "payload/./x",
            "payload/CON",
            "payload/nul.txt",
            "payload/a:b",
            "",
            "payload/x.",
        ] {
            assert!(!is_safe_relative_path(bad), "{bad}");
        }
    }

    #[test]
    fn installer_args() {
        assert!(is_valid_installer_arg("/S"));
        assert!(is_valid_installer_arg("--mode=unattended"));
        assert!(!is_valid_installer_arg("a & calc"));
        assert!(!is_valid_installer_arg("$(id)"));
        assert!(!is_valid_installer_arg(""));
    }

    #[test]
    fn msi_codes() {
        assert!(is_valid_msi_product_code("{12345678-1234-1234-1234-1234567890AB}"));
        assert!(!is_valid_msi_product_code("12345678-1234-1234-1234-1234567890AB"));
    }
}
