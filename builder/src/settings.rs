//! Réglages persistants du Builder (`auxipak-builder set …`) : serveur, jeton
//! d'API et dépôt par défaut de `submit`.
//!
//! Fichier : `$XDG_CONFIG_HOME/auxipak/builder.json` (par défaut
//! `~/.config/auxipak/builder.json`) ou `%APPDATA%\AuxiPak\builder.json` ;
//! `AUXIPAK_BUILDER_CONFIG` désigne un autre fichier. Il contient un secret :
//! droits 0600 sous Unix. Les variables d'environnement et options de la ligne
//! de commande restent prioritaires.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::io::{BufRead, Write};
use std::path::PathBuf;

pub const KEYS: &[&str] = &["server", "token", "repository", "lang"];

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository: Option<String>,
    /// Langue de l'interface (`fr`, `en`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lang: Option<String>,
}

pub fn path() -> Result<PathBuf> {
    if let Some(p) = std::env::var_os("AUXIPAK_BUILDER_CONFIG").filter(|p| !p.is_empty()) {
        return Ok(PathBuf::from(p));
    }
    #[cfg(windows)]
    let dir = std::env::var_os("APPDATA")
        .map(|d| PathBuf::from(d).join("AuxiPak"))
        .context("APPDATA non défini")?;
    #[cfg(not(windows))]
    let dir = match std::env::var_os("XDG_CONFIG_HOME").filter(|d| !d.is_empty()) {
        Some(d) => PathBuf::from(d),
        None => PathBuf::from(std::env::var_os("HOME").context("HOME non défini")?).join(".config"),
    }
    .join("auxipak");
    Ok(dir.join("builder.json"))
}

impl Settings {
    pub fn load() -> Result<Settings> {
        let p = path()?;
        match std::fs::read(&p) {
            Ok(b) => serde_json::from_slice(&b).with_context(|| format!("réglages invalides : {}", p.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Settings::default()),
            Err(e) => Err(e).with_context(|| format!("lecture de {}", p.display())),
        }
    }

    pub fn save(&self) -> Result<PathBuf> {
        let p = path()?;
        if let Some(d) = p.parent() {
            std::fs::create_dir_all(d)?;
        }
        let tmp = p.with_extension("json.tmp");
        {
            let mut o = std::fs::OpenOptions::new();
            o.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                o.mode(0o600);
            }
            let mut f = o.open(&tmp).with_context(|| format!("écriture de {}", tmp.display()))?;
            f.write_all(serde_json::to_string_pretty(self)?.as_bytes())?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, &p)?;
        Ok(p)
    }

    pub fn set(&mut self, key: &str, value: &str) -> Result<()> {
        let value = value.trim();
        match key {
            "server" => {
                check_server(value)?;
                self.server = Some(value.trim_end_matches('/').to_string());
            }
            "token" => {
                if value.len() < 8 || value.len() > 512 || !value.chars().all(|c| c.is_ascii_graphic()) {
                    bail!("jeton invalide");
                }
                self.token = Some(value.to_string());
            }
            "repository" => {
                if !auxipak_core::ids::is_valid_repo_name(value) {
                    bail!("dépôt invalide : {value}");
                }
                self.repository = Some(value.to_string());
            }
            "lang" | "language" | "langue" => {
                let l = auxipak_core::i18n::Lang::parse(value).with_context(|| format!("langue inconnue : {value} (fr, en)"))?;
                self.lang = Some(l.code().to_string());
            }
            _ => bail!("réglage inconnu : {key} (valeurs possibles : {})", KEYS.join(", ")),
        }
        Ok(())
    }

    pub fn unset(&mut self, key: &str) -> Result<()> {
        match key {
            "server" => self.server = None,
            "token" => self.token = None,
            "repository" => self.repository = None,
            "lang" | "language" | "langue" => self.lang = None,
            _ => bail!("réglage inconnu : {key} (valeurs possibles : {})", KEYS.join(", ")),
        }
        Ok(())
    }
}

/// HTTPS obligatoire (HTTP accepté uniquement vers localhost).
pub fn check_server(server: &str) -> Result<url::Url> {
    let base = url::Url::parse(server).with_context(|| format!("URL invalide : {server}"))?;
    let local = matches!(base.host_str(), Some("localhost") | Some("127.0.0.1"));
    if base.scheme() != "https" && !(base.scheme() == "http" && local) {
        bail!("HTTPS obligatoire pour le serveur (HTTP accepté uniquement vers localhost)");
    }
    Ok(base)
}

/// Jeton masqué pour l'affichage.
pub fn mask(token: &str) -> String {
    let head: String = token.chars().take(8).collect();
    format!("{head}… ({} caractères)", token.chars().count())
}

/// Lit une valeur sur l'entrée standard (évite de la laisser dans l'historique
/// du shell).
pub fn read_value(key: &str) -> Result<String> {
    eprint!("{key} : ");
    std::io::stderr().flush()?;
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    Ok(line.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reglages() {
        let mut s = Settings::default();
        s.set("server", "https://auxipak.example.org/").unwrap();
        assert_eq!(s.server.as_deref(), Some("https://auxipak.example.org"));
        assert!(s.set("server", "http://example.org").is_err());
        s.set("server", "http://127.0.0.1:8080").unwrap();
        s.set("token", "apk_abcdefghijklmnop").unwrap();
        assert!(s.set("token", "apk_ abc def").is_err());
        assert!(s.set("repository", "../x").is_err());
        assert!(s.set("inconnu", "x").is_err());
        s.unset("token").unwrap();
        assert!(s.token.is_none());
        assert_eq!(mask("apk_abcdefghijkl"), "apk_abcd… (16 caractères)");
    }
}
