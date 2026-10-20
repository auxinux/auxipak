//! Mise à jour d'AuxiPak lui-même (`auxipak upgrade`).
//!
//! Le serveur du dépôt officiel publie les binaires du client dans
//! `/downloads/` avec leurs empreintes (`SHA256SUMS`), les mêmes que ceux
//! utilisés par `install.sh` / `install.ps1`. Le client y cherche une version
//! plus récente pour sa plateforme, la télécharge, vérifie son SHA-256 et
//! remplace ses binaires (`auxipak` et, s'il est installé à côté,
//! `auxipak-builder`).

use crate::config::Config;
use crate::download::{self, Expect, RedirectPolicy};
use crate::executor::{self, Tool};
use crate::paths::Paths;
use anyhow::{bail, Context, Result};
use auxipak_core::tr;
use std::path::{Path, PathBuf};
use url::Url;

pub const CURRENT: &str = env!("CARGO_PKG_VERSION");
const MAX_ARCHIVE: u64 = 512 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq)]
pub struct Available {
    pub version: String,
    pub file: String,
    pub sha256: String,
    pub url: Url,
}

/// Plateforme de ce binaire, au format des archives de release.
pub fn platform() -> String {
    let os = match std::env::consts::OS {
        "macos" => "macos",
        "windows" => "windows",
        _ => "linux",
    };
    let arch = match std::env::consts::ARCH {
        "aarch64" => "arm64",
        a => a,
    };
    format!("{os}-{arch}")
}

/// Version actuelle (variable `AUXIPAK_SELF_VERSION` : tests uniquement).
fn current() -> String {
    std::env::var("AUXIPAK_SELF_VERSION")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| CURRENT.to_string())
}

/// Racine du serveur à partir de l'URL du dépôt officiel
/// (`https://hôte/repos/official/` → `https://hôte/`).
pub fn server_base(repo_url: &str) -> Result<Url> {
    let u = Url::parse(repo_url)?;
    let path = u.path().trim_end_matches('/');
    let root = match path.rfind("/repos/") {
        Some(i) => &path[..i],
        None => bail!(tr!(
            "URL de dépôt inattendue : {repo_url}",
            "unexpected repository URL: {repo_url}"
        )),
    };
    let mut base = u.clone();
    base.set_path(&format!("{root}/"));
    base.set_query(None);
    Ok(base)
}

/// Archive la plus récente pour `platform` dans un `SHA256SUMS`, si elle est
/// plus récente que `current`.
pub fn pick(sums: &str, platform: &str, current: &str) -> Option<(String, String, String)> {
    let mut best: Option<(String, String, String)> = None;
    for line in sums.lines() {
        let mut it = line.split_whitespace();
        let (Some(sha), Some(name)) = (it.next(), it.next()) else {
            continue;
        };
        let name = name.trim_start_matches('*');
        if sha.len() != 64 || !sha.bytes().all(|b| b.is_ascii_hexdigit()) {
            continue;
        }
        let Some(rest) = name.strip_prefix("auxipak-v") else {
            continue;
        };
        let Some(ver) = rest
            .strip_suffix(&format!("-{platform}.tar.gz"))
            .or_else(|| rest.strip_suffix(&format!("-{platform}.zip")))
        else {
            continue;
        };
        if !auxipak_core::version::is_valid_version(ver) || !auxipak_core::ids::is_safe_file_name(name) {
            continue;
        }
        let newer_than_best = best
            .as_ref()
            .map(|(v, _, _)| auxipak_core::version::compare(ver, v).is_gt())
            .unwrap_or(true);
        if newer_than_best {
            best = Some((ver.to_string(), name.to_string(), sha.to_ascii_lowercase()));
        }
    }
    best.filter(|(v, _, _)| auxipak_core::version::compare(v, current).is_gt())
}

/// Cherche une version plus récente sur le serveur du dépôt officiel.
pub async fn check(config: &Config) -> Result<Option<Available>> {
    let Some(repo) = config
        .enabled_repos()
        .find(|r| r.official)
        .or_else(|| config.repo("official"))
    else {
        return Ok(None);
    };
    let base = server_base(&repo.url)?;
    if base.scheme() != "https" && !(repo.allow_insecure_localhost && base.scheme() == "http") {
        bail!(tr!("HTTPS obligatoire : {base}", "HTTPS required: {base}"));
    }
    let sums_url = base.join("downloads/SHA256SUMS")?;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(20))
        .build()?;
    let resp = client.get(sums_url.clone()).send().await?;
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    let sums = resp.error_for_status()?.text().await?;
    Ok(pick(&sums, &platform(), &current()).map(|(version, file, sha256)| Available {
        url: base.join(&format!("downloads/{file}")).expect("nom de fichier sûr"),
        version,
        file,
        sha256,
    }))
}

fn exe_name(name: &str) -> String {
    if cfg!(windows) {
        format!("{name}.exe")
    } else {
        name.to_string()
    }
}

/// Le répertoire est-il inscriptible (sans le modifier durablement) ?
fn writable(dir: &Path) -> bool {
    tempfile::Builder::new().prefix(".auxipak-check").tempfile_in(dir).is_ok()
}

/// Remplace `dst` par `src`. Sous Windows, le binaire en cours d'exécution
/// est renommé (`.old`, supprimé au prochain lancement).
fn replace(src: &Path, dst: &Path) -> Result<()> {
    let dir = dst.parent().context("binaire sans répertoire")?;
    let tmp = dir.join(format!(".{}.new", dst.file_name().unwrap().to_string_lossy()));
    std::fs::copy(src, &tmp)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))?;
    }
    #[cfg(windows)]
    {
        let old = dst.with_extension("exe.old");
        let _ = std::fs::remove_file(&old);
        if dst.exists() {
            std::fs::rename(dst, &old)?;
        }
    }
    std::fs::rename(&tmp, dst)?;
    Ok(())
}

/// Supprime les binaires remplacés lors d'une mise à jour précédente (Windows).
pub fn cleanup_old() {
    #[cfg(windows)]
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            for n in ["auxipak.exe.old", "auxipak-builder.exe.old"] {
                let _ = std::fs::remove_file(dir.join(n));
            }
        }
    }
}

/// Installe la version `a` à la place des binaires actuels.
pub async fn apply(paths: &Paths, a: &Available, allow_insecure_localhost: bool) -> Result<Vec<PathBuf>> {
    let exe = std::env::current_exe()?.canonicalize()?;
    let dir = exe.parent().context("binaire sans répertoire")?.to_path_buf();
    if !writable(&dir) {
        bail!(tr!(
            "{} n'est pas modifiable par cet utilisateur : relancez « sudo auxipak upgrade » (ou depuis une console administrateur sous Windows)",
            "{} is not writable by this user: run « sudo auxipak upgrade » (or from an administrator console on Windows)",
            dir.display()
        ));
    }
    let work_root = paths.cache_dir.join("self-update");
    std::fs::create_dir_all(&work_root)?;
    let work = tempfile::Builder::new().prefix("v").tempdir_in(&work_root)?;
    let archive = work.path().join(&a.file);
    download::fetch(
        &a.url,
        &archive,
        &Expect {
            sha256: a.sha256.clone(),
            size: None,
            max_size: MAX_ARCHIVE,
        },
        &RedirectPolicy {
            allowed_hosts: vec![],
            allow_insecure_localhost,
        },
        &a.file,
    )
    .await?;
    let out = work.path().join("x");
    std::fs::create_dir_all(&out)?;
    let tar = executor::resolve(Tool::Tar)?;
    let flags = if a.file.ends_with(".zip") { "-xf" } else { "-xzf" };
    let res = executor::run(
        &tar,
        &[
            flags.into(),
            archive.into_os_string(),
            "-C".into(),
            out.clone().into_os_string(),
        ],
        &Default::default(),
    )
    .await?;
    if res.code != 0 {
        bail!(tr!("extraction impossible : {}", "extraction failed: {}", res.stderr.trim()));
    }
    let stem = a.file.trim_end_matches(".tar.gz").trim_end_matches(".zip");
    let src = out.join(stem);
    let mut done = Vec::new();
    for name in ["auxipak", "auxipak-builder"] {
        let file = exe_name(name);
        let new = src.join(&file);
        let dst = dir.join(&file);
        // auxipak est toujours remplacé ; le Builder seulement s'il est installé.
        if !new.is_file() || (name != "auxipak" && !dst.exists()) {
            continue;
        }
        replace(&new, &dst)?;
        done.push(dst);
    }
    if done.is_empty() {
        bail!(tr!("archive invalide : {}", "invalid archive: {}", a.file));
    }
    Ok(done)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SUMS: &str = "\
1111111111111111111111111111111111111111111111111111111111111111  auxipak-v1.0.2-linux-x86_64.tar.gz
2222222222222222222222222222222222222222222222222222222222222222  auxipak-v1.0.10-linux-x86_64.tar.gz
3333333333333333333333333333333333333333333333333333333333333333  auxipak-v1.1.0-windows-x86_64.zip
4444444444444444444444444444444444444444444444444444444444444444  auxipak-v9.0.0-linux-x86_64.tar.gz.evil
nothex  auxipak-v9.9.9-linux-x86_64.tar.gz
";

    #[test]
    fn choix_de_version() {
        let (v, f, _) = pick(SUMS, "linux-x86_64", "1.0.2").unwrap();
        assert_eq!((v.as_str(), f.as_str()), ("1.0.10", "auxipak-v1.0.10-linux-x86_64.tar.gz"));
        assert!(pick(SUMS, "linux-x86_64", "1.0.10").is_none());
        assert!(pick(SUMS, "linux-x86_64", "2.0.0").is_none());
        assert_eq!(pick(SUMS, "windows-x86_64", "1.0.0").unwrap().0, "1.1.0");
        assert!(pick(SUMS, "macos-arm64", "1.0.0").is_none());
    }

    #[test]
    fn racine_du_serveur() {
        assert_eq!(
            server_base("https://auxipak.auxinux.ca/repos/official/").unwrap().as_str(),
            "https://auxipak.auxinux.ca/"
        );
        assert_eq!(
            server_base("https://exemple.org/pak/repos/official").unwrap().as_str(),
            "https://exemple.org/pak/"
        );
        assert!(server_base("https://exemple.org/autre/").is_err());
    }
}
