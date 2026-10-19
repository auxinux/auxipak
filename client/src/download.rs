//! Téléchargements contrôlés : reprise, limites de taille, vérification
//! SHA-256 et politique de redirection stricte.

use anyhow::{anyhow, bail, Context, Result};
use auxipak_core::hash::{digest_eq, sha256_file};
use auxipak_core::netpolicy;
use futures::StreamExt;
use std::io::Write;
use std::path::Path;
use std::time::Duration;
use url::Url;

/// Ce qui est attendu d'un téléchargement.
#[derive(Debug, Clone)]
pub struct Expect {
    pub sha256: String,
    pub size: Option<u64>,
    /// Limite stricte (taille déclarée ou politique).
    pub max_size: u64,
}

/// Politique de redirection.
#[derive(Debug, Clone)]
pub struct RedirectPolicy {
    /// Hôtes autorisés (l'hôte initial y est toujours ajouté).
    pub allowed_hosts: Vec<String>,
    /// HTTP local autorisé (développement).
    pub allow_insecure_localhost: bool,
}

fn client(policy: &RedirectPolicy, origin: &Url) -> Result<reqwest::Client> {
    let mut allowed = policy.allowed_hosts.clone();
    if let Some(h) = origin.host_str() {
        allowed.push(h.to_string());
    }
    let insecure = policy.allow_insecure_localhost;
    let origin_scheme = origin.scheme().to_string();
    let redirect = reqwest::redirect::Policy::custom(move |attempt| {
        if attempt.previous().len() >= 5 {
            return attempt.error("trop de redirections");
        }
        let next = attempt.url().clone();
        let local_http = insecure
            && origin_scheme == "http"
            && next.scheme() == "http"
            && matches!(next.host_str(), Some("localhost") | Some("127.0.0.1"));
        if local_http && allowed.iter().any(|a| Some(a.as_str()) == next.host_str()) {
            return attempt.follow();
        }
        match netpolicy::redirect_allowed(&next, &allowed) {
            Ok(()) => attempt.follow(),
            Err(e) => attempt.error(e),
        }
    });
    Ok(reqwest::Client::builder()
        .redirect(redirect)
        .connect_timeout(Duration::from_secs(15))
        .read_timeout(Duration::from_secs(120))
        .user_agent(concat!("auxipak/", env!("CARGO_PKG_VERSION")))
        .build()?)
}

/// Vérifie l'espace disque disponible.
pub fn ensure_space(dir: &Path, needed: u64) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    let avail = fs4::available_space(dir).unwrap_or(u64::MAX);
    // Marge de 5 % + 64 Mio.
    let required = needed + needed / 20 + 64 * 1024 * 1024;
    if avail < required {
        bail!(
            "espace disque insuffisant dans {} : {} Mio disponibles, {} Mio nécessaires",
            dir.display(),
            avail / 1_048_576,
            required / 1_048_576
        );
    }
    Ok(())
}

/// Télécharge `url` vers `dest`, avec reprise depuis `dest.part`, et vérifie
/// l'empreinte. En cas d'échec de vérification, le fichier partiel est supprimé.
pub async fn fetch(url: &Url, dest: &Path, expect: &Expect, policy: &RedirectPolicy) -> Result<()> {
    if dest.exists() {
        let (sha, size) = sha256_file(dest)?;
        if digest_eq(&sha, &expect.sha256) && expect.size.map(|s| s == size).unwrap_or(true) {
            return Ok(());
        }
        std::fs::remove_file(dest)?;
    }
    let dir = dest.parent().context("destination sans répertoire parent")?;
    ensure_space(dir, expect.size.unwrap_or(0))?;
    let part = dest.with_extension(format!(
        "{}.part",
        dest.extension().and_then(|e| e.to_str()).unwrap_or("dl")
    ));
    match url.scheme() {
        "file" => {
            let src = url.to_file_path().map_err(|_| anyhow!("URL de fichier invalide"))?;
            let len = std::fs::metadata(&src)?.len();
            if len > expect.max_size {
                bail!("fichier trop volumineux ({len} octets)");
            }
            std::fs::copy(&src, &part)?;
        }
        "https" | "http" => download_http(url, &part, expect, policy).await?,
        s => bail!("schéma non pris en charge : {s}"),
    }
    let (sha, size) = sha256_file(&part)?;
    if !digest_eq(&sha, &expect.sha256) || expect.size.map(|s| s != size).unwrap_or(false) {
        let _ = std::fs::remove_file(&part);
        bail!(
            "vérification d'intégrité échouée pour {url} : SHA-256 attendu {}, obtenu {sha} ({size} octets)",
            expect.sha256
        );
    }
    std::fs::rename(&part, dest)?;
    Ok(())
}

async fn download_http(url: &Url, part: &Path, expect: &Expect, policy: &RedirectPolicy) -> Result<()> {
    if url.scheme() == "http" && !policy.allow_insecure_localhost {
        bail!("téléchargement HTTP refusé : {url}");
    }
    let c = client(policy, url)?;
    let mut attempt = 0;
    loop {
        attempt += 1;
        let existing = std::fs::metadata(part).map(|m| m.len()).unwrap_or(0);
        if let Some(sz) = expect.size {
            if existing > sz {
                std::fs::remove_file(part)?;
                continue;
            }
            if existing == sz && sz > 0 {
                return Ok(());
            }
        }
        let mut req = c.get(url.clone());
        if existing > 0 {
            req = req.header(reqwest::header::RANGE, format!("bytes={existing}-"));
        }
        let result: Result<()> = async {
            let resp = req.send().await.with_context(|| format!("connexion à {url}"))?;
            let status = resp.status();
            let append = status == reqwest::StatusCode::PARTIAL_CONTENT && existing > 0;
            if !status.is_success() {
                if status == reqwest::StatusCode::RANGE_NOT_SATISFIABLE {
                    std::fs::remove_file(part)?;
                }
                bail!("{url} : réponse HTTP {status}");
            }
            if let Some(len) = resp.content_length() {
                let total = if append { existing + len } else { len };
                if total > expect.max_size || expect.size.map(|s| total != s).unwrap_or(false) {
                    bail!("{url} : taille annoncée inattendue ({total} octets)");
                }
            }
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .append(append)
                .truncate(!append)
                .open(part)?;
            let mut written = if append { existing } else { 0 };
            let mut stream = resp.bytes_stream();
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.context("téléchargement interrompu")?;
                written += chunk.len() as u64;
                if written > expect.max_size || expect.size.map(|s| written > s).unwrap_or(false) {
                    drop(file);
                    let _ = std::fs::remove_file(part);
                    bail!("{url} : taille maximale dépassée");
                }
                file.write_all(&chunk)?;
            }
            file.sync_all()?;
            Ok(())
        }
        .await;
        match result {
            Ok(()) => return Ok(()),
            Err(e) if attempt < 4 => {
                tracing::warn!(%url, attempt, error = %e, "nouvelle tentative de téléchargement");
                tokio::time::sleep(Duration::from_secs(1 << attempt)).await;
            }
            Err(e) => return Err(e),
        }
    }
}
