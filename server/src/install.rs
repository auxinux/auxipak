//! Installation du client : scripts `install.sh` / `uninstall.sh` (Linux,
//! macOS) et `install.ps1` / `uninstall.ps1` (Windows), et distribution des
//! binaires du client (`/downloads/`).
//!
//! Les scripts sont générés à partir de gabarits embarqués : l'URL publique du
//! serveur et les ancres de confiance du dépôt officiel (`root.json`,
//! `package-keys.json`, publics) y sont insérées. Les binaires proviennent
//! d'une release (archives + `SHA256SUMS`) déposée dans `AUXIPAK_DOWNLOADS_DIR`
//! (voir `deploy/scripts/fetch-client.sh`) ; les scripts vérifient leur
//! empreinte SHA-256 avant installation.

use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{header, HeaderValue};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use base64::Engine;

const INSTALL_SH: &str = include_str!("../install/install.sh");
const UNINSTALL_SH: &str = include_str!("../install/uninstall.sh");
const INSTALL_PS1: &str = include_str!("../install/install.ps1");
const UNINSTALL_PS1: &str = include_str!("../install/uninstall.ps1");

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/install.sh", get(install_sh))
        .route("/uninstall.sh", get(uninstall_sh))
        .route("/install.ps1", get(install_ps1))
        .route("/uninstall.ps1", get(uninstall_ps1))
        .route("/downloads/{file}", get(download))
}

/// URL publique sans barre finale, refusée si elle contient un caractère
/// significatif pour sh ou PowerShell (elle est insérée entre apostrophes).
fn base_url(st: &AppState) -> ApiResult<String> {
    let u = st.config.public_url.as_str().trim_end_matches('/').to_string();
    if u.chars()
        .any(|c| matches!(c, '\'' | '"' | '`' | '$' | '\\' | '\n' | '\r' | ' '))
    {
        return Err(ApiError::Internal(anyhow::anyhow!(
            "{}",
            auxipak_core::tr!(
                "AUXIPAK_PUBLIC_URL contient un caractère interdit",
                "AUXIPAK_PUBLIC_URL contains a forbidden character"
            )
        )));
    }
    Ok(u)
}

fn script(body: String) -> Response {
    let mut r = body.into_response();
    let h = r.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain; charset=utf-8"));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    r
}

/// Contenu JSON inséré tel quel dans un document « here » sh : il ne doit pas
/// contenir la ligne de fin (impossible pour un JSON valide, vérifié tout de même).
fn heredoc_safe(json: &[u8]) -> ApiResult<&str> {
    let s = std::str::from_utf8(json).map_err(|_| {
        ApiError::Internal(anyhow::anyhow!(auxipak_core::tr!(
            "ancre de confiance non UTF-8",
            "trust anchor is not UTF-8"
        )))
    })?;
    if s.lines().any(|l| l.trim() == "AUXIPAK_EOF") {
        return Err(ApiError::Internal(anyhow::anyhow!(auxipak_core::tr!(
            "ancre de confiance invalide",
            "invalid trust anchor"
        ))));
    }
    Ok(s.trim_end())
}

fn fill(tpl: &str, st: &AppState, ps1: bool) -> ApiResult<String> {
    let k = &st.keys;
    let mut s = tpl
        .replace("@@AUXIPAK_URL@@", &base_url(st)?)
        .replace("@@ROOT_SHA256@@", &auxipak_core::hash::sha256_hex(&k.root_json));
    // Les ancres sont insérées en dernier : leur contenu n'est plus interprété.
    if ps1 {
        let b64 = base64::engine::general_purpose::STANDARD;
        s = s
            .replace("@@ROOT_B64@@", &b64.encode(&k.root_json))
            .replace("@@KEYS_B64@@", &b64.encode(&k.package_keys_json));
    } else {
        s = s
            .replace("@@ROOT_JSON@@", heredoc_safe(&k.root_json)?)
            .replace("@@KEYS_JSON@@", heredoc_safe(&k.package_keys_json)?);
    }
    Ok(s)
}

pub async fn install_sh(State(st): State<AppState>) -> ApiResult<Response> {
    Ok(script(fill(INSTALL_SH, &st, false)?))
}

pub async fn uninstall_sh(State(st): State<AppState>) -> ApiResult<Response> {
    Ok(script(fill(UNINSTALL_SH, &st, false)?))
}

pub async fn install_ps1(State(st): State<AppState>) -> ApiResult<Response> {
    // PowerShell 5.1 lit un fichier sans BOM en ANSI : gabarit en ASCII pur.
    Ok(script(fill(INSTALL_PS1, &st, true)?))
}

pub async fn uninstall_ps1(State(st): State<AppState>) -> ApiResult<Response> {
    Ok(script(fill(UNINSTALL_PS1, &st, true)?))
}

/// Nom de fichier téléchargeable : caractères sûrs, sans répertoire ni fichier caché.
fn is_safe_name(f: &str) -> bool {
    !f.is_empty()
        && f.len() <= 128
        && !f.starts_with('.')
        && f.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// `GET /downloads/{file}` : archives du client et `SHA256SUMS`.
pub async fn download(State(st): State<AppState>, Path(file): Path<String>) -> ApiResult<Response> {
    if !is_safe_name(&file) {
        return Err(ApiError::NotFound);
    }
    let path = st.config.downloads_dir.join(&file);
    let meta = tokio::fs::metadata(&path).await.map_err(|_| ApiError::NotFound)?;
    if !meta.is_file() {
        return Err(ApiError::NotFound);
    }
    let f = tokio::fs::File::open(&path).await?;
    let mut r = Response::new(Body::from_stream(tokio_util::io::ReaderStream::new(f)));
    let h = r.headers_mut();
    let ctype = if file == "SHA256SUMS" {
        "text/plain; charset=utf-8"
    } else {
        "application/octet-stream"
    };
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static(ctype));
    h.insert(header::CONTENT_LENGTH, HeaderValue::from(meta.len()));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    Ok(r)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noms_de_fichiers() {
        assert!(is_safe_name("auxipak-v1.0.0-linux-x86_64.tar.gz"));
        assert!(is_safe_name("SHA256SUMS"));
        for bad in ["", ".env", "../x", "a/b", "a\\b", "a b", "%2e%2e"] {
            assert!(!is_safe_name(bad), "{bad}");
        }
    }

    #[test]
    fn gabarits_powershell_ascii() {
        for t in [INSTALL_PS1, UNINSTALL_PS1] {
            assert!(t.is_ascii(), "les gabarits doivent rester en ASCII (PowerShell 5.1)");
        }
    }
}
