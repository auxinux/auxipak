//! Politique réseau : validation des URL de téléchargement et des redirections.

use url::{Host, Url};

/// Valide une URL de téléchargement distant : HTTPS obligatoire, nom d'hôte DNS
/// (pas d'adresse IP littérale), pas d'identifiants intégrés, pas de fragment.
pub fn validate_https_url(raw: &str) -> Result<Url, String> {
    let u = Url::parse(raw).map_err(|e| format!("URL invalide « {raw} » : {e}"))?;
    if u.scheme() != "https" {
        return Err(format!("URL refusée (HTTPS obligatoire) : {raw}"));
    }
    if !u.username().is_empty() || u.password().is_some() {
        return Err("URL refusée : identifiants intégrés interdits".into());
    }
    if u.fragment().is_some() {
        return Err("URL refusée : fragment interdit".into());
    }
    match u.host() {
        Some(Host::Domain(d)) if is_valid_host(d) => Ok(u),
        Some(Host::Domain(_)) => Err(format!("nom d'hôte invalide : {raw}")),
        Some(_) => Err("URL refusée : les adresses IP littérales sont interdites".into()),
        None => Err("URL refusée : hôte manquant".into()),
    }
}

/// Nom d'hôte DNS syntaxiquement valide (sans joker).
pub fn is_valid_host(h: &str) -> bool {
    let h = h.trim_end_matches('.');
    !h.is_empty()
        && h.len() <= 253
        && h.contains('.')
        && h.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
        })
}

/// Vérifie qu'une redirection vers `next` est autorisée : HTTPS et hôte dans
/// la liste blanche (hôte d'origine + `allowed_hosts`). Une politique de
/// redirection doit appeler cette fonction pour chaque saut.
pub fn redirect_allowed(next: &Url, allowed_hosts: &[String]) -> Result<(), String> {
    if next.scheme() != "https" {
        return Err(format!("redirection refusée vers une URL non HTTPS : {next}"));
    }
    let host = next.host_str().unwrap_or_default().to_ascii_lowercase();
    if allowed_hosts.iter().any(|a| a.eq_ignore_ascii_case(&host)) {
        Ok(())
    } else {
        Err(format!("redirection refusée vers un hôte non autorisé : {host}"))
    }
}

/// URL de dépôt : HTTPS, `file://` (miroir local, toujours vérifié par TUF) ou
/// HTTP limité à la boucle locale lorsque `allow_insecure_localhost` est vrai
/// (développement uniquement).
pub fn validate_repo_url(raw: &str, allow_insecure_localhost: bool) -> Result<Url, String> {
    let mut u = Url::parse(raw).map_err(|e| format!("URL de dépôt invalide « {raw} » : {e}"))?;
    if !u.path().ends_with('/') {
        let p = format!("{}/", u.path());
        u.set_path(&p);
    }
    if !u.username().is_empty() || u.password().is_some() {
        return Err("URL de dépôt refusée : identifiants intégrés interdits".into());
    }
    match u.scheme() {
        "https" | "file" => Ok(u),
        "http" => {
            let local = matches!(u.host_str(), Some("localhost") | Some("127.0.0.1") | Some("[::1]"));
            if local && allow_insecure_localhost {
                Ok(u)
            } else {
                Err(format!(
                    "URL de dépôt refusée (HTTPS obligatoire{}) : {raw}",
                    if local { " ; HTTP local exige allow_insecure_localhost" } else { "" }
                ))
            }
        }
        s => Err(format!("schéma d'URL non pris en charge : {s}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn https_only() {
        assert!(validate_https_url("https://download.mozilla.org/a.msi").is_ok());
        assert!(validate_https_url("http://download.mozilla.org/a.msi").is_err());
        assert!(validate_https_url("https://user:pw@x.org/a").is_err());
        assert!(validate_https_url("https://127.0.0.1/a").is_err());
        assert!(validate_https_url("https://[::1]/a").is_err());
        assert!(validate_https_url("ftp://x.org/a").is_err());
        assert!(validate_https_url("file:///etc/passwd").is_err());
    }

    #[test]
    fn redirects() {
        let allowed = vec!["a.example.org".to_string(), "cdn.example.org".to_string()];
        assert!(redirect_allowed(&Url::parse("https://cdn.example.org/x").unwrap(), &allowed).is_ok());
        assert!(redirect_allowed(&Url::parse("https://evil.example.com/x").unwrap(), &allowed).is_err());
        assert!(redirect_allowed(&Url::parse("http://cdn.example.org/x").unwrap(), &allowed).is_err());
    }

    #[test]
    fn repo_urls() {
        assert!(validate_repo_url("https://pak.auxinux.ca/repos/official", false).is_ok());
        assert_eq!(
            validate_repo_url("https://pak.auxinux.ca/repos/official", false).unwrap().as_str(),
            "https://pak.auxinux.ca/repos/official/"
        );
        assert!(validate_repo_url("http://pak.auxinux.ca/", true).is_err());
        assert!(validate_repo_url("http://127.0.0.1:8080/repos/official", false).is_err());
        assert!(validate_repo_url("http://127.0.0.1:8080/repos/official", true).is_ok());
        assert!(validate_repo_url("file:///srv/mirror/", false).is_ok());
    }
}
