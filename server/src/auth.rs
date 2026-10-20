//! Authentification (sessions, jetons d'API) et autorisation (rôles, portées).
//!
//! Rôles humains :
//! - `publisher` : construit et soumet des paquets ;
//! - `reviewer`  : en plus, approuve/rejette, classe, dépublie, révoque ;
//! - `admin`     : en plus, gère comptes, jetons, dépôts, régénération, journaux.
//!
//! Jetons d'API : portées explicites (`read`, `build`, `submit`, `review`,
//! `evaluate`, `admin`), bornées par le rôle du propriétaire. Un jeton de type
//! `agent` (automatisation, IA) est limité à `read`, `build` et `submit` :
//! il ne peut jamais approuver, publier, classer, ni toucher aux comptes ou
//! aux clés. Un jeton `ci` ne peut pas non plus approuver ni classer.

use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use argon2::password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use auxipak_core::tr;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::Method;
use axum_extra::extract::CookieJar;
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub const SESSION_COOKIE: &str = "auxipak_session";
pub const SESSION_HOURS: i64 = 12;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Publisher,
    Reviewer,
    Admin,
}

impl Role {
    pub fn parse(s: &str) -> Option<Role> {
        match s {
            "publisher" => Some(Role::Publisher),
            "reviewer" => Some(Role::Reviewer),
            "admin" => Some(Role::Admin),
            _ => None,
        }
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            Role::Publisher => "publisher",
            Role::Reviewer => "reviewer",
            Role::Admin => "admin",
        }
    }
    /// Portées accessibles à ce rôle.
    pub fn allowed_scopes(&self) -> &'static [Scope] {
        match self {
            Role::Publisher => &[Scope::Read, Scope::Build, Scope::Submit],
            Role::Reviewer => &[Scope::Read, Scope::Build, Scope::Submit, Scope::Review, Scope::Evaluate],
            Role::Admin => &[
                Scope::Read,
                Scope::Build,
                Scope::Submit,
                Scope::Review,
                Scope::Evaluate,
                Scope::Admin,
            ],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    Read,
    Build,
    Submit,
    Review,
    Evaluate,
    Admin,
}

impl Scope {
    pub fn parse(s: &str) -> Option<Scope> {
        match s {
            "read" => Some(Scope::Read),
            "build" => Some(Scope::Build),
            "submit" => Some(Scope::Submit),
            "review" => Some(Scope::Review),
            "evaluate" => Some(Scope::Evaluate),
            "admin" => Some(Scope::Admin),
            _ => None,
        }
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            Scope::Read => "read",
            Scope::Build => "build",
            Scope::Submit => "submit",
            Scope::Review => "review",
            Scope::Evaluate => "evaluate",
            Scope::Admin => "admin",
        }
    }
    /// Portée sensible : réservée aux humains.
    pub fn human_only(&self) -> bool {
        matches!(self, Scope::Review | Scope::Evaluate | Scope::Admin)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TokenKind {
    Human,
    Ci,
    Agent,
}

impl TokenKind {
    pub fn parse(s: &str) -> Option<TokenKind> {
        match s {
            "human" => Some(TokenKind::Human),
            "ci" => Some(TokenKind::Ci),
            "agent" => Some(TokenKind::Agent),
            _ => None,
        }
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            TokenKind::Human => "human",
            TokenKind::Ci => "ci",
            TokenKind::Agent => "agent",
        }
    }
}

/// Mode d'authentification de l'acteur.
#[derive(Debug, Clone)]
pub enum Via {
    Session {
        csrf: String,
        token_hash: String,
    },
    Token {
        id: Uuid,
        kind: TokenKind,
        scopes: Vec<Scope>,
        provider: Option<String>,
    },
}

/// Acteur authentifié.
#[derive(Debug, Clone)]
pub struct Actor {
    pub user_id: Uuid,
    pub username: String,
    pub role: Role,
    pub via: Via,
    pub ip: Option<String>,
}

impl Actor {
    /// Type d'acteur pour le journal (`session`, `human`, `ci`, `agent`).
    pub fn kind(&self) -> &'static str {
        match &self.via {
            Via::Session { .. } => "session",
            Via::Token { kind, .. } => kind.as_str(),
        }
    }

    pub fn is_human(&self) -> bool {
        matches!(
            self.via,
            Via::Session { .. }
                | Via::Token {
                    kind: TokenKind::Human,
                    ..
                }
        )
    }

    pub fn token_id(&self) -> Option<Uuid> {
        match &self.via {
            Via::Token { id, .. } => Some(*id),
            _ => None,
        }
    }

    pub fn display(&self) -> String {
        match &self.via {
            Via::Session { .. } => self.username.clone(),
            Via::Token { kind, provider, .. } => format!(
                "{} [{}{}]",
                self.username,
                kind.as_str(),
                provider.as_ref().map(|p| format!(" : {p}")).unwrap_or_default()
            ),
        }
    }

    pub fn has(&self, scope: Scope) -> bool {
        if !self.role.allowed_scopes().contains(&scope) {
            return false;
        }
        match &self.via {
            Via::Session { .. } => true,
            Via::Token { kind, scopes, .. } => {
                if scope.human_only() && *kind != TokenKind::Human {
                    return false;
                }
                scopes.contains(&scope)
            }
        }
    }

    pub fn require(&self, scope: Scope) -> ApiResult<()> {
        if self.has(scope) {
            Ok(())
        } else {
            let human = if scope.human_only() && !self.is_human() {
                tr!(" (réservée à un humain)", " (reserved for a human)")
            } else {
                String::new()
            };
            Err(ApiError::Forbidden(tr!(
                "droits insuffisants : la portée « {} » est requise{}",
                "insufficient permissions: the '{}' scope is required{}",
                scope.as_str(),
                human
            )))
        }
    }
}

pub fn hash_password(pw: &str) -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    Ok(Argon2::default()
        .hash_password(pw.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("hachage : {e}"))?
        .to_string())
}

pub fn verify_password(pw: &str, hash: &str) -> bool {
    PasswordHash::new(hash)
        .map(|h| Argon2::default().verify_password(pw.as_bytes(), &h).is_ok())
        .unwrap_or(false)
}

/// Règles minimales de mot de passe.
pub fn check_password_strength(pw: &str) -> Result<(), String> {
    if pw.chars().count() < 12 {
        return Err(tr!(
            "le mot de passe doit contenir au moins 12 caractères",
            "the password must contain at least 12 characters"
        ));
    }
    if pw.chars().all(|c| c.is_ascii_lowercase()) || pw.chars().all(|c| c.is_ascii_digit()) {
        return Err(tr!(
            "le mot de passe doit mélanger plusieurs types de caractères",
            "the password must mix several types of characters"
        ));
    }
    Ok(())
}

pub fn random_token(prefix: &str) -> String {
    let mut b = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut b);
    format!("{prefix}{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b))
}

pub fn token_hash(t: &str) -> String {
    hex::encode(Sha256::digest(t.as_bytes()))
}

#[derive(sqlx::FromRow)]
struct TokenRow {
    id: Uuid,
    user_id: Uuid,
    username: String,
    role: String,
    kind: String,
    provider: Option<String>,
    scopes: Vec<String>,
    expires_at: Option<DateTime<Utc>>,
}

#[derive(sqlx::FromRow)]
struct SessionRow {
    user_id: Uuid,
    username: String,
    role: String,
    csrf_token: String,
}

/// Adresse IP du client (en-tête X-Forwarded-For pris en compte uniquement
/// derrière un mandataire de confiance).
pub fn client_ip(state: &AppState, parts: &Parts) -> Option<String> {
    let peer = parts
        .extensions
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|c| c.0.ip().to_string());
    match &peer {
        Some(p) if state.config.trusted_proxies.contains(p) => parts
            .headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next_back())
            .map(|s| s.trim().to_string())
            .or(peer),
        _ => peer,
    }
}

/// Authentifie une requête (jeton Bearer ou cookie de session).
pub async fn authenticate(state: &AppState, parts: &Parts) -> ApiResult<Option<Actor>> {
    let ip = client_ip(state, parts);
    if let Some(h) = parts.headers.get(axum::http::header::AUTHORIZATION) {
        let v = h.to_str().map_err(|_| ApiError::Unauthorized)?;
        let tok = v.strip_prefix("Bearer ").ok_or(ApiError::Unauthorized)?.trim();
        let row: Option<TokenRow> = sqlx::query_as(
            "SELECT t.id, t.user_id, u.username, u.role, t.kind, t.provider, t.scopes, t.expires_at
             FROM api_tokens t JOIN users u ON u.id = t.user_id
             WHERE t.token_hash = $1 AND NOT t.revoked AND u.active",
        )
        .bind(token_hash(tok))
        .fetch_optional(&state.db)
        .await?;
        let row = row.ok_or(ApiError::Unauthorized)?;
        if row.expires_at.map(|e| e < Utc::now()).unwrap_or(false) {
            return Err(ApiError::Unauthorized);
        }
        sqlx::query("UPDATE api_tokens SET last_used_at = now() WHERE id = $1")
            .bind(row.id)
            .execute(&state.db)
            .await?;
        let role = Role::parse(&row.role).ok_or(ApiError::Unauthorized)?;
        let kind = TokenKind::parse(&row.kind).ok_or(ApiError::Unauthorized)?;
        return Ok(Some(Actor {
            user_id: row.user_id,
            username: row.username,
            role,
            via: Via::Token {
                id: row.id,
                kind,
                scopes: row.scopes.iter().filter_map(|s| Scope::parse(s)).collect(),
                provider: row.provider,
            },
            ip,
        }));
    }
    let jar = CookieJar::from_headers(&parts.headers);
    if let Some(c) = jar.get(SESSION_COOKIE) {
        let th = token_hash(c.value());
        let row: Option<SessionRow> = sqlx::query_as(
            "SELECT s.user_id, u.username, u.role, s.csrf_token FROM sessions s JOIN users u ON u.id = s.user_id
             WHERE s.token_hash = $1 AND s.expires_at > now() AND u.active",
        )
        .bind(&th)
        .fetch_optional(&state.db)
        .await?;
        if let Some(r) = row {
            let role = Role::parse(&r.role).ok_or(ApiError::Unauthorized)?;
            return Ok(Some(Actor {
                user_id: r.user_id,
                username: r.username,
                role,
                via: Via::Session {
                    csrf: r.csrf_token,
                    token_hash: th,
                },
                ip,
            }));
        }
    }
    Ok(None)
}

/// Extracteur : acteur authentifié obligatoire. Pour une session, les
/// requêtes non sûres exigent l'en-tête `X-CSRF-Token`.
impl FromRequestParts<AppState> for Actor {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let actor = authenticate(state, parts).await?.ok_or(ApiError::Unauthorized)?;
        if let Via::Session { csrf, .. } = &actor.via {
            let safe = matches!(parts.method, Method::GET | Method::HEAD | Method::OPTIONS);
            if !safe {
                let hdr = parts.headers.get("x-csrf-token").and_then(|v| v.to_str().ok()).unwrap_or("");
                if !crate::util::ct_eq(hdr, csrf) {
                    return Err(ApiError::Forbidden(tr!(
                        "jeton CSRF manquant ou invalide",
                        "missing or invalid CSRF token"
                    )));
                }
            }
        }
        Ok(actor)
    }
}

/// Crée une session et retourne (jeton en clair, jeton CSRF).
pub async fn create_session(state: &AppState, user_id: Uuid, ip: Option<String>) -> anyhow::Result<(String, String)> {
    let token = random_token("s_");
    let csrf = random_token("");
    sqlx::query("INSERT INTO sessions (token_hash, user_id, csrf_token, expires_at, ip) VALUES ($1, $2, $3, $4, $5)")
        .bind(token_hash(&token))
        .bind(user_id)
        .bind(&csrf)
        .bind(Utc::now() + Duration::hours(SESSION_HOURS))
        .bind(ip)
        .execute(&state.db)
        .await?;
    sqlx::query("UPDATE users SET last_login_at = now() WHERE id = $1")
        .bind(user_id)
        .execute(&state.db)
        .await?;
    sqlx::query("DELETE FROM sessions WHERE expires_at < now()")
        .execute(&state.db)
        .await?;
    Ok((token, csrf))
}

/// Limitation des tentatives de connexion (mémoire, par IP et identifiant).
#[derive(Default)]
pub struct LoginThrottle {
    attempts: std::sync::Mutex<std::collections::HashMap<String, Vec<DateTime<Utc>>>>,
}

impl LoginThrottle {
    const WINDOW_MIN: i64 = 15;
    const MAX: usize = 5;

    pub fn check(&self, key: &str) -> bool {
        let mut m = self.attempts.lock().unwrap();
        let cutoff = Utc::now() - Duration::minutes(Self::WINDOW_MIN);
        let v = m.entry(key.to_string()).or_default();
        v.retain(|t| *t > cutoff);
        v.len() < Self::MAX
    }

    pub fn fail(&self, key: &str) {
        self.attempts
            .lock()
            .unwrap()
            .entry(key.to_string())
            .or_default()
            .push(Utc::now());
    }

    pub fn success(&self, key: &str) {
        self.attempts.lock().unwrap().remove(key);
    }
}

/// Vérifie une demande de création de jeton.
pub fn validate_token_request(owner_role: Role, kind: TokenKind, scopes: &[Scope]) -> Result<(), String> {
    if scopes.is_empty() {
        return Err(tr!("au moins une portée est requise", "at least one scope is required"));
    }
    for s in scopes {
        if !owner_role.allowed_scopes().contains(s) {
            return Err(tr!(
                "portée « {} » non autorisée pour le rôle {}",
                "scope '{}' is not allowed for the {} role",
                s.as_str(),
                owner_role.as_str()
            ));
        }
        if s.human_only() && kind != TokenKind::Human {
            return Err(tr!(
                "portée « {} » interdite pour un jeton {}",
                "scope '{}' is forbidden for a {} token",
                s.as_str(),
                kind.as_str()
            ));
        }
    }
    Ok(())
}

/// Adresse du pair TCP (si le serveur a été lancé avec `ConnectInfo`).
pub struct Peer(pub Option<std::net::SocketAddr>);

impl<S: Send + Sync> FromRequestParts<S> for Peer {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        Ok(Peer(
            parts
                .extensions
                .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
                .map(|c| c.0),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn actor(role: Role, via: Via) -> Actor {
        Actor {
            user_id: Uuid::nil(),
            username: "x".into(),
            role,
            via,
            ip: None,
        }
    }

    #[test]
    fn passwords() {
        let h = hash_password("Correct-horse-42").unwrap();
        assert!(verify_password("Correct-horse-42", &h));
        assert!(!verify_password("wrong", &h));
        assert!(check_password_strength("short").is_err());
        assert!(check_password_strength("aaaaaaaaaaaaaaa").is_err());
        assert!(check_password_strength("Bonne-Phrase-2026").is_ok());
    }

    #[test]
    fn agent_tokens_can_never_review_or_admin() {
        let agent = actor(
            Role::Admin,
            Via::Token {
                id: Uuid::nil(),
                kind: TokenKind::Agent,
                scopes: vec![Scope::Build, Scope::Submit, Scope::Review, Scope::Admin],
                provider: Some("mon-agent".into()),
            },
        );
        assert!(agent.has(Scope::Build));
        assert!(agent.has(Scope::Submit));
        assert!(!agent.has(Scope::Review));
        assert!(!agent.has(Scope::Evaluate));
        assert!(!agent.has(Scope::Admin));
        assert!(validate_token_request(Role::Admin, TokenKind::Agent, &[Scope::Review]).is_err());
        assert!(validate_token_request(Role::Admin, TokenKind::Ci, &[Scope::Admin]).is_err());
        assert!(validate_token_request(Role::Admin, TokenKind::Agent, &[Scope::Build, Scope::Submit]).is_ok());
    }

    #[test]
    fn role_bounds_scopes() {
        let publisher = actor(
            Role::Publisher,
            Via::Session {
                csrf: String::new(),
                token_hash: String::new(),
            },
        );
        assert!(publisher.has(Scope::Submit));
        assert!(!publisher.has(Scope::Review));
        assert!(validate_token_request(Role::Publisher, TokenKind::Human, &[Scope::Review]).is_err());
        let reviewer = actor(
            Role::Reviewer,
            Via::Session {
                csrf: String::new(),
                token_hash: String::new(),
            },
        );
        assert!(reviewer.has(Scope::Review));
        assert!(!reviewer.has(Scope::Admin));
    }

    #[test]
    fn throttle() {
        let t = LoginThrottle::default();
        for _ in 0..5 {
            assert!(t.check("k"));
            t.fail("k");
        }
        assert!(!t.check("k"));
        t.success("k");
        assert!(t.check("k"));
    }
}
