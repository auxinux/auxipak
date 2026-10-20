//! Connexion, déconnexion et jetons personnels.

use crate::audit;
use crate::auth::{self, Actor, Role, Scope, TokenKind, Via};
use crate::error::{bad, forbidden, ApiError, ApiResult};
use crate::state::AppState;
use auxipak_core::tr;
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::Json;
use axum_extra::extract::cookie::{Cookie, SameSite};
use axum_extra::extract::CookieJar;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use uuid::Uuid;

#[derive(Deserialize)]
pub struct LoginReq {
    pub username: String,
    pub password: String,
}

#[derive(sqlx::FromRow)]
pub struct UserAuthRow {
    pub id: Uuid,
    pub password_hash: String,
    pub role: String,
    pub active: bool,
}

/// Vérifie des identifiants (avec limitation des tentatives) ; retourne l'utilisateur.
pub async fn check_credentials(st: &AppState, username: &str, password: &str, ip: &str) -> ApiResult<(Uuid, Role)> {
    let key = format!("{ip}|{}", username.to_lowercase());
    if !st.throttle.check(&key) {
        return Err(ApiError::TooManyRequests);
    }
    let row: Option<UserAuthRow> = sqlx::query_as("SELECT id, password_hash, role, active FROM users WHERE username = $1")
        .bind(username.to_lowercase())
        .fetch_optional(&st.db)
        .await?;
    // Hachage factice : temps de réponse homogène si l'utilisateur n'existe pas
    // (pas d'énumération des comptes).
    static DUMMY: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    let ok = match &row {
        Some(r) => r.active && auth::verify_password(password, &r.password_hash),
        None => {
            let d = DUMMY.get_or_init(|| auth::hash_password("valeur-factice-anti-enumeration").unwrap_or_default());
            let _ = auth::verify_password(password, d);
            false
        }
    };
    if !ok {
        st.throttle.fail(&key);
        audit::log(&st.db, None, "auth.login_failed", username, serde_json::json!({"ip": ip})).await;
        return Err(ApiError::Unauthorized);
    }
    st.throttle.success(&key);
    let r = row.unwrap();
    Ok((r.id, Role::parse(&r.role).ok_or(ApiError::Unauthorized)?))
}

pub fn session_cookie(st: &AppState, token: String) -> Cookie<'static> {
    Cookie::build((auth::SESSION_COOKIE, token))
        .http_only(true)
        .secure(st.config.cookie_secure)
        .same_site(SameSite::Strict)
        .path("/")
        .max_age(time_duration(auth::SESSION_HOURS))
        .build()
}

fn time_duration(hours: i64) -> time::Duration {
    time::Duration::hours(hours)
}

pub fn peer_ip(st: &AppState, peer: Option<SocketAddr>, headers: &HeaderMap) -> String {
    let p = peer.map(|p| p.ip().to_string()).unwrap_or_default();
    if st.config.trusted_proxies.contains(&p) {
        if let Some(f) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
            if let Some(last) = f.split(',').next_back() {
                return last.trim().to_string();
            }
        }
    }
    p
}

pub async fn login(
    State(st): State<AppState>,
    peer: crate::auth::Peer,
    headers: HeaderMap,
    jar: CookieJar,
    Json(req): Json<LoginReq>,
) -> ApiResult<(CookieJar, Json<serde_json::Value>)> {
    let ip = peer_ip(&st, peer.0, &headers);
    let (uid, role) = check_credentials(&st, &req.username, &req.password, &ip).await?;
    let (token, csrf) = auth::create_session(&st, uid, Some(ip.clone())).await?;
    audit::log(&st.db, None, "auth.login", &req.username, serde_json::json!({"ip": ip})).await;
    Ok((
        jar.add(session_cookie(&st, token)),
        Json(serde_json::json!({"user": req.username.to_lowercase(), "role": role.as_str(), "csrf_token": csrf})),
    ))
}

pub async fn logout(State(st): State<AppState>, actor: Actor, jar: CookieJar) -> ApiResult<(CookieJar, Json<serde_json::Value>)> {
    if let Via::Session { token_hash, .. } = &actor.via {
        sqlx::query("DELETE FROM sessions WHERE token_hash = $1")
            .bind(token_hash)
            .execute(&st.db)
            .await?;
    }
    Ok((
        jar.remove(Cookie::from(auth::SESSION_COOKIE)),
        Json(serde_json::json!({"ok": true})),
    ))
}

pub async fn me(actor: Actor) -> Json<serde_json::Value> {
    let scopes: Vec<&str> = [
        Scope::Read,
        Scope::Build,
        Scope::Submit,
        Scope::Review,
        Scope::Evaluate,
        Scope::Admin,
    ]
    .into_iter()
    .filter(|s| actor.has(*s))
    .map(|s| s.as_str())
    .collect();
    Json(serde_json::json!({
        "user": actor.username, "role": actor.role.as_str(), "kind": actor.kind(), "scopes": scopes,
        "csrf_token": match &actor.via { Via::Session { csrf, .. } => Some(csrf.clone()), _ => None },
    }))
}

#[derive(Deserialize)]
pub struct TokenReq {
    pub name: String,
    pub kind: String,
    pub scopes: Vec<String>,
    #[serde(default)]
    pub provider: Option<String>,
    #[serde(default)]
    pub expires_days: Option<i64>,
    /// Administration uniquement : propriétaire du jeton.
    #[serde(default)]
    pub user_id: Option<Uuid>,
}

#[derive(sqlx::FromRow, Serialize)]
pub struct TokenRow {
    pub id: Uuid,
    pub name: String,
    pub user_id: Uuid,
    pub username: String,
    pub kind: String,
    pub provider: Option<String>,
    pub scopes: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub revoked: bool,
    pub expired: bool,
}

/// Crée un jeton ; retourne (identifiant, jeton en clair — affiché une seule fois).
pub async fn issue_token(
    st: &AppState,
    actor: &Actor,
    owner: Uuid,
    owner_role: Role,
    req: &TokenReq,
) -> ApiResult<(Uuid, String)> {
    if !actor.is_human() {
        return Err(forbidden(tr!(
            "seul un humain peut créer des jetons",
            "only a human can create tokens"
        )));
    }
    // Un jeton ne peut jamais servir à obtenir davantage de droits : seule une
    // session interactive, ou un jeton humain de portée « admin », peut émettre
    // un jeton, et uniquement avec des portées que l'émetteur détient lui-même.
    if let Via::Token { .. } = &actor.via {
        if !actor.has(Scope::Admin) {
            return Err(forbidden(tr!(
                "la création de jetons exige une session ou un jeton administrateur",
                "creating tokens requires a session or an administrator token"
            )));
        }
        for s in &req.scopes {
            if !Scope::parse(s).map(|sc| actor.has(sc)).unwrap_or(false) {
                return Err(forbidden(tr!(
                    "portée « {s} » non détenue par le jeton émetteur",
                    "scope '{s}' is not held by the issuing token"
                )));
            }
        }
    }
    let name = req.name.trim();
    if name.is_empty() || name.len() > 64 {
        return Err(bad(tr!("nom de jeton invalide", "invalid token name")));
    }
    let kind = TokenKind::parse(&req.kind).ok_or_else(|| {
        bad(tr!(
            "type de jeton invalide (human, ci, agent)",
            "invalid token type (human, ci, agent)"
        ))
    })?;
    let scopes: Vec<Scope> = req
        .scopes
        .iter()
        .map(|s| Scope::parse(s).ok_or_else(|| bad(tr!("portée inconnue : {s}", "unknown scope: {s}"))))
        .collect::<ApiResult<_>>()?;
    auth::validate_token_request(owner_role, kind, &scopes).map_err(bad)?;
    if let Some(p) = &req.provider {
        if p.len() > 64 || p.chars().any(|c| c.is_control()) {
            return Err(bad(tr!("fournisseur invalide", "invalid provider")));
        }
    }
    let days = req.expires_days.unwrap_or(90);
    if !(1..=366).contains(&days) {
        return Err(bad(tr!(
            "durée de validité : 1 à 366 jours",
            "validity period: 1 to 366 days"
        )));
    }
    let token = auth::random_token("apk_");
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO api_tokens (id, name, token_hash, user_id, kind, provider, scopes, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(id)
    .bind(name)
    .bind(auth::token_hash(&token))
    .bind(owner)
    .bind(kind.as_str())
    .bind(&req.provider)
    .bind(scopes.iter().map(|s| s.as_str().to_string()).collect::<Vec<_>>())
    .bind(Utc::now() + Duration::days(days))
    .execute(&st.db)
    .await?;
    audit::log(
        &st.db,
        Some(actor),
        "token.create",
        name,
        serde_json::json!({"token": id, "owner": owner, "kind": kind.as_str(), "scopes": req.scopes, "provider": req.provider}),
    )
    .await;
    Ok((id, token))
}

pub async fn create_own_token(
    State(st): State<AppState>,
    actor: Actor,
    Json(req): Json<TokenReq>,
) -> ApiResult<Json<serde_json::Value>> {
    if req.user_id.is_some_and(|u| u != actor.user_id) {
        return Err(forbidden(tr!(
            "utilisez /api/v1/admin/tokens pour un autre utilisateur",
            "use /api/v1/admin/tokens for another user"
        )));
    }
    let (id, token) = issue_token(&st, &actor, actor.user_id, actor.role, &req).await?;
    Ok(Json(
        serde_json::json!({"id": id, "token": token, "warning": tr!("ce jeton ne sera plus affiché", "this token will not be shown again")}),
    ))
}

pub async fn list_own_tokens(State(st): State<AppState>, actor: Actor) -> ApiResult<Json<Vec<TokenRow>>> {
    Ok(Json(
        sqlx::query_as(
            "SELECT t.id, t.name, t.user_id, u.username, t.kind, t.provider, t.scopes, t.created_at, t.expires_at, t.last_used_at, t.revoked,
                (t.expires_at IS NOT NULL AND t.expires_at < now()) AS expired
             FROM api_tokens t JOIN users u ON u.id = t.user_id WHERE t.user_id = $1 ORDER BY t.created_at DESC",
        )
        .bind(actor.user_id)
        .fetch_all(&st.db)
        .await?,
    ))
}

pub async fn revoke_own_token(
    State(st): State<AppState>,
    actor: Actor,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<serde_json::Value>> {
    let r = sqlx::query("UPDATE api_tokens SET revoked = TRUE WHERE id = $1 AND user_id = $2")
        .bind(id)
        .bind(actor.user_id)
        .execute(&st.db)
        .await?;
    if r.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    audit::log(&st.db, Some(&actor), "token.revoke", &id.to_string(), serde_json::json!({})).await;
    Ok(Json(serde_json::json!({"ok": true})))
}
