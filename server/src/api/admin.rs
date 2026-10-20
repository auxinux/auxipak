//! Administration : comptes, jetons, dépôts, versions, classification, journaux.

use crate::api::auth_routes::{issue_token, TokenReq, TokenRow};
use crate::audit;
use crate::auth::{self, Actor, Role, Scope};
use crate::error::{bad, forbidden, ApiError, ApiResult};
use crate::state::AppState;
use axum::extract::{Path, Query, State};
use axum::Json;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

fn require_admin(actor: &Actor) -> ApiResult<()> {
    actor.require(Scope::Admin)
}

#[derive(sqlx::FromRow, Serialize)]
pub struct UserRow {
    pub id: Uuid,
    pub username: String,
    pub display_name: String,
    pub role: String,
    pub active: bool,
    pub created_at: DateTime<Utc>,
    pub last_login_at: Option<DateTime<Utc>>,
}

pub async fn users(st: &AppState) -> ApiResult<Vec<UserRow>> {
    Ok(
        sqlx::query_as("SELECT id, username, display_name, role, active, created_at, last_login_at FROM users ORDER BY username")
            .fetch_all(&st.db)
            .await?,
    )
}

pub async fn list_users(State(st): State<AppState>, actor: Actor) -> ApiResult<Json<Vec<UserRow>>> {
    require_admin(&actor)?;
    Ok(Json(users(&st).await?))
}

#[derive(Deserialize)]
pub struct CreateUserReq {
    pub username: String,
    #[serde(default)]
    pub display_name: String,
    pub password: String,
    pub role: String,
}

/// Crée un compte (utilisé aussi par la commande `create-admin`).
pub async fn insert_user(st: &AppState, username: &str, display: &str, password: &str, role: Role) -> ApiResult<Uuid> {
    let username = username.trim().to_lowercase();
    let valid = username.len() >= 2
        && username.len() <= 32
        && username.chars().next().map(|c| c.is_ascii_alphanumeric()).unwrap_or(false)
        && username
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-'));
    if !valid {
        return Err(bad("identifiant invalide (minuscules, chiffres, . _ -, 2 à 32 caractères)"));
    }
    auth::check_password_strength(password).map_err(bad)?;
    let id = Uuid::new_v4();
    let hash = auth::hash_password(password)?;
    let r = sqlx::query("INSERT INTO users (id, username, display_name, password_hash, role) VALUES ($1, $2, $3, $4, $5)")
        .bind(id)
        .bind(&username)
        .bind(display)
        .bind(hash)
        .bind(role.as_str())
        .execute(&st.db)
        .await;
    match r {
        Ok(_) => Ok(id),
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => Err(ApiError::Conflict("cet identifiant existe déjà".into())),
        Err(e) => Err(e.into()),
    }
}

pub async fn create_user(
    State(st): State<AppState>,
    actor: Actor,
    Json(req): Json<CreateUserReq>,
) -> ApiResult<Json<serde_json::Value>> {
    require_admin(&actor)?;
    let role = Role::parse(&req.role).ok_or_else(|| bad("rôle invalide (admin, reviewer, publisher)"))?;
    let id = insert_user(&st, &req.username, &req.display_name, &req.password, role).await?;
    audit::log(
        &st.db,
        Some(&actor),
        "user.create",
        &req.username,
        serde_json::json!({"user": id, "role": role.as_str()}),
    )
    .await;
    Ok(Json(serde_json::json!({"id": id})))
}

#[derive(Deserialize, Default)]
pub struct UpdateUserReq {
    pub role: Option<String>,
    pub active: Option<bool>,
    pub password: Option<String>,
    pub display_name: Option<String>,
}

pub async fn apply_user_update(st: &AppState, actor: &Actor, id: Uuid, req: &UpdateUserReq) -> ApiResult<()> {
    require_admin(actor)?;
    if id == actor.user_id && (req.active == Some(false) || req.role.as_deref().is_some_and(|r| r != "admin")) {
        return Err(forbidden(
            "un administrateur ne peut pas se désactiver ni se rétrograder lui-même",
        ));
    }
    if let Some(r) = &req.role {
        let role = Role::parse(r).ok_or_else(|| bad("rôle invalide"))?;
        sqlx::query("UPDATE users SET role = $2 WHERE id = $1")
            .bind(id)
            .bind(role.as_str())
            .execute(&st.db)
            .await?;
        // Les jetons existants ne peuvent dépasser le nouveau rôle : on les révoque.
        sqlx::query("UPDATE api_tokens SET revoked = TRUE WHERE user_id = $1")
            .bind(id)
            .execute(&st.db)
            .await?;
    }
    if let Some(a) = req.active {
        sqlx::query("UPDATE users SET active = $2 WHERE id = $1")
            .bind(id)
            .bind(a)
            .execute(&st.db)
            .await?;
        if !a {
            sqlx::query("DELETE FROM sessions WHERE user_id = $1")
                .bind(id)
                .execute(&st.db)
                .await?;
        }
    }
    if let Some(p) = &req.password {
        auth::check_password_strength(p).map_err(bad)?;
        sqlx::query("UPDATE users SET password_hash = $2 WHERE id = $1")
            .bind(id)
            .bind(auth::hash_password(p)?)
            .execute(&st.db)
            .await?;
        sqlx::query("DELETE FROM sessions WHERE user_id = $1")
            .bind(id)
            .execute(&st.db)
            .await?;
    }
    if let Some(d) = &req.display_name {
        sqlx::query("UPDATE users SET display_name = $2 WHERE id = $1")
            .bind(id)
            .bind(d)
            .execute(&st.db)
            .await?;
    }
    audit::log(
        &st.db,
        Some(actor),
        "user.update",
        &id.to_string(),
        serde_json::json!({"role": req.role, "active": req.active, "password_changed": req.password.is_some()}),
    )
    .await;
    Ok(())
}

pub async fn update_user(
    State(st): State<AppState>,
    actor: Actor,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateUserReq>,
) -> ApiResult<Json<serde_json::Value>> {
    apply_user_update(&st, &actor, id, &req).await?;
    Ok(Json(serde_json::json!({"ok": true})))
}

pub async fn tokens(st: &AppState) -> ApiResult<Vec<TokenRow>> {
    Ok(sqlx::query_as(
        "SELECT t.id, t.name, t.user_id, u.username, t.kind, t.provider, t.scopes, t.created_at, t.expires_at, t.last_used_at, t.revoked,
                (t.expires_at IS NOT NULL AND t.expires_at < now()) AS expired
         FROM api_tokens t JOIN users u ON u.id = t.user_id ORDER BY t.created_at DESC",
    )
    .fetch_all(&st.db)
    .await?)
}

pub async fn list_tokens(State(st): State<AppState>, actor: Actor) -> ApiResult<Json<Vec<TokenRow>>> {
    require_admin(&actor)?;
    Ok(Json(tokens(&st).await?))
}

pub async fn create_token(
    State(st): State<AppState>,
    actor: Actor,
    Json(req): Json<TokenReq>,
) -> ApiResult<Json<serde_json::Value>> {
    require_admin(&actor)?;
    let owner = req.user_id.unwrap_or(actor.user_id);
    let role: (String,) = sqlx::query_as("SELECT role FROM users WHERE id = $1 AND active")
        .bind(owner)
        .fetch_optional(&st.db)
        .await?
        .ok_or(ApiError::NotFound)?;
    let role = Role::parse(&role.0).ok_or(ApiError::NotFound)?;
    let (id, token) = issue_token(&st, &actor, owner, role, &req).await?;
    Ok(Json(
        serde_json::json!({"id": id, "token": token, "warning": "ce jeton ne sera plus affiché"}),
    ))
}

pub async fn revoke_token(State(st): State<AppState>, actor: Actor, Path(id): Path<Uuid>) -> ApiResult<Json<serde_json::Value>> {
    require_admin(&actor)?;
    let r = sqlx::query("UPDATE api_tokens SET revoked = TRUE WHERE id = $1")
        .bind(id)
        .execute(&st.db)
        .await?;
    if r.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    audit::log(&st.db, Some(&actor), "token.revoke", &id.to_string(), serde_json::json!({})).await;
    Ok(Json(serde_json::json!({"ok": true})))
}

#[derive(sqlx::FromRow, Serialize)]
pub struct RepoRow {
    pub name: String,
    pub title: String,
    pub description: String,
    pub official: bool,
    pub enabled: bool,
    pub generation: i64,
    pub published_at: Option<DateTime<Utc>>,
}

pub async fn repositories(st: &AppState) -> ApiResult<Vec<RepoRow>> {
    Ok(sqlx::query_as(
        "SELECT name, title, description, official, enabled, generation, published_at FROM repositories ORDER BY name",
    )
    .fetch_all(&st.db)
    .await?)
}

pub async fn list_repositories(State(st): State<AppState>, actor: Actor) -> ApiResult<Json<Vec<RepoRow>>> {
    actor.require(Scope::Read)?;
    Ok(Json(repositories(&st).await?))
}

#[derive(Deserialize)]
pub struct RepoReq {
    pub name: String,
    pub title: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub official: bool,
}

pub async fn create_repository(
    State(st): State<AppState>,
    actor: Actor,
    Json(req): Json<RepoReq>,
) -> ApiResult<Json<serde_json::Value>> {
    require_admin(&actor)?;
    if !auxipak_core::ids::is_valid_repo_name(&req.name) {
        return Err(bad("nom de dépôt invalide"));
    }
    let r = sqlx::query("INSERT INTO repositories (name, title, description, official) VALUES ($1, $2, $3, $4)")
        .bind(&req.name)
        .bind(&req.title)
        .bind(&req.description)
        .bind(req.official)
        .execute(&st.db)
        .await;
    if let Err(sqlx::Error::Database(e)) = &r {
        if e.is_unique_violation() {
            return Err(ApiError::Conflict("ce dépôt existe déjà".into()));
        }
    }
    r?;
    audit::log(
        &st.db,
        Some(&actor),
        "repository.create",
        &req.name,
        serde_json::json!({"official": req.official}),
    )
    .await;
    crate::publisher::regenerate(&st, &req.name, Some(&actor)).await?;
    Ok(Json(serde_json::json!({"ok": true})))
}

#[derive(Deserialize)]
pub struct RepoUpdate {
    pub title: Option<String>,
    pub description: Option<String>,
    pub official: Option<bool>,
    pub enabled: Option<bool>,
}

pub async fn update_repository(
    State(st): State<AppState>,
    actor: Actor,
    Path(name): Path<String>,
    Json(req): Json<RepoUpdate>,
) -> ApiResult<Json<serde_json::Value>> {
    require_admin(&actor)?;
    let r = sqlx::query(
        "UPDATE repositories SET title = COALESCE($2, title), description = COALESCE($3, description),
            official = COALESCE($4, official), enabled = COALESCE($5, enabled) WHERE name = $1",
    )
    .bind(&name)
    .bind(&req.title)
    .bind(&req.description)
    .bind(req.official)
    .bind(req.enabled)
    .execute(&st.db)
    .await?;
    if r.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    audit::log(
        &st.db,
        Some(&actor),
        "repository.update",
        &name,
        serde_json::json!({"official": req.official, "enabled": req.enabled}),
    )
    .await;
    crate::publisher::regenerate(&st, &name, Some(&actor)).await?;
    Ok(Json(serde_json::json!({"ok": true})))
}

pub async fn regenerate(
    State(st): State<AppState>,
    actor: Actor,
    Path(name): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    require_admin(&actor)?;
    let g = crate::publisher::regenerate(&st, &name, Some(&actor)).await?;
    Ok(Json(serde_json::json!({"generation": g})))
}

#[derive(Deserialize)]
pub struct ReleaseQuery {
    pub repository: Option<String>,
    pub app_id: Option<String>,
}

#[derive(sqlx::FromRow, Serialize)]
pub struct AdminReleaseRow {
    pub id: Uuid,
    pub repository: String,
    pub app_id: String,
    pub version: String,
    pub file_name: String,
    pub size: i64,
    pub sha256: String,
    pub signature_key_id: String,
    pub uses_scripts: bool,
    pub state: String,
    pub state_reason: Option<String>,
    pub published_at: DateTime<Utc>,
    pub published_by: Option<String>,
}

pub async fn releases(st: &AppState, repo: Option<&str>, app: Option<&str>) -> ApiResult<Vec<AdminReleaseRow>> {
    Ok(sqlx::query_as(
        "SELECT r.id, r.repository, r.app_id, r.version, r.file_name, r.size, r.sha256, r.signature_key_id, r.uses_scripts,
                r.state, r.state_reason, r.published_at, u.username AS published_by
         FROM releases r LEFT JOIN users u ON u.id = r.published_by
         WHERE r.state <> 'purged' AND ($1::text IS NULL OR r.repository = $1) AND ($2::text IS NULL OR r.app_id = $2)
         ORDER BY r.published_at DESC LIMIT 1000",
    )
    .bind(repo)
    .bind(app)
    .fetch_all(&st.db)
    .await?)
}

pub async fn list_releases(
    State(st): State<AppState>,
    actor: Actor,
    Query(q): Query<ReleaseQuery>,
) -> ApiResult<Json<Vec<AdminReleaseRow>>> {
    actor.require(Scope::Read)?;
    Ok(Json(releases(&st, q.repository.as_deref(), q.app_id.as_deref()).await?))
}

#[derive(Deserialize)]
pub struct StateReq {
    pub state: String,
    #[serde(default)]
    pub reason: String,
}

pub async fn set_release_state(
    State(st): State<AppState>,
    actor: Actor,
    Path(id): Path<Uuid>,
    Json(req): Json<StateReq>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::publisher::set_release_state(&st, &actor, id, &req.state, &req.reason).await?;
    Ok(Json(serde_json::json!({"ok": true})))
}

#[derive(Deserialize)]
pub struct EvaluationReq {
    pub status: String,
    #[serde(default)]
    pub note: Option<String>,
    /// Grille d'évaluation (vie privée, télémétrie, sécurité, licence…).
    #[serde(default)]
    pub criteria: serde_json::Value,
}

/// Classification officielle (statut AuxiNux) : relecteur humain uniquement.
pub async fn apply_evaluation(st: &AppState, actor: &Actor, app_id: &str, req: &EvaluationReq) -> ApiResult<()> {
    actor.require(Scope::Evaluate)?;
    let status: auxipak_core::index::Status = req.status.parse().map_err(bad)?;
    if status == auxipak_core::index::Status::Compatible && req.note.as_deref().unwrap_or("").trim().is_empty() {
        return Err(bad(
            "le statut « compatible » exige que les réserves soient documentées dans la note",
        ));
    }
    let exists: Option<(String,)> = sqlx::query_as("SELECT id FROM apps WHERE id = $1")
        .bind(app_id)
        .fetch_optional(&st.db)
        .await?;
    if exists.is_none() {
        return Err(ApiError::NotFound);
    }
    let criteria = if req.criteria.is_null() {
        serde_json::json!({})
    } else {
        req.criteria.clone()
    };
    let mut tx = st.db.begin().await?;
    sqlx::query(
        "INSERT INTO evaluations (app_id, status, note, criteria, evaluated_by, evaluated_at) VALUES ($1, $2, $3, $4, $5, now())
         ON CONFLICT (app_id) DO UPDATE SET status = EXCLUDED.status, note = EXCLUDED.note, criteria = EXCLUDED.criteria,
            evaluated_by = EXCLUDED.evaluated_by, evaluated_at = now()",
    )
    .bind(app_id)
    .bind(status.as_str())
    .bind(&req.note)
    .bind(&criteria)
    .bind(actor.user_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query("INSERT INTO evaluation_history (app_id, status, note, evaluated_by) VALUES ($1, $2, $3, $4)")
        .bind(app_id)
        .bind(status.as_str())
        .bind(&req.note)
        .bind(actor.user_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    audit::log(
        &st.db,
        Some(actor),
        "app.evaluate",
        app_id,
        serde_json::json!({"status": status.as_str(), "note": req.note}),
    )
    .await;
    let repos: Vec<(String,)> =
        sqlx::query_as("SELECT DISTINCT repository FROM releases WHERE app_id = $1 AND state = 'published'")
            .bind(app_id)
            .fetch_all(&st.db)
            .await?;
    for (r,) in repos {
        crate::publisher::regenerate(st, &r, Some(actor)).await?;
    }
    Ok(())
}

pub async fn set_evaluation(
    State(st): State<AppState>,
    actor: Actor,
    Path(id): Path<String>,
    Json(req): Json<EvaluationReq>,
) -> ApiResult<Json<serde_json::Value>> {
    apply_evaluation(&st, &actor, &id, &req).await?;
    Ok(Json(serde_json::json!({"ok": true})))
}

#[derive(Deserialize)]
pub struct AuditQuery {
    pub limit: Option<i64>,
    pub before_id: Option<i64>,
}

#[derive(sqlx::FromRow, Serialize)]
pub struct AuditRow {
    pub id: i64,
    pub at: DateTime<Utc>,
    pub actor_name: String,
    pub actor_kind: String,
    pub action: String,
    pub target: String,
    pub details: serde_json::Value,
    pub ip: Option<String>,
}

pub async fn audit_rows(st: &AppState, limit: i64, before: Option<i64>) -> ApiResult<Vec<AuditRow>> {
    Ok(sqlx::query_as(
        "SELECT id, at, actor_name, actor_kind, action, target, details, ip FROM audit_log
         WHERE ($2::bigint IS NULL OR id < $2) ORDER BY id DESC LIMIT $1",
    )
    .bind(limit.clamp(1, 1000))
    .bind(before)
    .fetch_all(&st.db)
    .await?)
}

pub async fn audit(State(st): State<AppState>, actor: Actor, Query(q): Query<AuditQuery>) -> ApiResult<Json<Vec<AuditRow>>> {
    require_admin(&actor)?;
    Ok(Json(audit_rows(&st, q.limit.unwrap_or(200), q.before_id).await?))
}
