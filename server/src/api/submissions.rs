//! Demandes de publication.
//!
//! Une soumission ne publie jamais rien : elle crée une demande `pending`
//! (ou `invalid` si l'analyse échoue) qu'un relecteur humain doit approuver.

use crate::audit;
use crate::auth::{Actor, Scope};
use crate::error::{bad, forbidden, ApiError, ApiResult};
use crate::publisher;
use crate::state::AppState;
use auxipak_core::signature::PackageSignature;
use auxipak_core::tr;
use axum::body::{Body, Bytes};
use axum::extract::{Path, Query, State};
use axum::Json;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Deserialize)]
pub struct CreateQuery {
    pub repository: Option<String>,
    pub file_name: Option<String>,
    #[serde(default)]
    pub note: String,
}

#[derive(sqlx::FromRow, Serialize, Clone)]
pub struct SubmissionView {
    pub id: Uuid,
    pub repository: String,
    pub file_name: String,
    pub size: i64,
    pub sha256: String,
    pub app_id: Option<String>,
    pub version: Option<String>,
    pub validation: serde_json::Value,
    pub has_signature: bool,
    pub status: String,
    pub submitter: Option<String>,
    pub submitter_kind: String,
    pub note: String,
    pub reviewer: Option<String>,
    pub reviewed_at: Option<DateTime<Utc>>,
    pub review_note: Option<String>,
    pub created_at: DateTime<Utc>,
    pub manifest: Option<serde_json::Value>,
}

const SELECT: &str = "SELECT s.id, s.repository, s.file_name, s.size, s.sha256, s.app_id, s.version, s.validation,
        (s.signature IS NOT NULL) AS has_signature, s.status, u.username AS submitter, s.submitter_kind, s.note,
        r.username AS reviewer, s.reviewed_at, s.review_note, s.created_at, s.manifest
     FROM submissions s LEFT JOIN users u ON u.id = s.submitted_by LEFT JOIN users r ON r.id = s.reviewed_by";

/// Crée une soumission à partir d'un fichier déjà écrit sur disque.
#[allow(clippy::too_many_arguments)]
pub async fn create_from_file(
    st: &AppState,
    actor: &Actor,
    repository: &str,
    file_name: Option<&str>,
    note: &str,
    tmp_path: &std::path::Path,
    sha256: String,
    size: u64,
) -> ApiResult<SubmissionView> {
    actor.require(Scope::Submit)?;
    let repo: Option<(bool,)> = sqlx::query_as("SELECT enabled FROM repositories WHERE name = $1")
        .bind(repository)
        .fetch_optional(&st.db)
        .await?;
    if !repo.map(|r| r.0).unwrap_or(false) {
        return Err(bad(tr!(
            "dépôt inconnu ou désactivé : {repository}",
            "unknown or disabled repository: {repository}"
        )));
    }
    if note.len() > 2000 {
        return Err(bad(tr!("note trop longue", "note too long")));
    }
    let id = Uuid::new_v4();
    let (insp, report) = crate::validation::analyze(tmp_path);
    let file_name = match (file_name, &insp) {
        (Some(f), _) if auxipak_core::ids::is_safe_file_name(f) && auxipak_core::archive::is_package_name(f) => f.to_string(),
        (_, Some(i)) => i.manifest.suggested_file_name(),
        _ => format!("{id}.aupak"),
    };
    let status = if report.ok { "pending" } else { "invalid" };
    let dest = publisher::submission_file(st, id);
    std::fs::create_dir_all(st.config.submissions_dir())?;
    std::fs::rename(tmp_path, &dest)?;
    sqlx::query(
        "INSERT INTO submissions (id, repository, file_name, size, sha256, app_id, version, manifest, validation, status,
            submitted_by, token_id, submitter_kind, note)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)",
    )
    .bind(id)
    .bind(repository)
    .bind(&file_name)
    .bind(size as i64)
    .bind(&sha256)
    .bind(insp.as_ref().map(|i| i.manifest.id.clone()))
    .bind(insp.as_ref().map(|i| i.manifest.version.clone()))
    .bind(insp.as_ref().map(|i| serde_json::to_value(&i.manifest).unwrap_or_default()))
    .bind(serde_json::to_value(&report).map_err(anyhow::Error::from)?)
    .bind(status)
    .bind(actor.user_id)
    .bind(actor.token_id())
    .bind(actor.kind())
    .bind(note)
    .execute(&st.db)
    .await?;
    audit::log(
        &st.db,
        Some(actor),
        "submission.create",
        &file_name,
        serde_json::json!({"submission": id, "status": status, "sha256": sha256, "repository": repository}),
    )
    .await;
    load(st, id).await
}

pub async fn load(st: &AppState, id: Uuid) -> ApiResult<SubmissionView> {
    let q = format!("{SELECT} WHERE s.id = $1");
    let mut v: SubmissionView = sqlx::query_as(sqlx::AssertSqlSafe(q))
        .bind(id)
        .fetch_optional(&st.db)
        .await?
        .ok_or(ApiError::NotFound)?;
    crate::validation::localize(&mut v.validation);
    Ok(v)
}

pub async fn create(
    State(st): State<AppState>,
    actor: Actor,
    Query(q): Query<CreateQuery>,
    body: Body,
) -> ApiResult<Json<SubmissionView>> {
    actor.require(Scope::Submit)?;
    std::fs::create_dir_all(st.config.tmp_dir())?;
    let tmp = st.config.tmp_dir().join(format!("upload-{}.aupak", Uuid::new_v4()));
    let (sha, size) = crate::api::body_to_file(body, &tmp, st.config.max_upload_bytes).await?;
    let repo = q.repository.unwrap_or_else(|| "official".into());
    let r = create_from_file(&st, &actor, &repo, q.file_name.as_deref(), &q.note, &tmp, sha, size).await;
    let _ = std::fs::remove_file(&tmp);
    Ok(Json(r?))
}

#[derive(Deserialize)]
pub struct ListQuery {
    pub status: Option<String>,
}

pub async fn list_for(st: &AppState, actor: &Actor, status: Option<&str>) -> ApiResult<Vec<SubmissionView>> {
    let all = actor.has(Scope::Review);
    if !all {
        actor.require(Scope::Submit)?;
    }
    let q = format!(
        "{SELECT} WHERE ($1::text IS NULL OR s.status = $1) AND ($2 OR s.submitted_by = $3) ORDER BY s.created_at DESC LIMIT 500"
    );
    let mut rows: Vec<SubmissionView> = sqlx::query_as(sqlx::AssertSqlSafe(q))
        .bind(status)
        .bind(all)
        .bind(actor.user_id)
        .fetch_all(&st.db)
        .await?;
    for r in &mut rows {
        crate::validation::localize(&mut r.validation);
    }
    Ok(rows)
}

pub async fn list(State(st): State<AppState>, actor: Actor, Query(q): Query<ListQuery>) -> ApiResult<Json<Vec<SubmissionView>>> {
    Ok(Json(list_for(&st, &actor, q.status.as_deref()).await?))
}

async fn owned_or_reviewer(st: &AppState, actor: &Actor, id: Uuid) -> ApiResult<SubmissionView> {
    let s = load(st, id).await?;
    if !actor.has(Scope::Review) {
        actor.require(Scope::Submit)?;
        let owner: Option<(Option<Uuid>,)> = sqlx::query_as("SELECT submitted_by FROM submissions WHERE id = $1")
            .bind(id)
            .fetch_optional(&st.db)
            .await?;
        if owner.and_then(|o| o.0) != Some(actor.user_id) {
            return Err(ApiError::NotFound);
        }
    }
    Ok(s)
}

pub async fn get_one(State(st): State<AppState>, actor: Actor, Path(id): Path<Uuid>) -> ApiResult<Json<SubmissionView>> {
    Ok(Json(owned_or_reviewer(&st, &actor, id).await?))
}

/// Joint une signature détachée (vérifiée immédiatement).
pub async fn put_signature(
    State(st): State<AppState>,
    actor: Actor,
    Path(id): Path<Uuid>,
    body: Bytes,
) -> ApiResult<Json<SubmissionView>> {
    let s = owned_or_reviewer(&st, &actor, id).await?;
    if s.status != "pending" {
        return Err(ApiError::Conflict(tr!(
            "seule une demande en attente peut recevoir une signature",
            "only a pending submission can receive a signature"
        )));
    }
    let sig =
        PackageSignature::from_json(&body).map_err(|e| bad(tr!("signature illisible : {e}", "unreadable signature: {e}")))?;
    let insp = auxipak_core::archive::inspect(&publisher::submission_file(&st, id), &Default::default())
        .map_err(|e| bad(e.to_string()))?;
    let key = crate::validation::check_signature(&sig, &insp, &st.keys.package_keys)
        .map_err(|e| bad(tr!("signature refusée : {e}", "signature rejected: {e}")))?;
    sqlx::query("UPDATE submissions SET signature = $2 WHERE id = $1")
        .bind(id)
        .bind(serde_json::to_value(&sig).map_err(anyhow::Error::from)?)
        .execute(&st.db)
        .await?;
    audit::log(
        &st.db,
        Some(&actor),
        "submission.signature",
        &s.file_name,
        serde_json::json!({"submission": id, "key": key}),
    )
    .await;
    Ok(Json(load(&st, id).await?))
}

#[derive(Deserialize, Default)]
pub struct ReviewReq {
    #[serde(default)]
    pub note: String,
}

pub async fn approve(
    State(st): State<AppState>,
    actor: Actor,
    Path(id): Path<Uuid>,
    body: Option<Json<ReviewReq>>,
) -> ApiResult<Json<serde_json::Value>> {
    let note = body.map(|b| b.0.note).unwrap_or_default();
    let releases = publisher::approve(&st, &actor, id, &note).await?;
    Ok(Json(serde_json::json!({"status": "published", "releases": releases})))
}

pub async fn reject_submission(st: &AppState, actor: &Actor, id: Uuid, note: &str) -> ApiResult<()> {
    actor.require(Scope::Review)?;
    if note.trim().is_empty() {
        return Err(bad(tr!(
            "un motif de rejet est obligatoire",
            "a rejection reason is required"
        )));
    }
    let r = sqlx::query(
        "UPDATE submissions SET status = 'rejected', reviewed_by = $2, reviewed_at = now(), review_note = $3
         WHERE id = $1 AND status IN ('pending', 'invalid')",
    )
    .bind(id)
    .bind(actor.user_id)
    .bind(note)
    .execute(&st.db)
    .await?;
    if r.rows_affected() == 0 {
        return Err(ApiError::Conflict(tr!(
            "demande introuvable ou déjà traitée",
            "submission not found or already processed"
        )));
    }
    let _ = std::fs::remove_file(publisher::submission_file(st, id));
    audit::log(
        &st.db,
        Some(actor),
        "submission.reject",
        &id.to_string(),
        serde_json::json!({"note": note}),
    )
    .await;
    Ok(())
}

pub async fn reject(
    State(st): State<AppState>,
    actor: Actor,
    Path(id): Path<Uuid>,
    Json(req): Json<ReviewReq>,
) -> ApiResult<Json<serde_json::Value>> {
    if !actor.has(Scope::Review) {
        return Err(forbidden(tr!(
            "la portée « review » est requise",
            "the 'review' scope is required"
        )));
    }
    reject_submission(&st, &actor, id, &req.note).await?;
    Ok(Json(serde_json::json!({"status": "rejected"})))
}
