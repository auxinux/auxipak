//! Nettoyage : jetons révoqués ou expirés, versions révoquées, demandes
//! terminées. Chaque suppression est inscrite au journal d'audit.
//!
//! Une version révoquée n'est jamais oubliée : ses fichiers sont supprimés et
//! elle passe à l'état `purged`, mais elle reste dans `revocations.json` pour
//! que les clients continuent de la refuser.

use crate::audit;
use crate::auth::{Actor, Scope};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use auxipak_core::tr;
use uuid::Uuid;

/// États de demande qui peuvent être supprimés (jamais une demande en cours).
pub const DELETABLE_SUBMISSIONS: &[&str] = &["invalid", "rejected", "failed", "published"];

fn require(actor: &Actor, scope: Scope) -> ApiResult<()> {
    if actor.has(scope) {
        Ok(())
    } else {
        Err(ApiError::Forbidden(tr!("droits insuffisants", "insufficient permissions")))
    }
}

/// Supprime les jetons révoqués ou expirés (`id` : un seul). Un administrateur
/// nettoie tous les jetons, les autres uniquement les leurs.
pub async fn purge_tokens(st: &AppState, actor: &Actor, id: Option<Uuid>) -> ApiResult<u64> {
    let all = actor.has(Scope::Admin);
    let rows: Vec<(Uuid, String)> = sqlx::query_as(
        "DELETE FROM api_tokens
         WHERE (revoked OR (expires_at IS NOT NULL AND expires_at < now()))
           AND ($1 OR user_id = $2)
           AND ($3::uuid IS NULL OR id = $3)
         RETURNING id, name",
    )
    .bind(all)
    .bind(actor.user_id)
    .bind(id)
    .fetch_all(&st.db)
    .await?;
    if id.is_some() && rows.is_empty() {
        return Err(ApiError::Conflict(tr!(
            "seul un jeton révoqué ou expiré peut être supprimé",
            "only a revoked or expired token can be deleted"
        )));
    }
    for (tid, name) in &rows {
        audit::log(&st.db, Some(actor), "token.delete", name, serde_json::json!({"token": tid})).await;
    }
    Ok(rows.len() as u64)
}

/// Supprime les fichiers des versions révoquées (`id` : une seule) et les
/// masque (état `purged`).
pub async fn purge_releases(st: &AppState, actor: &Actor, id: Option<Uuid>) -> ApiResult<u64> {
    require(actor, Scope::Review)?;
    let rows: Vec<(Uuid, String, String, String)> = sqlx::query_as(
        "SELECT id, repository, app_id, version FROM releases
         WHERE state = 'revoked' AND ($1::uuid IS NULL OR id = $1)",
    )
    .bind(id)
    .fetch_all(&st.db)
    .await?;
    if id.is_some() && rows.is_empty() {
        return Err(ApiError::Conflict(tr!(
            "seule une version révoquée peut être supprimée",
            "only a revoked release can be deleted"
        )));
    }
    for (rid, repo, app, version) in &rows {
        let dir = st.config.packages_dir().join(repo).join(app).join(version);
        if dir.exists() {
            std::fs::remove_dir_all(&dir).map_err(anyhow::Error::from)?;
        }
        // Répertoire de l'application vide : supprimé aussi.
        if let Some(parent) = dir.parent() {
            let _ = std::fs::remove_dir(parent);
        }
        sqlx::query("UPDATE releases SET state = 'purged' WHERE id = $1 AND state = 'revoked'")
            .bind(rid)
            .execute(&st.db)
            .await?;
        audit::log(
            &st.db,
            Some(actor),
            "release.purge",
            &format!("{app} {version}"),
            serde_json::json!({"release": rid, "repository": repo}),
        )
        .await;
    }
    Ok(rows.len() as u64)
}

/// Supprime les demandes terminées (`id` : une seule) et leur fichier. Les
/// versions publiées gardent leur propre copie du paquet.
pub async fn purge_submissions(st: &AppState, actor: &Actor, id: Option<Uuid>) -> ApiResult<u64> {
    require(actor, Scope::Review)?;
    let states: Vec<String> = DELETABLE_SUBMISSIONS.iter().map(|s| s.to_string()).collect();
    let rows: Vec<(Uuid, String, String)> = sqlx::query_as(
        "DELETE FROM submissions WHERE status = ANY($1) AND ($2::uuid IS NULL OR id = $2)
         RETURNING id, file_name, status",
    )
    .bind(&states)
    .bind(id)
    .fetch_all(&st.db)
    .await?;
    if id.is_some() && rows.is_empty() {
        return Err(ApiError::Conflict(tr!(
            "une demande en attente ou approuvée ne peut pas être supprimée",
            "a pending or approved submission cannot be deleted"
        )));
    }
    for (sid, file_name, status) in &rows {
        let _ = std::fs::remove_file(crate::publisher::submission_file(st, *sid));
        let _ = std::fs::remove_file(st.config.submissions_dir().join(format!("{sid}.sig")));
        audit::log(
            &st.db,
            Some(actor),
            "submission.delete",
            file_name,
            serde_json::json!({"submission": sid, "status": status}),
        )
        .await;
    }
    Ok(rows.len() as u64)
}
