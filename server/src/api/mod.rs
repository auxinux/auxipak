//! API REST versionnée (`/api/v1`) et distribution des dépôts.

pub mod admin;
pub mod auth_routes;
pub mod builder;
pub mod public;
pub mod submissions;

use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use axum::body::Body;
use axum::routing::{delete, get, patch, post, put};
use axum::Router;
use futures::StreamExt;
use sha2::{Digest, Sha256};
use std::path::Path;
use tokio::io::AsyncWriteExt;

/// Routes de l'API et des dépôts.
pub fn router() -> Router<AppState> {
    Router::new()
        // Public
        .route("/index", get(public::catalog))
        .route("/repos/{repo}/{*path}", get(public::repo_file))
        .route("/api/v1/health", get(public::health))
        .route("/api/v1/openapi.yaml", get(public::openapi))
        .route("/api/v1/repositories", get(public::repositories))
        .route("/api/v1/apps", get(public::apps))
        .route("/api/v1/apps/{id}", get(public::app))
        // Authentification
        .route("/api/v1/auth/login", post(auth_routes::login))
        .route("/api/v1/auth/logout", post(auth_routes::logout))
        .route("/api/v1/auth/me", get(auth_routes::me))
        .route(
            "/api/v1/tokens",
            get(auth_routes::list_own_tokens).post(auth_routes::create_own_token),
        )
        .route("/api/v1/tokens/{id}", delete(auth_routes::revoke_own_token))
        // Soumissions
        .route("/api/v1/submissions", get(submissions::list).post(submissions::create))
        .route("/api/v1/submissions/{id}", get(submissions::get_one))
        .route("/api/v1/submissions/{id}/signature", put(submissions::put_signature))
        .route("/api/v1/submissions/{id}/approve", post(submissions::approve))
        .route("/api/v1/submissions/{id}/reject", post(submissions::reject))
        // Builder
        .route("/api/v1/builder/projects", get(builder::list).post(builder::create))
        .route(
            "/api/v1/builder/projects/{id}",
            get(builder::get_one).delete(builder::delete_project),
        )
        .route(
            "/api/v1/builder/projects/{id}/manifest",
            put(builder::put_manifest).patch(builder::patch_manifest),
        )
        .route(
            "/api/v1/builder/projects/{id}/files/{*path}",
            put(builder::put_file).delete(builder::delete_file),
        )
        .route("/api/v1/builder/projects/{id}/validate", post(builder::validate))
        .route("/api/v1/builder/projects/{id}/build", post(builder::build))
        .route("/api/v1/builder/projects/{id}/test", post(builder::test))
        .route("/api/v1/builder/projects/{id}/artifact", get(builder::artifact))
        .route("/api/v1/builder/projects/{id}/submit", post(builder::submit))
        // Administration
        .route("/api/v1/admin/users", get(admin::list_users).post(admin::create_user))
        .route("/api/v1/admin/users/{id}", patch(admin::update_user))
        .route("/api/v1/admin/tokens", get(admin::list_tokens).post(admin::create_token))
        .route("/api/v1/admin/tokens/{id}", delete(admin::revoke_token))
        .route(
            "/api/v1/admin/repositories",
            get(admin::list_repositories).post(admin::create_repository),
        )
        .route("/api/v1/admin/repositories/{name}", patch(admin::update_repository))
        .route("/api/v1/admin/repositories/{name}/regenerate", post(admin::regenerate))
        .route("/api/v1/admin/releases", get(admin::list_releases))
        .route("/api/v1/admin/releases/{id}/state", post(admin::set_release_state))
        .route("/api/v1/admin/apps/{id}/evaluation", put(admin::set_evaluation))
        .route("/api/v1/admin/audit", get(admin::audit))
}

/// Liste (méthode, chemin) des routes de l'API, utilisée pour vérifier que
/// la documentation OpenAPI est complète.
pub const DOCUMENTED_ROUTES: &[(&str, &str)] = &[
    ("get", "/index"),
    ("get", "/repos/{repo}/{path}"),
    ("get", "/api/v1/health"),
    ("get", "/api/v1/openapi.yaml"),
    ("get", "/api/v1/repositories"),
    ("get", "/api/v1/apps"),
    ("get", "/api/v1/apps/{id}"),
    ("post", "/api/v1/auth/login"),
    ("post", "/api/v1/auth/logout"),
    ("get", "/api/v1/auth/me"),
    ("get", "/api/v1/tokens"),
    ("post", "/api/v1/tokens"),
    ("delete", "/api/v1/tokens/{id}"),
    ("get", "/api/v1/submissions"),
    ("post", "/api/v1/submissions"),
    ("get", "/api/v1/submissions/{id}"),
    ("put", "/api/v1/submissions/{id}/signature"),
    ("post", "/api/v1/submissions/{id}/approve"),
    ("post", "/api/v1/submissions/{id}/reject"),
    ("get", "/api/v1/builder/projects"),
    ("post", "/api/v1/builder/projects"),
    ("get", "/api/v1/builder/projects/{id}"),
    ("delete", "/api/v1/builder/projects/{id}"),
    ("put", "/api/v1/builder/projects/{id}/manifest"),
    ("patch", "/api/v1/builder/projects/{id}/manifest"),
    ("put", "/api/v1/builder/projects/{id}/files/{path}"),
    ("delete", "/api/v1/builder/projects/{id}/files/{path}"),
    ("post", "/api/v1/builder/projects/{id}/validate"),
    ("post", "/api/v1/builder/projects/{id}/build"),
    ("post", "/api/v1/builder/projects/{id}/test"),
    ("get", "/api/v1/builder/projects/{id}/artifact"),
    ("post", "/api/v1/builder/projects/{id}/submit"),
    ("get", "/api/v1/admin/users"),
    ("post", "/api/v1/admin/users"),
    ("patch", "/api/v1/admin/users/{id}"),
    ("get", "/api/v1/admin/tokens"),
    ("post", "/api/v1/admin/tokens"),
    ("delete", "/api/v1/admin/tokens/{id}"),
    ("get", "/api/v1/admin/repositories"),
    ("post", "/api/v1/admin/repositories"),
    ("patch", "/api/v1/admin/repositories/{name}"),
    ("post", "/api/v1/admin/repositories/{name}/regenerate"),
    ("get", "/api/v1/admin/releases"),
    ("post", "/api/v1/admin/releases/{id}/state"),
    ("put", "/api/v1/admin/apps/{id}/evaluation"),
    ("get", "/api/v1/admin/audit"),
];

/// Écrit un corps de requête dans un fichier, avec limite de taille, et
/// retourne (SHA-256, taille).
pub async fn body_to_file(body: Body, dest: &Path, limit: u64) -> ApiResult<(String, u64)> {
    let mut f = tokio::fs::File::create(dest).await?;
    let mut stream = body.into_data_stream();
    let mut h = Sha256::new();
    let mut n = 0u64;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| ApiError::BadRequest(format!("corps de requête : {e}")))?;
        n += chunk.len() as u64;
        if n > limit {
            drop(f);
            let _ = tokio::fs::remove_file(dest).await;
            return Err(ApiError::TooLarge);
        }
        h.update(&chunk);
        f.write_all(&chunk).await?;
    }
    f.sync_all().await?;
    Ok((hex::encode(h.finalize()), n))
}
