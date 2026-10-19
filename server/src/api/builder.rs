//! API Builder : construction de paquets pilotable par des outils
//! d'automatisation (CI, agents IA de tout fournisseur).
//!
//! Le serveur n'exécute jamais le contenu d'un paquet : la construction se
//! limite à l'assemblage d'une archive et les tests sont statiques. Les tests
//! dynamiques (installation réelle) doivent être exécutés dans des
//! environnements isolés (CI, machines virtuelles jetables), sans secrets.

use crate::audit;
use crate::auth::{Actor, Scope};
use crate::error::{bad, ApiError, ApiResult};
use crate::state::AppState;
use auxipak_core::ids;
use auxipak_core::manifest::MANIFEST_FILE;
use auxipak_core::project;
use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::header;
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;

const MAX_PROJECT_FILE: u64 = 4 * 1024 * 1024 * 1024;

#[derive(sqlx::FromRow, Serialize)]
pub struct ProjectRow {
    pub id: Uuid,
    pub name: String,
    pub owner_user: Uuid,
    pub manifest_yaml: String,
    pub last_build: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Serialize)]
pub struct ProjectView {
    #[serde(flatten)]
    pub project: ProjectRow,
    pub files: Vec<FileInfo>,
}

#[derive(Serialize)]
pub struct FileInfo {
    pub path: String,
    pub size: u64,
    pub sha256: String,
}

fn project_dir(st: &AppState, id: Uuid) -> PathBuf {
    st.config.builder_dir().join(id.to_string()).join("project")
}

fn artifact_path(st: &AppState, id: Uuid) -> PathBuf {
    st.config.builder_dir().join(id.to_string()).join("artifact.apak")
}

async fn load(st: &AppState, actor: &Actor, id: Uuid) -> ApiResult<ProjectRow> {
    actor.require(Scope::Build)?;
    let p: ProjectRow = sqlx::query_as(
        "SELECT id, name, owner_user, manifest_yaml, last_build, created_at, updated_at FROM builder_projects WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&st.db)
    .await?
    .ok_or(ApiError::NotFound)?;
    if p.owner_user != actor.user_id && !actor.has(Scope::Admin) {
        return Err(ApiError::NotFound);
    }
    Ok(p)
}

fn view(st: &AppState, p: ProjectRow) -> ApiResult<ProjectView> {
    let dir = project_dir(st, p.id);
    let files = project::project_files(&dir)
        .map_err(|e| ApiError::Internal(e))?
        .into_iter()
        .map(|f| {
            let (sha256, size) = auxipak_core::hash::sha256_file(&f.source).unwrap_or_default();
            FileInfo { path: f.archive_path, size, sha256 }
        })
        .collect();
    Ok(ProjectView { project: p, files })
}

#[derive(Deserialize)]
pub struct CreateReq {
    pub name: String,
    /// Manifeste YAML initial ; sinon un modèle est généré à partir des champs ci-dessous.
    #[serde(default)]
    pub manifest: Option<String>,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub publisher: Option<String>,
    #[serde(default)]
    pub language: Option<String>,
    #[serde(default)]
    pub license: Option<String>,
}

fn check_yaml_size(y: &str) -> ApiResult<()> {
    if y.len() > auxipak_core::manifest::MAX_MANIFEST_SIZE {
        return Err(ApiError::TooLarge);
    }
    Ok(())
}

pub async fn create(State(st): State<AppState>, actor: Actor, Json(req): Json<CreateReq>) -> ApiResult<Json<ProjectView>> {
    actor.require(Scope::Build)?;
    let name = req.name.trim();
    if name.is_empty() || name.len() > 128 {
        return Err(bad("nom de projet invalide"));
    }
    let manifest = match req.manifest {
        Some(m) => m,
        None => {
            let app_id = req.id.clone().ok_or_else(|| bad("« id » ou « manifest » est requis"))?;
            if !ids::is_valid_app_id(&app_id) {
                return Err(bad("identifiant d'application invalide"));
            }
            project::render_template(
                &app_id,
                name,
                req.version.as_deref().unwrap_or("1.0.0"),
                req.publisher.as_deref().unwrap_or("Éditeur inconnu"),
                req.language.as_deref().unwrap_or("fr"),
                req.license.as_deref().unwrap_or("GPL-3.0-or-later"),
            )
        }
    };
    check_yaml_size(&manifest)?;
    let id = Uuid::new_v4();
    let dir = project_dir(&st, id);
    std::fs::create_dir_all(dir.join("payload"))?;
    std::fs::create_dir_all(dir.join("scripts"))?;
    std::fs::write(dir.join(MANIFEST_FILE), &manifest)?;
    sqlx::query("INSERT INTO builder_projects (id, name, owner_user, token_id, manifest_yaml) VALUES ($1, $2, $3, $4, $5)")
        .bind(id)
        .bind(name)
        .bind(actor.user_id)
        .bind(actor.token_id())
        .bind(&manifest)
        .execute(&st.db)
        .await?;
    audit::log(&st.db, Some(&actor), "builder.create", name, serde_json::json!({"project": id})).await;
    let p = load(&st, &actor, id).await?;
    Ok(Json(view(&st, p)?))
}

pub async fn list(State(st): State<AppState>, actor: Actor) -> ApiResult<Json<Vec<ProjectRow>>> {
    actor.require(Scope::Build)?;
    Ok(Json(
        sqlx::query_as(
            "SELECT id, name, owner_user, manifest_yaml, last_build, created_at, updated_at FROM builder_projects
             WHERE owner_user = $1 ORDER BY updated_at DESC",
        )
        .bind(actor.user_id)
        .fetch_all(&st.db)
        .await?,
    ))
}

pub async fn get_one(State(st): State<AppState>, actor: Actor, Path(id): Path<Uuid>) -> ApiResult<Json<ProjectView>> {
    let p = load(&st, &actor, id).await?;
    Ok(Json(view(&st, p)?))
}

pub async fn delete_project(State(st): State<AppState>, actor: Actor, Path(id): Path<Uuid>) -> ApiResult<Json<serde_json::Value>> {
    let p = load(&st, &actor, id).await?;
    sqlx::query("DELETE FROM builder_projects WHERE id = $1").bind(id).execute(&st.db).await?;
    let _ = std::fs::remove_dir_all(st.config.builder_dir().join(id.to_string()));
    audit::log(&st.db, Some(&actor), "builder.delete", &p.name, serde_json::json!({"project": id})).await;
    Ok(Json(serde_json::json!({"ok": true})))
}

async fn save_manifest(st: &AppState, id: Uuid, yaml: &str) -> ApiResult<()> {
    check_yaml_size(yaml)?;
    // Le YAML doit au moins être analysable ; la validation complète a lieu à la construction.
    auxipak_core::manifest::parse_yaml_value(yaml).map_err(|e| bad(e.to_string()))?;
    std::fs::write(project_dir(st, id).join(MANIFEST_FILE), yaml)?;
    sqlx::query("UPDATE builder_projects SET manifest_yaml = $2, updated_at = now() WHERE id = $1")
        .bind(id)
        .bind(yaml)
        .execute(&st.db)
        .await?;
    Ok(())
}

/// Remplace le manifeste (corps : YAML).
pub async fn put_manifest(State(st): State<AppState>, actor: Actor, Path(id): Path<Uuid>, body: String) -> ApiResult<Json<ProjectView>> {
    load(&st, &actor, id).await?;
    save_manifest(&st, id, &body).await?;
    Ok(Json(view(&st, load(&st, &actor, id).await?)?))
}

/// Modifie le manifeste par fusion JSON (RFC 7386) : métadonnées,
/// plateformes (`targets`), dépendances, instructions…
pub async fn patch_manifest(
    State(st): State<AppState>,
    actor: Actor,
    Path(id): Path<Uuid>,
    Json(patch): Json<serde_json::Value>,
) -> ApiResult<Json<ProjectView>> {
    let p = load(&st, &actor, id).await?;
    let mut v = auxipak_core::manifest::parse_yaml_value(&p.manifest_yaml).map_err(|e| bad(e.to_string()))?;
    crate::util::merge_patch(&mut v, &patch);
    let yaml = serde_yaml_ng::to_string(&v).map_err(|e| bad(e.to_string()))?;
    save_manifest(&st, id, &yaml).await?;
    Ok(Json(view(&st, load(&st, &actor, id).await?)?))
}

fn file_path(st: &AppState, id: Uuid, path: &str) -> ApiResult<PathBuf> {
    if !ids::is_safe_relative_path(path) || !(path.starts_with("payload/") || path.starts_with("scripts/")) {
        return Err(bad("chemin invalide : payload/... ou scripts/... attendu"));
    }
    let mut p = project_dir(st, id);
    for c in path.split('/') {
        p.push(c);
    }
    Ok(p)
}

/// Importe un fichier (corps brut).
pub async fn put_file(State(st): State<AppState>, actor: Actor, Path((id, path)): Path<(Uuid, String)>, body: Body) -> ApiResult<Json<FileInfo>> {
    load(&st, &actor, id).await?;
    let dest = file_path(&st, id, &path)?;
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if std::fs::symlink_metadata(&dest).map(|m| m.is_dir()).unwrap_or(false) {
        return Err(bad("un répertoire existe à cet emplacement"));
    }
    let tmp = dest.with_file_name(format!(".upload-{}", Uuid::new_v4()));
    let (sha256, size) = crate::api::body_to_file(body, &tmp, MAX_PROJECT_FILE.min(st.config.max_upload_bytes)).await?;
    std::fs::rename(&tmp, &dest)?;
    sqlx::query("UPDATE builder_projects SET updated_at = now() WHERE id = $1").bind(id).execute(&st.db).await?;
    audit::log(&st.db, Some(&actor), "builder.file", &path, serde_json::json!({"project": id, "sha256": sha256, "size": size})).await;
    Ok(Json(FileInfo { path, size, sha256 }))
}

pub async fn delete_file(State(st): State<AppState>, actor: Actor, Path((id, path)): Path<(Uuid, String)>) -> ApiResult<Json<serde_json::Value>> {
    load(&st, &actor, id).await?;
    let p = file_path(&st, id, &path)?;
    std::fs::remove_file(&p).map_err(|_| ApiError::NotFound)?;
    Ok(Json(serde_json::json!({"ok": true})))
}

pub async fn validate(State(st): State<AppState>, actor: Actor, Path(id): Path<Uuid>) -> ApiResult<Json<serde_json::Value>> {
    load(&st, &actor, id).await?;
    let dir = project_dir(&st, id);
    Ok(Json(match project::load_manifest(&dir) {
        Ok((m, warnings)) => serde_json::json!({
            "valid": true, "id": m.id, "version": m.version,
            "warnings": warnings.iter().map(|w| w.to_string()).collect::<Vec<_>>(),
        }),
        Err(e) => serde_json::json!({"valid": false, "errors": format!("{e:#}").lines().collect::<Vec<_>>()}),
    }))
}

pub async fn build(State(st): State<AppState>, actor: Actor, Path(id): Path<Uuid>) -> ApiResult<Json<serde_json::Value>> {
    load(&st, &actor, id).await?;
    let dir = project_dir(&st, id);
    let out = artifact_path(&st, id);
    let _ = std::fs::remove_file(&out);
    let result = tokio::task::spawn_blocking(move || project::build(&dir, &out)).await.map_err(anyhow::Error::from)?;
    let v = match result {
        Ok((m, insp)) => serde_json::json!({
            "ok": true, "id": m.id, "version": m.version, "file_name": m.suggested_file_name(),
            "sha256": insp.archive_sha256, "size": insp.archive_size, "entries": insp.entries.len(),
            "built_at": Utc::now(),
        }),
        Err(e) => serde_json::json!({"ok": false, "errors": format!("{e:#}").lines().collect::<Vec<_>>()}),
    };
    sqlx::query("UPDATE builder_projects SET last_build = $2, updated_at = now() WHERE id = $1").bind(id).bind(&v).execute(&st.db).await?;
    audit::log(&st.db, Some(&actor), "builder.build", &id.to_string(), v.clone()).await;
    Ok(Json(v))
}

pub async fn test(State(st): State<AppState>, actor: Actor, Path(id): Path<Uuid>) -> ApiResult<Json<serde_json::Value>> {
    load(&st, &actor, id).await?;
    let out = artifact_path(&st, id);
    if !out.exists() {
        return Err(bad("aucune construction disponible : appelez /build d'abord"));
    }
    // Tests purement statiques côté serveur : aucun outil externe n'est invoqué.
    let checks = tokio::task::spawn_blocking(move || project::static_tests(&out, false))
        .await
        .map_err(anyhow::Error::from)?
        .map_err(ApiError::Internal)?;
    let ok = checks.iter().all(|c| c.ok);
    Ok(Json(serde_json::json!({
        "ok": ok, "checks": checks,
        "note": "tests statiques uniquement ; les tests d'installation s'exécutent dans un environnement isolé (CI)",
    })))
}

pub async fn artifact(State(st): State<AppState>, actor: Actor, Path(id): Path<Uuid>) -> ApiResult<Response> {
    load(&st, &actor, id).await?;
    let out = artifact_path(&st, id);
    let f = tokio::fs::File::open(&out).await.map_err(|_| ApiError::NotFound)?;
    Ok((
        [(header::CONTENT_TYPE, "application/octet-stream")],
        Body::from_stream(tokio_util::io::ReaderStream::new(f)),
    )
        .into_response())
}

#[derive(Deserialize)]
pub struct SubmitReq {
    #[serde(default = "official")]
    pub repository: String,
    #[serde(default)]
    pub note: String,
}

fn official() -> String {
    "official".into()
}

/// Soumet la dernière construction (crée une demande de publication).
pub async fn submit(State(st): State<AppState>, actor: Actor, Path(id): Path<Uuid>, Json(req): Json<SubmitReq>) -> ApiResult<Json<crate::api::submissions::SubmissionView>> {
    load(&st, &actor, id).await?;
    actor.require(Scope::Submit)?;
    let out = artifact_path(&st, id);
    if !out.exists() {
        return Err(bad("aucune construction disponible"));
    }
    std::fs::create_dir_all(st.config.tmp_dir())?;
    let tmp = st.config.tmp_dir().join(format!("builder-{}.apak", Uuid::new_v4()));
    std::fs::copy(&out, &tmp)?;
    let (sha, size) = auxipak_core::hash::sha256_file(&tmp)?;
    let r = crate::api::submissions::create_from_file(&st, &actor, &req.repository, None, &req.note, &tmp, sha, size).await;
    let _ = std::fs::remove_file(&tmp);
    Ok(Json(r?))
}
