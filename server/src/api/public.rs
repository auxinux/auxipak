//! Routes publiques : catalogue, fichiers des dépôts, applications, santé.

use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use auxipak_core::index::{CatalogRepository, RepoIndex, RepositoryInfo, ServerCatalog, INDEX_META_VERSION};
use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncSeekExt};

pub const OPENAPI: &str = include_str!("../../openapi.yaml");

#[derive(sqlx::FromRow, Serialize)]
pub struct RepoListRow {
    pub name: String,
    pub title: String,
    pub description: String,
    pub official: bool,
    pub generation: i64,
    pub published_at: Option<DateTime<Utc>>,
}

/// `GET /index` : catalogue des dépôts disponibles.
pub async fn catalog(State(st): State<AppState>) -> ApiResult<Json<ServerCatalog>> {
    let repos: Vec<RepoListRow> = sqlx::query_as(
        "SELECT name, title, description, official, generation, published_at FROM repositories WHERE enabled ORDER BY official DESC, name",
    )
    .fetch_all(&st.db)
    .await?;
    let base = st.config.public_url.clone();
    let mut out = Vec::new();
    for r in repos {
        let idx_path = st.config.repos_dir().join(&r.name).join("current/targets/index.json");
        let channels = match tokio::fs::read(&idx_path).await {
            Ok(b) => serde_json::from_slice::<RepoIndex>(&b)
                .map(|i| i.channels)
                .unwrap_or_default(),
            Err(_) => vec![],
        };
        out.push(CatalogRepository {
            info: RepositoryInfo {
                name: r.name.clone(),
                title: r.title,
                description: r.description,
                official: r.official,
            },
            url: base
                .join(&format!("repos/{}/", r.name))
                .map(|u| u.to_string())
                .unwrap_or_default(),
            channels,
        });
    }
    Ok(Json(ServerCatalog {
        meta_version: INDEX_META_VERSION,
        server: base.host_str().unwrap_or("").to_string(),
        generated_at: Utc::now(),
        repositories: out,
    }))
}

/// `GET /repos/{repo}/{*path}` : métadonnées TUF, cibles et clés publiques du
/// dépôt actuellement publié. Prend en charge `Range: bytes=N-` (reprise).
pub async fn repo_file(
    State(st): State<AppState>,
    Path((repo, path)): Path<(String, String)>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    if !auxipak_core::ids::is_valid_repo_name(&repo) || !auxipak_core::ids::is_safe_relative_path(&path) {
        return Err(ApiError::NotFound);
    }
    let top = path.split('/').next().unwrap_or("");
    if !matches!(top, "metadata" | "targets" | "keys") {
        return Err(ApiError::NotFound);
    }
    let base = st.config.repos_dir().join(&repo).join("current");
    let mut full = base.clone();
    for c in path.split('/') {
        full.push(c);
    }
    // Le chemin résolu doit rester dans la génération courante.
    let base_c = tokio::fs::canonicalize(&base).await.map_err(|_| ApiError::NotFound)?;
    let full_c = tokio::fs::canonicalize(&full).await.map_err(|_| ApiError::NotFound)?;
    let pkg_root = tokio::fs::canonicalize(st.config.packages_dir()).await.ok();
    let inside = full_c.starts_with(&base_c) || pkg_root.map(|p| full_c.starts_with(p)).unwrap_or(false);
    if !inside {
        return Err(ApiError::NotFound);
    }
    let meta = tokio::fs::metadata(&full_c).await.map_err(|_| ApiError::NotFound)?;
    if !meta.is_file() {
        return Err(ApiError::NotFound);
    }
    let len = meta.len();
    let ctype = if path.ends_with(".json") || path.ends_with(".sig") {
        "application/json"
    } else {
        "application/octet-stream"
    };
    // Les métadonnées changent à chaque génération : pas de cache côté client.
    let cache = if top == "metadata" {
        "no-cache"
    } else {
        "public, max-age=300"
    };
    let mut file = tokio::fs::File::open(&full_c).await?;
    let start = headers
        .get(header::RANGE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("bytes="))
        .and_then(|v| v.strip_suffix('-'))
        .and_then(|v| v.parse::<u64>().ok());
    let mut resp = match start {
        Some(s) if s >= len => {
            let mut r = StatusCode::RANGE_NOT_SATISFIABLE.into_response();
            r.headers_mut().insert(
                header::CONTENT_RANGE,
                HeaderValue::from_str(&format!("bytes */{len}")).unwrap(),
            );
            return Ok(r);
        }
        Some(s) => {
            file.seek(std::io::SeekFrom::Start(s)).await?;
            let body = Body::from_stream(tokio_util::io::ReaderStream::new(file.take(len - s)));
            let mut r = Response::new(body);
            *r.status_mut() = StatusCode::PARTIAL_CONTENT;
            r.headers_mut().insert(
                header::CONTENT_RANGE,
                HeaderValue::from_str(&format!("bytes {s}-{}/{len}", len - 1)).unwrap(),
            );
            r.headers_mut().insert(header::CONTENT_LENGTH, HeaderValue::from(len - s));
            r
        }
        None => {
            let mut r = Response::new(Body::from_stream(tokio_util::io::ReaderStream::new(file)));
            r.headers_mut().insert(header::CONTENT_LENGTH, HeaderValue::from(len));
            r
        }
    };
    let h = resp.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static(ctype));
    h.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static(cache));
    h.insert("x-content-type-options", HeaderValue::from_static("nosniff"));
    Ok(resp)
}

pub async fn health(State(st): State<AppState>) -> Response {
    let db_ok = sqlx::query("SELECT 1").execute(&st.db).await.is_ok();
    let body = serde_json::json!({
        "status": if db_ok { "ok" } else { "degraded" },
        "database": db_ok,
        "version": env!("CARGO_PKG_VERSION"),
        "package_signing_key": st.keys.signer.as_ref().map(|s| s.key_id().to_string()),
    });
    let code = if db_ok {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (code, Json(body)).into_response()
}

pub async fn openapi() -> Response {
    ([(header::CONTENT_TYPE, "application/yaml; charset=utf-8")], OPENAPI).into_response()
}

pub async fn repositories(State(st): State<AppState>) -> ApiResult<Json<Vec<RepoListRow>>> {
    Ok(Json(
        sqlx::query_as(
            "SELECT name, title, description, official, generation, published_at FROM repositories WHERE enabled ORDER BY official DESC, name",
        )
        .fetch_all(&st.db)
        .await?,
    ))
}

#[derive(Deserialize)]
pub struct AppsQuery {
    pub q: Option<String>,
    pub repository: Option<String>,
    pub status: Option<String>,
    /// `linux`, `macos` ou `windows` : applications ayant une variante pour ce système.
    pub platform: Option<String>,
}

#[derive(sqlx::FromRow, Serialize, Clone)]
pub struct AppListRow {
    pub id: String,
    pub name: String,
    pub publisher: String,
    pub summary: String,
    pub license: String,
    pub status: String,
    pub latest_version: Option<String>,
    pub repositories: Vec<String>,
    /// Systèmes couverts par les versions publiées (`linux`, `macos`, `windows`).
    pub platforms: Vec<String>,
    pub updated_at: DateTime<Utc>,
    /// Traductions du manifeste ; `name` et `summary` sont déjà dans la langue
    /// de la requête quand elle est disponible.
    pub translations: serde_json::Value,
    /// Origine du statut : `human` (relecteur), `ai` (pré-évaluation
    /// automatique, indicative) ou absente (non évalué).
    pub status_source: Option<String>,
}

/// Recherche dans les applications publiées.
pub async fn search_apps(st: &AppState, q: &AppsQuery) -> ApiResult<Vec<AppListRow>> {
    let pattern = format!("%{}%", q.q.clone().unwrap_or_default().to_lowercase().replace(['%', '_'], ""));
    let rows: Vec<AppListRow> = sqlx::query_as(
        "SELECT a.id, a.name, a.publisher, a.summary, a.license,
                COALESCE(NULLIF(e.status, 'unreviewed'), ai.status, 'unreviewed') AS status,
                CASE WHEN NULLIF(e.status, 'unreviewed') IS NOT NULL THEN 'human' WHEN ai.status IS NOT NULL THEN 'ai' END AS status_source,
                (SELECT r.version FROM releases r WHERE r.app_id = a.id AND r.state = 'published'
                   ORDER BY r.published_at DESC LIMIT 1) AS latest_version,
                ARRAY(SELECT DISTINCT r.repository FROM releases r WHERE r.app_id = a.id AND r.state = 'published') AS repositories,
                ARRAY(SELECT DISTINCT t->>'platform' FROM releases r, jsonb_array_elements(r.manifest->'targets') t
                        WHERE r.app_id = a.id AND r.state = 'published' ORDER BY 1) AS platforms,
                a.updated_at, a.translations
         FROM apps a LEFT JOIN evaluations e ON e.app_id = a.id LEFT JOIN ai_evaluations ai ON ai.app_id = a.id
         WHERE EXISTS (SELECT 1 FROM releases r WHERE r.app_id = a.id AND r.state = 'published'
                         AND ($2::text IS NULL OR r.repository = $2)
                         AND ($4::text IS NULL OR EXISTS (
                               SELECT 1 FROM jsonb_array_elements(r.manifest->'targets') t WHERE t->>'platform' = $4)))
           AND (lower(a.id) LIKE $1 OR lower(a.name) LIKE $1 OR lower(a.summary) LIKE $1
                OR lower(a.translations::text) LIKE $1)
           AND ($3::text IS NULL OR COALESCE(NULLIF(e.status, 'unreviewed'), ai.status, 'unreviewed') = $3)
         ORDER BY a.name LIMIT 500",
    )
    .bind(pattern)
    .bind(&q.repository)
    .bind(&q.status)
    .bind(q.platform.as_deref().filter(|p| matches!(*p, "linux" | "macos" | "windows")))
    .fetch_all(&st.db)
    .await?;
    let lang = auxipak_core::i18n::current().code();
    let mut rows = rows;
    for r in &mut rows {
        if let Some(t) = translation(&r.translations, lang) {
            if let Some(n) = t.name {
                r.name = n;
            }
            r.summary = t.summary;
        }
    }
    Ok(rows)
}

pub async fn apps(State(st): State<AppState>, Query(q): Query<AppsQuery>) -> ApiResult<Json<Vec<AppListRow>>> {
    Ok(Json(search_apps(&st, &q).await?))
}

#[derive(sqlx::FromRow, Serialize, Clone)]
pub struct AppDetailRow {
    pub id: String,
    pub name: String,
    pub publisher: String,
    pub summary: String,
    pub description: Option<String>,
    pub license: String,
    pub homepage: Option<String>,
    pub categories: Vec<String>,
    pub status: String,
    pub status_note: Option<String>,
    pub evaluated_at: Option<DateTime<Utc>>,
    pub translations: serde_json::Value,
    /// `human`, `ai` (pré-évaluation automatique) ou absent.
    pub status_source: Option<String>,
    #[serde(skip)]
    pub ai_notes: Option<serde_json::Value>,
    /// Sources de la pré-évaluation IA.
    pub ai_sources: Option<Vec<String>>,
}

#[derive(sqlx::FromRow, Serialize, Clone)]
pub struct PublicReleaseRow {
    pub id: uuid::Uuid,
    pub repository: String,
    pub version: String,
    pub file_name: String,
    pub languages: Vec<String>,
    pub size: i64,
    pub sha256: String,
    pub signature_key_id: String,
    pub uses_scripts: bool,
    pub state: String,
    pub state_reason: Option<String>,
    pub published_at: DateTime<Utc>,
    pub manifest: serde_json::Value,
}

#[derive(Serialize, Clone)]
pub struct AppDetail {
    pub app: AppDetailRow,
    pub releases: Vec<PublicReleaseRow>,
}

pub async fn load_app(st: &AppState, id: &str) -> ApiResult<AppDetail> {
    let app: AppDetailRow = sqlx::query_as(
        "SELECT a.id, a.name, a.publisher, a.summary, a.description, a.license, a.homepage, a.categories,
                COALESCE(NULLIF(e.status, 'unreviewed'), ai.status, 'unreviewed') AS status, e.note AS status_note,
                CASE WHEN NULLIF(e.status, 'unreviewed') IS NOT NULL THEN e.evaluated_at ELSE ai.evaluated_at END AS evaluated_at, a.translations,
                CASE WHEN NULLIF(e.status, 'unreviewed') IS NOT NULL THEN 'human' WHEN ai.status IS NOT NULL THEN 'ai' END AS status_source,
                CASE WHEN NULLIF(e.status, 'unreviewed') IS NULL THEN ai.notes END AS ai_notes,
                CASE WHEN NULLIF(e.status, 'unreviewed') IS NULL THEN ai.sources END AS ai_sources
         FROM apps a LEFT JOIN evaluations e ON e.app_id = a.id LEFT JOIN ai_evaluations ai ON ai.app_id = a.id
         WHERE a.id = $1",
    )
    .bind(id)
    .fetch_optional(&st.db)
    .await?
    .ok_or(ApiError::NotFound)?;
    let releases: Vec<PublicReleaseRow> = sqlx::query_as(
        "SELECT id, repository, version, file_name, languages, size, sha256, signature_key_id, uses_scripts, state, state_reason,
                published_at, manifest
         FROM releases WHERE app_id = $1 AND state IN ('published', 'revoked') ORDER BY published_at DESC",
    )
    .bind(id)
    .fetch_all(&st.db)
    .await?;
    if releases.is_empty() {
        return Err(ApiError::NotFound);
    }
    let mut app = app;
    // Pré-évaluation IA : ses réserves, dans la langue de la requête.
    if app.status_source.as_deref() == Some("ai") {
        let notes: std::collections::BTreeMap<String, String> = app
            .ai_notes
            .clone()
            .and_then(|v| serde_json::from_value(v).ok())
            .unwrap_or_default();
        let lang = auxipak_core::i18n::current().code();
        app.status_note = notes
            .get(lang)
            .or_else(|| notes.get("fr"))
            .or_else(|| notes.values().next())
            .cloned();
    }
    if let Some(t) = translation(&app.translations, auxipak_core::i18n::current().code()) {
        if let Some(n) = t.name {
            app.name = n;
        }
        app.summary = t.summary;
        if t.description.is_some() {
            app.description = t.description;
        }
    }
    Ok(AppDetail { app, releases })
}

/// Traduction du manifeste pour la langue de la requête, si elle existe.
fn translation(v: &serde_json::Value, lang: &str) -> Option<auxipak_core::manifest::Translation> {
    let map: std::collections::BTreeMap<String, auxipak_core::manifest::Translation> = serde_json::from_value(v.clone()).ok()?;
    auxipak_core::index::pick_translation(&map, lang).cloned()
}

pub async fn app(State(st): State<AppState>, Path(id): Path<String>) -> ApiResult<Json<AppDetail>> {
    Ok(Json(load_app(&st, &id).await?))
}
