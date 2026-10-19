//! Interface Web publique et d'administration (rendu côté serveur).
//!
//! - Gabarits MiniJinja (échappement HTML automatique) embarqués dans le binaire
//!   depuis `web/templates`, feuilles de style et thèmes depuis `web/static`.
//! - Bilingue : français par défaut, anglais via le cookie `lang`
//!   (`web/i18n/fr.json`, `web/i18n/en.json`).
//! - Administration : session (cookie HttpOnly, SameSite=Strict) et jeton
//!   CSRF obligatoire sur chaque formulaire.

use crate::api::{admin, auth_routes, public, submissions};
use crate::auth::{self, Actor, Role, Scope, Via};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use axum::extract::{DefaultBodyLimit, Multipart, Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Form, Router};
use axum_extra::extract::cookie::{Cookie, SameSite};
use axum_extra::extract::CookieJar;
use minijinja::{context, Environment, Value};
use rust_embed::RustEmbed;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

#[derive(RustEmbed)]
#[folder = "../web/"]
struct Assets;

pub struct Templates {
    env: Environment<'static>,
    i18n: BTreeMap<String, serde_json::Value>,
}

impl Templates {
    pub fn new() -> anyhow::Result<Templates> {
        let mut env = Environment::new();
        for f in Assets::iter() {
            if let Some(name) = f.strip_prefix("templates/") {
                let data = Assets::get(&f).unwrap();
                let text = String::from_utf8(data.data.into_owned())?;
                env.add_template_owned(name.to_string(), text)?;
            }
        }
        env.add_filter("filesize", |n: i64| -> String {
            let n = n as f64;
            if n >= 1073741824.0 {
                format!("{:.1} Gio", n / 1073741824.0)
            } else if n >= 1048576.0 {
                format!("{:.1} Mio", n / 1048576.0)
            } else if n >= 1024.0 {
                format!("{:.1} Kio", n / 1024.0)
            } else {
                format!("{n} o")
            }
        });
        env.add_filter("date", |s: String| -> String { s.get(..16).unwrap_or(&s).replace('T', " ") });
        env.add_filter("short", |s: String| -> String { s.get(..12).unwrap_or(&s).to_string() });
        let mut i18n = BTreeMap::new();
        for lang in ["fr", "en"] {
            let f = Assets::get(&format!("i18n/{lang}.json")).ok_or_else(|| anyhow::anyhow!("traduction {lang} absente"))?;
            i18n.insert(lang.to_string(), serde_json::from_slice(&f.data)?);
        }
        Ok(Templates { env, i18n })
    }

    pub fn render(&self, name: &str, lang: &str, ctx: Value) -> Response {
        let tr = Value::from_serialize(self.i18n.get(lang).or_else(|| self.i18n.get("fr")));
        let full = context! { lang => lang, tr => tr, ..ctx };
        match self.env.get_template(name).and_then(|t| t.render(full)) {
            Ok(html) => Html(html).into_response(),
            Err(e) => {
                tracing::error!(template = name, error = %e, "rendu de gabarit");
                (StatusCode::INTERNAL_SERVER_ERROR, "erreur de rendu").into_response()
            }
        }
    }

    pub fn has_lang(&self, l: &str) -> bool {
        self.i18n.contains_key(l)
    }
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(home))
        .route("/apps/{id}", get(app_page))
        .route("/values", get(values))
        .route("/docs", get(docs))
        .route("/lang/{lang}", get(set_lang))
        .route("/static/{*file}", get(static_file))
        .route("/admin/login", get(login_page).post(login_post))
        .route("/admin/logout", post(logout))
        .route("/admin", get(dashboard))
        .route("/admin/submissions", get(submissions_page))
        .route("/admin/submissions/{id}", get(submission_page))
        .route("/admin/submissions/{id}/approve", post(submission_approve))
        .route("/admin/submissions/{id}/reject", post(submission_reject))
        .route("/admin/upload", get(upload_page).post(upload_post).layer(DefaultBodyLimit::disable()))
        .route("/admin/releases", get(releases_page))
        .route("/admin/releases/{id}/state", post(release_state))
        .route("/admin/apps", get(apps_page))
        .route("/admin/apps/{id}/evaluation", post(app_evaluation))
        .route("/admin/repositories", get(repos_page).post(repo_create))
        .route("/admin/repositories/{name}/regenerate", post(repo_regenerate))
        .route("/admin/users", get(users_page).post(user_create))
        .route("/admin/users/{id}", post(user_update))
        .route("/admin/tokens", get(tokens_page).post(token_create))
        .route("/admin/tokens/{id}/revoke", post(token_revoke))
        .route("/admin/audit", get(audit_page))
}

fn lang_of(st: &AppState, jar: &CookieJar) -> String {
    jar.get("lang").map(|c| c.value().to_string()).filter(|l| st.web.has_lang(l)).unwrap_or_else(|| "fr".into())
}

fn page(st: &AppState, jar: &CookieJar, name: &str, ctx: Value) -> Response {
    st.web.render(name, &lang_of(st, jar), ctx)
}

fn error_page(st: &AppState, jar: &CookieJar, e: ApiError) -> Response {
    let code = e.status();
    let mut r = page(st, jar, "error.html", context! { status => code.as_u16(), message => e.to_string() });
    *r.status_mut() = code;
    r
}

async fn static_file(Path(file): Path<String>) -> Response {
    if !auxipak_core::ids::is_safe_relative_path(&file) {
        return StatusCode::NOT_FOUND.into_response();
    }
    match Assets::get(&format!("static/{file}")) {
        Some(f) => {
            let mime = mime_guess::from_path(&file).first_or_octet_stream();
            ([(header::CONTENT_TYPE, mime.to_string()), (header::CACHE_CONTROL, "public, max-age=3600".into())], f.data.into_owned())
                .into_response()
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

#[derive(Deserialize)]
struct LangQuery {
    next: Option<String>,
}

async fn set_lang(State(st): State<AppState>, Path(lang): Path<String>, Query(q): Query<LangQuery>, jar: CookieJar) -> Response {
    let lang = if st.web.has_lang(&lang) { lang } else { "fr".into() };
    // Redirection locale uniquement (pas de redirection ouverte).
    let next = q.next.filter(|n| n.starts_with('/') && !n.starts_with("//") && !n.contains('\\')).unwrap_or_else(|| "/".into());
    let c = Cookie::build(("lang", lang)).path("/").same_site(SameSite::Lax).max_age(time::Duration::days(365)).build();
    (jar.add(c), Redirect::to(&next)).into_response()
}

// ---------- Pages publiques ----------

#[derive(Deserialize, Default)]
struct SearchQuery {
    q: Option<String>,
    status: Option<String>,
}

async fn home(State(st): State<AppState>, jar: CookieJar, Query(q): Query<SearchQuery>) -> Response {
    let status = q.status.clone().filter(|s| matches!(s.as_str(), "verified" | "compatible" | "unreviewed"));
    let aq = public::AppsQuery { q: q.q.clone(), repository: None, status: status.clone() };
    match public::search_apps(&st, &aq).await {
        Ok(apps) => page(&st, &jar, "index.html", context! { apps => apps, q => q.q.unwrap_or_default(), status => status, user => web_user(&st, &jar).await }),
        Err(e) => error_page(&st, &jar, e),
    }
}

async fn app_page(State(st): State<AppState>, jar: CookieJar, Path(id): Path<String>) -> Response {
    match public::load_app(&st, &id).await {
        Ok(detail) => {
            let base = st.config.public_url.to_string();
            page(&st, &jar, "app.html", context! { d => detail, base => base, user => web_user(&st, &jar).await })
        }
        Err(e) => error_page(&st, &jar, e),
    }
}

async fn values(State(st): State<AppState>, jar: CookieJar) -> Response {
    page(&st, &jar, "values.html", context! { user => web_user(&st, &jar).await })
}

async fn docs(State(st): State<AppState>, jar: CookieJar) -> Response {
    let base = st.config.public_url.to_string();
    page(&st, &jar, "docs.html", context! { base => base, user => web_user(&st, &jar).await })
}

// ---------- Authentification Web ----------

#[derive(serde::Serialize, Clone)]
struct WebUser {
    username: String,
    role: String,
    csrf: String,
    can_review: bool,
    is_admin: bool,
}

async fn session_actor(st: &AppState, jar: &CookieJar) -> Option<Actor> {
    let c = jar.get(auth::SESSION_COOKIE)?;
    let th = auth::token_hash(c.value());
    #[derive(sqlx::FromRow)]
    struct SessRow {
        user_id: Uuid,
        username: String,
        role: String,
        csrf_token: String,
    }
    let r: SessRow = sqlx::query_as(
        "SELECT s.user_id, u.username, u.role, s.csrf_token FROM sessions s JOIN users u ON u.id = s.user_id
         WHERE s.token_hash = $1 AND s.expires_at > now() AND u.active",
    )
    .bind(&th)
    .fetch_optional(&st.db)
    .await
    .ok()??;
    Some(Actor {
        user_id: r.user_id,
        username: r.username,
        role: Role::parse(&r.role)?,
        via: Via::Session { csrf: r.csrf_token, token_hash: th },
        ip: None,
    })
}

async fn web_user(st: &AppState, jar: &CookieJar) -> Option<WebUser> {
    session_actor(st, jar).await.map(|a| to_web_user(&a))
}

fn to_web_user(a: &Actor) -> WebUser {
    WebUser {
        username: a.username.clone(),
        role: a.role.as_str().into(),
        csrf: match &a.via {
            Via::Session { csrf, .. } => csrf.clone(),
            _ => String::new(),
        },
        can_review: a.has(Scope::Review),
        is_admin: a.has(Scope::Admin),
    }
}

/// Session obligatoire ; redirige vers la page de connexion sinon.
async fn require_session(st: &AppState, jar: &CookieJar) -> Result<Actor, Response> {
    session_actor(st, jar).await.ok_or_else(|| Redirect::to("/admin/login").into_response())
}

fn check_csrf(actor: &Actor, token: &str) -> ApiResult<()> {
    match &actor.via {
        Via::Session { csrf, .. } if crate::util::ct_eq(csrf, token) => Ok(()),
        _ => Err(ApiError::Forbidden("jeton CSRF invalide : rechargez la page".into())),
    }
}

fn with_ip(mut a: Actor, peer: Option<SocketAddr>, st: &AppState, headers: &HeaderMap) -> Actor {
    a.ip = Some(auth_routes::peer_ip(st, peer, headers));
    a
}

fn back(path: &str, msg: &str) -> Response {
    let enc: String = url::form_urlencoded::byte_serialize(msg.as_bytes()).collect();
    Redirect::to(&format!("{path}?msg={enc}")).into_response()
}

#[derive(Deserialize, Default)]
struct MsgQuery {
    msg: Option<String>,
    status: Option<String>,
}

async fn login_page(State(st): State<AppState>, jar: CookieJar, Query(q): Query<MsgQuery>) -> Response {
    page(&st, &jar, "admin/login.html", context! { msg => q.msg })
}

#[derive(Deserialize)]
struct LoginForm {
    username: String,
    password: String,
}

async fn login_post(
    State(st): State<AppState>,
    peer: crate::auth::Peer,
    headers: HeaderMap,
    jar: CookieJar,
    Form(f): Form<LoginForm>,
) -> Response {
    let ip = auth_routes::peer_ip(&st, peer.0, &headers);
    match auth_routes::check_credentials(&st, &f.username, &f.password, &ip).await {
        Ok((uid, _)) => match auth::create_session(&st, uid, Some(ip.clone())).await {
            Ok((token, _)) => {
                crate::audit::log(&st.db, None, "auth.login", &f.username, serde_json::json!({"ip": ip, "via": "web"})).await;
                (jar.add(auth_routes::session_cookie(&st, token)), Redirect::to("/admin")).into_response()
            }
            Err(e) => error_page(&st, &jar, ApiError::Internal(e)),
        },
        Err(ApiError::TooManyRequests) => back("/admin/login", "throttled"),
        Err(_) => back("/admin/login", "invalid"),
    }
}

#[derive(Deserialize)]
struct CsrfForm {
    csrf: String,
}

async fn logout(State(st): State<AppState>, jar: CookieJar, Form(f): Form<CsrfForm>) -> Response {
    if let Some(a) = session_actor(&st, &jar).await {
        if check_csrf(&a, &f.csrf).is_ok() {
            if let Via::Session { token_hash, .. } = &a.via {
                let _ = sqlx::query("DELETE FROM sessions WHERE token_hash = $1").bind(token_hash).execute(&st.db).await;
            }
        }
    }
    (jar.remove(Cookie::from(auth::SESSION_COOKIE)), Redirect::to("/")).into_response()
}

// ---------- Administration ----------

macro_rules! session {
    ($st:expr, $jar:expr) => {
        match require_session(&$st, &$jar).await {
            Ok(a) => a,
            Err(r) => return r,
        }
    };
}

macro_rules! tryp {
    ($st:expr, $jar:expr, $e:expr) => {
        match $e {
            Ok(v) => v,
            Err(e) => return error_page(&$st, &$jar, e),
        }
    };
}

async fn dashboard(State(st): State<AppState>, jar: CookieJar) -> Response {
    let a = session!(st, jar);
    #[derive(sqlx::FromRow, serde::Serialize)]
    struct Counts {
        pending: i64,
        published: i64,
        apps: i64,
        verified: i64,
        revoked: i64,
    }
    let c: Counts = tryp!(
        st,
        jar,
        sqlx::query_as(
            "SELECT (SELECT count(*) FROM submissions WHERE status = 'pending') AS pending,
                    (SELECT count(*) FROM releases WHERE state = 'published') AS published,
                    (SELECT count(*) FROM apps) AS apps,
                    (SELECT count(*) FROM evaluations WHERE status = 'verified') AS verified,
                    (SELECT count(*) FROM releases WHERE state = 'revoked') AS revoked"
        )
        .fetch_one(&st.db)
        .await
        .map_err(ApiError::from)
    );
    let repos = tryp!(st, jar, admin::repositories(&st).await);
    let key = st.keys.signer.as_ref().map(|s| s.key_id().to_string());
    page(&st, &jar, "admin/dashboard.html", context! { user => to_web_user(&a), c => c, repos => repos, signing_key => key })
}

async fn submissions_page(State(st): State<AppState>, jar: CookieJar, Query(q): Query<MsgQuery>) -> Response {
    let a = session!(st, jar);
    let status = q.status.clone().filter(|s| !s.is_empty());
    let list = tryp!(st, jar, submissions::list_for(&st, &a, status.as_deref()).await);
    page(&st, &jar, "admin/submissions.html", context! { user => to_web_user(&a), list => list, msg => q.msg, status => status })
}

async fn submission_page(State(st): State<AppState>, jar: CookieJar, Path(id): Path<Uuid>, Query(q): Query<MsgQuery>) -> Response {
    let a = session!(st, jar);
    let s = tryp!(st, jar, submissions::load(&st, id).await);
    if !a.has(Scope::Review) && s.submitter.as_deref() != Some(a.username.as_str()) {
        return error_page(&st, &jar, ApiError::NotFound);
    }
    let manifest_yaml = s.manifest.as_ref().and_then(|m| serde_yaml_ng::to_string(m).ok());
    page(&st, &jar, "admin/submission.html", context! { user => to_web_user(&a), s => s, manifest_yaml => manifest_yaml, msg => q.msg })
}

#[derive(Deserialize)]
struct ReviewForm {
    csrf: String,
    #[serde(default)]
    note: String,
}

async fn submission_approve(
    State(st): State<AppState>,
    peer: crate::auth::Peer,
    headers: HeaderMap,
    jar: CookieJar,
    Path(id): Path<Uuid>,
    Form(f): Form<ReviewForm>,
) -> Response {
    let a = with_ip(session!(st, jar), peer.0, &st, &headers);
    tryp!(st, jar, check_csrf(&a, &f.csrf));
    match crate::publisher::approve(&st, &a, id, &f.note).await {
        Ok(_) => back(&format!("/admin/submissions/{id}"), "approved"),
        Err(e) => back(&format!("/admin/submissions/{id}"), &e.to_string()),
    }
}

async fn submission_reject(
    State(st): State<AppState>,
    peer: crate::auth::Peer,
    headers: HeaderMap,
    jar: CookieJar,
    Path(id): Path<Uuid>,
    Form(f): Form<ReviewForm>,
) -> Response {
    let a = with_ip(session!(st, jar), peer.0, &st, &headers);
    tryp!(st, jar, check_csrf(&a, &f.csrf));
    match submissions::reject_submission(&st, &a, id, &f.note).await {
        Ok(()) => back(&format!("/admin/submissions/{id}"), "rejected"),
        Err(e) => back(&format!("/admin/submissions/{id}"), &e.to_string()),
    }
}

async fn upload_page(State(st): State<AppState>, jar: CookieJar, Query(q): Query<MsgQuery>) -> Response {
    let a = session!(st, jar);
    let repos = tryp!(st, jar, admin::repositories(&st).await);
    page(&st, &jar, "admin/upload.html", context! { user => to_web_user(&a), repos => repos, msg => q.msg })
}

/// Import d'un fichier `.apak` depuis l'interface (crée une demande de publication).
async fn upload_post(
    State(st): State<AppState>,
    peer: crate::auth::Peer,
    headers: HeaderMap,
    jar: CookieJar,
    mut mp: Multipart,
) -> Response {
    let a = with_ip(session!(st, jar), peer.0, &st, &headers);
    let mut csrf = String::new();
    let mut repo = "official".to_string();
    let mut note = String::new();
    let mut file: Option<(std::path::PathBuf, String, u64, String)> = None;
    let _ = std::fs::create_dir_all(st.config.tmp_dir());
    loop {
        let field = match mp.next_field().await {
            Ok(Some(f)) => f,
            Ok(None) => break,
            Err(e) => return back("/admin/upload", &format!("formulaire invalide : {e}")),
        };
        match field.name().unwrap_or("") {
            "csrf" => csrf = field.text().await.unwrap_or_default(),
            "repository" => repo = field.text().await.unwrap_or_default(),
            "note" => note = field.text().await.unwrap_or_default(),
            "file" => {
                // Le jeton CSRF doit précéder le fichier dans le formulaire.
                if check_csrf(&a, &csrf).is_err() {
                    return error_page(&st, &jar, ApiError::Forbidden("jeton CSRF invalide".into()));
                }
                let name = field.file_name().unwrap_or("paquet.apak").to_string();
                let tmp = st.config.tmp_dir().join(format!("web-{}.apak", Uuid::new_v4()));
                let mut out = match tokio::fs::File::create(&tmp).await {
                    Ok(f) => f,
                    Err(e) => return error_page(&st, &jar, e.into()),
                };
                let mut h = <sha2::Sha256 as sha2::Digest>::new();
                let mut n = 0u64;
                let mut field = field;
                loop {
                    match field.chunk().await {
                        Ok(Some(c)) => {
                            n += c.len() as u64;
                            if n > st.config.max_upload_bytes {
                                let _ = tokio::fs::remove_file(&tmp).await;
                                return back("/admin/upload", "fichier trop volumineux");
                            }
                            sha2::Digest::update(&mut h, &c);
                            if out.write_all(&c).await.is_err() {
                                return back("/admin/upload", "écriture impossible");
                            }
                        }
                        Ok(None) => break,
                        Err(e) => return back("/admin/upload", &format!("transfert interrompu : {e}")),
                    }
                }
                let _ = out.sync_all().await;
                file = Some((tmp, hex::encode(sha2::Digest::finalize(h)), n, name));
            }
            _ => {}
        }
    }
    tryp!(st, jar, check_csrf(&a, &csrf));
    let Some((tmp, sha, size, name)) = file else { return back("/admin/upload", "aucun fichier") };
    let r = submissions::create_from_file(&st, &a, &repo, Some(&name), &note, &tmp, sha, size).await;
    let _ = std::fs::remove_file(&tmp);
    match r {
        Ok(s) => Redirect::to(&format!("/admin/submissions/{}", s.id)).into_response(),
        Err(e) => back("/admin/upload", &e.to_string()),
    }
}

#[derive(Deserialize, Default)]
struct ReleasesQuery {
    repository: Option<String>,
    app_id: Option<String>,
    msg: Option<String>,
}

async fn releases_page(State(st): State<AppState>, jar: CookieJar, Query(q): Query<ReleasesQuery>) -> Response {
    let a = session!(st, jar);
    let list = tryp!(st, jar, admin::releases(&st, q.repository.as_deref().filter(|s| !s.is_empty()), q.app_id.as_deref().filter(|s| !s.is_empty())).await);
    page(&st, &jar, "admin/releases.html", context! { user => to_web_user(&a), list => list, msg => q.msg })
}

#[derive(Deserialize)]
struct StateForm {
    csrf: String,
    state: String,
    #[serde(default)]
    reason: String,
}

async fn release_state(
    State(st): State<AppState>,
    peer: crate::auth::Peer,
    headers: HeaderMap,
    jar: CookieJar,
    Path(id): Path<Uuid>,
    Form(f): Form<StateForm>,
) -> Response {
    let a = with_ip(session!(st, jar), peer.0, &st, &headers);
    tryp!(st, jar, check_csrf(&a, &f.csrf));
    match crate::publisher::set_release_state(&st, &a, id, &f.state, &f.reason).await {
        Ok(()) => back("/admin/releases", "ok"),
        Err(e) => back("/admin/releases", &e.to_string()),
    }
}

async fn apps_page(State(st): State<AppState>, jar: CookieJar, Query(q): Query<MsgQuery>) -> Response {
    let a = session!(st, jar);
    #[derive(sqlx::FromRow, serde::Serialize)]
    struct Row {
        id: String,
        name: String,
        publisher: String,
        license: String,
        status: String,
        note: Option<String>,
        evaluated_at: Option<chrono::DateTime<chrono::Utc>>,
        evaluated_by: Option<String>,
    }
    let rows: Vec<Row> = tryp!(
        st,
        jar,
        sqlx::query_as(
            "SELECT a.id, a.name, a.publisher, a.license, COALESCE(e.status, 'unreviewed') AS status, e.note, e.evaluated_at,
                    u.username AS evaluated_by
             FROM apps a LEFT JOIN evaluations e ON e.app_id = a.id LEFT JOIN users u ON u.id = e.evaluated_by ORDER BY a.name"
        )
        .fetch_all(&st.db)
        .await
        .map_err(ApiError::from)
    );
    page(&st, &jar, "admin/apps.html", context! { user => to_web_user(&a), apps => rows, msg => q.msg })
}

#[derive(Deserialize)]
struct EvalForm {
    csrf: String,
    status: String,
    #[serde(default)]
    note: String,
}

async fn app_evaluation(
    State(st): State<AppState>,
    peer: crate::auth::Peer,
    headers: HeaderMap,
    jar: CookieJar,
    Path(id): Path<String>,
    Form(f): Form<EvalForm>,
) -> Response {
    let a = with_ip(session!(st, jar), peer.0, &st, &headers);
    tryp!(st, jar, check_csrf(&a, &f.csrf));
    let req = admin::EvaluationReq {
        status: f.status,
        note: Some(f.note).filter(|n| !n.trim().is_empty()),
        criteria: serde_json::Value::Null,
    };
    match admin::apply_evaluation(&st, &a, &id, &req).await {
        Ok(()) => back("/admin/apps", "ok"),
        Err(e) => back("/admin/apps", &e.to_string()),
    }
}

async fn repos_page(State(st): State<AppState>, jar: CookieJar, Query(q): Query<MsgQuery>) -> Response {
    let a = session!(st, jar);
    let repos = tryp!(st, jar, admin::repositories(&st).await);
    let base = st.config.public_url.to_string();
    page(&st, &jar, "admin/repositories.html", context! { user => to_web_user(&a), repos => repos, base => base, msg => q.msg })
}

#[derive(Deserialize)]
struct RepoForm {
    csrf: String,
    name: String,
    title: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    official: Option<String>,
}

async fn repo_create(State(st): State<AppState>, jar: CookieJar, Form(f): Form<RepoForm>) -> Response {
    let a = session!(st, jar);
    tryp!(st, jar, check_csrf(&a, &f.csrf));
    let req = admin::RepoReq { name: f.name, title: f.title, description: f.description, official: f.official.is_some() };
    match admin::create_repository(State(st.clone()), a, axum::Json(req)).await {
        Ok(_) => back("/admin/repositories", "ok"),
        Err(e) => back("/admin/repositories", &e.to_string()),
    }
}

async fn repo_regenerate(State(st): State<AppState>, jar: CookieJar, Path(name): Path<String>, Form(f): Form<CsrfForm>) -> Response {
    let a = session!(st, jar);
    tryp!(st, jar, check_csrf(&a, &f.csrf));
    match admin::regenerate(State(st.clone()), a, Path(name)).await {
        Ok(_) => back("/admin/repositories", "ok"),
        Err(e) => back("/admin/repositories", &e.to_string()),
    }
}

async fn users_page(State(st): State<AppState>, jar: CookieJar, Query(q): Query<MsgQuery>) -> Response {
    let a = session!(st, jar);
    if !a.has(Scope::Admin) {
        return error_page(&st, &jar, ApiError::Forbidden("réservé aux administrateurs".into()));
    }
    let users = tryp!(st, jar, admin::users(&st).await);
    page(&st, &jar, "admin/users.html", context! { user => to_web_user(&a), users => users, msg => q.msg })
}

#[derive(Deserialize)]
struct UserForm {
    csrf: String,
    username: String,
    #[serde(default)]
    display_name: String,
    password: String,
    role: String,
}

async fn user_create(State(st): State<AppState>, jar: CookieJar, Form(f): Form<UserForm>) -> Response {
    let a = session!(st, jar);
    tryp!(st, jar, check_csrf(&a, &f.csrf));
    let req = admin::CreateUserReq { username: f.username, display_name: f.display_name, password: f.password, role: f.role };
    match admin::create_user(State(st.clone()), a, axum::Json(req)).await {
        Ok(_) => back("/admin/users", "ok"),
        Err(e) => back("/admin/users", &e.to_string()),
    }
}

#[derive(Deserialize)]
struct UserUpdateForm {
    csrf: String,
    #[serde(default)]
    role: Option<String>,
    #[serde(default)]
    active: Option<String>,
    #[serde(default)]
    password: Option<String>,
}

async fn user_update(State(st): State<AppState>, jar: CookieJar, Path(id): Path<Uuid>, Form(f): Form<UserUpdateForm>) -> Response {
    let a = session!(st, jar);
    tryp!(st, jar, check_csrf(&a, &f.csrf));
    let req = admin::UpdateUserReq {
        role: f.role.filter(|r| !r.is_empty()),
        active: f.active.as_deref().map(|v| v == "1"),
        password: f.password.filter(|p| !p.is_empty()),
        display_name: None,
    };
    match admin::apply_user_update(&st, &a, id, &req).await {
        Ok(()) => back("/admin/users", "ok"),
        Err(e) => back("/admin/users", &e.to_string()),
    }
}

async fn tokens_page(State(st): State<AppState>, jar: CookieJar, Query(q): Query<MsgQuery>) -> Response {
    let a = session!(st, jar);
    let list: Vec<auth_routes::TokenRow> = if a.has(Scope::Admin) {
        tryp!(st, jar, admin::tokens(&st).await)
    } else {
        tryp!(st, jar, auth_routes::list_own_tokens(State(st.clone()), a.clone()).await.map(|j| j.0))
    };
    let users = if a.has(Scope::Admin) { tryp!(st, jar, admin::users(&st).await) } else { vec![] };
    page(&st, &jar, "admin/tokens.html", context! { user => to_web_user(&a), tokens => list, users => users, msg => q.msg, new_token => Value::UNDEFINED })
}

#[derive(Deserialize)]
struct TokenForm {
    csrf: String,
    name: String,
    kind: String,
    #[serde(default)]
    provider: String,
    #[serde(default)]
    scope_read: Option<String>,
    #[serde(default)]
    scope_build: Option<String>,
    #[serde(default)]
    scope_submit: Option<String>,
    #[serde(default)]
    scope_review: Option<String>,
    #[serde(default)]
    scope_evaluate: Option<String>,
    #[serde(default)]
    scope_admin: Option<String>,
    #[serde(default)]
    expires_days: Option<i64>,
    #[serde(default)]
    user_id: Option<String>,
}

async fn token_create(State(st): State<AppState>, jar: CookieJar, Form(f): Form<TokenForm>) -> Response {
    let a = session!(st, jar);
    tryp!(st, jar, check_csrf(&a, &f.csrf));
    let mut scopes = Vec::new();
    for (on, s) in [
        (&f.scope_read, "read"),
        (&f.scope_build, "build"),
        (&f.scope_submit, "submit"),
        (&f.scope_review, "review"),
        (&f.scope_evaluate, "evaluate"),
        (&f.scope_admin, "admin"),
    ] {
        if on.is_some() {
            scopes.push(s.to_string());
        }
    }
    let owner = f.user_id.as_deref().and_then(|u| Uuid::parse_str(u).ok()).filter(|_| a.has(Scope::Admin)).unwrap_or(a.user_id);
    let owner_role: Option<(String,)> = sqlx::query_as("SELECT role FROM users WHERE id = $1").bind(owner).fetch_optional(&st.db).await.ok().flatten();
    let Some(role) = owner_role.and_then(|r| Role::parse(&r.0)) else { return back("/admin/tokens", "utilisateur inconnu") };
    let req = auth_routes::TokenReq {
        name: f.name,
        kind: f.kind,
        scopes,
        provider: Some(f.provider).filter(|p| !p.trim().is_empty()),
        expires_days: f.expires_days,
        user_id: Some(owner),
    };
    match auth_routes::issue_token(&st, &a, owner, role, &req).await {
        Ok((_, token)) => {
            let list = if a.has(Scope::Admin) { admin::tokens(&st).await.unwrap_or_default() } else { vec![] };
            let users = if a.has(Scope::Admin) { admin::users(&st).await.unwrap_or_default() } else { vec![] };
            page(&st, &jar, "admin/tokens.html", context! { user => to_web_user(&a), tokens => list, users => users, new_token => token })
        }
        Err(e) => back("/admin/tokens", &e.to_string()),
    }
}

async fn token_revoke(State(st): State<AppState>, jar: CookieJar, Path(id): Path<Uuid>, Form(f): Form<CsrfForm>) -> Response {
    let a = session!(st, jar);
    tryp!(st, jar, check_csrf(&a, &f.csrf));
    let r = if a.has(Scope::Admin) {
        admin::revoke_token(State(st.clone()), a, Path(id)).await.map(|_| ())
    } else {
        auth_routes::revoke_own_token(State(st.clone()), a, Path(id)).await.map(|_| ())
    };
    match r {
        Ok(()) => back("/admin/tokens", "ok"),
        Err(e) => back("/admin/tokens", &e.to_string()),
    }
}

#[derive(Deserialize, Default)]
struct AuditQ {
    before_id: Option<i64>,
}

async fn audit_page(State(st): State<AppState>, jar: CookieJar, Query(q): Query<AuditQ>) -> Response {
    let a = session!(st, jar);
    if !a.has(Scope::Admin) {
        return error_page(&st, &jar, ApiError::Forbidden("réservé aux administrateurs".into()));
    }
    let rows = tryp!(st, jar, admin::audit_rows(&st, 200, q.before_id).await);
    let next = rows.last().map(|r| r.id);
    page(&st, &jar, "admin/audit.html", context! { user => to_web_user(&a), rows => rows, next => next })
}

