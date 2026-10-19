//! AuxiPak Server : API REST, dépôts TUF, publication, classification et
//! interface Web.

pub mod api;
pub mod audit;
pub mod auth;
pub mod config;
pub mod error;
pub mod keys;
pub mod publisher;
pub mod state;
pub mod util;
pub mod validation;
pub mod web;

use axum::extract::DefaultBodyLimit;
use axum::http::{header, HeaderValue};
use axum::Router;
use state::AppState;
use std::sync::Arc;
use tower_http::set_header::SetResponseHeaderLayer;

pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// Construit l'état partagé : connexion, migrations, clés, gabarits.
pub async fn build_state(cfg: config::Config) -> anyhow::Result<AppState> {
    let db = sqlx::postgres::PgPoolOptions::new()
        .max_connections(16)
        .acquire_timeout(std::time::Duration::from_secs(10))
        .connect(&cfg.database_url)
        .await
        .map_err(|e| anyhow::anyhow!("connexion à PostgreSQL impossible : {e}"))?;
    MIGRATOR.run(&db).await?;
    for d in [cfg.submissions_dir(), cfg.packages_dir(), cfg.repos_dir(), cfg.builder_dir(), cfg.tmp_dir()] {
        std::fs::create_dir_all(d)?;
    }
    let keys = keys::Keys::load(&cfg).await?;
    Ok(AppState {
        config: Arc::new(cfg),
        db,
        keys: Arc::new(keys),
        throttle: Arc::new(auth::LoginThrottle::default()),
        publish_lock: Arc::new(tokio::sync::Mutex::new(())),
        web: Arc::new(web::Templates::new()?),
    })
}

/// Régénère les dépôts jamais publiés (premier démarrage).
pub async fn initial_publish(state: &AppState) -> anyhow::Result<()> {
    let repos: Vec<(String,)> = sqlx::query_as("SELECT name FROM repositories WHERE enabled AND generation = 0").fetch_all(&state.db).await?;
    for (r,) in repos {
        publisher::regenerate(state, &r, None).await?;
    }
    Ok(())
}

/// Application complète.
pub fn app(state: AppState) -> Router {
    Router::new()
        .merge(api::router())
        .merge(web::router())
        .layer(DefaultBodyLimit::max(2 * 1024 * 1024))
        .layer(SetResponseHeaderLayer::if_not_present(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff")))
        .layer(SetResponseHeaderLayer::if_not_present(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY")))
        .layer(SetResponseHeaderLayer::if_not_present(header::REFERRER_POLICY, HeaderValue::from_static("same-origin")))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static("default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'"),
        ))
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .with_state(state)
}
