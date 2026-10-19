//! `auxipak-server` — serveur AuxiPak.

use anyhow::{Context, Result};
use auxipak_server::{app, build_state, config::Config, initial_publish, publisher};
use clap::{Parser, Subcommand};
use std::io::BufRead;
use std::net::SocketAddr;

#[derive(Parser)]
#[command(name = "auxipak-server", version, about = "Serveur AuxiPak (pak.auxinux.ca)")]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Démarrer le serveur (par défaut).
    Serve,
    /// Appliquer les migrations de base de données puis quitter.
    Migrate,
    /// Créer un compte administrateur (mot de passe lu sur l'entrée standard
    /// ou dans AUXIPAK_ADMIN_PASSWORD).
    CreateAdmin {
        #[arg(long)]
        username: String,
        #[arg(long, default_value = "")]
        display_name: String,
    },
    /// Régénérer les index et métadonnées TUF d'un dépôt.
    Regenerate {
        #[arg(long, default_value = "official")]
        repository: String,
    },
    /// Vérifier la configuration, la base de données et les clés.
    CheckConfig,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_env("AUXIPAK_LOG").unwrap_or_else(|_| "info,tower_http=info,sqlx=warn".into()))
        .with_target(false)
        .init();
    if let Err(e) = run(Cli::parse()).await {
        eprintln!("erreur : {e:#}");
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<()> {
    let cfg = Config::from_env()?;
    match cli.cmd.unwrap_or(Cmd::Serve) {
        Cmd::Migrate => {
            let db = sqlx::PgPool::connect(&cfg.database_url).await?;
            auxipak_server::MIGRATOR.run(&db).await?;
            println!("migrations appliquées");
        }
        Cmd::CreateAdmin { username, display_name } => {
            let password = match std::env::var("AUXIPAK_ADMIN_PASSWORD") {
                Ok(p) if !p.is_empty() => p,
                _ => {
                    eprintln!("mot de passe (12 caractères minimum), puis Entrée :");
                    let mut line = String::new();
                    std::io::stdin().lock().read_line(&mut line)?;
                    line.trim_end_matches(['\n', '\r']).to_string()
                }
            };
            let state = build_state(cfg).await?;
            let id = auxipak_server::api::admin::insert_user(&state, &username, &display_name, &password, auxipak_server::auth::Role::Admin)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            auxipak_server::audit::log(&state.db, None, "user.create_admin", &username, serde_json::json!({"user": id})).await;
            println!("administrateur « {username} » créé ({id})");
        }
        Cmd::Regenerate { repository } => {
            let state = build_state(cfg).await?;
            let g = publisher::regenerate(&state, &repository, None).await?;
            println!("dépôt {repository} régénéré (génération {g})");
        }
        Cmd::CheckConfig => {
            let mode = cfg.mode;
            let state = build_state(cfg).await?;
            println!("mode : {mode:?}");
            println!("base de données : OK");
            println!("racine TUF : {}", state.keys.root_path.display());
            let s = auxipak_core::tuf::summarize_root(&state.keys.root_json)?;
            println!("  version {} — expire {}", s.version, s.expires);
            match &state.keys.signer {
                Some(k) => println!("clé de signature des paquets : {}", k.key_id()),
                None => println!("clé de signature des paquets : ABSENTE (seuls les paquets pré-signés seront publiables)"),
            }
            let admins: (i64,) = sqlx::query_as("SELECT count(*) FROM users WHERE role = 'admin' AND active").fetch_one(&state.db).await?;
            if admins.0 == 0 {
                println!("ATTENTION : aucun administrateur — utilisez « auxipak-server create-admin »");
            }
        }
        Cmd::Serve => {
            let bind: SocketAddr = cfg.bind;
            let state = build_state(cfg).await.context("initialisation")?;
            initial_publish(&state).await?;
            tokio::spawn(publisher::refresh_loop(state.clone()));
            let listener = tokio::net::TcpListener::bind(bind).await.with_context(|| format!("écoute sur {bind}"))?;
            tracing::info!(%bind, "AuxiPak Server démarré");
            if state.config.mode == auxipak_server::config::Mode::Development {
                tracing::warn!("MODE DÉVELOPPEMENT : ne pas exposer ce serveur sur Internet");
            }
            let app = app(state).into_make_service_with_connect_info::<SocketAddr>();
            axum::serve(listener, app).with_graceful_shutdown(shutdown()).await?;
        }
    }
    Ok(())
}

async fn shutdown() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        if let Ok(mut s) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            s.recv().await;
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! { _ = ctrl_c => {}, _ = term => {} }
    tracing::info!("arrêt demandé");
}
