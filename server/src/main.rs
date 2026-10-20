//! `auxipak-server` — serveur AuxiPak.

use anyhow::{Context, Result};
use auxipak_core::tr;
use auxipak_server::{app, build_state, config::Config, initial_publish, publisher};
use clap::{CommandFactory, FromArgMatches, Parser, Subcommand};
use std::io::BufRead;
use std::net::SocketAddr;

#[derive(Parser)]
#[command(name = "auxipak-server", version, about = "AuxiPak Server")]
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
    /// Vérifier qu'une instance locale répond (sonde de santé des conteneurs).
    Healthcheck,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("AUXIPAK_LOG")
                .unwrap_or_else(|_| "info,tower_http=info,sqlx=warn".into()),
        )
        .with_target(false)
        .init();
    let cli = match Cli::from_arg_matches(&localized_command().get_matches()) {
        Ok(c) => c,
        Err(e) => e.exit(),
    };
    if let Err(e) = run(cli).await {
        eprintln!("{}", tr!("erreur : {e:#}", "error: {e:#}"));
        std::process::exit(1);
    }
}

/// Aide de la ligne de commande dans la langue du système.
fn localized_command() -> clap::Command {
    let help: &[(&str, String)] = &[
        ("serve", tr!("Démarrer le serveur (par défaut)", "Start the server (default)")),
        (
            "migrate",
            tr!(
                "Appliquer les migrations de base de données puis quitter",
                "Apply database migrations, then exit"
            ),
        ),
        (
            "create-admin",
            tr!(
                "Créer un compte administrateur (mot de passe lu sur l'entrée standard ou dans AUXIPAK_ADMIN_PASSWORD)",
                "Create an administrator account (password read from standard input or AUXIPAK_ADMIN_PASSWORD)"
            ),
        ),
        (
            "regenerate",
            tr!(
                "Régénérer les index et métadonnées TUF d'un dépôt",
                "Regenerate a repository's indexes and TUF metadata"
            ),
        ),
        (
            "check-config",
            tr!(
                "Vérifier la configuration, la base de données et les clés",
                "Check the configuration, database and keys"
            ),
        ),
        (
            "healthcheck",
            tr!(
                "Vérifier qu'une instance locale répond (sonde de santé des conteneurs)",
                "Check that a local instance responds (container health probe)"
            ),
        ),
    ];
    let mut cmd = Cli::command().about(tr!("Serveur AuxiPak", "AuxiPak Server"));
    for (name, text) in help {
        cmd = cmd.mut_subcommand(*name, |c| c.about(text.clone()));
    }
    cmd
}

async fn run(cli: Cli) -> Result<()> {
    if let Some(Cmd::Healthcheck) = cli.cmd {
        return healthcheck().await;
    }
    let cfg = Config::from_env()?;
    match cli.cmd.unwrap_or(Cmd::Serve) {
        Cmd::Migrate => {
            let db = sqlx::PgPool::connect(&cfg.database_url).await?;
            auxipak_server::MIGRATOR.run(&db).await?;
            println!("{}", tr!("migrations appliquées", "migrations applied"));
        }
        Cmd::CreateAdmin { username, display_name } => {
            let password = match std::env::var("AUXIPAK_ADMIN_PASSWORD") {
                Ok(p) if !p.is_empty() => p,
                _ => {
                    eprintln!(
                        "{}",
                        tr!(
                            "mot de passe (12 caractères minimum), puis Entrée :",
                            "password (at least 12 characters), then Enter:"
                        )
                    );
                    let mut line = String::new();
                    std::io::stdin().lock().read_line(&mut line)?;
                    line.trim_end_matches(['\n', '\r']).to_string()
                }
            };
            let state = build_state(cfg).await?;
            let id = auxipak_server::api::admin::insert_user(
                &state,
                &username,
                &display_name,
                &password,
                auxipak_server::auth::Role::Admin,
            )
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
            auxipak_server::audit::log(
                &state.db,
                None,
                "user.create_admin",
                &username,
                serde_json::json!({"user": id}),
            )
            .await;
            println!(
                "{}",
                tr!(
                    "administrateur « {username} » créé ({id})",
                    "administrator « {username} » created ({id})"
                )
            );
        }
        Cmd::Regenerate { repository } => {
            let state = build_state(cfg).await?;
            let g = publisher::regenerate(&state, &repository, None).await?;
            println!(
                "{}",
                tr!(
                    "dépôt {repository} régénéré (génération {g})",
                    "repository {repository} regenerated (generation {g})"
                )
            );
        }
        Cmd::Healthcheck => unreachable!(),
        Cmd::CheckConfig => {
            let mode = cfg.mode;
            let state = build_state(cfg).await?;
            println!("mode : {mode:?}");
            println!("{}", tr!("base de données : OK", "database: OK"));
            println!("{}", tr!("racine TUF : {}", "TUF root: {}", state.keys.root_path.display()));
            let s = auxipak_core::tuf::summarize_root(&state.keys.root_json)?;
            println!(
                "{}",
                tr!("  version {} — expire {}", "  version {} — expires {}", s.version, s.expires)
            );
            match &state.keys.signer {
                Some(k) => println!(
                    "{}",
                    tr!("clé de signature des paquets : {}", "package signing key: {}", k.key_id())
                ),
                None => println!(
                    "{}",
                    tr!(
                        "clé de signature des paquets : ABSENTE (seuls les paquets pré-signés seront publiables)",
                        "package signing key: MISSING (only pre-signed packages can be published)"
                    )
                ),
            }
            let admins: (i64,) = sqlx::query_as("SELECT count(*) FROM users WHERE role = 'admin' AND active")
                .fetch_one(&state.db)
                .await?;
            if admins.0 == 0 {
                println!(
                    "{}",
                    tr!(
                        "ATTENTION : aucun administrateur — utilisez « auxipak-server create-admin »",
                        "WARNING: no administrator — use 'auxipak-server create-admin'"
                    )
                );
            }
        }
        Cmd::Serve => {
            let bind: SocketAddr = cfg.bind;
            let state = build_state(cfg).await.context(tr!("initialisation", "initialization"))?;
            initial_publish(&state).await?;
            tokio::spawn(publisher::refresh_loop(state.clone()));
            let listener = tokio::net::TcpListener::bind(bind)
                .await
                .with_context(|| tr!("écoute sur {bind}", "listening on {bind}"))?;
            tracing::info!(%bind, "{}", tr!("AuxiPak Server démarré", "AuxiPak Server started"));
            if state.config.mode == auxipak_server::config::Mode::Development {
                tracing::warn!(
                    "{}",
                    tr!(
                        "MODE DÉVELOPPEMENT : ne pas exposer ce serveur sur Internet",
                        "DEVELOPMENT MODE: do not expose this server to the Internet"
                    )
                );
            }
            let app = app(state).into_make_service_with_connect_info::<SocketAddr>();
            axum::serve(listener, app).with_graceful_shutdown(shutdown()).await?;
        }
    }
    Ok(())
}

/// Requête HTTP minimale vers l'instance locale (aucune dépendance externe).
async fn healthcheck() -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let bind: SocketAddr = std::env::var("AUXIPAK_BIND")
        .unwrap_or_else(|_| "127.0.0.1:8080".into())
        .parse()?;
    let target = if bind.ip().is_unspecified() {
        SocketAddr::from(([127, 0, 0, 1], bind.port()))
    } else {
        bind
    };
    let fut = async {
        let mut s = tokio::net::TcpStream::connect(target).await?;
        s.write_all(b"GET /api/v1/health HTTP/1.0\r\nHost: localhost\r\n\r\n").await?;
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).await?;
        Ok::<_, anyhow::Error>(String::from_utf8_lossy(&buf).into_owned())
    };
    let resp = tokio::time::timeout(std::time::Duration::from_secs(5), fut)
        .await
        .context(tr!("délai dépassé", "timed out"))??;
    if resp.starts_with("HTTP/1.0 200") || resp.starts_with("HTTP/1.1 200") {
        println!("ok");
        Ok(())
    } else {
        anyhow::bail!(tr!(
            "réponse inattendue : {}",
            "unexpected response: {}",
            resp.lines().next().unwrap_or("")
        ))
    }
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
    tracing::info!("{}", tr!("arrêt demandé", "shutdown requested"));
}
