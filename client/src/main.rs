//! `auxipak` — client de distribution d'applications de l'écosystème AuxiNux.

mod catalog;
mod config;
mod detect;
mod download;
mod engine;
mod executor;
mod methods;
mod paths;
mod privileges;
mod registry;
mod repo;

use anyhow::{bail, Context, Result};
use auxipak_core::archive::{self, Limits};
use auxipak_core::signature::{KeyPurpose, PackageSignature};
use clap::{Parser, Subcommand};
use config::{Config, RepoConfig};
use engine::{Env, InstallOpts};
use paths::Paths;
use registry::{Registry, StateLock, Transaction};
use repo::Need;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(
    name = "auxipak",
    version,
    about = "AuxiPak — distribution et gestion d'applications pour l'écosystème AuxiNux",
    long_about = "AuxiPak installe, met à niveau et désinstalle des applications distribuées au format .apak, \
                  en utilisant les mécanismes natifs autorisés par chaque système (APT, auxi, MSI, pkg…).\n\
                  AuxiPak ne met jamais à jour le système d'exploitation lui-même."
)]
struct Cli {
    /// Sortie au format JSON (commandes de consultation).
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Rechercher une application dans les index (cache local, actualisé si nécessaire).
    Search {
        /// Terme recherché (identifiant, nom ou description).
        query: Option<String>,
        /// Ne jamais contacter le réseau.
        #[arg(long)]
        offline: bool,
    },
    /// Installer une application (ex. « firefox » ou « Firefox-150.1-fr »).
    Install {
        package: String,
        #[arg(long)]
        version: Option<String>,
        #[arg(long)]
        lang: Option<String>,
        #[arg(long)]
        repo: Option<String>,
        /// Autoriser explicitement les scripts personnalisés du paquet.
        #[arg(long)]
        allow_scripts: bool,
        /// Faire suivre par AuxiPak une application déjà installée nativement, sans la réinstaller.
        #[arg(long)]
        adopt: bool,
        #[arg(long)]
        reinstall: bool,
    },
    /// Désinstaller une application gérée par AuxiPak.
    Remove {
        package: String,
        /// Supprimer même si d'autres applications en dépendent.
        #[arg(long)]
        force: bool,
        /// Supprimer aussi les dépendances installées automatiquement devenues inutiles.
        #[arg(long)]
        autoremove: bool,
        #[arg(long)]
        allow_scripts: bool,
    },
    /// Forcer la synchronisation des index de tous les dépôts (ne met pas à jour les applications).
    Update,
    /// Mettre à niveau toutes les applications gérées, ou celle indiquée.
    Upgrade {
        package: Option<String>,
        #[arg(long)]
        allow_scripts: bool,
    },
    /// Lister les applications installées et suivies par AuxiPak.
    List {
        /// Vérifier la présence réelle de chaque application (réconciliation).
        #[arg(long)]
        check: bool,
    },
    /// Afficher les métadonnées, dépendances, statut et informations de sécurité.
    Info {
        package: String,
        #[arg(long)]
        offline: bool,
    },
    /// Vérifier un fichier .apak local (structure, manifeste, signature). N'exécute rien.
    Verify {
        file: PathBuf,
        /// Document de signature (par défaut : <fichier>.sig s'il existe).
        #[arg(long)]
        signature: Option<PathBuf>,
    },
    /// Nettoyer le cache (paquets téléchargés, répertoires de travail).
    Clean {
        /// Supprimer aussi les index en cache (une synchronisation sera nécessaire).
        #[arg(long)]
        all: bool,
    },
    /// Gérer les dépôts.
    Repo {
        #[command(subcommand)]
        cmd: RepoCmd,
    },
    /// Reprendre ou nettoyer les opérations interrompues.
    Repair,
    /// Diagnostic : profil système, dépôts, état du cache.
    Doctor,
}

#[derive(Subcommand)]
enum RepoCmd {
    /// Lister les dépôts configurés.
    List,
    /// Ajouter un dépôt externe.
    Add {
        url: String,
        #[arg(long)]
        name: Option<String>,
        /// root.json TUF de confiance (obtenu par un canal sûr).
        #[arg(long)]
        root: Option<PathBuf>,
        /// Clés publiques de signature des paquets (package-keys.json).
        #[arg(long)]
        keys: Option<PathBuf>,
        /// Récupérer root.json et les clés depuis le dépôt lui-même (confiance au premier usage, moins sûr).
        #[arg(long)]
        trust_on_first_use: bool,
        /// Autoriser l'exécution des scripts de ce dépôt (déconseillé).
        #[arg(long)]
        allow_scripts: bool,
        /// Développement : autoriser HTTP vers localhost.
        #[arg(long, hide = true)]
        allow_insecure_localhost: bool,
    },
    /// Retirer un dépôt.
    Remove { name: String },
}

fn init_logging(paths: &Paths) {
    use tracing_subscriber::prelude::*;
    let _ = std::fs::create_dir_all(&paths.log_dir);
    let file = std::fs::OpenOptions::new().create(true).append(true).open(paths.log_file());
    let filter = tracing_subscriber::EnvFilter::try_from_env("AUXIPAK_LOG").unwrap_or_else(|_| "info".into());
    if let Ok(f) = file {
        let layer = tracing_subscriber::fmt::layer().with_ansi(false).with_writer(std::sync::Mutex::new(f));
        let _ = tracing_subscriber::registry().with(filter).with(layer).try_init();
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let paths = Paths::detect();
    if let Err(e) = paths.ensure() {
        eprintln!("erreur : impossible de préparer {} : {e}", paths.state_dir.display());
        return ExitCode::from(1);
    }
    init_logging(&paths);
    tracing::info!(args = ?std::env::args().collect::<Vec<_>>(), "démarrage");
    match run(cli, paths).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(error = %format!("{e:#}"), "échec");
            eprintln!("erreur : {e:#}");
            ExitCode::from(1)
        }
    }
}

fn pending_warning(paths: &Paths) {
    if let Ok(p) = Transaction::pending(paths) {
        if !p.is_empty() {
            eprintln!(
                "avertissement : {} opération(s) interrompue(s) détectée(s) ; exécutez « auxipak repair »",
                p.len()
            );
        }
    }
}

async fn env_for(paths: Paths, need: Need) -> Result<Env> {
    let config = Config::load(&paths)?;
    let status = detect::load_or_detect(&paths)?;
    if status.first_run {
        eprintln!(
            "premier lancement : profil système enregistré ({} {}, {})",
            status.profile.distribution, status.profile.version, status.profile.arch
        );
    }
    if status.changed {
        eprintln!(
            "changement de système détecté ({}) : les index vont être resynchronisés",
            status.profile.pretty_name
        );
    }
    if status.profile.channel().is_none() {
        eprintln!(
            "avertissement : {} ({}) n'est pas une plateforme prise en charge par AuxiPak",
            status.profile.pretty_name, status.profile.distribution
        );
    }
    let env = Env::load(paths, config, status.profile, need).await;
    env.print_warnings();
    Ok(env)
}

async fn run(cli: Cli, paths: Paths) -> Result<()> {
    match cli.cmd {
        Cmd::Search { query, offline } => {
            let env = if offline { offline_env(paths)? } else { env_for(paths, Need::Browse).await? };
            if env.repos.is_empty() {
                bail!("aucun index disponible (exécutez « auxipak update » avec une connexion réseau)");
            }
            for r in &env.repos {
                if r.freshness(env.config.cache_ttl_seconds, &env.profile) != repo::Freshness::Fresh {
                    eprintln!("index « {} » : dernière synchronisation il y a {}", r.config.name, repo::age_label(&r.state));
                }
            }
            let hits = catalog::search(&env.repos, query.as_deref().unwrap_or(""), &env.config.language);
            if cli.json {
                let v: Vec<_> = hits
                    .iter()
                    .map(|c| {
                        serde_json::json!({
                            "id": c.release.id, "name": c.name(), "version": c.release.version,
                            "languages": c.release.languages, "status": c.status().short(),
                            "platform": c.release.platform, "repository": c.repo.config.name,
                            "summary": c.app.map(|a| a.summary.clone()).unwrap_or_default(),
                        })
                    })
                    .collect();
                println!("{}", serde_json::to_string_pretty(&v)?);
            } else if hits.is_empty() {
                println!("Aucun résultat.");
            } else {
                println!("{:<24} {:<12} {:<8} {:<12} {:<9} DESCRIPTION", "NOM (ID)", "VERSION", "LANGUE", "STATUT", "PLATEF.");
                for c in hits {
                    println!(
                        "{:<24} {:<12} {:<8} {:<12} {:<9} {}{}",
                        truncate(&format!("{} ({})", c.name(), c.release.id), 24),
                        truncate(&c.release.version, 12),
                        truncate(&c.release.languages.join(","), 8),
                        c.status().short(),
                        c.release.platform,
                        c.app.map(|a| a.summary.as_str()).unwrap_or(""),
                        if c.repo.config.official { String::new() } else { format!(" [{}]", c.repo.config.name) }
                    );
                }
            }
        }
        Cmd::Install { package, version, lang, repo, allow_scripts, adopt, reinstall } => {
            let _lock = StateLock::acquire(&paths)?;
            pending_warning(&paths);
            let env = env_for(paths, Need::Install).await?;
            let opts = InstallOpts {
                allow_scripts,
                adopt,
                reinstall,
                selector: engine::selector(version.as_deref(), lang.as_deref(), repo.as_deref())?,
            };
            let mut reg = Registry::load(&env.paths)?;
            for m in engine::install(&env, &package, &opts, &mut reg).await? {
                println!("{m}");
            }
        }
        Cmd::Remove { package, force, autoremove, allow_scripts } => {
            let _lock = StateLock::acquire(&paths)?;
            pending_warning(&paths);
            let config = Config::load(&paths)?;
            let profile = detect::load_or_detect(&paths)?.profile;
            let env = Env { paths, config, profile, repos: vec![], warnings: vec![] };
            let mut reg = Registry::load(&env.paths)?;
            for m in engine::remove(&env, &package, force, autoremove, allow_scripts, &mut reg).await? {
                println!("{m}");
            }
        }
        Cmd::Update => {
            let config = Config::load(&paths)?;
            let profile = detect::load_or_detect(&paths)?.profile;
            let mut failures = 0;
            for r in config.enabled_repos() {
                match repo::sync(r, &paths, &profile).await {
                    Ok(d) => println!(
                        "{} : index synchronisé (génération {}, {} version(s) pour {} {}, métadonnées valides jusqu'au {})",
                        r.name,
                        d.state.generation,
                        d.channel.as_ref().map(|c| c.releases.len()).unwrap_or(0),
                        profile.channel().map(|c| c.as_str()).unwrap_or("?"),
                        profile.arch,
                        d.state.metadata_expires.format("%Y-%m-%d %H:%M UTC")
                    ),
                    Err(e) => {
                        failures += 1;
                        eprintln!("{} : échec : {e:#}", r.name);
                    }
                }
            }
            if failures > 0 {
                bail!("{failures} dépôt(s) n'ont pas pu être synchronisés");
            }
        }
        Cmd::Upgrade { package, allow_scripts } => {
            let _lock = StateLock::acquire(&paths)?;
            pending_warning(&paths);
            let env = env_for(paths, Need::Install).await?;
            let mut reg = Registry::load(&env.paths)?;
            let opts = InstallOpts { allow_scripts, ..Default::default() };
            for m in engine::upgrade(&env, package.as_deref(), &opts, &mut reg).await? {
                println!("{m}");
            }
        }
        Cmd::List { check } => {
            pending_warning(&paths);
            let reg = Registry::load(&paths)?;
            let presence = if check {
                let config = Config::load(&paths)?;
                let profile = detect::load_or_detect(&paths)?.profile;
                let env = Env { paths: paths.clone(), config, profile, repos: vec![], warnings: vec![] };
                engine::reconcile(&env, &reg).await.into_iter().collect::<std::collections::BTreeMap<_, _>>()
            } else {
                Default::default()
            };
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&reg.apps)?);
            } else if reg.apps.is_empty() {
                println!("Aucune application installée par AuxiPak.");
            } else {
                println!("{:<22} {:<12} {:<10} {:<10} {:<10} {:<10} INSTALLÉ LE", "ID", "VERSION", "DÉPÔT", "MÉTHODE", "GEST.", "ÉTAT");
                for a in reg.apps.values() {
                    let mut state = format!("{:?}", a.state).to_lowercase();
                    if a.simulated {
                        state.push_str("*");
                    }
                    if let Some(p) = presence.get(&a.id) {
                        match p {
                            Some(false) => state.push_str(" (absente!)"),
                            None => state.push_str(" (?)"),
                            _ => {}
                        }
                    }
                    println!(
                        "{:<22} {:<12} {:<10} {:<10} {:<10} {:<10} {}{}",
                        truncate(&a.id, 22),
                        truncate(&a.version, 12),
                        a.repo,
                        a.method,
                        a.manager,
                        state,
                        a.installed_at.format("%Y-%m-%d %H:%M"),
                        if a.auto_installed { " (dépendance)" } else { "" }
                    );
                }
                if reg.apps.values().any(|a| a.simulated) {
                    println!("* installation réalisée en mode simulation (tests) : non valide comme installation réelle");
                }
            }
        }
        Cmd::Info { package, offline } => {
            let env = if offline { offline_env(paths)? } else { env_for(paths, Need::Browse).await? };
            info(&env, &package, cli.json)?;
        }
        Cmd::Verify { file, signature } => verify(&paths, &file, signature, cli.json)?,
        Cmd::Clean { all } => {
            let _lock = StateLock::acquire(&paths)?;
            let pending = Transaction::pending(&paths)?;
            let mut freed = 0u64;
            freed += remove_dir_size(&paths.package_cache_dir())?;
            if pending.is_empty() {
                freed += remove_dir_size(&paths.work_dir())?;
            } else {
                eprintln!("répertoires de travail conservés : opérations interrompues en attente (« auxipak repair »)");
            }
            if all {
                freed += remove_dir_size(&paths.cache_dir.join("repos"))?;
            }
            println!("Cache nettoyé ({} Kio libérés).", freed / 1024);
        }
        Cmd::Repo { cmd } => repo_cmd(&paths, cmd, cli.json).await?,
        Cmd::Repair => {
            let _lock = StateLock::acquire(&paths)?;
            let config = Config::load(&paths)?;
            let profile = detect::load_or_detect(&paths)?.profile;
            let env = Env { paths, config, profile, repos: vec![], warnings: vec![] };
            let mut reg = Registry::load(&env.paths)?;
            for m in engine::repair(&env, &mut reg).await? {
                println!("{m}");
            }
        }
        Cmd::Doctor => {
            let config = Config::load(&paths)?;
            let st = detect::load_or_detect(&paths)?;
            let p = &st.profile;
            println!("Système      : {} ({} {}, {})", p.pretty_name, p.distribution, p.version, p.arch);
            println!("Canal        : {}", p.channel().map(|c| c.as_str()).unwrap_or("non pris en charge"));
            println!("Immuable     : {}", if p.immutable { "oui" } else { "non" });
            println!("Portée       : {:?} (administrateur : {})", paths.scope, privileges::is_elevated());
            println!("Configuration: {}", paths.config_file().display());
            println!("État         : {}", paths.state_dir.display());
            println!("Cache        : {} (durée de validité {} s)", paths.cache_dir.display(), config.cache_ttl_seconds);
            println!("Journal      : {}", paths.log_file().display());
            if executor::is_simulation() {
                println!("MODE SIMULATION ACTIF (AUXIPAK_TEST_TOOLS_DIR)");
            }
            for r in &config.repositories {
                let trust = match r.trust(&paths) {
                    Ok(t) => format!("confiance : {}", t.source),
                    Err(e) => format!("CONFIANCE ABSENTE : {e}"),
                };
                let cache = match repo::load_cached(r, &paths) {
                    Ok(Some(d)) => format!(
                        "« {} », génération {}, synchronisé il y a {} ({:?})",
                        d.index.repository.title,
                        d.index.generation,
                        repo::age_label(&d.state),
                        d.freshness(config.cache_ttl_seconds, p)
                    ),
                    _ => "jamais synchronisé".into(),
                };
                println!("Dépôt {} : {} — {} — {}", r.name, r.url, trust, cache);
            }
            let pending = Transaction::pending(&paths)?;
            println!("Opérations interrompues : {}", pending.len());
            if !config.adapters.auxi.validated && p.distribution == auxipak_core::platform::Distribution::Auxinuxos {
                println!("Adaptateur auxi : syntaxe NON VALIDÉE sur ce système (voir docs/CLI_REFERENCE.md)");
            }
        }
    }
    Ok(())
}

fn offline_env(paths: Paths) -> Result<Env> {
    let config = Config::load(&paths)?;
    let profile = detect::load_or_detect(&paths)?.profile;
    let mut repos = Vec::new();
    for r in config.enabled_repos() {
        if let Some(d) = repo::load_cached(r, &paths)? {
            repos.push(d);
        }
    }
    Ok(Env { paths, config, profile, repos, warnings: vec![] })
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(n - 1).collect::<String>())
    }
}

fn remove_dir_size(p: &std::path::Path) -> Result<u64> {
    if !p.exists() {
        return Ok(0);
    }
    fn size(p: &std::path::Path) -> u64 {
        std::fs::read_dir(p)
            .map(|rd| {
                rd.flatten()
                    .map(|e| match e.file_type() {
                        Ok(t) if t.is_dir() => size(&e.path()),
                        _ => e.metadata().map(|m| m.len()).unwrap_or(0),
                    })
                    .sum()
            })
            .unwrap_or(0)
    }
    let s = size(p);
    std::fs::remove_dir_all(p)?;
    Ok(s)
}

fn info(env: &Env, package: &str, json: bool) -> Result<()> {
    let reg = Registry::load(&env.paths)?;
    let installed = reg.get(package);
    let c = catalog::resolve(&env.repos, package, &Default::default(), &env.config.language);
    let c = match (c, installed) {
        (Ok(c), _) => c,
        (Err(e), None) => return Err(e),
        (Err(_), Some(a)) => {
            println!("{} {} (installé, absent des index disponibles)", a.id, a.version);
            println!("{}", serde_json::to_string_pretty(a)?);
            return Ok(());
        }
    };
    let rel = c.release;
    let versions: Vec<String> = catalog::all_candidates(&env.repos)
        .iter()
        .filter(|x| x.release.id == rel.id && x.repo.config.name == c.repo.config.name)
        .map(|x| format!("{}{}", x.release.version, if x.is_revoked() { " (révoquée)" } else { "" }))
        .collect();
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "app": c.app, "release": rel, "repository": c.repo.config.name,
                "official_repository": c.repo.config.official, "status": c.status().short(),
                "versions": versions, "installed": installed,
            }))?
        );
        return Ok(());
    }
    println!("{} ({})", c.name(), rel.id);
    if let Some(a) = c.app {
        println!("  {}", a.summary);
        println!("Éditeur        : {}", a.publisher);
        println!("Licence        : {}", a.license);
        if let Some(h) = &a.homepage {
            println!("Site           : {h}");
        }
    }
    println!("Statut AuxiNux : {}", c.status().label());
    if let Some(note) = c.app.and_then(|a| a.status_note.as_ref()) {
        println!("  Réserves     : {note}");
    }
    println!("Version        : {} (disponibles : {})", rel.version, versions.join(", "));
    println!("Langues        : {}", rel.languages.join(", "));
    println!(
        "Plateforme     : {} — {} — {}",
        rel.platform,
        rel.distributions.iter().map(|d| d.as_str()).collect::<Vec<_>>().join(", "),
        rel.architectures.iter().map(|a| a.as_str()).collect::<Vec<_>>().join(", ")
    );
    println!("Dépôt          : {}{}", c.repo.config.name, if c.repo.config.official { " (officiel)" } else { " (externe)" });
    println!("Mode           : {} — privilèges : {:?}", rel.mode, rel.privileges);
    let deps: Vec<String> = rel.dependencies.iter().map(|d| format!("{} ({})", d.id, d.version)).collect();
    println!("Dépendances    : {}", if deps.is_empty() { "aucune".into() } else { deps.join(", ") });
    println!("Sécurité :");
    println!("  Fichier      : {} ({} octets)", rel.file_name, rel.size);
    println!("  SHA-256      : {}", rel.sha256);
    println!("  Signature    : clé {} ({})", rel.signature.key_id, rel.signature.target);
    println!("  Scripts      : {}", if rel.uses_scripts { "OUI — autorisation explicite requise" } else { "non" });
    println!("  Révoqué      : {}", if c.is_revoked() { "OUI" } else { "non" });
    println!("  Publié le    : {}", rel.published_at.format("%Y-%m-%d %H:%M UTC"));
    if let Some(i) = installed {
        println!("Installé       : {} le {} ({:?}, {})", i.version, i.installed_at.format("%Y-%m-%d"), i.state, i.manager);
    }
    Ok(())
}

fn verify(paths: &Paths, file: &std::path::Path, signature: Option<PathBuf>, json: bool) -> Result<()> {
    if file.extension().and_then(|e| e.to_str()) != Some("apak") {
        bail!("le fichier doit porter l'extension .apak");
    }
    let insp = archive::inspect(file, &Limits::default()).map_err(|e| anyhow::anyhow!("paquet INVALIDE : {e}"))?;
    let sig_path = signature.or_else(|| {
        let p = PathBuf::from(format!("{}.sig", file.display()));
        p.exists().then_some(p)
    });
    let mut sig_result: Option<Result<String, String>> = None;
    if let Some(sp) = &sig_path {
        let doc = PackageSignature::from_json(&std::fs::read(sp)?)?;
        let config = Config::load(paths)?;
        let mut last = Err("aucune clé de confiance configurée".to_string());
        for r in &config.repositories {
            if let Ok(t) = r.trust(paths) {
                match doc.verify(&insp.archive_sha256, insp.archive_size, &t.package_keys, &[KeyPurpose::PackageSigning]) {
                    Ok(v) => {
                        last = Ok(format!("valide (clé {} — {}, dépôt {})", v.key_id, v.owner, r.name));
                        break;
                    }
                    Err(e) => last = Err(e.to_string()),
                }
            }
        }
        sig_result = Some(last);
    }
    let m = &insp.manifest;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "valid": sig_result.as_ref().map(|r| r.is_ok()).unwrap_or(true),
                "id": m.id, "version": m.version, "sha256": insp.archive_sha256, "size": insp.archive_size,
                "unpacked_size": insp.total_unpacked, "entries": insp.entries.len(),
                "targets": m.targets.iter().map(|t| &t.name).collect::<Vec<_>>(),
                "uses_scripts": m.targets.iter().any(|t| t.uses_scripts()),
                "warnings": insp.warnings.iter().map(|w| w.to_string()).collect::<Vec<_>>(),
                "signature": sig_result.as_ref().map(|r| match r { Ok(s) => s.clone(), Err(e) => format!("INVALIDE : {e}") }),
            }))?
        );
    } else {
        println!("Paquet       : {}", file.display());
        println!("Application  : {} {} ({})", m.name, m.version, m.id);
        println!("Structure    : conforme au format .apak v{} ({} entrées)", archive::APAK_FORMAT_VERSION, insp.entries.len());
        println!("Manifeste    : valide (schéma et règles sémantiques)");
        println!("SHA-256      : {}", insp.archive_sha256);
        println!("Taille       : {} octets ({} décompressés)", insp.archive_size, insp.total_unpacked);
        println!("Variantes    : {}", m.targets.iter().map(|t| format!("{} [{} {}]", t.name, t.platform, t.mode)).collect::<Vec<_>>().join(", "));
        if m.targets.iter().any(|t| t.uses_scripts()) {
            println!("Scripts      : présents (exécution soumise à autorisation explicite)");
        }
        for w in &insp.warnings {
            println!("{w}");
        }
        match &sig_result {
            None => println!("Signature    : non vérifiée (aucun document .sig fourni)"),
            Some(Ok(s)) => println!("Signature    : {s}"),
            Some(Err(e)) => println!("Signature    : INVALIDE — {e}"),
        }
    }
    if let Some(Err(e)) = sig_result {
        bail!("signature invalide : {e}");
    }
    Ok(())
}

async fn repo_cmd(paths: &Paths, cmd: RepoCmd, json: bool) -> Result<()> {
    let mut config = Config::load(paths)?;
    match cmd {
        RepoCmd::List => {
            if json {
                println!("{}", serde_json::to_string_pretty(&config.repositories)?);
                return Ok(());
            }
            for r in &config.repositories {
                let kind = if r.official { "officiel" } else { "EXTERNE" };
                println!(
                    "{:<12} {:<9} {:<8} {}{}",
                    r.name,
                    kind,
                    if r.enabled { "actif" } else { "inactif" },
                    r.url,
                    if r.allow_scripts { " (scripts autorisés)" } else { "" }
                );
            }
        }
        RepoCmd::Add { url, name, root, keys, trust_on_first_use, allow_scripts, allow_insecure_localhost } => {
            let base = auxipak_core::netpolicy::validate_repo_url(&url, allow_insecure_localhost).map_err(|e| anyhow::anyhow!(e))?;
            let name = match name {
                Some(n) => n,
                None => base
                    .host_str()
                    .unwrap_or("repo")
                    .split('.')
                    .next()
                    .unwrap_or("repo")
                    .to_lowercase(),
            };
            if !auxipak_core::ids::is_valid_repo_name(&name) {
                bail!("nom de dépôt invalide : {name} (utilisez --name)");
            }
            if config.repo(&name).is_some() {
                bail!("le dépôt « {name} » existe déjà");
            }
            let trust_dir = paths.config_dir.join("trust").join(&name);
            std::fs::create_dir_all(&trust_dir)?;
            let (root_bytes, keys_bytes) = match (root, keys, trust_on_first_use) {
                (Some(r), Some(k), _) => (std::fs::read(&r).context("lecture de --root")?, std::fs::read(&k).context("lecture de --keys")?),
                (None, None, true) => {
                    eprintln!("ATTENTION : confiance au premier usage — vérifiez les empreintes ci-dessous auprès de l'éditeur du dépôt");
                    let client = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build()?;
                    let get = |u: url::Url| {
                        let client = client.clone();
                        async move {
                            let r = client.get(u.clone()).send().await?.error_for_status()?;
                            Ok::<_, anyhow::Error>(r.bytes().await?.to_vec())
                        }
                    };
                    if base.scheme() == "file" {
                        let p = base.to_file_path().map_err(|_| anyhow::anyhow!("URL invalide"))?;
                        (std::fs::read(p.join("metadata/1.root.json"))?, std::fs::read(p.join("keys/package-keys.json"))?)
                    } else {
                        (get(base.join("metadata/1.root.json")?).await?, get(base.join("keys/package-keys.json")?).await?)
                    }
                }
                _ => bail!("fournissez --root et --keys (obtenus par un canal sûr), ou --trust-on-first-use"),
            };
            let summary = auxipak_core::tuf::summarize_root(&root_bytes)?;
            let keys: auxipak_core::signature::TrustedKeys = serde_json::from_slice(&keys_bytes).context("package-keys.json invalide")?;
            paths::atomic_write(&trust_dir.join("root.json"), &root_bytes)?;
            paths::atomic_write(&trust_dir.join("package-keys.json"), &keys_bytes)?;
            println!("Racine TUF version {} (expire {}), empreinte {}", summary.version, summary.expires, auxipak_core::hash::sha256_hex(&root_bytes));
            for k in &keys.keys {
                println!("Clé de paquets {} — {}", k.key_id, k.owner);
            }
            config.repositories.push(RepoConfig {
                name: name.clone(),
                url: base.to_string(),
                root: PathBuf::from("trust").join(&name).join("root.json"),
                package_keys: PathBuf::from("trust").join(&name).join("package-keys.json"),
                // Un dépôt ajouté par l'utilisateur est toujours externe : il ne
                // peut pas s'attribuer les certifications officielles AuxiNux.
                official: false,
                enabled: true,
                allow_scripts,
                require_signatures: true,
                allow_insecure_localhost,
                priority: 10,
            });
            config.save(paths)?;
            println!("Dépôt externe « {name} » ajouté. Exécutez « auxipak update ».");
        }
        RepoCmd::Remove { name } => {
            let before = config.repositories.len();
            config.repositories.retain(|r| r.name != name);
            if config.repositories.len() == before {
                bail!("dépôt inconnu : {name}");
            }
            config.save(paths)?;
            repo::drop_cache(paths, &name)?;
            let _ = std::fs::remove_dir_all(paths.config_dir.join("trust").join(&name));
            println!("Dépôt « {name} » retiré (les applications installées restent dans le registre).");
        }
    }
    Ok(())
}
