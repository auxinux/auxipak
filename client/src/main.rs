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
mod progress;
mod registry;
mod repo;
mod selfupdate;

use anyhow::{bail, Context, Result};
use auxipak_core::archive::{self, Limits};
use auxipak_core::signature::{KeyPurpose, PackageSignature};
use auxipak_core::tr;
use clap::{CommandFactory, FromArgMatches, Parser, Subcommand};
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
    long_about = "AuxiPak installe, met à niveau et désinstalle des applications distribuées au format .aupak, \
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
        /// Identifiant, nom ou nom de fichier du paquet.
        package: String,
        /// Version ou contrainte de version (ex. 150.1 ou « >=150 »).
        #[arg(long)]
        version: Option<String>,
        /// Langue de paquet préférée (ex. fr, en).
        #[arg(long)]
        lang: Option<String>,
        /// Installer depuis ce dépôt uniquement.
        #[arg(long)]
        repo: Option<String>,
        /// Autoriser explicitement les scripts personnalisés du paquet.
        #[arg(long)]
        allow_scripts: bool,
        /// Faire suivre par AuxiPak une application déjà installée nativement, sans la réinstaller.
        #[arg(long)]
        adopt: bool,
        /// Réinstaller même si cette version est déjà installée.
        #[arg(long)]
        reinstall: bool,
    },
    /// Désinstaller une application gérée par AuxiPak.
    Remove {
        /// Identifiant de l'application installée.
        package: String,
        /// Supprimer même si d'autres applications en dépendent.
        #[arg(long)]
        force: bool,
        /// Supprimer aussi les dépendances installées automatiquement devenues inutiles.
        #[arg(long)]
        autoremove: bool,
        /// Autoriser explicitement les scripts de désinstallation du paquet.
        #[arg(long)]
        allow_scripts: bool,
    },
    /// Forcer la synchronisation des index de tous les dépôts (ne met pas à jour les applications).
    Update,
    /// Régler une préférence : « auxipak set lang fr » ou « auxipak set lang en ».
    Set {
        /// Préférence (lang) ; « lang=fr » est aussi accepté.
        key: String,
        /// Valeur (fr, en) ; absente : affiche la valeur actuelle.
        value: Option<String>,
    },
    /// Mettre à niveau AuxiPak lui-même puis toutes les applications gérées, ou celle indiquée.
    Upgrade {
        /// Identifiant de l'application à mettre à niveau (par défaut : toutes).
        package: Option<String>,
        /// Autoriser explicitement les scripts personnalisés des paquets.
        #[arg(long)]
        allow_scripts: bool,
        /// Ne pas mettre à jour AuxiPak lui-même.
        #[arg(long)]
        no_self: bool,
    },
    /// Lister les applications installées et suivies par AuxiPak.
    List {
        /// Vérifier la présence réelle de chaque application (réconciliation).
        #[arg(long)]
        check: bool,
    },
    /// Afficher les métadonnées, dépendances, statut et informations de sécurité.
    Info {
        /// Identifiant ou nom de l'application.
        package: String,
        /// Ne jamais contacter le réseau.
        #[arg(long)]
        offline: bool,
    },
    /// Vérifier un fichier .aupak local (structure, manifeste, signature). N'exécute rien.
    Verify {
        /// Fichier de paquet (.aupak).
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
        /// URL du dépôt (HTTPS).
        url: String,
        /// Nom local du dépôt (par défaut : déduit du nom d'hôte).
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
    Remove {
        /// Nom du dépôt.
        name: String,
    },
}

fn init_logging(paths: &Paths) {
    use tracing_subscriber::prelude::*;
    let _ = std::fs::create_dir_all(&paths.log_dir);
    let file = std::fs::OpenOptions::new().create(true).append(true).open(paths.log_file());
    let filter = tracing_subscriber::EnvFilter::try_from_env("AUXIPAK_LOG").unwrap_or_else(|_| "info".into());
    if let Ok(f) = file {
        let layer = tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .with_writer(std::sync::Mutex::new(f));
        let _ = tracing_subscriber::registry().with(filter).with(layer).try_init();
    }
}

/// Langue de l'interface : `AUXIPAK_LANG`, puis « auxipak set lang »
/// (utilisateur, puis système), puis langue du système, puis anglais.
fn apply_language(paths: &Paths) {
    use auxipak_core::i18n::{self, Lang};
    if std::env::var("AUXIPAK_LANG").ok().and_then(|v| Lang::parse(&v)).is_some() {
        return;
    }
    let files = [
        Some(paths.config_dir.join("language")),
        paths.system_config_dir.as_ref().map(|d| d.join("language")),
    ];
    for f in files.into_iter().flatten() {
        if let Some(l) = std::fs::read_to_string(&f).ok().and_then(|s| Lang::parse(&s)) {
            i18n::set(l);
            return;
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    // La langue doit être connue avant l'analyse de la ligne de commande (aide).
    let paths = Paths::detect();
    apply_language(&paths);
    let matches = localize_help(Cli::command()).get_matches();
    let cli = match Cli::from_arg_matches(&matches) {
        Ok(c) => c,
        Err(e) => e.exit(),
    };
    if let Err(e) = paths.ensure() {
        eprintln!(
            "{}",
            tr!(
                "erreur : impossible de préparer {} : {e}",
                "error: cannot prepare {}: {e}",
                paths.state_dir.display()
            )
        );
        return ExitCode::from(1);
    }
    init_logging(&paths);
    selfupdate::cleanup_old();
    tracing::info!(args = ?std::env::args().collect::<Vec<_>>(), "{}", tr!("démarrage", "start"));
    match run(cli, paths).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(error = %format!("{e:#}"), "{}", tr!("échec", "failure"));
            eprintln!("{}", tr!("erreur : {e:#}", "error: {e:#}"));
            ExitCode::from(1)
        }
    }
}

/// Aide en anglais : les commentaires de documentation (français) servent
/// de texte d'aide en français ; cette table les remplace sinon.
/// Chemin : sous-commandes séparées par des espaces ; argument vide : la
/// description de la commande elle-même.
const HELP_EN: &[(&str, &str, &str)] = &[
    ("", "json", "JSON output (query commands)."),
    (
        "search",
        "",
        "Search the indexes for an application (local cache, refreshed when needed).",
    ),
    ("search", "query", "Search term (identifier, name or description)."),
    ("search", "offline", "Never use the network."),
    (
        "install",
        "",
        "Install an application (e.g. \"firefox\" or \"Firefox-150.1-fr\").",
    ),
    ("install", "package", "Application identifier, name or package file name."),
    (
        "install",
        "version",
        "Version or version constraint (e.g. 150.1 or \">=150\").",
    ),
    ("install", "lang", "Preferred package language (e.g. fr, en)."),
    ("install", "repo", "Install from this repository only."),
    ("install", "allow_scripts", "Explicitly allow the package's custom scripts."),
    (
        "install",
        "adopt",
        "Track an application already installed natively with AuxiPak, without reinstalling it.",
    ),
    ("install", "reinstall", "Reinstall even if this version is already installed."),
    ("remove", "", "Remove an application managed by AuxiPak."),
    ("remove", "package", "Identifier of the installed application."),
    ("remove", "force", "Remove even if other applications depend on it."),
    (
        "remove",
        "autoremove",
        "Also remove automatically installed dependencies that are no longer needed.",
    ),
    ("remove", "allow_scripts", "Explicitly allow the package's removal scripts."),
    (
        "update",
        "",
        "Sync the indexes of all repositories (does not upgrade applications).",
    ),
    (
        "set",
        "",
        "Change a setting: \"auxipak set lang en\" or \"auxipak set lang fr\".",
    ),
    ("set", "key", "Setting (lang); \"lang=fr\" is also accepted."),
    ("set", "value", "Value (fr, en); omitted: shows the current value."),
    (
        "upgrade",
        "",
        "Upgrade AuxiPak itself, then all managed applications, or the one given.",
    ),
    (
        "upgrade",
        "package",
        "Identifier of the application to upgrade (default: all).",
    ),
    ("upgrade", "allow_scripts", "Explicitly allow the packages' custom scripts."),
    ("upgrade", "no_self", "Do not update AuxiPak itself."),
    ("list", "", "List the applications installed and tracked by AuxiPak."),
    (
        "list",
        "check",
        "Check that each application is really present (reconciliation).",
    ),
    ("info", "", "Show metadata, dependencies, status and security information."),
    ("info", "package", "Application identifier or name."),
    ("info", "offline", "Never use the network."),
    (
        "verify",
        "",
        "Check a local .aupak file (structure, manifest, signature). Runs nothing.",
    ),
    ("verify", "file", "Package file (.aupak)."),
    (
        "verify",
        "signature",
        "Signature document (default: <file>.sig if it exists).",
    ),
    ("clean", "", "Clean the cache (downloaded packages, working directories)."),
    ("clean", "all", "Also remove the cached indexes (a sync will be needed)."),
    ("repo", "", "Manage repositories."),
    ("repo list", "", "List the configured repositories."),
    ("repo add", "", "Add an external repository."),
    ("repo add", "url", "Repository URL (HTTPS)."),
    (
        "repo add",
        "name",
        "Local name of the repository (default: derived from the host name).",
    ),
    (
        "repo add",
        "root",
        "Trusted TUF root.json (obtained through a secure channel).",
    ),
    ("repo add", "keys", "Public package signing keys (package-keys.json)."),
    (
        "repo add",
        "trust_on_first_use",
        "Fetch root.json and the keys from the repository itself (trust on first use, less secure).",
    ),
    (
        "repo add",
        "allow_scripts",
        "Allow this repository's scripts to run (not recommended).",
    ),
    ("repo remove", "", "Remove a repository."),
    ("repo remove", "name", "Name of the repository."),
    ("repair", "", "Resume or clean up interrupted operations."),
    ("doctor", "", "Diagnostics: system profile, repositories, cache state."),
];

/// Remplace l'aide par sa version anglaise si l'interface n'est pas en français.
fn localize_help(cmd: clap::Command) -> clap::Command {
    if auxipak_core::i18n::is_fr() {
        return cmd;
    }
    let mut cmd = cmd
        .about("AuxiPak — application distribution and management for the AuxiNux ecosystem")
        .long_about(
            "AuxiPak installs, upgrades and removes applications distributed as .aupak packages, \
             using the native mechanisms allowed on each system (APT, auxi, MSI, pkg…).\n\
             AuxiPak never updates the operating system itself.",
        );
    for (path, arg, text) in HELP_EN {
        cmd = apply_help(cmd, path, arg, text);
    }
    cmd
}

fn apply_help(cmd: clap::Command, path: &str, arg: &str, text: &'static str) -> clap::Command {
    match path.split_once(' ') {
        Some((head, rest)) => cmd.mut_subcommand(head, |c| apply_help(c, rest, arg, text)),
        None if path.is_empty() => cmd.mut_arg(arg, |a| a.help(text)),
        None => cmd.mut_subcommand(path, |c| {
            if arg.is_empty() {
                c.about(text).long_about(None::<&str>)
            } else {
                c.mut_arg(arg, |a| a.help(text))
            }
        }),
    }
}

fn pending_warning(paths: &Paths) {
    if let Ok(p) = Transaction::pending(paths) {
        if !p.is_empty() {
            eprintln!(
                "{}",
                tr!(
                    "avertissement : {} opération(s) interrompue(s) détectée(s) ; exécutez « auxipak repair »",
                    "warning: {} interrupted operation(s) detected; run \"auxipak repair\"",
                    p.len()
                )
            );
        }
    }
}

async fn env_for(paths: Paths, need: Need) -> Result<Env> {
    let config = Config::load(&paths)?;
    let status = detect::load_or_detect(&paths)?;
    if status.first_run {
        eprintln!(
            "{}",
            tr!(
                "premier lancement : profil système enregistré ({} {}, {})",
                "first run: system profile saved ({} {}, {})",
                status.profile.distribution,
                status.profile.version,
                status.profile.arch
            )
        );
    }
    if status.changed {
        eprintln!(
            "{}",
            tr!(
                "changement de système détecté ({}) : les index vont être resynchronisés",
                "system change detected ({}): the indexes will be synced again",
                status.profile.pretty_name
            )
        );
    }
    if status.profile.channel().is_none() {
        eprintln!(
            "{}",
            tr!(
                "avertissement : {} ({}) n'est pas une plateforme prise en charge par AuxiPak",
                "warning: {} ({}) is not a platform supported by AuxiPak",
                status.profile.pretty_name,
                status.profile.distribution
            )
        );
    }
    let env = Env::load(paths, config, status.profile, need).await;
    env.print_warnings();
    Ok(env)
}

async fn run(cli: Cli, paths: Paths) -> Result<()> {
    match cli.cmd {
        Cmd::Search { query, offline } => {
            let env = if offline {
                offline_env(paths)?
            } else {
                env_for(paths, Need::Browse).await?
            };
            if env.repos.is_empty() {
                bail!(tr!(
                    "aucun index disponible (exécutez « auxipak update » avec une connexion réseau)",
                    "no index available (run \"auxipak update\" with a network connection)"
                ));
            }
            for r in &env.repos {
                if r.freshness(env.config.cache_ttl_seconds, &env.profile) != repo::Freshness::Fresh {
                    eprintln!(
                        "{}",
                        tr!(
                            "index « {} » : dernière synchronisation il y a {}",
                            "index \"{}\": last synced {} ago",
                            r.config.name,
                            repo::age_label(&r.state)
                        )
                    );
                }
            }
            let hits = catalog::search(&env.repos, query.as_deref().unwrap_or(""), &env.config.package_language());
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
                println!("{}", tr!("Aucun résultat.", "No results."));
            } else {
                let fr = auxipak_core::i18n::is_fr();
                println!(
                    "{:<22} {:<20} {:<12} {:<8} {:<12} {:<9} DESCRIPTION",
                    "ID",
                    if fr { "NOM" } else { "NAME" },
                    "VERSION",
                    if fr { "LANGUE" } else { "LANGUAGE" },
                    if fr { "STATUT" } else { "STATUS" },
                    if fr { "PLATEF." } else { "PLATFORM" }
                );
                for c in hits {
                    println!(
                        "{:<22} {:<20} {:<12} {:<8} {:<12} {:<9} {}{}",
                        c.release.id,
                        truncate(c.name(), 20),
                        truncate(&c.release.version, 12),
                        truncate(&c.release.languages.join(","), 8),
                        c.status().short(),
                        c.release.platform,
                        c.app.map(|a| a.summary.as_str()).unwrap_or(""),
                        if c.repo.config.official {
                            String::new()
                        } else {
                            format!(" [{}]", c.repo.config.name)
                        }
                    );
                }
            }
        }
        Cmd::Install {
            package,
            version,
            lang,
            repo,
            allow_scripts,
            adopt,
            reinstall,
        } => {
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
        Cmd::Remove {
            package,
            force,
            autoremove,
            allow_scripts,
        } => {
            let _lock = StateLock::acquire(&paths)?;
            pending_warning(&paths);
            let config = Config::load(&paths)?;
            let profile = detect::load_or_detect(&paths)?.profile;
            let env = Env {
                paths,
                config,
                profile,
                repos: vec![],
                warnings: vec![],
            };
            let mut reg = Registry::load(&env.paths)?;
            for m in engine::remove(&env, &package, force, autoremove, allow_scripts, &mut reg).await? {
                println!("{m}");
            }
        }
        Cmd::Set { key, value } => {
            use auxipak_core::i18n::{self, Lang};
            let (key, value) = match key.split_once('=') {
                Some((k, v)) => (k.to_string(), Some(v.to_string())),
                None => (key, value),
            };
            if !matches!(key.to_ascii_lowercase().as_str(), "lang" | "language" | "langue") {
                bail!(tr!(
                    "préférence inconnue : {key} (disponible : lang)",
                    "unknown setting: {key} (available: lang)"
                ));
            }
            let Some(value) = value else {
                println!("lang = {}", i18n::current().code());
                return Ok(());
            };
            let l = Lang::parse(&value).ok_or_else(|| {
                anyhow::anyhow!(tr!(
                    "langue inconnue : {value} (fr, en)",
                    "unknown language: {value} (fr, en)"
                ))
            })?;
            let file = paths.config_dir.join("language");
            paths::atomic_write(&file, format!("{}\n", l.code()).as_bytes())?;
            i18n::set(l);
            println!("{}", tr!("Langue : français ({})", "Language: English ({})", file.display()));
        }
        Cmd::Update => {
            let config = Config::load(&paths)?;
            let profile = detect::load_or_detect(&paths)?.profile;
            let mut failures = 0;
            for r in config.enabled_repos() {
                match repo::sync(r, &paths, &profile).await {
                    Ok(d) => println!(
                        "{}",
                        tr!(
                            "{} : index synchronisé (génération {}, {} version(s) pour {} {}, métadonnées valides jusqu'au {})",
                            "{}: index synced (generation {}, {} version(s) for {} {}, metadata valid until {})",
                            r.name,
                            d.state.generation,
                            d.channel.as_ref().map(|c| c.releases.len()).unwrap_or(0),
                            profile.channel().map(|c| c.as_str()).unwrap_or("?"),
                            profile.arch,
                            d.state.metadata_expires.format("%Y-%m-%d %H:%M UTC")
                        )
                    ),
                    Err(e) => {
                        failures += 1;
                        eprintln!("{}", tr!("{} : échec : {e:#}", "{}: failed: {e:#}", r.name));
                    }
                }
            }
            if failures > 0 {
                bail!(tr!(
                    "{failures} dépôt(s) n'ont pas pu être synchronisés",
                    "{failures} repository(ies) could not be synced"
                ));
            }
            if let Ok(Some(a)) = selfupdate::check(&config).await {
                println!(
                    "{}",
                    tr!(
                        "AuxiPak {} est disponible (version actuelle {}) : auxipak upgrade",
                        "AuxiPak {} is available (current version {}): auxipak upgrade",
                        a.version,
                        selfupdate::CURRENT
                    )
                );
            }
        }
        Cmd::Upgrade {
            package,
            allow_scripts,
            no_self,
        } => {
            let _lock = StateLock::acquire(&paths)?;
            pending_warning(&paths);
            if package.is_none() && !no_self {
                let config = Config::load(&paths)?;
                let insecure = config
                    .enabled_repos()
                    .find(|r| r.official)
                    .map(|r| r.allow_insecure_localhost)
                    .unwrap_or(false);
                match selfupdate::check(&config).await {
                    Ok(Some(a)) => {
                        eprintln!(
                            "{}",
                            tr!(
                                "Mise à jour d'AuxiPak : {} → {}",
                                "Updating AuxiPak: {} → {}",
                                selfupdate::CURRENT,
                                a.version
                            )
                        );
                        match selfupdate::apply(&paths, &a, insecure).await {
                            Ok(files) => {
                                for f in files {
                                    println!(
                                        "{}",
                                        tr!("  ✓ {} mis à jour ({})", "  ✓ {} updated ({})", f.display(), a.version)
                                    );
                                }
                            }
                            Err(e) => eprintln!("{}", tr!("avertissement : {e:#}", "warning: {e:#}")),
                        }
                    }
                    Ok(None) => {}
                    Err(e) => tracing::warn!(
                        error = %e,
                        "{}",
                        tr!(
                            "vérification de la version d'AuxiPak impossible",
                            "cannot check for a newer AuxiPak version"
                        )
                    ),
                }
            }
            let env = env_for(paths, Need::Install).await?;
            let mut reg = Registry::load(&env.paths)?;
            let opts = InstallOpts {
                allow_scripts,
                ..Default::default()
            };
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
                let env = Env {
                    paths: paths.clone(),
                    config,
                    profile,
                    repos: vec![],
                    warnings: vec![],
                };
                engine::reconcile(&env, &reg)
                    .await
                    .into_iter()
                    .collect::<std::collections::BTreeMap<_, _>>()
            } else {
                Default::default()
            };
            // Révocations connues (dernier index validé, sans réseau).
            let revoked: std::collections::BTreeSet<String> = match Config::load(&paths) {
                Ok(cfg) => reg
                    .apps
                    .values()
                    .filter(|a| {
                        cfg.repo(&a.repo)
                            .and_then(|r| repo::load_cached(r, &paths).ok().flatten())
                            .map(|d| d.revocations.is_revoked(&a.id, &a.version, &a.package_sha256).is_some())
                            .unwrap_or(false)
                    })
                    .map(|a| a.id.clone())
                    .collect(),
                Err(_) => Default::default(),
            };
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&reg.apps)?);
            } else if reg.apps.is_empty() {
                println!(
                    "{}",
                    tr!(
                        "Aucune application installée par AuxiPak.",
                        "No application installed by AuxiPak."
                    )
                );
            } else {
                let fr = auxipak_core::i18n::is_fr();
                println!(
                    "{:<22} {:<12} {:<10} {:<10} {:<10} {:<10} {}",
                    "ID",
                    "VERSION",
                    if fr { "DÉPÔT" } else { "REPO" },
                    if fr { "MÉTHODE" } else { "METHOD" },
                    if fr { "GEST." } else { "MANAGER" },
                    if fr { "ÉTAT" } else { "STATE" },
                    if fr { "INSTALLÉ LE" } else { "INSTALLED ON" }
                );
                for a in reg.apps.values() {
                    let mut state = format!("{:?}", a.state).to_lowercase();
                    if a.simulated {
                        state.push('*');
                    }
                    if revoked.contains(&a.id) {
                        state.push_str(if fr { " RÉVOQUÉE" } else { " REVOKED" });
                    }
                    if let Some(p) = presence.get(&a.id) {
                        match p {
                            Some(false) => state.push_str(if fr { " (absente!)" } else { " (missing!)" }),
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
                        if !a.auto_installed {
                            ""
                        } else if fr {
                            " (dépendance)"
                        } else {
                            " (dependency)"
                        }
                    );
                }
                if !revoked.is_empty() {
                    println!(
                        "{}",
                        tr!(
                            "ATTENTION : version(s) révoquée(s) installée(s) — mettez à niveau ou désinstallez-les",
                            "WARNING: revoked version(s) installed — upgrade or remove them"
                        )
                    );
                }
                if reg.apps.values().any(|a| a.simulated) {
                    println!(
                        "{}",
                        tr!(
                            "* installation réalisée en mode simulation (tests) : non valide comme installation réelle",
                            "* installed in simulation mode (tests): not valid as a real installation"
                        )
                    );
                }
            }
        }
        Cmd::Info { package, offline } => {
            let env = if offline {
                offline_env(paths)?
            } else {
                env_for(paths, Need::Browse).await?
            };
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
                eprintln!(
                    "{}",
                    tr!(
                        "répertoires de travail conservés : opérations interrompues en attente (« auxipak repair »)",
                        "working directories kept: interrupted operations pending (\"auxipak repair\")"
                    )
                );
            }
            if all {
                freed += remove_dir_size(&paths.cache_dir.join("repos"))?;
            }
            println!(
                "{}",
                tr!(
                    "Cache nettoyé ({} Kio libérés).",
                    "Cache cleaned ({} KiB freed).",
                    freed / 1024
                )
            );
        }
        Cmd::Repo { cmd } => repo_cmd(&paths, cmd, cli.json).await?,
        Cmd::Repair => {
            let _lock = StateLock::acquire(&paths)?;
            let config = Config::load(&paths)?;
            let profile = detect::load_or_detect(&paths)?.profile;
            let env = Env {
                paths,
                config,
                profile,
                repos: vec![],
                warnings: vec![],
            };
            let mut reg = Registry::load(&env.paths)?;
            for m in engine::repair(&env, &mut reg).await? {
                println!("{m}");
            }
        }
        Cmd::Doctor => {
            let config = Config::load(&paths)?;
            let st = detect::load_or_detect(&paths)?;
            let p = &st.profile;
            let fr = auxipak_core::i18n::is_fr();
            let yes_no = |b: bool| match (b, fr) {
                (true, true) => "oui",
                (false, true) => "non",
                (true, false) => "yes",
                (false, false) => "no",
            };
            println!(
                "{}",
                tr!(
                    "Système      : {} ({} {}, {})",
                    "System       : {} ({} {}, {})",
                    p.pretty_name,
                    p.distribution,
                    p.version,
                    p.arch
                )
            );
            println!(
                "{}",
                tr!(
                    "Canal        : {}",
                    "Channel      : {}",
                    p.channel()
                        .map(|c| c.as_str().to_string())
                        .unwrap_or_else(|| tr!("non pris en charge", "not supported"))
                )
            );
            println!("{}", tr!("Immuable     : {}", "Immutable    : {}", yes_no(p.immutable)));
            println!(
                "{}",
                tr!(
                    "Portée       : {} (administrateur : {})",
                    "Scope        : {} (administrator: {})",
                    match (paths.scope, fr) {
                        (paths::Scope::System, true) => "système",
                        (paths::Scope::User, true) => "utilisateur",
                        (paths::Scope::System, false) => "system",
                        (paths::Scope::User, false) => "user",
                    },
                    yes_no(privileges::is_elevated())
                )
            );
            println!("Configuration: {}", paths.config_file().display());
            println!("{}", tr!("État         : {}", "State        : {}", paths.state_dir.display()));
            println!(
                "{}",
                tr!(
                    "Cache        : {} (durée de validité {} s)",
                    "Cache        : {} (valid for {} s)",
                    paths.cache_dir.display(),
                    config.cache_ttl_seconds
                )
            );
            println!(
                "{}",
                tr!("Journal      : {}", "Log          : {}", paths.log_file().display())
            );
            println!(
                "{}",
                tr!("Langue       : {}", "Language     : {}", auxipak_core::i18n::current().code())
            );
            if executor::is_simulation() {
                println!(
                    "{}",
                    tr!(
                        "MODE SIMULATION ACTIF (AUXIPAK_TEST_TOOLS_DIR)",
                        "SIMULATION MODE ACTIVE (AUXIPAK_TEST_TOOLS_DIR)"
                    )
                );
            }
            for r in &config.repositories {
                let trust = match r.trust(&paths) {
                    Ok(t) => tr!("confiance : {}", "trust: {}", t.source),
                    Err(e) => tr!("CONFIANCE ABSENTE : {e}", "NO TRUST ROOT: {e}"),
                };
                let cache = match repo::load_cached(r, &paths) {
                    Ok(Some(d)) => tr!(
                        "« {} », génération {}, synchronisé il y a {} ({:?})",
                        "\"{}\", generation {}, synced {} ago ({:?})",
                        d.index.repository.title,
                        d.index.generation,
                        repo::age_label(&d.state),
                        d.freshness(config.cache_ttl_seconds, p)
                    ),
                    _ => tr!("jamais synchronisé", "never synced"),
                };
                println!(
                    "{}",
                    tr!(
                        "Dépôt {} : {} — {} — {}",
                        "Repository {}: {} — {} — {}",
                        r.name,
                        r.url,
                        trust,
                        cache
                    )
                );
            }
            let pending = Transaction::pending(&paths)?;
            println!(
                "{}",
                tr!("Opérations interrompues : {}", "Interrupted operations: {}", pending.len())
            );
            if !config.adapters.auxi.validated && p.distribution == auxipak_core::platform::Distribution::Auxinuxos {
                println!(
                    "{}",
                    tr!(
                        "Adaptateur auxi : syntaxe NON VALIDÉE sur ce système (voir docs/CLI_REFERENCE.md)",
                        "auxi adapter: syntax NOT VALIDATED on this system (see docs/CLI_REFERENCE.md)"
                    )
                );
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
    Ok(Env {
        paths,
        config,
        profile,
        repos,
        warnings: vec![],
    })
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
    let c = catalog::resolve(&env.repos, package, &Default::default(), &env.config.package_language());
    let c = match (c, installed) {
        (Ok(c), _) => c,
        (Err(e), None) => return Err(e),
        (Err(_), Some(a)) => {
            println!(
                "{}",
                tr!(
                    "{} {} (installé, absent des index disponibles)",
                    "{} {} (installed, not in the available indexes)",
                    a.id,
                    a.version
                )
            );
            println!("{}", serde_json::to_string_pretty(a)?);
            return Ok(());
        }
    };
    let rel = c.release;
    let versions: Vec<String> = catalog::all_candidates(&env.repos)
        .iter()
        .filter(|x| x.release.id == rel.id && x.repo.config.name == c.repo.config.name)
        .map(|x| {
            format!(
                "{}{}",
                x.release.version,
                if x.is_revoked() {
                    tr!(" (révoquée)", " (revoked)")
                } else {
                    String::new()
                }
            )
        })
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
        println!("{}", tr!("Éditeur        : {}", "Publisher      : {}", a.publisher));
        println!("{}", tr!("Licence        : {}", "License        : {}", a.license));
        if let Some(h) = &a.homepage {
            println!("{}", tr!("Site           : {h}", "Website        : {h}"));
        }
    }
    println!("{}", tr!("Statut AuxiNux : {}", "AuxiNux status : {}", c.status().label()));
    if let Some(note) = c.app.and_then(|a| a.status_note.as_ref()) {
        println!("{}", tr!("  Réserves     : {note}", "  Caveats      : {note}"));
    }
    println!(
        "{}",
        tr!(
            "Version        : {} (disponibles : {})",
            "Version        : {} (available: {})",
            rel.version,
            versions.join(", ")
        )
    );
    println!(
        "{}",
        tr!("Langues        : {}", "Languages      : {}", rel.languages.join(", "))
    );
    println!(
        "{}",
        tr!(
            "Plateforme     : {} — {} — {}",
            "Platform       : {} — {} — {}",
            rel.platform,
            rel.distributions.iter().map(|d| d.as_str()).collect::<Vec<_>>().join(", "),
            rel.architectures.iter().map(|a| a.as_str()).collect::<Vec<_>>().join(", ")
        )
    );
    println!(
        "{}",
        tr!(
            "Dépôt          : {}{}",
            "Repository     : {}{}",
            c.repo.config.name,
            if c.repo.config.official {
                tr!(" (officiel)", " (official)")
            } else {
                tr!(" (externe)", " (external)")
            }
        )
    );
    println!(
        "{}",
        tr!(
            "Mode           : {} — privilèges : {:?}",
            "Mode           : {} — privileges: {:?}",
            rel.mode,
            rel.privileges
        )
    );
    let deps: Vec<String> = rel.dependencies.iter().map(|d| format!("{} ({})", d.id, d.version)).collect();
    println!(
        "{}",
        tr!(
            "Dépendances    : {}",
            "Dependencies   : {}",
            if deps.is_empty() {
                tr!("aucune", "none")
            } else {
                deps.join(", ")
            }
        )
    );
    let fr = auxipak_core::i18n::is_fr();
    let yes_no = |b: bool| match (b, fr) {
        (true, true) => "OUI",
        (false, true) => "non",
        (true, false) => "YES",
        (false, false) => "no",
    };
    println!("{}", tr!("Sécurité :", "Security:"));
    println!(
        "{}",
        tr!(
            "  Fichier      : {} ({} octets)",
            "  File         : {} ({} bytes)",
            rel.file_name,
            rel.size
        )
    );
    println!("  SHA-256      : {}", rel.sha256);
    println!(
        "{}",
        tr!(
            "  Signature    : clé {} ({})",
            "  Signature    : key {} ({})",
            rel.signature.key_id,
            rel.signature.target
        )
    );
    println!(
        "  Scripts      : {}",
        if rel.uses_scripts {
            tr!("OUI — autorisation explicite requise", "YES — explicit permission required")
        } else {
            yes_no(false).to_string()
        }
    );
    println!(
        "{}",
        tr!("  Révoqué      : {}", "  Revoked      : {}", yes_no(c.is_revoked()))
    );
    println!(
        "{}",
        tr!(
            "  Publié le    : {}",
            "  Published on : {}",
            rel.published_at.format("%Y-%m-%d %H:%M UTC")
        )
    );
    if let Some(i) = installed {
        println!(
            "{}",
            tr!(
                "Installé       : {} le {} ({:?}, {})",
                "Installed      : {} on {} ({:?}, {})",
                i.version,
                i.installed_at.format("%Y-%m-%d"),
                i.state,
                i.manager
            )
        );
    }
    Ok(())
}

fn verify(paths: &Paths, file: &std::path::Path, signature: Option<PathBuf>, json: bool) -> Result<()> {
    if !auxipak_core::archive::is_package_path(file) {
        bail!(tr!(
            "le fichier doit porter l'extension .aupak",
            "the file must have the .aupak extension"
        ));
    }
    let insp = archive::inspect(file, &Limits::default())
        .map_err(|e| anyhow::anyhow!(tr!("paquet INVALIDE : {e}", "INVALID package: {e}")))?;
    let sig_path = signature.or_else(|| {
        let p = PathBuf::from(format!("{}.sig", file.display()));
        p.exists().then_some(p)
    });
    let mut sig_result: Option<Result<String, String>> = None;
    if let Some(sp) = &sig_path {
        let doc = PackageSignature::from_json(&std::fs::read(sp)?)?;
        let config = Config::load(paths)?;
        let mut last = Err(tr!("aucune clé de confiance configurée", "no trusted key configured"));
        for r in &config.repositories {
            if let Ok(t) = r.trust(paths) {
                match doc.verify(
                    &insp.archive_sha256,
                    insp.archive_size,
                    &t.package_keys,
                    &[KeyPurpose::PackageSigning],
                ) {
                    Ok(v) => {
                        last = Ok(tr!(
                            "valide (clé {} — {}, dépôt {})",
                            "valid (key {} — {}, repository {})",
                            v.key_id,
                            v.owner,
                            r.name
                        ));
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
                "signature": sig_result.as_ref().map(|r| match r { Ok(s) => s.clone(), Err(e) => tr!("INVALIDE : {e}", "INVALID: {e}") }),
            }))?
        );
    } else {
        println!("{}", tr!("Paquet       : {}", "Package      : {}", file.display()));
        println!("Application  : {} {} ({})", m.name, m.version, m.id);
        println!(
            "{}",
            tr!(
                "Structure    : conforme au format .aupak v{} ({} entrées)",
                "Structure    : conforms to the .aupak v{} format ({} entries)",
                archive::AUPAK_FORMAT_VERSION,
                insp.entries.len()
            )
        );
        println!(
            "{}",
            tr!(
                "Manifeste    : valide (schéma et règles sémantiques)",
                "Manifest     : valid (schema and semantic rules)"
            )
        );
        println!("SHA-256      : {}", insp.archive_sha256);
        println!(
            "{}",
            tr!(
                "Taille       : {} octets ({} décompressés)",
                "Size         : {} bytes ({} unpacked)",
                insp.archive_size,
                insp.total_unpacked
            )
        );
        println!(
            "{}{}",
            tr!("Variantes    : ", "Targets      : "),
            m.targets
                .iter()
                .map(|t| format!("{} [{} {}]", t.name, t.platform, t.mode))
                .collect::<Vec<_>>()
                .join(", ")
        );
        if m.targets.iter().any(|t| t.uses_scripts()) {
            println!(
                "{}",
                tr!(
                    "Scripts      : présents (exécution soumise à autorisation explicite)",
                    "Scripts      : present (running them requires explicit permission)"
                )
            );
        }
        for w in &insp.warnings {
            println!("{w}");
        }
        match &sig_result {
            None => println!(
                "{}",
                tr!(
                    "Signature    : non vérifiée (aucun document .sig fourni)",
                    "Signature    : not verified (no .sig document provided)"
                )
            ),
            Some(Ok(s)) => println!("Signature    : {s}"),
            Some(Err(e)) => println!("{}", tr!("Signature    : INVALIDE — {e}", "Signature    : INVALID — {e}")),
        }
    }
    if let Some(Err(e)) = sig_result {
        bail!(tr!("signature invalide : {e}", "invalid signature: {e}"));
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
                let kind = if r.official {
                    tr!("officiel", "official")
                } else {
                    tr!("EXTERNE", "EXTERNAL")
                };
                println!(
                    "{:<12} {:<9} {:<8} {}{}",
                    r.name,
                    kind,
                    if r.enabled {
                        tr!("actif", "enabled")
                    } else {
                        tr!("inactif", "disabled")
                    },
                    r.url,
                    if r.allow_scripts {
                        tr!(" (scripts autorisés)", " (scripts allowed)")
                    } else {
                        String::new()
                    }
                );
            }
        }
        RepoCmd::Add {
            url,
            name,
            root,
            keys,
            trust_on_first_use,
            allow_scripts,
            allow_insecure_localhost,
        } => {
            let base =
                auxipak_core::netpolicy::validate_repo_url(&url, allow_insecure_localhost).map_err(|e| anyhow::anyhow!(e))?;
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
                bail!(tr!(
                    "nom de dépôt invalide : {name} (utilisez --name)",
                    "invalid repository name: {name} (use --name)"
                ));
            }
            if config.repo(&name).is_some() {
                bail!(tr!("le dépôt « {name} » existe déjà", "repository \"{name}\" already exists"));
            }
            let trust_dir = paths.config_dir.join("trust").join(&name);
            std::fs::create_dir_all(&trust_dir)?;
            let (root_bytes, keys_bytes) = match (root, keys, trust_on_first_use) {
                (Some(r), Some(k), _) => (
                    std::fs::read(&r).context(tr!("lecture de --root", "reading --root"))?,
                    std::fs::read(&k).context(tr!("lecture de --keys", "reading --keys"))?,
                ),
                (None, None, true) => {
                    eprintln!(
                        "{}",
                        tr!(
                            "ATTENTION : confiance au premier usage — vérifiez les empreintes ci-dessous auprès de l'éditeur du dépôt",
                            "WARNING: trust on first use — check the fingerprints below with the repository publisher"
                        )
                    );
                    let client = reqwest::Client::builder()
                        .redirect(reqwest::redirect::Policy::none())
                        .build()?;
                    let get = |u: url::Url| {
                        let client = client.clone();
                        async move {
                            let r = client.get(u.clone()).send().await?.error_for_status()?;
                            Ok::<_, anyhow::Error>(r.bytes().await?.to_vec())
                        }
                    };
                    if base.scheme() == "file" {
                        let p = base
                            .to_file_path()
                            .map_err(|_| anyhow::anyhow!(tr!("URL invalide", "invalid URL")))?;
                        (
                            std::fs::read(p.join("metadata/1.root.json"))?,
                            std::fs::read(p.join("keys/package-keys.json"))?,
                        )
                    } else {
                        (
                            get(base.join("metadata/1.root.json")?).await?,
                            get(base.join("keys/package-keys.json")?).await?,
                        )
                    }
                }
                _ => bail!(tr!(
                    "fournissez --root et --keys (obtenus par un canal sûr), ou --trust-on-first-use",
                    "provide --root and --keys (obtained through a secure channel), or --trust-on-first-use"
                )),
            };
            let summary = auxipak_core::tuf::summarize_root(&root_bytes)?;
            let keys: auxipak_core::signature::TrustedKeys =
                serde_json::from_slice(&keys_bytes).context(tr!("package-keys.json invalide", "invalid package-keys.json"))?;
            paths::atomic_write(&trust_dir.join("root.json"), &root_bytes)?;
            paths::atomic_write(&trust_dir.join("package-keys.json"), &keys_bytes)?;
            println!(
                "{}",
                tr!(
                    "Racine TUF version {} (expire {}), empreinte {}",
                    "TUF root version {} (expires {}), fingerprint {}",
                    summary.version,
                    summary.expires,
                    auxipak_core::hash::sha256_hex(&root_bytes)
                )
            );
            for k in &keys.keys {
                println!("{}", tr!("Clé de paquets {} — {}", "Package key {} — {}", k.key_id, k.owner));
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
            println!(
                "{}",
                tr!(
                    "Dépôt externe « {name} » ajouté. Exécutez « auxipak update ».",
                    "External repository \"{name}\" added. Run \"auxipak update\"."
                )
            );
        }
        RepoCmd::Remove { name } => {
            let before = config.repositories.len();
            config.repositories.retain(|r| r.name != name);
            if config.repositories.len() == before {
                bail!(tr!("dépôt inconnu : {name}", "unknown repository: {name}"));
            }
            config.save(paths)?;
            repo::drop_cache(paths, &name)?;
            let _ = std::fs::remove_dir_all(paths.config_dir.join("trust").join(&name));
            println!(
                "{}",
                tr!(
                    "Dépôt « {name} » retiré (les applications installées restent dans le registre).",
                    "Repository \"{name}\" removed (installed applications stay in the registry)."
                )
            );
        }
    }
    Ok(())
}
