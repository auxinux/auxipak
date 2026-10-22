//! Méthodes d'installation, de désinstallation et de détection.
//!
//! Chaque méthode traduit des paramètres déclaratifs validés en appels de
//! processus à arguments structurés (voir [`crate::executor`]).

use crate::config::{adapter_for, AdapterConfig, Config};
use crate::download::{self, Expect, RedirectPolicy};
use crate::executor::{self, os, resolve, verdict, RunOpts, Tool, Verdict};
use crate::paths::Paths;
use crate::registry::Transaction;
use anyhow::{anyhow, bail, Context, Result};
use auxipak_core::manifest::{Detect, FileCopy, Install, Manager, MsiScope, Remove, Source, Target};
use auxipak_core::platform::{Distribution, SystemProfile};
use auxipak_core::{ids, tr};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Contexte d'une opération.
pub struct Ctx<'a> {
    pub paths: &'a Paths,
    pub config: &'a Config,
    pub profile: &'a SystemProfile,
    pub app_id: &'a str,
    pub version: &'a str,
    pub target: &'a Target,
    /// Répertoire d'extraction (`payload/`, `scripts/`) ou copie conservée.
    pub root: &'a Path,
    /// Répertoire de travail privé de l'opération.
    pub work: &'a Path,
    pub scripts_allowed: bool,
    /// Fichiers appartenant déjà à cette application (mise à niveau).
    pub owned_files: &'a [PathBuf],
}

/// Résultat d'une installation.
#[derive(Debug, Default)]
pub struct Outcome {
    pub manager: String,
    pub files: Vec<PathBuf>,
    pub reboot: bool,
}

impl Ctx<'_> {
    fn timeout(&self) -> Duration {
        Duration::from_secs(self.target.timeout_seconds.unwrap_or(3600))
    }

    fn opts(&self) -> RunOpts {
        RunOpts {
            cwd: Some(self.work.to_path_buf()),
            env: vec![],
            timeout: Some(self.timeout()),
        }
    }

    /// Développe un chemin `{racine}/...`.
    pub fn expand(&self, templated: &str) -> Result<PathBuf> {
        expand_path(self.paths, self.app_id, templated)
    }

    fn check(&self, what: &str, out: &executor::Output, extra_reboot: &[i32]) -> Result<bool> {
        let mut reboot_codes = self.target.reboot_codes.clone();
        reboot_codes.extend_from_slice(extra_reboot);
        match verdict(out.code, &self.target.success_codes, &reboot_codes) {
            Verdict::Success => Ok(false),
            Verdict::SuccessRebootRequired => Ok(true),
            Verdict::Failure => bail!(tr!(
                "{what} a échoué (code {}) : {}",
                "{what} failed (code {}): {}",
                out.code,
                last_lines(if out.stderr.trim().is_empty() {
                    &out.stdout
                } else {
                    &out.stderr
                })
            )),
        }
    }
}

fn last_lines(s: &str) -> String {
    let lines: Vec<&str> = s.trim().lines().collect();
    lines[lines.len().saturating_sub(5)..].join(" | ")
}

/// Développe les racines connues d'un chemin de manifeste.
pub fn expand_path(paths: &Paths, app_id: &str, templated: &str) -> Result<PathBuf> {
    let (root, rest) = match templated.find('}') {
        Some(i) => (&templated[..=i], templated[i + 1..].trim_start_matches('/')),
        None => bail!(tr!("chemin sans racine : {templated}", "path without a root: {templated}")),
    };
    let base: PathBuf = match root {
        "{app}" => paths.apps_dir.join(app_id),
        "{bin}" => paths.bin_dir.clone(),
        "{data}" => paths.data_dir.join(app_id),
        "{program_files}" => env_dir("ProgramFiles")?,
        "{program_files_x86}" => env_dir("ProgramFiles(x86)")?,
        "{local_app_data}" => env_dir("LOCALAPPDATA")?,
        r => bail!(tr!("racine inconnue : {r}", "unknown root: {r}")),
    };
    if rest.is_empty() {
        return Ok(base);
    }
    if !ids::is_safe_relative_path(rest) {
        bail!(tr!("chemin dangereux : {templated}", "dangerous path: {templated}"));
    }
    let mut p = base;
    for c in rest.split('/') {
        p.push(c);
    }
    Ok(p)
}

fn env_dir(var: &str) -> Result<PathBuf> {
    std::env::var_os(var)
        .map(PathBuf::from)
        .ok_or_else(|| anyhow!(tr!("variable {var} absente", "variable {var} missing")))
}

/// Chemin local de l'installateur : fichier extrait ou téléchargement contrôlé.
async fn artifact(ctx: &Ctx<'_>, source: &Source) -> Result<PathBuf> {
    if let Some(f) = &source.file {
        let p = ctx.root.join(f);
        if !p.is_file() {
            bail!(tr!("fichier intégré absent : {f}", "embedded file missing: {f}"));
        }
        return Ok(p);
    }
    let url_s = source
        .url
        .as_deref()
        .context(tr!("source sans fichier ni URL", "source has neither a file nor a URL"))?;
    let url = auxipak_core::netpolicy::validate_https_url(url_s).map_err(|e| anyhow!(e))?;
    let sha = source.sha256.as_deref().context(tr!(
        "SHA-256 obligatoire pour une source distante",
        "SHA-256 required for a remote source"
    ))?;
    let name = match &source.file_name {
        Some(n) => n.clone(),
        None => url
            .path_segments()
            .and_then(|mut s| s.next_back().map(|x| x.to_string()))
            .context(tr!("nom de fichier indéterminable", "cannot determine the file name"))?,
    };
    if !ids::is_safe_file_name(&name) {
        bail!(tr!(
            "nom de fichier distant dangereux : {name}",
            "dangerous remote file name: {name}"
        ));
    }
    let dir = ctx.work.join("remote");
    std::fs::create_dir_all(&dir)?;
    let dest = dir.join(&name);
    eprintln!("{}", tr!("  source : {url}", "  source: {url}"));
    download::fetch(
        &url,
        &dest,
        &Expect {
            sha256: sha.to_string(),
            size: source.size,
            max_size: source.size.unwrap_or(ctx.config.policy.max_download_bytes),
        },
        &RedirectPolicy {
            allowed_hosts: source.allowed_hosts.clone(),
            allow_insecure_localhost: false,
        },
        &name,
    )
    .await?;
    Ok(dest)
}

/// Commande d'adaptateur avec substitution de paramètres validés.
fn adapter_args(template: &[String], packages: &[String], file: Option<&Path>) -> Result<Vec<OsString>> {
    let mut v = Vec::new();
    for a in template {
        match a.as_str() {
            "{packages}" => {
                for p in packages {
                    if !ids::is_valid_native_package(p) {
                        bail!(tr!("paquet natif invalide : {p}", "invalid native package: {p}"));
                    }
                    v.push(os(p));
                }
            }
            "{package}" => {
                let p = packages.first().context(tr!("paquet manquant", "missing package"))?;
                if !ids::is_valid_native_package(p) {
                    bail!(tr!("paquet natif invalide : {p}", "invalid native package: {p}"));
                }
                v.push(os(p));
            }
            "{file}" => v.push(file.context(tr!("fichier manquant", "missing file"))?.as_os_str().to_owned()),
            other if other.starts_with('{') => bail!(tr!(
                "paramètre d'adaptateur inconnu : {other}",
                "unknown adapter parameter: {other}"
            )),
            other => v.push(os(other)),
        }
    }
    Ok(v)
}

fn adapter(ctx: &Ctx<'_>, m: Manager) -> Result<&'static str> {
    let _ = ctx;
    Ok(m.as_str())
}

async fn run_adapter(
    ctx: &Ctx<'_>,
    a: &AdapterConfig,
    which: &str,
    cmd: &[String],
    packages: &[String],
    file: Option<&Path>,
) -> Result<executor::Output> {
    if cmd.is_empty() {
        bail!(tr!(
            "l'adaptateur « {which} » n'est pas configuré pour cette opération (voir [adapters] dans config.toml et docs/CLI_REFERENCE.md)",
            "the \"{which}\" adapter is not configured for this operation (see [adapters] in config.toml and docs/CLI_REFERENCE.md)"
        ));
    }
    if !a.validated {
        tracing::warn!(
            adapter = which,
            "{}",
            tr!(
                "syntaxe d'adaptateur non validée sur le système réel",
                "adapter syntax not validated on a real system"
            )
        );
    }
    let prog = executor::resolve_program(&a.program)?;
    executor::run(&prog, &adapter_args(cmd, packages, file)?, &ctx.opts()).await
}

/// Gestionnaire effectivement utilisé : sur AuxiNux OS, une variante Debian
/// (voir `Distribution::base`) demande APT, qui y est bloqué ; les mêmes
/// paquets Debian passent alors par `auxi`.
fn system_manager(ctx: &Ctx<'_>, m: Manager) -> Manager {
    match (m, ctx.profile.distribution) {
        (Manager::Apt, Distribution::Auxinuxos) => Manager::Auxi,
        _ => m,
    }
}

/// Exécute une commande d'adaptateur : une seule fois si elle prend la liste
/// `{packages}`, une fois par paquet si elle n'en prend qu'un (`{package}` ;
/// `auxi uninstall --deb` ne retire que le premier paquet nommé).
async fn run_adapter_each(
    ctx: &Ctx<'_>,
    a: &AdapterConfig,
    m: Manager,
    cmd: &[String],
    packages: &[String],
    (what, label): (&str, String),
) -> Result<bool> {
    let per_package = cmd.iter().any(|c| c == "{package}") && !cmd.iter().any(|c| c == "{packages}");
    let batches: Vec<&[String]> = if per_package && !packages.is_empty() {
        packages.chunks(1).collect()
    } else {
        vec![packages]
    };
    let mut reboot = false;
    for batch in batches {
        let out = crate::progress::step(
            format!("{label} {}", batch.join(" ")),
            run_adapter(ctx, a, m.as_str(), cmd, batch, None),
        )
        .await?;
        reboot |= ctx.check(&format!("{m} {what}"), &out, &[])?;
    }
    Ok(reboot)
}

/// Installe des paquets avec le gestionnaire natif autorisé.
async fn manager_install(ctx: &Ctx<'_>, m: Manager, packages: &[String]) -> Result<bool> {
    let m = system_manager(ctx, m);
    check_manager_allowed(ctx, m)?;
    for p in packages {
        if !ids::is_valid_native_package(p) {
            bail!(tr!("paquet natif invalide : {p}", "invalid native package: {p}"));
        }
    }
    match m {
        Manager::Apt => {
            let mut args = vec![os("install"), os("-y"), os("--no-install-recommends")];
            args.extend(packages.iter().map(os));
            let mut o = ctx.opts();
            o.env.push(("DEBIAN_FRONTEND".into(), "noninteractive".into()));
            let out = crate::progress::step(
                tr!("installation par APT : {}", "installing with APT: {}", packages.join(" ")),
                executor::run(&resolve(Tool::AptGet)?, &args, &o),
            )
            .await?;
            ctx.check("apt-get install", &out, &[])
        }
        Manager::Auxi | Manager::Virtuaos => {
            let a = adapter_for(ctx.config, m).context(tr!("adaptateur absent", "adapter missing"))?;
            if m == Manager::Auxi && !a.install.is_empty() {
                crate::debtoggle::ensure_enabled(ctx.paths, &executor::resolve_program(&a.program)?)?;
            }
            let label = tr!("installation par {} :", "installing with {}:", m.as_str());
            run_adapter_each(ctx, a, m, &a.install, packages, ("install", label)).await
        }
        Manager::Winget => {
            let mut reboot = false;
            for p in packages {
                let args = [
                    "install",
                    "--id",
                    p,
                    "--exact",
                    "--silent",
                    "--accept-package-agreements",
                    "--accept-source-agreements",
                    "--disable-interactivity",
                ]
                .map(os);
                let out = crate::progress::step(
                    tr!("installation par winget : {p}", "installing with winget: {p}"),
                    executor::run(&resolve(Tool::Winget)?, &args, &ctx.opts()),
                )
                .await?;
                reboot |= ctx.check("winget install", &out, &[])?;
            }
            Ok(reboot)
        }
        Manager::Brew => {
            let mut args = vec![os("install")];
            args.extend(packages.iter().map(os));
            let out = crate::progress::step(
                tr!(
                    "installation par Homebrew : {}",
                    "installing with Homebrew: {}",
                    packages.join(" ")
                ),
                executor::run(&resolve(Tool::Brew)?, &args, &ctx.opts()),
            )
            .await?;
            ctx.check("brew install", &out, &[])
        }
    }
}

fn check_manager_allowed(ctx: &Ctx<'_>, m: Manager) -> Result<()> {
    if !m.allowed_on().contains(&ctx.profile.distribution) {
        bail!(tr!(
            "le gestionnaire {m} n'est pas autorisé sur {}",
            "the {m} package manager is not allowed on {}",
            ctx.profile.distribution
        ));
    }
    if m == Manager::Brew {
        if !ctx.config.policy.allow_brew {
            bail!(tr!(
                "Homebrew est désactivé par la politique locale",
                "Homebrew is disabled by local policy"
            ));
        }
        if crate::privileges::is_elevated() && !executor::is_simulation() {
            bail!(tr!(
                "Homebrew ne doit pas être utilisé en tant qu'administrateur : relancez sans sudo",
                "Homebrew must not be used as administrator: run again without sudo"
            ));
        }
    }
    Ok(())
}

async fn manager_remove(ctx: &Ctx<'_>, m: Manager, packages: &[String]) -> Result<bool> {
    let m = system_manager(ctx, m);
    check_manager_allowed(ctx, m)?;
    match m {
        Manager::Apt => {
            let mut args = vec![os("remove"), os("-y")];
            for p in packages {
                if !ids::is_valid_native_package(p) {
                    bail!(tr!("paquet natif invalide : {p}", "invalid native package: {p}"));
                }
                args.push(os(p));
            }
            let mut o = ctx.opts();
            o.env.push(("DEBIAN_FRONTEND".into(), "noninteractive".into()));
            let out = crate::progress::step(
                tr!("désinstallation par APT", "removing with APT"),
                executor::run(&resolve(Tool::AptGet)?, &args, &o),
            )
            .await?;
            ctx.check("apt-get remove", &out, &[])
        }
        Manager::Auxi | Manager::Virtuaos => {
            let a = adapter_for(ctx.config, m).context(tr!("adaptateur absent", "adapter missing"))?;
            for p in packages {
                if !ids::is_valid_native_package(p) {
                    bail!(tr!("paquet natif invalide : {p}", "invalid native package: {p}"));
                }
            }
            let label = tr!("désinstallation par {} :", "removing with {}:", m.as_str());
            run_adapter_each(ctx, a, m, &a.remove, packages, ("remove", label)).await
        }
        Manager::Winget => {
            let mut reboot = false;
            for p in packages {
                let args = ["uninstall", "--id", p, "--exact", "--silent", "--disable-interactivity"].map(os);
                let out = crate::progress::step(
                    tr!("désinstallation par winget : {p}", "removing with winget: {p}"),
                    executor::run(&resolve(Tool::Winget)?, &args, &ctx.opts()),
                )
                .await?;
                reboot |= ctx.check("winget uninstall", &out, &[])?;
            }
            Ok(reboot)
        }
        Manager::Brew => {
            let mut args = vec![os("uninstall")];
            args.extend(packages.iter().map(os));
            let out = crate::progress::step(
                tr!("désinstallation par Homebrew", "removing with Homebrew"),
                executor::run(&resolve(Tool::Brew)?, &args, &ctx.opts()),
            )
            .await?;
            ctx.check("brew uninstall", &out, &[])
        }
    }
}

/// Gestionnaire natif de la distribution (dépendances natives).
fn native_manager(d: Distribution) -> Option<Manager> {
    match d {
        Distribution::Debian | Distribution::Ubuntu => Some(Manager::Apt),
        Distribution::Auxinuxos => Some(Manager::Auxi),
        Distribution::Virtuaos => Some(Manager::Virtuaos),
        _ => None,
    }
}

/// Exécute un script du paquet, si la politique l'autorise.
pub async fn run_script(ctx: &Ctx<'_>, script: &str, args: &[String], action: &str) -> Result<bool> {
    if !ctx.scripts_allowed {
        bail!(
            "le paquet demande l'exécution du script « {script} » : refusé. Relancez avec --allow-scripts après avoir \
             examiné le paquet (auxipak info), ou autorisez explicitement les scripts de ce dépôt"
        );
    }
    if !script.starts_with("scripts/") || !ids::is_safe_relative_path(script) {
        bail!(tr!("chemin de script refusé : {script}", "script path refused: {script}"));
    }
    for a in args {
        if !ids::is_valid_installer_arg(a) {
            bail!(tr!("argument de script refusé : {a}", "script argument refused: {a}"));
        }
    }
    let path = ctx.root.join(script);
    let meta =
        std::fs::symlink_metadata(&path).with_context(|| tr!("script introuvable : {script}", "script not found: {script}"))?;
    if !meta.is_file() {
        bail!(tr!(
            "le script doit être un fichier ordinaire : {script}",
            "the script must be a regular file: {script}"
        ));
    }
    let (program, mut argv) = if script.ends_with(".ps1") {
        (
            resolve(Tool::PowerShell)?,
            vec![
                os("-NoProfile"),
                os("-NonInteractive"),
                os("-ExecutionPolicy"),
                os("Bypass"),
                os("-File"),
                path.into_os_string(),
            ],
        )
    } else {
        (
            resolve(Tool::Bash)?,
            vec![os("--noprofile"), os("--norc"), path.into_os_string()],
        )
    };
    argv.extend(args.iter().map(os));
    let mut o = ctx.opts();
    o.cwd = Some(ctx.root.to_path_buf());
    o.env.extend([
        ("AUXIPAK_ACTION".to_string(), action.to_string()),
        ("AUXIPAK_APP_ID".into(), ctx.app_id.into()),
        ("AUXIPAK_VERSION".into(), ctx.version.into()),
        (
            "AUXIPAK_PAYLOAD_DIR".into(),
            // Absent à la désinstallation : seuls le manifeste et les scripts sont conservés.
            if ctx.root.join("payload").is_dir() {
                ctx.root.join("payload").display().to_string()
            } else {
                String::new()
            },
        ),
        (
            "AUXIPAK_APP_DIR".into(),
            ctx.paths.apps_dir.join(ctx.app_id).display().to_string(),
        ),
        ("AUXIPAK_BIN_DIR".into(), ctx.paths.bin_dir.display().to_string()),
        (
            "AUXIPAK_DATA_DIR".into(),
            ctx.paths.data_dir.join(ctx.app_id).display().to_string(),
        ),
    ]);
    let out = crate::progress::step(format!("script {script} ({action})"), executor::run(&program, &argv, &o)).await?;
    ctx.check(&format!("script {script}"), &out, &[])
}

/// Installe la variante.
pub async fn install(ctx: &Ctx<'_>, txn: &mut Transaction) -> Result<Outcome> {
    let t = ctx.target;
    if !t.native_dependencies.is_empty() {
        let m = native_manager(ctx.profile.distribution).context(tr!(
            "dépendances natives non prises en charge ici",
            "native dependencies are not supported here"
        ))?;
        eprintln!(
            "{}",
            tr!(
                "  dépendances natives ({m}) : {}",
                "  native dependencies ({m}): {}",
                t.native_dependencies.join(", ")
            )
        );
        manager_install(ctx, m, &t.native_dependencies).await?;
    }
    let mut outcome = Outcome::default();
    if let Some(s) = &t.scripts.pre_install {
        outcome.reboot |= run_script(ctx, s, &[], "pre_install").await?;
    }
    match &t.install {
        Install::PackageManager { manager, packages } => {
            outcome.manager = adapter(ctx, *manager)?.into();
            outcome.reboot |= manager_install(ctx, *manager, packages).await?;
        }
        Install::Deb { source, .. } => {
            let file = artifact(ctx, source).await?;
            if ctx.profile.distribution == Distribution::Auxinuxos || ctx.profile.distribution == Distribution::Virtuaos {
                // APT est bloqué sur ces systèmes : délégation à l'adaptateur système.
                let m = native_manager(ctx.profile.distribution).unwrap();
                let a = adapter_for(ctx.config, m).context(tr!("adaptateur absent", "adapter missing"))?;
                outcome.manager = m.as_str().into();
                if m == Manager::Auxi && !a.install_local_deb.is_empty() {
                    crate::debtoggle::ensure_enabled(ctx.paths, &executor::resolve_program(&a.program)?)?;
                }
                // Chemin absolu : apt-get (derrière auxi) ne prend un argument
                // pour un fichier que s'il contient « / ».
                let abs = file.canonicalize()?;
                let out = crate::progress::step(
                    tr!(
                        "installation du paquet .deb par {}",
                        "installing the .deb package with {}",
                        m.as_str()
                    ),
                    run_adapter(ctx, a, m.as_str(), &a.install_local_deb, &[], Some(&abs)),
                )
                .await?;
                outcome.reboot |= ctx.check(&tr!("installation du paquet .deb", ".deb package installation"), &out, &[])?;
            } else {
                outcome.manager = "apt".into();
                let mut o = ctx.opts();
                o.env.push(("DEBIAN_FRONTEND".into(), "noninteractive".into()));
                let abs = file.canonicalize()?;
                let args = vec![os("install"), os("-y"), os("--no-install-recommends"), abs.into_os_string()];
                let out = crate::progress::step(
                    tr!("installation du paquet .deb par APT", "installing the .deb package with APT"),
                    executor::run(&resolve(Tool::AptGet)?, &args, &o),
                )
                .await?;
                outcome.reboot |= ctx.check("apt-get install (.deb)", &out, &[])?;
            }
        }
        Install::Msi {
            source,
            properties,
            scope,
            ..
        } => {
            let file = artifact(ctx, source).await?;
            outcome.manager = "msiexec".into();
            let mut args = vec![os("/i"), file.into_os_string(), os("/qn"), os("/norestart")];
            if *scope == MsiScope::User {
                args.push(os("ALLUSERS=2"));
                args.push(os("MSIINSTALLPERUSER=1"));
            }
            for (k, v) in properties {
                if !ids::is_valid_msi_property(k) || !ids::is_valid_installer_arg(v) {
                    bail!(tr!("propriété MSI refusée : {k}", "MSI property refused: {k}"));
                }
                args.push(os(format!("{k}={v}")));
            }
            let out = crate::progress::step(
                tr!("installation MSI (msiexec)", "MSI installation (msiexec)"),
                executor::run(&resolve(Tool::Msiexec)?, &args, &ctx.opts()),
            )
            .await?;
            outcome.reboot |= ctx.check("msiexec", &out, &[3010, 1641])?;
        }
        Install::Exe { source, args } => {
            let file = artifact(ctx, source).await?;
            outcome.manager = "exe".into();
            for a in args {
                if !ids::is_valid_installer_arg(a) {
                    bail!(tr!("argument refusé : {a}", "argument refused: {a}"));
                }
            }
            let argv: Vec<OsString> = args.iter().map(os).collect();
            let out = crate::progress::step(
                tr!("exécution de l'installateur", "running the installer"),
                executor::run(&file, &argv, &ctx.opts()),
            )
            .await?;
            outcome.reboot |= ctx.check(&tr!("installateur exe", "exe installer"), &out, &[])?;
        }
        Install::Pkg { source, .. } => {
            let file = artifact(ctx, source).await?;
            outcome.manager = "installer".into();
            let args = vec![os("-pkg"), file.into_os_string(), os("-target"), os("/")];
            let out = crate::progress::step(
                tr!("installation du paquet .pkg", "installing the .pkg package"),
                executor::run(&resolve(Tool::Installer)?, &args, &ctx.opts()),
            )
            .await?;
            outcome.reboot |= ctx.check("installer -pkg", &out, &[])?;
        }
        Install::Dmg { source, app } => {
            let file = artifact(ctx, source).await?;
            outcome.manager = "hdiutil".into();
            let dest = install_dmg(ctx, &file, app).await?;
            txn.record_file(dest.clone())?;
            outcome.files.push(dest);
        }
        Install::Files { files } => {
            outcome.manager = "files".into();
            for f in files {
                for p in copy_files(ctx, f, txn)? {
                    outcome.files.push(p);
                }
            }
        }
        Install::Script { script, args } => {
            outcome.manager = "script".into();
            outcome.reboot |= run_script(ctx, script, args, "install").await?;
        }
    }
    if let Some(s) = &t.scripts.post_install {
        outcome.reboot |= run_script(ctx, s, &[], "post_install").await?;
    }
    Ok(outcome)
}

/// Copie des fichiers (méthode `files`), sans jamais écraser un fichier
/// qui n'appartient pas à l'application.
fn copy_files(ctx: &Ctx<'_>, f: &FileCopy, txn: &mut Transaction) -> Result<Vec<PathBuf>> {
    let src = ctx.root.join(&f.source);
    let mut pairs = Vec::new();
    let meta = std::fs::symlink_metadata(&src).with_context(|| tr!("source absente : {}", "source missing: {}", f.source))?;
    if meta.is_file() {
        pairs.push((src.clone(), ctx.expand(&f.destination)?));
    } else if meta.is_dir() {
        let dest_root = ctx.expand(&f.destination)?;
        collect_dir(&src, &src, &dest_root, &mut pairs)?;
    } else {
        bail!(tr!("source non ordinaire : {}", "source is not a regular file: {}", f.source));
    }
    let mut written = Vec::new();
    for (from, to) in pairs {
        if let Ok(m) = std::fs::symlink_metadata(&to) {
            if m.file_type().is_symlink() || m.is_dir() {
                bail!(tr!(
                    "destination occupée par un lien ou un répertoire : {}",
                    "destination is taken by a link or a directory: {}",
                    to.display()
                ));
            }
            if !ctx.owned_files.contains(&to) {
                bail!(tr!(
                    "le fichier {} existe déjà et n'est pas géré par AuxiPak pour {} : installation interrompue",
                    "the file {} already exists and is not managed by AuxiPak for {}: installation stopped",
                    to.display(),
                    ctx.app_id
                ));
            }
        }
        let parent = to.parent().context(tr!("destination invalide", "invalid destination"))?;
        std::fs::create_dir_all(parent)?;
        let mut tmp = tempfile::Builder::new().prefix(".auxipak-").tempfile_in(parent)?;
        std::io::copy(&mut std::fs::File::open(&from)?, tmp.as_file_mut())?;
        tmp.as_file().sync_all()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let exec = f.executable || std::fs::metadata(&from)?.permissions().mode() & 0o100 != 0;
            std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(if exec { 0o755 } else { 0o644 }))?;
        }
        // Enregistré avant le renommage : en cas d'interruption, le retour
        // arrière connaît tous les fichiers potentiellement écrits.
        txn.record_file(to.clone())?;
        tmp.persist(&to).map_err(|e| e.error)?;
        written.push(to);
    }
    Ok(written)
}

fn collect_dir(base: &Path, dir: &Path, dest: &Path, out: &mut Vec<(PathBuf, PathBuf)>) -> Result<()> {
    for e in std::fs::read_dir(dir)? {
        let e = e?;
        let ft = e.file_type()?;
        let rel = e.path().strip_prefix(base)?.to_path_buf();
        if ft.is_dir() {
            collect_dir(base, &e.path(), dest, out)?;
        } else if ft.is_file() {
            out.push((e.path(), dest.join(rel)));
        } else {
            bail!(tr!(
                "entrée non ordinaire refusée : {}",
                "non-regular entry refused: {}",
                e.path().display()
            ));
        }
    }
    Ok(())
}

fn applications_dir() -> PathBuf {
    if crate::privileges::is_elevated() {
        "/Applications".into()
    } else {
        std::env::var_os("HOME")
            .map(|h| PathBuf::from(h).join("Applications"))
            .unwrap_or_else(|| "/Applications".into())
    }
}

async fn install_dmg(ctx: &Ctx<'_>, file: &Path, app: &str) -> Result<PathBuf> {
    if !ids::is_safe_file_name(app) || !app.ends_with(".app") {
        bail!(tr!("bundle invalide : {app}", "invalid bundle: {app}"));
    }
    let mnt = ctx.work.join("mnt");
    std::fs::create_dir_all(&mnt)?;
    let hdiutil = resolve(Tool::Hdiutil)?;
    let attach = vec![
        os("attach"),
        os("-nobrowse"),
        os("-readonly"),
        os("-noautoopen"),
        os("-mountpoint"),
        mnt.clone().into_os_string(),
        file.as_os_str().to_owned(),
    ];
    let out = crate::progress::step(
        tr!("montage de l'image disque", "mounting the disk image"),
        executor::run(&hdiutil, &attach, &ctx.opts()),
    )
    .await?;
    ctx.check("hdiutil attach", &out, &[])?;
    let result = async {
        let src = mnt.join(app);
        let m = std::fs::symlink_metadata(&src)
            .with_context(|| tr!("{app} absent de l'image disque", "{app} missing from the disk image"))?;
        if !m.is_dir() {
            bail!(tr!("{app} n'est pas un bundle valide", "{app} is not a valid bundle"));
        }
        let dest_dir = applications_dir();
        std::fs::create_dir_all(&dest_dir)?;
        let dest = dest_dir.join(app);
        if dest.exists() && !ctx.owned_files.contains(&dest) {
            bail!(tr!(
                "{} existe déjà et n'est pas géré par AuxiPak",
                "{} already exists and is not managed by AuxiPak",
                dest.display()
            ));
        }
        if dest.exists() {
            std::fs::remove_dir_all(&dest)?;
        }
        let out = crate::progress::step(
            tr!("copie de {app} vers {}", "copying {app} to {}", dest_dir.display()),
            executor::run(
                &resolve(Tool::Ditto)?,
                &[src.into_os_string(), dest.clone().into_os_string()],
                &ctx.opts(),
            ),
        )
        .await?;
        ctx.check("ditto", &out, &[])?;
        Ok(dest)
    }
    .await;
    let detach = vec![os("detach"), mnt.into_os_string(), os("-force")];
    let _ = executor::run(&hdiutil, &detach, &ctx.opts()).await;
    result
}

/// Désinstalle une application. `files` : fichiers enregistrés à l'installation.
pub async fn remove(ctx: &Ctx<'_>, files: &[PathBuf]) -> Result<bool> {
    let t = ctx.target;
    let mut reboot = false;
    if let Some(s) = &t.scripts.pre_remove {
        reboot |= run_script(ctx, s, &[], "pre_remove").await?;
    }
    let r = t
        .effective_remove()
        .context(tr!("aucune procédure de désinstallation", "no removal procedure"))?;
    match &r {
        Remove::PackageManager { manager, packages } => reboot |= manager_remove(ctx, *manager, packages).await?,
        Remove::Deb { package } => {
            let m = native_manager(ctx.profile.distribution).unwrap_or(Manager::Apt);
            reboot |= manager_remove(ctx, m, std::slice::from_ref(package)).await?;
        }
        Remove::Msi { product_code } => {
            if !ids::is_valid_msi_product_code(product_code) {
                bail!(tr!("code produit invalide", "invalid product code"));
            }
            let args = vec![os("/x"), os(product_code), os("/qn"), os("/norestart")];
            let out = crate::progress::step(
                tr!("désinstallation MSI (msiexec)", "MSI removal (msiexec)"),
                executor::run(&resolve(Tool::Msiexec)?, &args, &ctx.opts()),
            )
            .await?;
            reboot |= ctx.check("msiexec /x", &out, &[3010, 1641])?;
        }
        Remove::Exe { path, args } => {
            let exe = ctx.expand(path)?;
            for a in args {
                if !ids::is_valid_installer_arg(a) {
                    bail!(tr!("argument refusé : {a}", "argument refused: {a}"));
                }
            }
            let argv: Vec<OsString> = args.iter().map(os).collect();
            let out = crate::progress::step(
                tr!("exécution du désinstallateur", "running the uninstaller"),
                executor::run(&exe, &argv, &ctx.opts()),
            )
            .await?;
            reboot |= ctx.check("désinstallateur", &out, &[])?;
        }
        Remove::Pkg { package_id, paths } => {
            for p in paths {
                let ok = p
                    .strip_prefix("/Applications/")
                    .map(ids::is_safe_relative_path)
                    .unwrap_or(false);
                if !ok {
                    bail!(tr!("chemin refusé : {p}", "path refused: {p}"));
                }
                let pb = PathBuf::from(p);
                if pb.exists() {
                    if pb.is_dir() {
                        std::fs::remove_dir_all(&pb)?;
                    } else {
                        std::fs::remove_file(&pb)?;
                    }
                }
            }
            let out = executor::run(&resolve(Tool::Pkgutil)?, &[os("--forget"), os(package_id)], &ctx.opts()).await?;
            ctx.check("pkgutil --forget", &out, &[])?;
        }
        Remove::App { app } => {
            for f in files
                .iter()
                .filter(|f| f.file_name().map(|n| n == app.as_str()).unwrap_or(false))
            {
                if f.exists() {
                    std::fs::remove_dir_all(f)?;
                }
            }
        }
        Remove::Files => remove_files(files)?,
        Remove::Script { script, args } => reboot |= run_script(ctx, script, args, "remove").await?,
    }
    if !matches!(r, Remove::Files) && matches!(t.install, Install::Files { .. }) {
        remove_files(files)?;
    }
    if let Some(s) = &t.scripts.post_remove {
        reboot |= run_script(ctx, s, &[], "post_remove").await?;
    }
    Ok(reboot)
}

/// Supprime des fichiers enregistrés, puis les répertoires devenus vides.
pub fn remove_files(files: &[PathBuf]) -> Result<()> {
    for f in files {
        match std::fs::symlink_metadata(f) {
            Ok(m) if m.is_file() || m.file_type().is_symlink() => std::fs::remove_file(f)?,
            Ok(m) if m.is_dir() => std::fs::remove_dir_all(f)?,
            _ => {}
        }
        let mut p = f.parent();
        while let Some(dir) = p {
            if std::fs::remove_dir(dir).is_err() {
                break;
            }
            p = dir.parent();
        }
    }
    Ok(())
}

/// Détecte si l'application est présente sur le système. `None` : inconnu.
pub async fn detect(ctx: &Ctx<'_>) -> Result<Option<bool>> {
    let Some(d) = ctx.target.effective_detect() else {
        return Ok(None);
    };
    let quiet = RunOpts {
        timeout: Some(Duration::from_secs(120)),
        ..Default::default()
    };
    match d {
        Detect::PackageManager { manager, package } => {
            if !ids::is_valid_native_package(&package) {
                bail!(tr!("paquet invalide", "invalid package"));
            }
            // Un paquet .deb installé sur AuxiNuxOS/VirtuaOS l'a été via l'adaptateur
            // système : la détection passe par lui, jamais par APT.
            let manager = match (manager, native_manager(ctx.profile.distribution)) {
                (Manager::Apt, Some(m @ (Manager::Auxi | Manager::Virtuaos))) => m,
                (m, _) => m,
            };
            // auxi n'a pas de requête d'état ; il installe des paquets Debian,
            // que dpkg-query (lecture seule, jamais bloqué) sait interroger.
            let manager = match manager {
                Manager::Auxi if adapter_for(ctx.config, manager).is_none_or(|a| a.query.is_empty()) => Manager::Apt,
                m => m,
            };
            match manager {
                Manager::Apt => {
                    let Ok(dq) = resolve(Tool::DpkgQuery) else { return Ok(None) };
                    let out = executor::run(&dq, &[os("-W"), os("-f=${Status}"), os(&package)], &quiet).await?;
                    Ok(Some(out.code == 0 && out.stdout.contains("install ok installed")))
                }
                Manager::Auxi | Manager::Virtuaos => {
                    let Some(a) = adapter_for(ctx.config, manager) else {
                        return Ok(None);
                    };
                    if a.query.is_empty() {
                        return Ok(None);
                    }
                    let out = run_adapter(ctx, a, manager.as_str(), &a.query, &[package], None).await?;
                    Ok(Some(out.code == 0))
                }
                Manager::Winget => {
                    let Ok(w) = resolve(Tool::Winget) else { return Ok(None) };
                    let out = executor::run(&w, &["list", "--id", &package, "--exact"].map(os), &quiet).await?;
                    Ok(Some(out.code == 0))
                }
                Manager::Brew => {
                    let Ok(b) = resolve(Tool::Brew) else { return Ok(None) };
                    let out = executor::run(&b, &[os("list"), os("--versions"), os(&package)], &quiet).await?;
                    Ok(Some(out.code == 0 && !out.stdout.trim().is_empty()))
                }
            }
        }
        Detect::Msi { product_code } => {
            let Ok(reg) = resolve(Tool::Reg) else { return Ok(None) };
            for hive in [
                "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\",
                "HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\",
                "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\",
            ] {
                let out = executor::run(&reg, &[os("query"), os(format!("{hive}{product_code}"))], &quiet).await?;
                if out.code == 0 {
                    return Ok(Some(true));
                }
            }
            Ok(Some(false))
        }
        Detect::Pkg { package_id } => {
            let Ok(p) = resolve(Tool::Pkgutil) else { return Ok(None) };
            let out = executor::run(&p, &[os("--pkg-info"), os(&package_id)], &quiet).await?;
            Ok(Some(out.code == 0))
        }
        Detect::App { app } => Ok(Some(
            PathBuf::from("/Applications").join(&app).exists() || applications_dir().join(&app).exists(),
        )),
        Detect::Files { paths } => {
            let mut all = true;
            for p in &paths {
                all &= ctx.expand(p)?.exists();
            }
            Ok(Some(all))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expands_known_roots_only() {
        let d = tempfile::tempdir().unwrap();
        let p = Paths::under(d.path(), false);
        assert_eq!(expand_path(&p, "demo", "{bin}/demo").unwrap(), d.path().join("bin/demo"));
        assert_eq!(
            expand_path(&p, "demo", "{app}/lib/x").unwrap(),
            d.path().join("apps/demo/lib/x")
        );
        assert!(expand_path(&p, "demo", "{bin}/../../etc/passwd").is_err());
        assert!(expand_path(&p, "demo", "{root}/x").is_err());
        assert!(expand_path(&p, "demo", "/etc/x").is_err());
    }

    #[test]
    fn adapter_arguments_are_validated() {
        let t = vec!["install".to_string(), "--yes".into(), "{packages}".into()];
        let a = adapter_args(&t, &["firefox".into(), "vlc".into()], None).unwrap();
        assert_eq!(a, vec![os("install"), os("--yes"), os("firefox"), os("vlc")]);
        assert!(adapter_args(&t, &["x;rm".into()], None).is_err());
        assert!(adapter_args(&["{evil}".into()], &[], None).is_err());
    }
}
