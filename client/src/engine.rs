//! Orchestration des opérations : résolution, dépendances, téléchargement,
//! vérifications, installation transactionnelle, mise à niveau, suppression
//! et réparation après interruption.

use crate::catalog::{self, Candidate, Selector};
use crate::config::Config;
use crate::download::{self, Expect, RedirectPolicy};
use crate::methods::{self, Ctx};
use crate::paths::{restrict_dir, Paths};
use crate::registry::{HistoryEntry, InstallState, InstalledApp, Phase, Registry, Transaction};
use crate::repo::{self, Need, RepoData};
use anyhow::{anyhow, bail, Context, Result};
use auxipak_core::archive::{self, Inspection, Limits};
use auxipak_core::manifest::{Install, Manifest, Privileges, Target, MANIFEST_FILE};
use auxipak_core::platform::SystemProfile;
use auxipak_core::signature::{KeyPurpose, PackageSignature, VerifiedSignature};
use auxipak_core::tr;
use auxipak_core::version::VersionReq;
use chrono::Utc;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Environnement d'exécution.
pub struct Env {
    pub paths: Paths,
    pub config: Config,
    pub profile: SystemProfile,
    pub repos: Vec<RepoData>,
    pub warnings: Vec<String>,
}

impl Env {
    /// Charge les dépôts selon la politique demandée.
    pub async fn load(paths: Paths, config: Config, profile: SystemProfile, need: Need) -> Env {
        let mut repos = Vec::new();
        let mut warnings = Vec::new();
        for r in config.enabled_repos() {
            let l = repo::ensure(r, &config, &paths, &profile, need).await;
            if let Some(w) = l.warning {
                warnings.push(w);
            }
            if let Some(d) = l.data {
                repos.push(d);
            }
        }
        Env {
            paths,
            config,
            profile,
            repos,
            warnings,
        }
    }

    pub fn print_warnings(&self) {
        for w in &self.warnings {
            eprintln!("{}", tr!("avertissement : {w}", "warning: {w}"));
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct InstallOpts {
    pub allow_scripts: bool,
    /// Prendre en charge une application déjà installée par le gestionnaire natif.
    pub adopt: bool,
    pub reinstall: bool,
    pub selector: Selector,
}

/// Paquet téléchargé et vérifié.
pub struct VerifiedPackage {
    pub path: PathBuf,
    pub inspection: Inspection,
    pub signature: Option<VerifiedSignature>,
}

fn targets_url(r: &RepoData) -> Result<url::Url> {
    Ok(repo::repo_urls(&r.config)?.1)
}

/// Télécharge et vérifie un paquet : empreinte (index authentifié par TUF),
/// révocation, signature, structure de l'archive et cohérence du manifeste.
pub async fn fetch_and_verify(env: &Env, c: &Candidate<'_>) -> Result<VerifiedPackage> {
    let r = c.repo;
    let rel = c.release;
    if c.is_revoked() {
        bail!(tr!(
            "{} {} a été révoqué : installation refusée",
            "{} {} has been revoked: installation refused",
            rel.id,
            rel.version
        ));
    }
    if r.freshness(env.config.cache_ttl_seconds, &env.profile) != repo::Freshness::Fresh {
        bail!(tr!(
            "l'index du dépôt « {} » n'est pas à jour : exécutez « auxipak update »",
            "the index of repository \"{}\" is out of date: run \"auxipak update\"",
            r.config.name
        ));
    }
    let base = targets_url(r)?;
    let url = base.join(&rel.target)?;
    let dir = env.paths.package_cache_dir().join(&r.config.name);
    std::fs::create_dir_all(&dir)?;
    let dest = dir.join(format!("{}.aupak", rel.sha256));
    let policy = RedirectPolicy {
        allowed_hosts: vec![],
        allow_insecure_localhost: r.config.allow_insecure_localhost,
    };
    download::fetch(
        &url,
        &dest,
        &Expect {
            sha256: rel.sha256.clone(),
            size: Some(rel.size),
            max_size: env.config.policy.max_download_bytes,
        },
        &policy,
        &rel.file_name,
    )
    .await
    .with_context(|| tr!("téléchargement de {}", "downloading {}", rel.file_name))?;

    // Signature détachée.
    let trust = r.config.trust(&env.paths)?;
    let signature_required = r.config.official || r.config.require_signatures;
    let sig_url = base.join(&rel.signature.target)?;
    let sig = fetch_small(&sig_url, &policy).await;
    let verified = match sig {
        Ok(bytes) => {
            let doc = PackageSignature::from_json(&bytes)?;
            let v = doc
                .verify(&rel.sha256, rel.size, &trust.package_keys, &[KeyPurpose::PackageSigning])
                .map_err(|e| {
                    anyhow!(tr!(
                        "signature du paquet {} refusée : {e}",
                        "package signature {} refused: {e}",
                        rel.file_name
                    ))
                })?;
            if doc.payload.package.id != rel.id || doc.payload.package.version != rel.version {
                bail!(tr!(
                    "la signature ne correspond pas à {} {}",
                    "the signature does not match {} {}",
                    rel.id,
                    rel.version
                ));
            }
            Some(v)
        }
        Err(e) if signature_required => bail!(tr!(
            "signature obligatoire introuvable pour {} : {e:#}",
            "required signature not found for {}: {e:#}",
            rel.file_name
        )),
        Err(_) => None,
    };

    let inspection =
        archive::inspect(&dest, &Limits::default()).map_err(|e| anyhow!(tr!("paquet refusé : {e}", "package refused: {e}")))?;
    let m = &inspection.manifest;
    if m.id != rel.id || m.version != rel.version {
        bail!(tr!(
            "le manifeste ({} {}) ne correspond pas à l'index ({} {})",
            "the manifest ({} {}) does not match the index ({} {})",
            m.id,
            m.version,
            rel.id,
            rel.version
        ));
    }
    Ok(VerifiedPackage {
        path: dest,
        inspection,
        signature: verified,
    })
}

async fn fetch_small(url: &url::Url, policy: &RedirectPolicy) -> Result<Vec<u8>> {
    let tmp = tempfile::tempdir()?;
    let p = tmp.path().join("sig");
    match url.scheme() {
        "file" => Ok(std::fs::read(
            url.to_file_path().map_err(|_| anyhow!(tr!("URL invalide", "invalid URL")))?,
        )?),
        _ => {
            // Petite taille, sans empreinte connue : téléchargement direct limité.
            let client = reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(std::time::Duration::from_secs(60))
                .build()?;
            if url.scheme() == "http" && !policy.allow_insecure_localhost {
                bail!(tr!("HTTP refusé", "HTTP refused"));
            }
            let resp = client.get(url.clone()).send().await?;
            if !resp.status().is_success() {
                bail!("HTTP {}", resp.status());
            }
            let b = resp.bytes().await?;
            if b.len() > 64 * 1024 {
                bail!(tr!("document de signature trop volumineux", "signature document too large"));
            }
            std::fs::write(&p, &b)?;
            Ok(b.to_vec())
        }
    }
}

/// Plan d'installation (dépendances d'abord).
pub fn plan<'a>(env: &'a Env, root: Candidate<'a>, registry: &Registry) -> Result<Vec<(Candidate<'a>, bool)>> {
    let mut out: Vec<(Candidate<'a>, bool)> = Vec::new();
    let mut visiting = BTreeSet::new();
    visit(env, root, registry, &mut out, &mut visiting, false)?;
    Ok(out)
}

fn visit<'a>(
    env: &'a Env,
    c: Candidate<'a>,
    registry: &Registry,
    out: &mut Vec<(Candidate<'a>, bool)>,
    visiting: &mut BTreeSet<String>,
    is_dep: bool,
) -> Result<()> {
    if !visiting.insert(c.release.id.clone()) {
        bail!(tr!(
            "dépendance circulaire impliquant {}",
            "circular dependency involving {}",
            c.release.id
        ));
    }
    for d in &c.release.dependencies {
        if out.iter().any(|(x, _)| x.release.id == d.id) {
            continue;
        }
        if let Some(inst) = registry.get(&d.id) {
            if d.version.matches(&inst.version) {
                continue;
            }
        }
        let sel = Selector {
            version: Some(d.version.clone()),
            language: None,
            repo: None,
        };
        let dc = catalog::resolve(&env.repos, &d.id, &sel, &env.config.package_language()).with_context(|| {
            tr!(
                "dépendance {} ({}) de {}",
                "dependency {} ({}) of {}",
                d.id,
                d.version,
                c.release.id
            )
        })?;
        visit(env, dc, registry, out, visiting, true)?;
    }
    visiting.remove(&c.release.id);
    out.push((c, is_dep));
    Ok(())
}

fn work_dir(paths: &Paths, txn: &Transaction) -> Result<PathBuf> {
    let w = paths.work_dir().join(&txn.id);
    std::fs::create_dir_all(&w)?;
    restrict_dir(&paths.work_dir())?;
    restrict_dir(&w)?;
    Ok(w)
}

/// Copie conservée du manifeste et des scripts (utile à la désinstallation).
fn stage_app_state(paths: &Paths, id: &str, extracted: &Path) -> Result<PathBuf> {
    let staged = paths.state_dir.join("apps").join(format!(".{id}.new"));
    if staged.exists() {
        std::fs::remove_dir_all(&staged)?;
    }
    std::fs::create_dir_all(&staged)?;
    std::fs::copy(extracted.join(MANIFEST_FILE), staged.join(MANIFEST_FILE))?;
    let scripts = extracted.join("scripts");
    if scripts.is_dir() {
        copy_tree(&scripts, &staged.join("scripts"))?;
    }
    Ok(staged)
}

fn commit_app_state(paths: &Paths, id: &str, staged: &Path) -> Result<()> {
    let final_dir = paths.app_state_dir(id);
    let old = paths.state_dir.join("apps").join(format!(".{id}.old"));
    if final_dir.exists() {
        let _ = std::fs::remove_dir_all(&old);
        std::fs::rename(&final_dir, &old)?;
    }
    std::fs::rename(staged, &final_dir)?;
    let _ = std::fs::remove_dir_all(&old);
    Ok(())
}

fn copy_tree(from: &Path, to: &Path) -> Result<()> {
    std::fs::create_dir_all(to)?;
    for e in std::fs::read_dir(from)? {
        let e = e?;
        let ft = e.file_type()?;
        if ft.is_dir() {
            copy_tree(&e.path(), &to.join(e.file_name()))?;
        } else if ft.is_file() {
            std::fs::copy(e.path(), to.join(e.file_name()))?;
        }
    }
    Ok(())
}

/// Application AuxiPak installée dont la détection est identique à celle de
/// `target` (par exemple Firefox ESR et Firefox, tous deux `Firefox.app`).
fn detect_owner(env: &Env, registry: &Registry, target: &Target) -> Option<String> {
    let wanted = target.effective_detect()?;
    registry.apps.values().find_map(|app| {
        let (_, t) = stored_target(&env.paths, app).ok()?;
        (t.platform == target.platform && t.effective_detect().as_ref() == Some(&wanted)).then(|| app.id.clone())
    })
}

/// Manifeste et cible enregistrés d'une application installée.
pub fn stored_target(paths: &Paths, app: &InstalledApp) -> Result<(Manifest, Target)> {
    let p = paths.app_state_dir(&app.id).join(MANIFEST_FILE);
    let bytes = std::fs::read(&p).with_context(|| {
        tr!(
            "manifeste enregistré introuvable : {}",
            "stored manifest not found: {}",
            p.display()
        )
    })?;
    let (m, _) = Manifest::parse(&bytes)?;
    let t = m.targets.iter().find(|t| t.name == app.target).cloned().ok_or_else(|| {
        anyhow!(tr!(
            "variante {} absente du manifeste enregistré",
            "target {} missing from the stored manifest",
            app.target
        ))
    })?;
    Ok((m, t))
}

fn require_privileges(target: &Target) -> Result<()> {
    if target.effective_privileges() == Privileges::Admin && !crate::privileges::is_elevated() {
        bail!(tr!(
            "cette installation exige les droits d'administration ({}) : {}",
            "this installation requires administrator rights ({}): {}",
            target.install.method_name(),
            crate::privileges::elevation_hint()
        ));
    }
    Ok(())
}

fn scripts_allowed(env: &Env, c: &Candidate, opts: &InstallOpts, signed: bool, target: &Target) -> Result<bool> {
    if !target.uses_scripts() {
        return Ok(false);
    }
    let allowed = (opts.allow_scripts || c.repo.config.allow_scripts) && (signed || !c.repo.config.require_signatures);
    if !allowed {
        bail!(tr!(
            "{} {} contient des scripts personnalisés ({}). Leur exécution exige une autorisation explicite : \
             examinez le paquet (« auxipak info {} ») puis relancez avec --allow-scripts",
            "{} {} contains custom scripts ({}). Running them requires explicit permission: \
             review the package (\"auxipak info {}\") then run again with --allow-scripts",
            c.release.id,
            c.release.version,
            target
                .scripts
                .all()
                .map(|(_, s)| s.clone())
                .chain(match &target.install {
                    Install::Script { script, .. } => Some(script.clone()),
                    _ => None,
                })
                .collect::<Vec<_>>()
                .join(", "),
            c.release.id
        ));
    }
    let _ = env;
    Ok(true)
}

/// Installe (ou met à niveau) un candidat déjà résolu.
pub async fn install_one(
    env: &Env,
    c: &Candidate<'_>,
    opts: &InstallOpts,
    auto: bool,
    registry: &mut Registry,
) -> Result<String> {
    let rel = c.release;
    let existing = registry.get(&rel.id).cloned();
    if let Some(e) = &existing {
        if e.version == rel.version && !opts.reinstall && e.state != InstallState::Partial {
            return Ok(tr!(
                "{} {} est déjà installé",
                "{} {} is already installed",
                rel.id,
                rel.version
            ));
        }
    }
    let vp = fetch_and_verify(env, c).await?;
    let manifest = vp.inspection.manifest.clone();
    let target = manifest.select_target(&env.profile).map_err(|e| anyhow!(e))?.clone();
    require_privileges(&target)?;
    let scripts_ok = scripts_allowed(env, c, opts, vp.signature.is_some(), &target)?;
    let simulated = crate::executor::is_simulation();
    if simulated {
        eprintln!(
            "{}",
            tr!(
                "ATTENTION : MODE SIMULATION (AUXIPAK_TEST_TOOLS_DIR) — aucune installation réelle ne valide ce résultat",
                "WARNING: SIMULATION MODE (AUXIPAK_TEST_TOOLS_DIR) — no real installation backs this result"
            )
        );
    }

    // Réconciliation : une application installée hors AuxiPak n'est jamais revendiquée implicitement.
    if existing.is_none() {
        let probe = Ctx {
            paths: &env.paths,
            config: &env.config,
            profile: &env.profile,
            app_id: &rel.id,
            version: &rel.version,
            target: &target,
            root: Path::new("."),
            work: &env.paths.cache_dir,
            scripts_allowed: false,
            owned_files: &[],
        };
        if methods::detect(&probe).await.unwrap_or(None) == Some(true) {
            // Même application (bundle, paquet natif, fichiers) qu'une autre
            // application AuxiPak : le dire, plutôt que « un autre moyen ».
            if let Some(owner) = detect_owner(env, registry, &target) {
                bail!(tr!(
                    "{} occupe déjà le même emplacement que {owner}, installée par AuxiPak (les deux ne peuvent pas coexister) : « auxipak remove {owner} » d'abord",
                    "{} uses the same location as {owner}, installed by AuxiPak (they cannot coexist): run \"auxipak remove {owner}\" first",
                    rel.id
                ));
            }
            if !opts.adopt {
                bail!(tr!(
                    "{} semble déjà installé par un autre moyen (gestionnaire natif ou installation manuelle). \
                     AuxiPak ne le revendique pas automatiquement : utilisez --adopt pour le faire suivre sans réinstaller",
                    "{} already seems to be installed by other means (native package manager or manual installation). \
                     AuxiPak does not claim it automatically: use --adopt to track it without reinstalling",
                    rel.id
                ));
            }
            let tmp = tempfile::tempdir()?;
            archive::extract(&vp.path, tmp.path(), &Limits::default())?;
            let staged = stage_app_state(&env.paths, &rel.id, tmp.path())?;
            commit_app_state(&env.paths, &rel.id, &staged)?;
            let rec = new_record(
                env,
                c,
                &vp,
                &target,
                "adopted",
                vec![],
                false,
                auto,
                InstallState::Adopted,
                simulated,
                None,
            );
            registry.apps.insert(rel.id.clone(), rec);
            registry.save(&env.paths)?;
            return Ok(tr!(
                "{} {} pris en charge (installation existante adoptée)",
                "{} {} is now tracked (existing installation adopted)",
                rel.id,
                rel.version
            ));
        }
    }

    let action = if existing.is_some() { "upgrade" } else { "install" };
    let mut txn = Transaction::begin(
        &env.paths,
        action,
        &rel.id,
        &rel.version,
        existing.as_ref().map(|e| e.version.clone()),
    )?;
    let result = install_txn(
        env,
        c,
        &vp,
        &target,
        scripts_ok,
        auto,
        existing.as_ref(),
        &mut txn,
        simulated,
        registry,
    )
    .await;
    match result {
        Ok(msg) => {
            txn.set_phase(Phase::Registered)?;
            txn.finish()?;
            Ok(msg)
        }
        Err(e) => {
            let detail = rollback(env, txn, registry, existing.as_ref()).await;
            Err(e.context(detail))
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn new_record(
    env: &Env,
    c: &Candidate,
    vp: &VerifiedPackage,
    target: &Target,
    manager: &str,
    files: Vec<PathBuf>,
    reboot: bool,
    auto: bool,
    state: InstallState,
    simulated: bool,
    previous: Option<&InstalledApp>,
) -> InstalledApp {
    let rel = c.release;
    let now = Utc::now();
    let mut history = previous.map(|p| p.history.clone()).unwrap_or_default();
    history.push(HistoryEntry {
        at: now,
        action: if previous.is_some() {
            "upgrade".into()
        } else if state == InstallState::Adopted {
            "adopt".into()
        } else {
            "install".into()
        },
        from: previous.map(|p| p.version.clone()),
        to: Some(rel.version.clone()),
        result: "ok".into(),
    });
    let base = targets_url(c.repo)
        .map(|u| u.join(&rel.target).map(|x| x.to_string()).unwrap_or_default())
        .unwrap_or_default();
    let _ = env;
    InstalledApp {
        id: rel.id.clone(),
        name: c.name().to_string(),
        version: rel.version.clone(),
        repo: c.repo.config.name.clone(),
        source: base,
        package_sha256: vp.inspection.archive_sha256.clone(),
        file_name: rel.file_name.clone(),
        target: target.name.clone(),
        mode: target.mode.to_string(),
        method: target.install.method_name().into(),
        manager: manager.into(),
        languages: rel.languages.clone(),
        installed_at: previous.map(|p| p.installed_at).unwrap_or(now),
        updated_at: now,
        state,
        auto_installed: previous.map(|p| p.auto_installed && auto).unwrap_or(auto),
        dependencies: rel.dependencies.iter().map(|d| d.id.clone()).collect(),
        files,
        reboot_required: reboot,
        simulated,
        history,
    }
}

#[allow(clippy::too_many_arguments)]
async fn install_txn(
    env: &Env,
    c: &Candidate<'_>,
    vp: &VerifiedPackage,
    target: &Target,
    scripts_ok: bool,
    auto: bool,
    existing: Option<&InstalledApp>,
    txn: &mut Transaction,
    simulated: bool,
    registry: &mut Registry,
) -> Result<String> {
    let rel = c.release;
    txn.set_phase(Phase::Verified)?;
    let work = work_dir(&env.paths, txn)?;
    txn.work_dir = Some(work.clone());
    let extracted = work.join("pkg");
    std::fs::create_dir_all(&extracted)?;
    download::ensure_space(&work, vp.inspection.total_unpacked)?;
    archive::extract(&vp.path, &extracted, &Limits::default())
        .map_err(|e| anyhow!(tr!("extraction : {e}", "extraction: {e}")))?;
    txn.set_phase(Phase::Extracted)?;
    crash_point("after_extract");
    let staged = stage_app_state(&env.paths, &rel.id, &extracted)?;

    // Stratégie de mise à niveau.
    let owned: Vec<PathBuf> = existing.map(|e| e.files.clone()).unwrap_or_default();
    if let Some(prev) = existing {
        if target.upgrade.strategy == auxipak_core::manifest::UpgradeStrategy::RemoveThenInstall {
            // Le système est modifié dès cette étape : la transaction le reflète.
            txn.pending_record = Some(prev.clone());
            txn.set_phase(Phase::Installing)?;
            eprintln!(
                "{}",
                tr!(
                    "  désinstallation de la version {} avant mise à niveau",
                    "  removing version {} before upgrading",
                    prev.version
                )
            );
            remove_installed(env, prev, scripts_ok).await?;
        }
    }

    txn.pending_record = Some(new_record(
        env,
        c,
        vp,
        target,
        "",
        vec![],
        false,
        auto,
        InstallState::Partial,
        simulated,
        existing,
    ));
    txn.set_phase(Phase::Installing)?;
    let ctx = Ctx {
        paths: &env.paths,
        config: &env.config,
        profile: &env.profile,
        app_id: &rel.id,
        version: &rel.version,
        target,
        root: &extracted,
        work: &work,
        scripts_allowed: scripts_ok,
        owned_files: &owned,
    };
    eprintln!(
        "{}",
        tr!(
            "  installation ({} / {})",
            "  installing ({} / {})",
            target.mode,
            target.install.method_name()
        )
    );
    let outcome = methods::install(&ctx, txn).await?;
    crash_point("after_install");
    txn.set_phase(Phase::Installed)?;
    if methods::detect(&ctx).await? == Some(false) {
        bail!(tr!(
            "l'installateur s'est terminé sans erreur mais l'application n'est pas détectée",
            "the installer finished without error but the application is not detected"
        ));
    }
    // Fichiers de l'ancienne version qui ne font plus partie de la nouvelle.
    if !owned.is_empty() {
        let stale: Vec<PathBuf> = owned.iter().filter(|f| !outcome.files.contains(f)).cloned().collect();
        methods::remove_files(&stale)?;
    }
    commit_app_state(&env.paths, &rel.id, &staged)?;
    let rec = new_record(
        env,
        c,
        vp,
        target,
        &outcome.manager,
        outcome.files,
        outcome.reboot,
        auto,
        InstallState::Installed,
        simulated,
        existing,
    );
    registry.apps.insert(rel.id.clone(), rec);
    registry.save(&env.paths)?;
    let mut msg = match existing {
        Some(p) if p.version != rel.version => tr!(
            "{} mis à niveau : {} → {}",
            "{} upgraded: {} → {}",
            rel.id,
            p.version,
            rel.version
        ),
        _ => tr!("{} {} installé", "{} {} installed", rel.id, rel.version),
    };
    if outcome.reboot || target.reboot == auxipak_core::manifest::Reboot::Required {
        msg.push_str(&tr!(" (redémarrage requis)", " (restart required)"));
    } else if target.reboot == auxipak_core::manifest::Reboot::Recommended {
        msg.push_str(&tr!(" (redémarrage recommandé)", " (restart recommended)"));
    }
    Ok(msg)
}

/// Retour arrière après un échec ; retourne une description de l'état final.
async fn rollback(env: &Env, txn: Transaction, registry: &mut Registry, existing: Option<&InstalledApp>) -> String {
    let staged = env.paths.state_dir.join("apps").join(format!(".{}.new", txn.app_id));
    let _ = std::fs::remove_dir_all(&staged);
    if txn.phase < Phase::Installing {
        let _ = txn.finish();
        return tr!(
            "aucune modification du système n'a été effectuée",
            "no change was made to the system"
        );
    }
    // Fichiers copiés par AuxiPak : retour arrière précis (sauf ceux de la version précédente).
    let owned: Vec<PathBuf> = existing.map(|e| e.files.clone()).unwrap_or_default();
    let ours: Vec<PathBuf> = txn.files_written.iter().filter(|f| !owned.contains(f)).cloned().collect();
    if !ours.is_empty() && methods::remove_files(&ours).is_ok() && existing.is_none() && is_files_only(&txn) {
        let _ = txn.finish();
        return tr!(
            "les fichiers partiellement installés ont été supprimés",
            "the partially installed files have been removed"
        );
    }
    // L'installateur natif a pu modifier le système : état « partiel » enregistré.
    if let Some(mut rec) = txn.pending_record.clone() {
        if let Some(prev) = existing {
            rec = prev.clone();
        }
        rec.state = InstallState::Partial;
        rec.history.push(HistoryEntry {
            at: Utc::now(),
            action: txn.action.clone(),
            from: txn.previous_version.clone(),
            to: Some(txn.version.clone()),
            result: "failed".into(),
        });
        registry.apps.insert(rec.id.clone(), rec);
        let _ = registry.save(&env.paths);
    }
    let _ = txn.finish();
    tr!(
        "installation partielle enregistrée : utilisez « auxipak remove » pour nettoyer ou relancez l'installation",
        "partial installation recorded: use \"auxipak remove\" to clean up or run the installation again"
    )
}

fn is_files_only(txn: &Transaction) -> bool {
    txn.pending_record.as_ref().map(|r| r.method == "files").unwrap_or(false)
}

/// Désinstalle une application installée (sans toucher au registre).
pub async fn remove_installed(env: &Env, app: &InstalledApp, scripts_allowed: bool) -> Result<bool> {
    if app.state == InstallState::Adopted {
        eprintln!(
            "{}",
            tr!(
                "  {} avait été adopté : désinstallation via le gestionnaire d'origine",
                "  {} was adopted: removing it through its original package manager",
                app.id
            )
        );
    }
    let (_, target) = stored_target(&env.paths, app)?;
    require_privileges(&target)?;
    if target.uses_scripts() && !scripts_allowed {
        bail!(tr!(
            "la désinstallation de {} exécute des scripts : relancez avec --allow-scripts",
            "removing {} runs scripts: run again with --allow-scripts",
            app.id
        ));
    }
    let root = env.paths.app_state_dir(&app.id);
    let work = tempfile::Builder::new().prefix("remove-").tempdir_in({
        std::fs::create_dir_all(env.paths.work_dir())?;
        env.paths.work_dir()
    })?;
    let ctx = Ctx {
        paths: &env.paths,
        config: &env.config,
        profile: &env.profile,
        app_id: &app.id,
        version: &app.version,
        target: &target,
        root: &root,
        work: work.path(),
        scripts_allowed,
        owned_files: &app.files,
    };
    methods::remove(&ctx, &app.files).await
}

/// `auxipak remove`.
pub async fn remove(
    env: &Env,
    id: &str,
    force: bool,
    autoremove: bool,
    allow_scripts: bool,
    registry: &mut Registry,
) -> Result<Vec<String>> {
    let app = registry.get(id).cloned().ok_or_else(|| {
        anyhow!(tr!(
            "{id} n'est pas installé par AuxiPak (voir « auxipak list »)",
            "{id} is not installed by AuxiPak (see \"auxipak list\")"
        ))
    })?;
    let dependents: Vec<String> = registry.dependents(id).iter().map(|a| a.id.clone()).collect();
    if !dependents.is_empty() && !force {
        bail!(tr!(
            "{id} est requis par : {} (utilisez --force pour passer outre)",
            "{id} is required by: {} (use --force to override)",
            dependents.join(", ")
        ));
    }
    let mut msgs = Vec::new();
    let mut txn = Transaction::begin(&env.paths, "remove", id, &app.version, None)?;
    txn.set_phase(Phase::Installing)?;
    let repo_allows = env.config.repo(&app.repo).map(|r| r.allow_scripts).unwrap_or(false);
    let reboot = remove_installed(env, &app, allow_scripts || repo_allows).await?;
    registry.apps.remove(id);
    registry.save(&env.paths)?;
    let _ = std::fs::remove_dir_all(env.paths.app_state_dir(id));
    let _ = std::fs::remove_dir_all(env.paths.data_dir.join(id));
    let _ = std::fs::remove_dir(env.paths.apps_dir.join(id));
    txn.finish()?;
    msgs.push(tr!(
        "{id} {} désinstallé{}",
        "{id} {} removed{}",
        app.version,
        if reboot {
            tr!(" (redémarrage requis)", " (restart required)")
        } else {
            String::new()
        }
    ));
    // Dépendances devenues orphelines.
    let orphans: Vec<String> = registry.orphans().iter().map(|a| a.id.clone()).collect();
    for o in orphans {
        if autoremove {
            let sub = Box::pin(remove(env, &o, false, true, allow_scripts, registry)).await?;
            msgs.extend(sub);
        } else {
            msgs.push(tr!(
                "la dépendance {o} n'est plus utilisée (« auxipak remove {o} » ou --autoremove)",
                "the dependency {o} is no longer used (\"auxipak remove {o}\" or --autoremove)"
            ));
        }
    }
    if app.method == "deb" || app.manager == "apt" {
        msgs.push(tr!(
            "les dépendances natives éventuelles restent gérées par APT (« apt autoremove » pour les nettoyer)",
            "any native dependencies remain managed by APT (\"apt autoremove\" to clean them up)"
        ));
    }
    Ok(msgs)
}

/// `auxipak upgrade [id]`.
pub async fn upgrade(env: &Env, only: Option<&str>, opts: &InstallOpts, registry: &mut Registry) -> Result<Vec<String>> {
    let mut msgs = Vec::new();
    let ids: Vec<String> = match only {
        Some(id) => {
            if registry.get(id).is_none() {
                bail!(tr!("{id} n'est pas installé par AuxiPak", "{id} is not installed by AuxiPak"));
            }
            vec![id.to_string()]
        }
        None => registry.apps.keys().cloned().collect(),
    };
    let mut errors = Vec::new();
    for id in ids {
        let app = registry.get(&id).cloned().unwrap();
        if app.state == InstallState::Adopted {
            msgs.push(tr!(
                "{id} : adopté, mise à niveau laissée au gestionnaire d'origine",
                "{id}: adopted, upgrades are left to its original package manager"
            ));
            continue;
        }
        let lang = app
            .languages
            .first()
            .cloned()
            .unwrap_or_else(|| env.config.package_language());
        match catalog::best_update(&env.repos, &id, &app.repo, &app.version, &lang) {
            None => msgs.push(tr!("{id} {} est à jour", "{id} {} is up to date", app.version)),
            Some(c) => {
                let auto = app.auto_installed;
                match install_one(env, &c, opts, auto, registry).await {
                    Ok(m) => msgs.push(m),
                    Err(e) => errors.push(tr!("{id} : {e:#}", "{id}: {e:#}")),
                }
            }
        }
    }
    if !errors.is_empty() {
        bail!("{}\n{}", msgs.join("\n"), errors.join("\n"));
    }
    Ok(msgs)
}

/// `auxipak install`.
pub async fn install(env: &Env, spec: &str, opts: &InstallOpts, registry: &mut Registry) -> Result<Vec<String>> {
    let root = catalog::resolve(&env.repos, spec, &opts.selector, &env.config.package_language())?;
    let steps = plan(env, root, registry)?;
    let mut msgs = Vec::new();
    for (c, is_dep) in steps {
        if is_dep {
            eprintln!(
                "{}",
                tr!("dépendance : {} {}", "dependency: {} {}", c.release.id, c.release.version)
            );
        } else {
            eprintln!(
                "{} {} ({}, {})",
                c.release.id,
                c.release.version,
                c.repo.config.name,
                c.status().label()
            );
        }
        let sub_opts = if is_dep {
            InstallOpts {
                reinstall: false,
                ..opts.clone()
            }
        } else {
            opts.clone()
        };
        msgs.push(install_one(env, &c, &sub_opts, is_dep, registry).await?);
    }
    Ok(msgs)
}

/// `auxipak repair` : reprend ou nettoie les transactions interrompues.
pub async fn repair(env: &Env, registry: &mut Registry) -> Result<Vec<String>> {
    let mut msgs = Vec::new();
    for txn in Transaction::pending(&env.paths)? {
        let label = format!("{} {} ({})", txn.app_id, txn.version, txn.action);
        let staged = env.paths.state_dir.join("apps").join(format!(".{}.new", txn.app_id));
        if txn.phase < Phase::Installing {
            let _ = std::fs::remove_dir_all(&staged);
            msgs.push(tr!(
                "{label} : interrompu avant toute modification du système, nettoyé",
                "{label}: interrupted before any change to the system, cleaned up"
            ));
            txn.finish()?;
            continue;
        }
        if txn.action == "remove" {
            // Suppression interrompue : vérifier si l'application est encore présente.
            if let Some(app) = registry.get(&txn.app_id).cloned() {
                let still = match stored_target(&env.paths, &app) {
                    Ok((_, t)) => detect_with(env, &app.id, &app.version, &t, &app.files).await,
                    Err(_) => None,
                };
                if still == Some(false) {
                    registry.apps.remove(&app.id);
                    registry.save(&env.paths)?;
                    let _ = std::fs::remove_dir_all(env.paths.app_state_dir(&app.id));
                    msgs.push(tr!(
                        "{label} : la désinstallation avait abouti, registre mis à jour",
                        "{label}: the removal had completed, registry updated"
                    ));
                } else {
                    msgs.push(tr!(
                        "{label} : application toujours présente, relancez « auxipak remove {} »",
                        "{label}: application still present, run \"auxipak remove {}\" again",
                        app.id
                    ));
                }
            }
            txn.finish()?;
            continue;
        }
        let Some(mut rec) = txn.pending_record.clone() else {
            msgs.push(tr!(
                "{label} : journal incomplet, nettoyé",
                "{label}: incomplete journal, cleaned up"
            ));
            txn.finish()?;
            continue;
        };
        let manifest_dir = if staged.exists() {
            staged.clone()
        } else {
            env.paths.app_state_dir(&txn.app_id)
        };
        let target = std::fs::read(manifest_dir.join(MANIFEST_FILE))
            .ok()
            .and_then(|b| Manifest::parse(&b).ok())
            .and_then(|(m, _)| m.targets.into_iter().find(|t| t.name == rec.target));
        let present = match &target {
            Some(t) => detect_with(env, &rec.id, &rec.version, t, &txn.files_written).await,
            None => None,
        };
        match present {
            Some(true) => {
                if staged.exists() {
                    commit_app_state(&env.paths, &rec.id, &staged)?;
                }
                rec.state = InstallState::Recovered;
                rec.files = txn.files_written.clone();
                registry.apps.insert(rec.id.clone(), rec);
                registry.save(&env.paths)?;
                msgs.push(tr!(
                    "{label} : installation achevée, enregistrée comme récupérée",
                    "{label}: installation completed, recorded as recovered"
                ));
            }
            _ => {
                let prev_files: Vec<PathBuf> = registry.get(&txn.app_id).map(|a| a.files.clone()).unwrap_or_default();
                let ours: Vec<PathBuf> = txn
                    .files_written
                    .iter()
                    .filter(|f| !prev_files.contains(f))
                    .cloned()
                    .collect();
                methods::remove_files(&ours)?;
                let _ = std::fs::remove_dir_all(&staged);
                if rec.method == "files" || present == Some(false) {
                    msgs.push(tr!(
                        "{label} : installation incomplète annulée, fichiers nettoyés",
                        "{label}: incomplete installation rolled back, files cleaned up"
                    ));
                } else {
                    rec.state = InstallState::Partial;
                    if registry.get(&rec.id).is_none() {
                        registry.apps.insert(rec.id.clone(), rec);
                        registry.save(&env.paths)?;
                    }
                    msgs.push(tr!(
                        "{label} : état indéterminé, enregistré comme partiel (« auxipak remove » pour nettoyer)",
                        "{label}: unknown state, recorded as partial (\"auxipak remove\" to clean up)"
                    ));
                }
            }
        }
        txn.finish()?;
    }
    if msgs.is_empty() {
        msgs.push(tr!("aucune opération interrompue", "no interrupted operation"));
    }
    Ok(msgs)
}

async fn detect_with(env: &Env, id: &str, version: &str, t: &Target, files: &[PathBuf]) -> Option<bool> {
    let work = env.paths.cache_dir.clone();
    let ctx = Ctx {
        paths: &env.paths,
        config: &env.config,
        profile: &env.profile,
        app_id: id,
        version,
        target: t,
        root: Path::new("."),
        work: &work,
        scripts_allowed: false,
        owned_files: files,
    };
    match methods::detect(&ctx).await {
        Ok(Some(v)) => Some(v),
        _ if !files.is_empty() => Some(files.iter().all(|f| f.exists())),
        _ => None,
    }
}

/// Réconciliation du registre avec l'état réel du système.
pub async fn reconcile(env: &Env, registry: &Registry) -> Vec<(String, Option<bool>)> {
    let mut out = Vec::new();
    for app in registry.apps.values() {
        let present = match stored_target(&env.paths, app) {
            Ok((_, t)) => detect_with(env, &app.id, &app.version, &t, &app.files).await,
            Err(_) => None,
        };
        out.push((app.id.clone(), present));
    }
    out
}

/// Sélecteur à partir d'options CLI.
pub fn selector(version: Option<&str>, lang: Option<&str>, repo: Option<&str>) -> Result<Selector> {
    Ok(Selector {
        version: version.map(VersionReq::parse).transpose().map_err(|e| anyhow!(e))?,
        language: lang.map(|s| s.to_string()),
        repo: repo.map(|s| s.to_string()),
    })
}

/// Interruption simulée (tests de reprise) : n'existe que dans les binaires
/// de débogage, jamais dans une version publiée.
fn crash_point(name: &str) {
    #[cfg(debug_assertions)]
    if std::env::var("AUXIPAK_TEST_CRASH_AT").as_deref() == Ok(name) {
        eprintln!(
            "{}",
            tr!(
                "[test] interruption simulée au point « {name} »",
                "[test] simulated crash at \"{name}\""
            )
        );
        std::process::abort();
    }
    #[cfg(not(debug_assertions))]
    let _ = name;
}
