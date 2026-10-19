//! Publication : approbation des demandes, signature, génération des index
//! et des métadonnées TUF, bascule atomique du dépôt servi.

use crate::audit;
use crate::auth::{Actor, Scope};
use crate::error::{bad, forbidden, ApiError, ApiResult};
use crate::state::AppState;
use anyhow::{anyhow, Context, Result};
use auxipak_core::index::{
    package_target, AppMeta, AppsIndex, ChannelIndex, ChannelRef, Release, RepoIndex, RepositoryInfo, Revocation,
    RevocationList, SignatureRef, Status, APPS_TARGET, INDEX_META_VERSION, REPO_INDEX_TARGET, REVOCATIONS_TARGET,
};
use auxipak_core::manifest::{Manifest, Target};
use auxipak_core::platform::{Arch, Channel, Distribution, Os};
use auxipak_core::signature::{PackageRef, PackageSignature};
use chrono::{DateTime, Duration, Utc};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use uuid::Uuid;

/// Entrée d'index d'une version pour un couple canal/architecture.
#[derive(Debug, Clone)]
pub struct ChannelEntry {
    pub channel: Channel,
    pub arch: Arch,
    pub distributions: Vec<Distribution>,
    pub architectures: Vec<Arch>,
    pub target: Target,
}

/// Couples canal/architecture couverts par un manifeste.
pub fn channel_entries(m: &Manifest) -> Vec<ChannelEntry> {
    let mut out: BTreeMap<(Channel, Arch), ChannelEntry> = BTreeMap::new();
    for t in &m.targets {
        let chans: Vec<(Channel, Vec<Distribution>)> = match t.platform {
            Os::Windows => vec![(Channel::Windows, vec![Distribution::Windows])],
            Os::Macos => vec![(Channel::Macos, vec![Distribution::Macos])],
            Os::Linux => {
                let mut m: BTreeMap<Channel, Vec<Distribution>> = BTreeMap::new();
                for d in &t.distributions {
                    if let Some(c) = Channel::for_distribution(*d) {
                        m.entry(c).or_default().push(*d);
                    }
                }
                m.into_iter().collect()
            }
        };
        let archs: Vec<Arch> = if t.architectures.contains(&Arch::Any) {
            vec![Arch::X86_64, Arch::Arm64]
        } else {
            t.architectures.clone()
        };
        for (c, dists) in chans {
            for a in &archs {
                out.entry((c, *a))
                    .and_modify(|e| {
                        for d in &dists {
                            if !e.distributions.contains(d) {
                                e.distributions.push(*d);
                            }
                        }
                    })
                    .or_insert(ChannelEntry {
                        channel: c,
                        arch: *a,
                        distributions: dists.clone(),
                        architectures: t.architectures.clone(),
                        target: t.clone(),
                    });
            }
        }
    }
    out.into_values().collect()
}

#[derive(sqlx::FromRow, Debug, Clone)]
pub struct SubmissionRow {
    pub id: Uuid,
    pub repository: String,
    pub file_name: String,
    pub size: i64,
    pub sha256: String,
    pub app_id: Option<String>,
    pub version: Option<String>,
    pub signature: Option<serde_json::Value>,
    pub status: String,
    pub submitted_by: Option<Uuid>,
    pub note: String,
}

pub fn submission_file(state: &AppState, id: Uuid) -> PathBuf {
    state.config.submissions_dir().join(format!("{id}.apak"))
}

/// Approuve une demande et publie le paquet.
pub async fn approve(state: &AppState, actor: &Actor, id: Uuid, note: &str) -> ApiResult<Vec<Uuid>> {
    actor.require(Scope::Review)?;
    let sub: SubmissionRow = sqlx::query_as(
        "SELECT id, repository, file_name, size, sha256, app_id, version, signature, status, submitted_by, note FROM submissions WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await?
    .ok_or(ApiError::NotFound)?;
    if sub.status != "pending" {
        return Err(ApiError::Conflict(format!("la demande est dans l'état « {} »", sub.status)));
    }
    if state.config.require_distinct_approver && sub.submitted_by == Some(actor.user_id) {
        return Err(forbidden(
            "politique d'approbation : la demande doit être approuvée par une autre personne que son auteur",
        ));
    }
    let path = submission_file(state, id);
    let (insp, report) = crate::validation::analyze(&path);
    let insp = insp.ok_or_else(|| bad(format!("paquet devenu invalide : {:?}", report.checks)))?;
    if insp.archive_sha256 != sub.sha256 {
        return Err(ApiError::Internal(anyhow!("le fichier stocké ne correspond plus à la soumission")));
    }
    let m = insp.manifest.clone();
    let exists: Option<(Uuid,)> = sqlx::query_as(
        "SELECT id FROM releases WHERE repository = $1 AND app_id = $2 AND version = $3 AND state <> 'unpublished'",
    )
    .bind(&sub.repository)
    .bind(&m.id)
    .bind(&m.version)
    .fetch_optional(&state.db)
    .await?;
    if exists.is_some() {
        return Err(ApiError::Conflict(format!("{} {} est déjà publié dans {}", m.id, m.version, sub.repository)));
    }

    // Signature : celle fournie si elle est valide, sinon signature par le serveur.
    let signature: PackageSignature = match &sub.signature {
        Some(v) => {
            let s: PackageSignature = serde_json::from_value(v.clone()).map_err(|e| bad(format!("signature : {e}")))?;
            crate::validation::check_signature(&s, &insp, &state.keys.package_keys).map_err(|e| bad(format!("signature refusée : {e}")))?;
            s
        }
        None => {
            let signer = state.keys.signer.as_ref().ok_or_else(|| {
                bad("aucune signature fournie et aucune clé de signature disponible sur le serveur")
            })?;
            signer.sign(PackageRef {
                id: m.id.clone(),
                version: m.version.clone(),
                file_name: sub.file_name.clone(),
                sha256: insp.archive_sha256.clone(),
                size: insp.archive_size,
            })
        }
    };
    // Vérification finale (défense en profondeur).
    crate::validation::check_signature(&signature, &insp, &state.keys.package_keys)
        .map_err(|e| ApiError::Internal(anyhow!("signature produite invalide : {e}")))?;

    // Stockage immuable du paquet publié.
    let dest_dir = state.config.packages_dir().join(&sub.repository).join(&m.id).join(&m.version);
    std::fs::create_dir_all(&dest_dir)?;
    let dest = dest_dir.join(&sub.file_name);
    if dest.exists() {
        return Err(ApiError::Conflict("un fichier publié porte déjà ce nom".into()));
    }
    let tmp = dest_dir.join(format!(".{}.tmp", sub.file_name));
    std::fs::copy(&path, &tmp)?;
    std::fs::File::open(&tmp)?.sync_all()?;
    std::fs::rename(&tmp, &dest)?;
    std::fs::write(dest_dir.join(format!("{}.sig", sub.file_name)), signature.to_json())?;

    let mut tx = state.db.begin().await?;
    sqlx::query(
        "INSERT INTO apps (id, name, publisher, summary, description, license, homepage, categories)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, publisher = EXCLUDED.publisher, summary = EXCLUDED.summary,
           description = EXCLUDED.description, license = EXCLUDED.license, homepage = EXCLUDED.homepage,
           categories = EXCLUDED.categories, updated_at = now()",
    )
    .bind(&m.id)
    .bind(&m.name)
    .bind(&m.publisher)
    .bind(&m.summary)
    .bind(&m.description)
    .bind(&m.license)
    .bind(&m.homepage)
    .bind(&m.categories)
    .execute(&mut *tx)
    .await?;
    // Une nouvelle application est toujours « non évaluée » : le manifeste ne
    // peut pas fixer la classification.
    sqlx::query("INSERT INTO evaluations (app_id, status, note) VALUES ($1, 'unreviewed', NULL) ON CONFLICT (app_id) DO NOTHING")
        .bind(&m.id)
        .execute(&mut *tx)
        .await?;
    let rel_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO releases (id, repository, app_id, version, file_name, languages, size, sha256, signature, signature_key_id,
            manifest, manifest_yaml, uses_scripts, submission_id, state, published_by)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, 'published', $15)",
    )
    .bind(rel_id)
    .bind(&sub.repository)
    .bind(&m.id)
    .bind(&m.version)
    .bind(&sub.file_name)
    .bind(&m.languages)
    .bind(insp.archive_size as i64)
    .bind(&insp.archive_sha256)
    .bind(serde_json::to_value(&signature).map_err(anyhow::Error::from)?)
    .bind(&signature.payload.key_id)
    .bind(serde_json::to_value(&m).map_err(anyhow::Error::from)?)
    .bind(String::from_utf8_lossy(&insp.manifest_bytes).into_owned())
    .bind(report.uses_scripts)
    .bind(id)
    .bind(actor.user_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query("UPDATE submissions SET status = 'published', reviewed_by = $2, reviewed_at = now(), review_note = $3 WHERE id = $1")
        .bind(id)
        .bind(actor.user_id)
        .bind(note)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    audit::log(
        &state.db,
        Some(actor),
        "submission.approve",
        &format!("{} {}", m.id, m.version),
        serde_json::json!({"submission": id, "release": rel_id, "repository": sub.repository, "signature_key": signature.payload.key_id}),
    )
    .await;
    regenerate(state, &sub.repository, Some(actor)).await?;
    Ok(vec![rel_id])
}

#[derive(sqlx::FromRow)]
struct ReleaseRow {
    id: Uuid,
    app_id: String,
    version: String,
    file_name: String,
    size: i64,
    sha256: String,
    signature_key_id: String,
    manifest: serde_json::Value,
    uses_scripts: bool,
    state: String,
    state_reason: Option<String>,
    state_changed_at: Option<DateTime<Utc>>,
    published_at: DateTime<Utc>,
}

#[derive(sqlx::FromRow)]
struct AppRow {
    id: String,
    name: String,
    publisher: String,
    summary: String,
    description: Option<String>,
    license: String,
    homepage: Option<String>,
    categories: Vec<String>,
    status: Option<String>,
    note: Option<String>,
    evaluated_at: Option<DateTime<Utc>>,
}

#[derive(sqlx::FromRow)]
struct RepoRow {
    name: String,
    title: String,
    description: String,
    official: bool,
    generation: i64,
}

fn write_json<T: serde::Serialize>(dir: &Path, name: &str, v: &T) -> Result<PathBuf> {
    let p = dir.join(name);
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&p, serde_json::to_vec_pretty(v)?)?;
    Ok(p)
}

/// Régénère les index et les métadonnées TUF d'un dépôt, puis bascule
/// atomiquement le lien `current`.
pub async fn regenerate(state: &AppState, repo: &str, actor: Option<&Actor>) -> Result<u64> {
    let _guard = state.publish_lock.lock().await;
    let mut conn = state.db.acquire().await?;
    // Verrou consultatif : une seule régénération à la fois, toutes instances confondues.
    sqlx::query("SELECT pg_advisory_lock(717171)").execute(&mut *conn).await?;
    let result = regenerate_locked(state, repo).await;
    sqlx::query("SELECT pg_advisory_unlock(717171)").execute(&mut *conn).await?;
    let generation = result?;
    audit::log(&state.db, actor, "repository.regenerate", repo, serde_json::json!({"generation": generation})).await;
    Ok(generation)
}

async fn regenerate_locked(state: &AppState, repo: &str) -> Result<u64> {
    let r: RepoRow = sqlx::query_as("SELECT name, title, description, official, generation FROM repositories WHERE name = $1")
        .bind(repo)
        .fetch_optional(&state.db)
        .await?
        .with_context(|| format!("dépôt inconnu : {repo}"))?;
    let generation = (r.generation + 1) as u64;
    let releases: Vec<ReleaseRow> = sqlx::query_as(
        "SELECT id, app_id, version, file_name, size, sha256, signature_key_id, manifest, uses_scripts, state, state_reason,
                state_changed_at, published_at
         FROM releases WHERE repository = $1 ORDER BY app_id, published_at",
    )
    .bind(repo)
    .fetch_all(&state.db)
    .await?;
    let apps: Vec<AppRow> = sqlx::query_as(
        "SELECT a.id, a.name, a.publisher, a.summary, a.description, a.license, a.homepage, a.categories,
                e.status, e.note, e.evaluated_at
         FROM apps a LEFT JOIN evaluations e ON e.app_id = a.id
         WHERE a.id IN (SELECT app_id FROM releases WHERE repository = $1 AND state = 'published')
         ORDER BY a.id",
    )
    .bind(repo)
    .fetch_all(&state.db)
    .await?;

    let now = Utc::now();
    std::fs::create_dir_all(state.config.tmp_dir())?;
    let work = tempfile::Builder::new().prefix("regen-").tempdir_in(state.config.tmp_dir())?;
    let src = work.path().join("src");
    std::fs::create_dir_all(&src)?;
    let mut targets: Vec<(String, PathBuf)> = Vec::new();

    let mut channels: BTreeMap<(Channel, Arch), Vec<Release>> = BTreeMap::new();
    let mut revoked = Vec::new();
    for rel in &releases {
        if rel.state == "revoked" {
            revoked.push(Revocation {
                id: rel.app_id.clone(),
                version: rel.version.clone(),
                sha256: rel.sha256.clone(),
                reason: rel.state_reason.clone().unwrap_or_default(),
                revoked_at: rel.state_changed_at.unwrap_or(now),
            });
            continue;
        }
        if rel.state != "published" {
            continue;
        }
        let m: Manifest = serde_json::from_value(rel.manifest.clone()).context("manifeste stocké invalide")?;
        let pkg_target = package_target(&rel.app_id, &rel.version, &rel.file_name);
        let sig_target = format!("{pkg_target}.sig");
        let stored = state.config.packages_dir().join(repo).join(&rel.app_id).join(&rel.version);
        let pkg_path = stored.join(&rel.file_name);
        let sig_path = stored.join(format!("{}.sig", rel.file_name));
        if !pkg_path.exists() || !sig_path.exists() {
            tracing::error!(release = %rel.id, "fichier publié manquant : version ignorée");
            continue;
        }
        targets.push((pkg_target.clone(), pkg_path));
        targets.push((sig_target.clone(), sig_path));
        for e in channel_entries(&m) {
            channels.entry((e.channel, e.arch)).or_default().push(Release {
                id: rel.app_id.clone(),
                version: rel.version.clone(),
                languages: m.languages.clone(),
                platform: e.target.platform,
                distributions: e.distributions.clone(),
                architectures: e.architectures.clone(),
                file_name: rel.file_name.clone(),
                target: pkg_target.clone(),
                size: rel.size as u64,
                sha256: rel.sha256.clone(),
                signature: SignatureRef { target: sig_target.clone(), key_id: rel.signature_key_id.clone() },
                published_at: rel.published_at,
                dependencies: m.dependencies.clone(),
                mode: e.target.mode,
                privileges: e.target.effective_privileges(),
                uses_scripts: rel.uses_scripts,
                revoked: false,
            });
        }
    }

    let mut chan_refs = Vec::new();
    for ((c, a), rels) in &channels {
        let name = c.index_target(*a);
        let p = write_json(
            &src,
            &name,
            &ChannelIndex { meta_version: INDEX_META_VERSION, channel: *c, arch: *a, generated_at: now, releases: rels.clone() },
        )?;
        targets.push((name.clone(), p));
        chan_refs.push(ChannelRef { channel: *c, arch: *a, target: name, releases: rels.len() });
    }
    let apps_idx = AppsIndex {
        meta_version: INDEX_META_VERSION,
        generated_at: now,
        apps: apps
            .iter()
            .map(|a| AppMeta {
                id: a.id.clone(),
                name: a.name.clone(),
                publisher: a.publisher.clone(),
                summary: a.summary.clone(),
                description: a.description.clone(),
                license: a.license.clone(),
                homepage: a.homepage.clone(),
                categories: a.categories.clone(),
                // Statut officiel : uniquement dans un dépôt officiel.
                status: if r.official {
                    a.status.as_deref().and_then(|s| s.parse().ok()).unwrap_or(Status::Unreviewed)
                } else {
                    Status::Unreviewed
                },
                status_note: if r.official { a.note.clone() } else { None },
                evaluated_at: if r.official { a.evaluated_at } else { None },
            })
            .collect(),
    };
    targets.push((APPS_TARGET.into(), write_json(&src, APPS_TARGET, &apps_idx)?));
    targets.push((
        REVOCATIONS_TARGET.into(),
        write_json(&src, REVOCATIONS_TARGET, &RevocationList { meta_version: INDEX_META_VERSION, generated_at: now, revoked })?,
    ));
    let index = RepoIndex {
        meta_version: INDEX_META_VERSION,
        repository: RepositoryInfo { name: r.name.clone(), title: r.title.clone(), description: r.description.clone(), official: r.official },
        generated_at: now,
        generation,
        apps: APPS_TARGET.into(),
        revocations: REVOCATIONS_TARGET.into(),
        channels: chan_refs,
    };
    targets.push((REPO_INDEX_TARGET.into(), write_json(&src, REPO_INDEX_TARGET, &index)?));

    let repo_dir = state.config.repos_dir().join(repo);
    std::fs::create_dir_all(&repo_dir)?;
    let gen_name = format!("gen-{generation}");
    let out = repo_dir.join(&gen_name);
    if out.exists() {
        std::fs::remove_dir_all(&out)?;
    }
    auxipak_core::tuf::publish(auxipak_core::tuf::PublishSpec {
        root_path: state.keys.root_path.clone(),
        keys: state.keys.tuf_sources(),
        targets,
        version: generation,
        targets_expires: now + Duration::days(auxipak_core::tuf::expiry::TARGETS_DAYS),
        snapshot_expires: now + Duration::days(auxipak_core::tuf::expiry::SNAPSHOT_DAYS),
        timestamp_expires: now + Duration::hours(state.config.timestamp_hours),
        out_dir: out.clone(),
    })
    .await?;
    std::fs::create_dir_all(out.join("keys"))?;
    std::fs::write(out.join("keys/package-keys.json"), &state.keys.package_keys_json)?;

    // Bascule atomique du lien symbolique `current`.
    let link = repo_dir.join("current");
    let tmp_link = repo_dir.join(format!(".current-{generation}"));
    let _ = std::fs::remove_file(&tmp_link);
    #[cfg(unix)]
    std::os::unix::fs::symlink(&gen_name, &tmp_link)?;
    #[cfg(not(unix))]
    anyhow::bail!("la publication de dépôts nécessite un système Unix");
    std::fs::rename(&tmp_link, &link)?;

    sqlx::query("UPDATE repositories SET generation = $2, published_at = now() WHERE name = $1")
        .bind(repo)
        .bind(generation as i64)
        .execute(&state.db)
        .await?;

    // Conservation des deux générations précédentes (clients en cours de téléchargement).
    let keep: BTreeSet<String> = (generation.saturating_sub(2)..=generation).map(|g| format!("gen-{g}")).collect();
    for e in std::fs::read_dir(&repo_dir)?.flatten() {
        let n = e.file_name().to_string_lossy().into_owned();
        if n.starts_with("gen-") && !keep.contains(&n) {
            let _ = std::fs::remove_dir_all(e.path());
        }
    }
    tracing::info!(repo, generation, "dépôt régénéré");
    Ok(generation)
}

/// Rafraîchit périodiquement les métadonnées (expiration de timestamp.json).
pub async fn refresh_loop(state: AppState) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(600));
    loop {
        interval.tick().await;
        let repos: Vec<(String, Option<DateTime<Utc>>)> =
            match sqlx::query_as("SELECT name, published_at FROM repositories WHERE enabled").fetch_all(&state.db).await {
                Ok(r) => r,
                Err(e) => {
                    tracing::error!(error = %e, "lecture des dépôts");
                    continue;
                }
            };
        let half = Duration::hours(state.config.timestamp_hours) / 2;
        for (name, published) in repos {
            let due = published.map(|p| Utc::now() - p > half).unwrap_or(true);
            if due {
                if let Err(e) = regenerate(&state, &name, None).await {
                    tracing::error!(repo = %name, error = %format!("{e:#}"), "rafraîchissement des métadonnées échoué");
                }
            }
        }
    }
}

/// Change l'état d'une version (dépublication, republication, révocation).
pub async fn set_release_state(state: &AppState, actor: &Actor, id: Uuid, new_state: &str, reason: &str) -> ApiResult<()> {
    actor.require(Scope::Review)?;
    if !matches!(new_state, "published" | "unpublished" | "revoked") {
        return Err(bad("état invalide"));
    }
    if new_state == "revoked" && reason.trim().is_empty() {
        return Err(bad("un motif de révocation est obligatoire"));
    }
    let row: Option<(String, String, String, String)> =
        sqlx::query_as("SELECT repository, app_id, version, state FROM releases WHERE id = $1")
            .bind(id)
            .fetch_optional(&state.db)
            .await?;
    let (repo, app, version, current) = row.ok_or(ApiError::NotFound)?;
    if current == "revoked" {
        return Err(ApiError::Conflict("une version révoquée ne peut plus changer d'état".into()));
    }
    sqlx::query("UPDATE releases SET state = $2, state_reason = $3, state_changed_at = now() WHERE id = $1")
        .bind(id)
        .bind(new_state)
        .bind(reason)
        .execute(&state.db)
        .await?;
    audit::log(
        &state.db,
        Some(actor),
        &format!("release.{new_state}"),
        &format!("{app} {version}"),
        serde_json::json!({"release": id, "reason": reason}),
    )
    .await;
    regenerate(state, &repo, Some(actor)).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_entries_cover_any_arch_and_split_distributions() {
        let yaml = r#"
format: 1
id: demo
name: Demo
version: "1.0"
publisher: X
summary: s
license: MIT
languages: [fr]
targets:
  - name: deb
    platform: linux
    distributions: [debian, ubuntu, auxinuxos]
    architectures: [any]
    mode: native
    install: { method: package_manager, manager: apt, packages: [demo] }
"#;
        // apt n'est pas autorisé sur auxinuxos : manifeste refusé.
        assert!(Manifest::parse(yaml.as_bytes()).is_err());
        let yaml = yaml.replace(", auxinuxos]", "]");
        let (m, _) = Manifest::parse(yaml.as_bytes()).unwrap();
        let e = channel_entries(&m);
        assert_eq!(e.len(), 2);
        assert!(e.iter().all(|x| x.channel == Channel::LinuxDeb));
        assert_eq!(e[0].distributions, vec![Distribution::Debian, Distribution::Ubuntu]);
    }
}
