//! Synchronisation des dépôts et cache local des index vérifiés.
//!
//! Chaque synchronisation charge les métadonnées TUF du dépôt avec `tough`
//! (vérification des signatures, des seuils, des versions — anti-retour en
//! arrière — et des dates d'expiration), puis télécharge et vérifie
//! `index.json`, `apps.json`, `revocations.json` et le sous-index du canal et
//! de l'architecture du système. Les fichiers vérifiés sont écrits
//! atomiquement dans le cache avec un fichier d'état.
//!
//! Règles de fraîcheur :
//! - un cache de moins de `cache_ttl_seconds` (3 600 s par défaut) dont les
//!   métadonnées TUF ne sont pas expirées est « frais » ;
//! - la recherche peut utiliser un cache périmé hors ligne, en l'indiquant ;
//! - l'installation et la mise à niveau exigent un cache frais : un cache
//!   périmé ne suffit jamais à autoriser une installation (révocations).

use crate::config::{Config, RepoConfig, TrustMaterial};
use crate::paths::{atomic_write, Paths};
use anyhow::{anyhow, bail, Context, Result};
use auxipak_core::index::{
    AppsIndex, ChannelIndex, RepoIndex, RevocationList, APPS_TARGET, INDEX_META_VERSION, REPO_INDEX_TARGET,
    REVOCATIONS_TARGET,
};
use auxipak_core::platform::{Arch, Channel, SystemProfile};
use chrono::{DateTime, Duration, Utc};
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tough::{ExpirationEnforcement, RepositoryLoader, TargetName};

/// Taille maximale d'un fichier d'index.
const MAX_INDEX_SIZE: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncState {
    pub repo: String,
    pub url: String,
    pub synced_at: DateTime<Utc>,
    /// Plus proche expiration des métadonnées TUF (timestamp/snapshot/targets).
    pub metadata_expires: DateTime<Utc>,
    pub tuf_version: u64,
    pub generation: u64,
    pub channel: Option<Channel>,
    pub arch: Arch,
    pub profile_fingerprint: String,
}

/// Données d'un dépôt chargées depuis le cache vérifié.
#[derive(Debug, Clone)]
pub struct RepoData {
    pub config: RepoConfig,
    pub state: SyncState,
    pub index: RepoIndex,
    pub apps: AppsIndex,
    pub revocations: RevocationList,
    pub channel: Option<ChannelIndex>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Freshness {
    Fresh,
    /// Périmé : âge en secondes.
    Stale(i64),
    /// Profil système différent de celui de la synchronisation.
    ProfileChanged,
    /// Métadonnées TUF expirées.
    Expired,
}

impl RepoData {
    pub fn freshness(&self, ttl: u64, profile: &SystemProfile) -> Freshness {
        freshness(&self.state, ttl, profile, Utc::now())
    }
}

pub fn freshness(state: &SyncState, ttl: u64, profile: &SystemProfile, now: DateTime<Utc>) -> Freshness {
    if state.profile_fingerprint != profile.fingerprint() {
        return Freshness::ProfileChanged;
    }
    if now >= state.metadata_expires {
        return Freshness::Expired;
    }
    let age = (now - state.synced_at).num_seconds();
    if age < 0 || age >= ttl as i64 {
        Freshness::Stale(age.max(0))
    } else {
        Freshness::Fresh
    }
}

fn cache_dir(paths: &Paths, repo: &str) -> PathBuf {
    paths.repo_cache_dir(repo)
}

fn verified_dir(paths: &Paths, repo: &str) -> PathBuf {
    cache_dir(paths, repo).join("verified")
}

fn state_file(paths: &Paths, repo: &str) -> PathBuf {
    cache_dir(paths, repo).join("state.json")
}

/// URL des métadonnées et des cibles d'un dépôt.
pub fn repo_urls(cfg: &RepoConfig) -> Result<(url::Url, url::Url)> {
    let base = auxipak_core::netpolicy::validate_repo_url(&cfg.url, cfg.allow_insecure_localhost).map_err(|e| anyhow!(e))?;
    Ok((base.join("metadata/")?, base.join("targets/")?))
}

fn to_chrono(t: jiff::Timestamp) -> DateTime<Utc> {
    DateTime::from_timestamp(t.as_second(), 0).unwrap_or_else(Utc::now)
}

async fn read_target(repo: &tough::Repository, name: &str) -> Result<Option<Vec<u8>>> {
    let tn = TargetName::new(name).map_err(|e| anyhow!("{e}"))?;
    let Some(mut stream) = repo.read_target(&tn).await.map_err(|e| anyhow!("lecture de {name} : {e}"))? else {
        return Ok(None);
    };
    let mut out = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| anyhow!("{name} : vérification TUF échouée : {e}"))?;
        if out.len() + chunk.len() > MAX_INDEX_SIZE {
            bail!("{name} : index trop volumineux");
        }
        out.extend_from_slice(&chunk);
    }
    Ok(Some(out))
}

/// Synchronise un dépôt (vérification TUF complète).
pub async fn sync(cfg: &RepoConfig, paths: &Paths, profile: &SystemProfile) -> Result<RepoData> {
    let trust: TrustMaterial = cfg.trust(paths)?;
    let (meta, targets) = repo_urls(cfg)?;
    let dir = cache_dir(paths, &cfg.name);
    let datastore = dir.join("tuf");
    std::fs::create_dir_all(&datastore)?;
    // Deux tentatives : une publication peut remplacer le dépôt entre la
    // lecture de timestamp.json et celle de snapshot.json.
    let mut last_err = None;
    let mut loaded = None;
    for _ in 0..2 {
        match RepositoryLoader::new(&trust.root_json, meta.clone(), targets.clone())
            .datastore(datastore.clone())
            .expiration_enforcement(ExpirationEnforcement::Safe)
            .load()
            .await
        {
            Ok(r) => {
                loaded = Some(r);
                break;
            }
            Err(e) => last_err = Some(e),
        }
    }
    let repo = loaded.ok_or_else(|| {
        anyhow!(
            "dépôt « {} » : métadonnées TUF refusées ou inaccessibles : {}",
            cfg.name,
            last_err.map(|e| e.to_string()).unwrap_or_default()
        )
    })?;

    let index_bytes = read_target(&repo, REPO_INDEX_TARGET).await?.context("index.json absent du dépôt")?;
    let index: RepoIndex = serde_json::from_slice(&index_bytes).context("index.json invalide")?;
    if index.meta_version != INDEX_META_VERSION {
        bail!("version de métadonnées d'index non prise en charge : {}", index.meta_version);
    }
    let apps_bytes = read_target(&repo, &index.apps).await?.context("apps.json absent")?;
    let apps: AppsIndex = serde_json::from_slice(&apps_bytes).context("apps.json invalide")?;
    let rev_bytes = read_target(&repo, &index.revocations).await?.context("revocations.json absent")?;
    let revocations: RevocationList = serde_json::from_slice(&rev_bytes).context("revocations.json invalide")?;

    let channel = profile.channel();
    let mut channel_bytes = None;
    let mut channel_index = None;
    if let Some(ch) = channel {
        if let Some(cref) = index.channels.iter().find(|c| c.channel == ch && c.arch == profile.arch) {
            let b = read_target(&repo, &cref.target).await?.context("sous-index absent")?;
            let ci: ChannelIndex = serde_json::from_slice(&b).context("sous-index invalide")?;
            if ci.channel != ch || ci.arch != profile.arch {
                bail!("sous-index incohérent (canal ou architecture)");
            }
            channel_bytes = Some(b);
            channel_index = Some(ci);
        }
    }

    let expires = [
        repo.timestamp().signed.expires,
        repo.snapshot().signed.expires,
        repo.targets().signed.expires,
    ]
    .into_iter()
    .map(to_chrono)
    .min()
    .unwrap_or_else(Utc::now);
    let state = SyncState {
        repo: cfg.name.clone(),
        url: cfg.url.clone(),
        synced_at: Utc::now(),
        metadata_expires: expires,
        tuf_version: repo.timestamp().signed.version.get(),
        generation: index.generation,
        channel,
        arch: profile.arch,
        profile_fingerprint: profile.fingerprint(),
    };

    // Écriture du cache : fichiers vérifiés puis état (dernier, atomique).
    let vdir = verified_dir(paths, &cfg.name);
    std::fs::create_dir_all(&vdir)?;
    atomic_write(&vdir.join(REPO_INDEX_TARGET), &index_bytes)?;
    atomic_write(&vdir.join(APPS_TARGET), &apps_bytes)?;
    atomic_write(&vdir.join(REVOCATIONS_TARGET), &rev_bytes)?;
    let chan_file = vdir.join("channel.json");
    match &channel_bytes {
        Some(b) => atomic_write(&chan_file, b)?,
        None => {
            let _ = std::fs::remove_file(&chan_file);
        }
    }
    atomic_write(&state_file(paths, &cfg.name), &serde_json::to_vec_pretty(&state)?)?;
    let _ = index_bytes;
    Ok(RepoData {
        config: cfg.clone(),
        state,
        index,
        apps,
        revocations,
        channel: channel_index,
    })
}

/// Charge un dépôt depuis le cache vérifié (sans réseau).
pub fn load_cached(cfg: &RepoConfig, paths: &Paths) -> Result<Option<RepoData>> {
    let sf = state_file(paths, &cfg.name);
    if !sf.exists() {
        return Ok(None);
    }
    let state: SyncState = serde_json::from_slice(&std::fs::read(&sf)?).context("état de cache invalide")?;
    if state.url != cfg.url {
        // L'URL du dépôt a changé : le cache ne correspond plus.
        return Ok(None);
    }
    let vdir = verified_dir(paths, &cfg.name);
    let read = |n: &str| -> Result<Vec<u8>> { std::fs::read(vdir.join(n)).with_context(|| format!("cache incomplet : {n}")) };
    let index: RepoIndex = serde_json::from_slice(&read(REPO_INDEX_TARGET)?)?;
    let apps: AppsIndex = serde_json::from_slice(&read(APPS_TARGET)?)?;
    let revocations: RevocationList = serde_json::from_slice(&read(REVOCATIONS_TARGET)?)?;
    let channel = match std::fs::read(vdir.join("channel.json")) {
        Ok(b) => Some(serde_json::from_slice(&b)?),
        Err(_) => None,
    };
    Ok(Some(RepoData { config: cfg.clone(), state, index, apps, revocations, channel }))
}

/// Supprime le cache d'un dépôt (y compris l'état TUF).
pub fn drop_cache(paths: &Paths, repo: &str) -> Result<()> {
    let d = cache_dir(paths, repo);
    if d.exists() {
        std::fs::remove_dir_all(d)?;
    }
    Ok(())
}

/// Politique de chargement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Need {
    /// Recherche/consultation : un cache périmé est acceptable hors ligne.
    Browse,
    /// Installation : cache frais obligatoire.
    Install,
    /// Synchronisation forcée (`auxipak update`).
    Force,
}

/// Résultat du chargement d'un dépôt.
pub struct Loaded {
    pub data: Option<RepoData>,
    pub warning: Option<String>,
}

/// Charge un dépôt selon la politique demandée, en synchronisant si nécessaire.
pub async fn ensure(cfg: &RepoConfig, config: &Config, paths: &Paths, profile: &SystemProfile, need: Need) -> Loaded {
    let cached = load_cached(cfg, paths).ok().flatten();
    let fresh = cached
        .as_ref()
        .map(|c| c.freshness(config.cache_ttl_seconds, profile) == Freshness::Fresh)
        .unwrap_or(false);
    if fresh && need != Need::Force {
        return Loaded { data: cached, warning: None };
    }
    match sync(cfg, paths, profile).await {
        Ok(d) => Loaded { data: Some(d), warning: None },
        Err(e) => {
            tracing::warn!(repo = %cfg.name, error = %e, "synchronisation échouée");
            match (need, cached) {
                (Need::Browse, Some(c)) => {
                    let age = (Utc::now() - c.state.synced_at).num_minutes();
                    let usable = c.state.profile_fingerprint == profile.fingerprint();
                    let warning = format!(
                        "dépôt « {} » : synchronisation impossible ({e:#}) ; utilisation du dernier index validé, vieux de {age} min",
                        cfg.name
                    );
                    Loaded { data: usable.then_some(c), warning: Some(warning) }
                }
                _ => Loaded {
                    data: None,
                    warning: Some(format!("dépôt « {} » : {e:#}", cfg.name)),
                },
            }
        }
    }
}

/// Âge lisible d'une synchronisation.
pub fn age_label(state: &SyncState) -> String {
    let d: Duration = Utc::now() - state.synced_at;
    if d.num_minutes() < 1 {
        "moins d'une minute".into()
    } else if d.num_hours() < 1 {
        format!("{} min", d.num_minutes())
    } else if d.num_days() < 1 {
        format!("{} h", d.num_hours())
    } else {
        format!("{} jours", d.num_days())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use auxipak_core::platform::{Distribution, Os};

    fn profile() -> SystemProfile {
        SystemProfile {
            os: Os::Linux,
            distribution: Distribution::Debian,
            version: "13".into(),
            arch: Arch::X86_64,
            raw_id: "debian".into(),
            pretty_name: "Debian".into(),
            immutable: false,
        }
    }

    fn state(age_s: i64, expires_in_s: i64) -> SyncState {
        let now = Utc::now();
        SyncState {
            repo: "r".into(),
            url: "https://x.org/".into(),
            synced_at: now - Duration::seconds(age_s),
            metadata_expires: now + Duration::seconds(expires_in_s),
            tuf_version: 1,
            generation: 1,
            channel: Some(Channel::LinuxDeb),
            arch: Arch::X86_64,
            profile_fingerprint: profile().fingerprint(),
        }
    }

    #[test]
    fn cache_younger_than_ttl_is_fresh() {
        assert_eq!(freshness(&state(59 * 60, 86400), 3600, &profile(), Utc::now()), Freshness::Fresh);
    }

    #[test]
    fn cache_older_than_ttl_is_stale() {
        assert!(matches!(freshness(&state(3601, 86400), 3600, &profile(), Utc::now()), Freshness::Stale(_)));
        assert!(matches!(freshness(&state(3600, 86400), 3600, &profile(), Utc::now()), Freshness::Stale(_)));
    }

    #[test]
    fn expired_metadata_is_never_fresh() {
        assert_eq!(freshness(&state(10, -1), 3600, &profile(), Utc::now()), Freshness::Expired);
    }

    #[test]
    fn profile_change_invalidates_cache() {
        let mut p = profile();
        p.arch = Arch::Arm64;
        assert_eq!(freshness(&state(10, 86400), 3600, &p, Utc::now()), Freshness::ProfileChanged);
    }

    #[test]
    fn clock_going_backwards_is_stale() {
        assert!(matches!(freshness(&state(-600, 86400), 3600, &profile(), Utc::now()), Freshness::Stale(_)));
    }
}
