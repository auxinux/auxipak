//! Génération des fichiers d'index d'un dépôt (sans signature TUF).
//!
//! Utilisé par le serveur lors de chaque publication et par les jeux d'essai
//! des tests. La signature des métadonnées est ensuite réalisée par
//! [`crate::tuf::publish`].

use crate::index::{
    package_target, AppMeta, AppsIndex, ChannelIndex, ChannelRef, Release, RepoIndex, RepositoryInfo, Revocation, RevocationList,
    SignatureRef, APPS_TARGET, INDEX_META_VERSION, REPO_INDEX_TARGET, REVOCATIONS_TARGET,
};
use crate::manifest::{Manifest, Target};
use crate::platform::{Arch, Channel, Distribution, Os};
use anyhow::Result;
use chrono::{DateTime, Utc};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Entrée d'index d'une version pour un couple canal/architecture.
#[derive(Debug, Clone)]
pub struct ChannelEntry {
    pub channel: Channel,
    pub arch: Arch,
    pub distributions: Vec<Distribution>,
    pub architectures: Vec<Arch>,
    pub target: Target,
}

/// Couples canal/architecture couverts par un manifeste. Une variante
/// `any` figure dans chaque architecture ; Debian et Ubuntu partagent le
/// canal `linux/deb`.
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

/// Paquet publié à inclure dans les index.
#[derive(Debug, Clone)]
pub struct PublishedPackage {
    pub manifest: Manifest,
    pub file_name: String,
    pub package_path: PathBuf,
    pub signature_path: PathBuf,
    pub size: u64,
    pub sha256: String,
    pub signature_key_id: String,
    pub published_at: DateTime<Utc>,
    pub uses_scripts: bool,
}

/// Contenu d'un dépôt à générer.
pub struct RepoContent {
    pub info: RepositoryInfo,
    pub generation: u64,
    pub packages: Vec<PublishedPackage>,
    pub apps: Vec<AppMeta>,
    pub revoked: Vec<Revocation>,
}

/// Écrit les index dans `src` et retourne la liste (nom de cible, fichier)
/// à signer, paquets et signatures compris.
pub fn write_indexes(content: &RepoContent, src: &Path, now: DateTime<Utc>) -> Result<Vec<(String, PathBuf)>> {
    let mut targets: Vec<(String, PathBuf)> = Vec::new();
    let mut channels: BTreeMap<(Channel, Arch), Vec<Release>> = BTreeMap::new();
    for p in &content.packages {
        let m = &p.manifest;
        let pkg_target = package_target(&m.id, &m.version, &p.file_name);
        let sig_target = format!("{pkg_target}.sig");
        targets.push((pkg_target.clone(), p.package_path.clone()));
        targets.push((sig_target.clone(), p.signature_path.clone()));
        for e in channel_entries(m) {
            channels.entry((e.channel, e.arch)).or_default().push(Release {
                id: m.id.clone(),
                version: m.version.clone(),
                languages: m.languages.clone(),
                platform: e.target.platform,
                distributions: e.distributions.clone(),
                architectures: e.architectures.clone(),
                file_name: p.file_name.clone(),
                target: pkg_target.clone(),
                size: p.size,
                sha256: p.sha256.clone(),
                signature: SignatureRef {
                    target: sig_target.clone(),
                    key_id: p.signature_key_id.clone(),
                },
                published_at: p.published_at,
                dependencies: m.dependencies.clone(),
                mode: e.target.mode,
                privileges: e.target.effective_privileges(),
                uses_scripts: p.uses_scripts,
                revoked: false,
            });
        }
    }
    let write = |name: &str, v: &serde_json::Value| -> Result<PathBuf> {
        let p = src.join(name);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&p, serde_json::to_vec_pretty(v)?)?;
        Ok(p)
    };
    let mut refs = Vec::new();
    for ((c, a), rels) in &channels {
        let name = c.index_target(*a);
        let ci = ChannelIndex {
            meta_version: INDEX_META_VERSION,
            channel: *c,
            arch: *a,
            generated_at: now,
            releases: rels.clone(),
        };
        targets.push((name.clone(), write(&name, &serde_json::to_value(&ci)?)?));
        refs.push(ChannelRef {
            channel: *c,
            arch: *a,
            target: name,
            releases: rels.len(),
        });
    }
    let apps = AppsIndex {
        meta_version: INDEX_META_VERSION,
        generated_at: now,
        apps: content.apps.clone(),
    };
    targets.push((APPS_TARGET.into(), write(APPS_TARGET, &serde_json::to_value(&apps)?)?));
    let rev = RevocationList {
        meta_version: INDEX_META_VERSION,
        generated_at: now,
        revoked: content.revoked.clone(),
    };
    targets.push((
        REVOCATIONS_TARGET.into(),
        write(REVOCATIONS_TARGET, &serde_json::to_value(&rev)?)?,
    ));
    let index = RepoIndex {
        meta_version: INDEX_META_VERSION,
        repository: content.info.clone(),
        generated_at: now,
        generation: content.generation,
        apps: APPS_TARGET.into(),
        revocations: REVOCATIONS_TARGET.into(),
        channels: refs,
    };
    targets.push((
        REPO_INDEX_TARGET.into(),
        write(REPO_INDEX_TARGET, &serde_json::to_value(&index)?)?,
    ));
    Ok(targets)
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
    distributions: [debian, ubuntu]
    architectures: [any]
    mode: native
    install: { method: package_manager, manager: apt, packages: [demo] }
  - name: win
    platform: windows
    architectures: [arm64]
    mode: native
    install: { method: package_manager, manager: winget, packages: [Demo.Demo] }
"#;
        let (m, _) = Manifest::parse(yaml.as_bytes()).unwrap();
        let e = channel_entries(&m);
        assert_eq!(e.len(), 3);
        assert_eq!(e.iter().filter(|x| x.channel == Channel::LinuxDeb).count(), 2);
        assert_eq!(e[0].distributions, vec![Distribution::Debian, Distribution::Ubuntu]);
        assert!(e.iter().any(|x| x.channel == Channel::Windows && x.arch == Arch::Arm64));
        assert!(!e.iter().any(|x| x.channel == Channel::Windows && x.arch == Arch::X86_64));
    }
}
