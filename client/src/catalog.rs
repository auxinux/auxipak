//! Recherche et résolution de paquets dans les index en cache.

use crate::repo::RepoData;
use anyhow::{bail, Result};
use auxipak_core::index::{AppMeta, Release, Status};
use auxipak_core::tr;
use auxipak_core::version::{self, VersionReq};
use std::cmp::Ordering;

/// Statut affiché : les statuts officiels ne sont crédibles que pour un dépôt
/// marqué officiel dans la configuration locale.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisplayStatus {
    Official(Status),
    /// Dépôt externe : aucune certification AuxiNux possible.
    External,
}

impl DisplayStatus {
    pub fn label(&self) -> &'static str {
        let fr = auxipak_core::i18n::is_fr();
        match self {
            DisplayStatus::Official(s) if fr => s.label_fr(),
            DisplayStatus::Official(s) => s.label_en(),
            DisplayStatus::External if fr => "Externe (non évalué par AuxiNux)",
            DisplayStatus::External => "External (not reviewed by AuxiNux)",
        }
    }

    pub fn short(&self) -> &'static str {
        let fr = auxipak_core::i18n::is_fr();
        match self {
            DisplayStatus::Official(Status::Verified) => {
                if fr {
                    "vérifié"
                } else {
                    "verified"
                }
            }
            DisplayStatus::Official(Status::Compatible) => "compatible",
            DisplayStatus::Official(Status::Unreviewed) => {
                if fr {
                    "non évalué"
                } else {
                    "unreviewed"
                }
            }
            DisplayStatus::External => {
                if fr {
                    "externe"
                } else {
                    "external"
                }
            }
        }
    }
}

pub fn display_status(repo: &RepoData, app: Option<&AppMeta>) -> DisplayStatus {
    if repo.config.official {
        DisplayStatus::Official(app.map(|a| a.status).unwrap_or_default())
    } else {
        DisplayStatus::External
    }
}

/// Version disponible avec son contexte.
#[derive(Debug, Clone, Copy)]
pub struct Candidate<'a> {
    pub repo: &'a RepoData,
    pub release: &'a Release,
    pub app: Option<&'a AppMeta>,
}

impl<'a> Candidate<'a> {
    pub fn status(&self) -> DisplayStatus {
        display_status(self.repo, self.app)
    }

    pub fn name(&self) -> &str {
        self.app.map(|a| a.name.as_str()).unwrap_or(&self.release.id)
    }

    pub fn is_revoked(&self) -> bool {
        self.release.revoked
            || self
                .repo
                .revocations
                .is_revoked(&self.release.id, &self.release.version, &self.release.sha256)
                .is_some()
    }
}

/// Toutes les versions disponibles pour le canal du système.
pub fn all_candidates(repos: &[RepoData]) -> Vec<Candidate<'_>> {
    let mut v = Vec::new();
    for r in repos {
        let Some(ch) = &r.channel else { continue };
        for rel in &ch.releases {
            let app = r.apps.apps.iter().find(|a| a.id == rel.id);
            v.push(Candidate {
                repo: r,
                release: rel,
                app,
            });
        }
    }
    v
}

fn normalize(s: &str) -> String {
    s.to_lowercase()
        .chars()
        .map(|c| match c {
            'à' | 'â' | 'ä' => 'a',
            'é' | 'è' | 'ê' | 'ë' => 'e',
            'î' | 'ï' => 'i',
            'ô' | 'ö' => 'o',
            'ù' | 'û' | 'ü' => 'u',
            'ç' => 'c',
            c => c,
        })
        .collect()
}

/// Score de langue : préférée > multilingue > autre.
fn lang_score(rel: &Release, pref: &str) -> u8 {
    let pref_base = pref.split('-').next().unwrap_or(pref);
    if rel.languages.iter().any(|l| l == pref) {
        3
    } else if rel.languages.iter().any(|l| l.split('-').next() == Some(pref_base)) {
        2
    } else if rel.languages.iter().any(|l| l == "mul") {
        1
    } else {
        0
    }
}

/// Résultat de recherche : dernière version de chaque application.
pub fn search<'a>(repos: &'a [RepoData], query: &str, lang: &str) -> Vec<Candidate<'a>> {
    let q = normalize(query.trim());
    let mut hits: Vec<Candidate> = all_candidates(repos)
        .into_iter()
        .filter(|c| !c.is_revoked())
        .filter(|c| {
            q.is_empty()
                || normalize(&c.release.id).contains(&q)
                || normalize(c.name()).contains(&q)
                || c.app.map(|a| normalize(&a.summary).contains(&q)).unwrap_or(false)
        })
        .collect();
    // Une ligne par (dépôt, application) : la meilleure version.
    hits.sort_by(|a, b| better(b, a, lang));
    let mut seen = std::collections::BTreeSet::new();
    hits.retain(|c| seen.insert((c.repo.config.name.clone(), c.release.id.clone())));
    hits.sort_by(|a, b| {
        let exact = |c: &Candidate| normalize(&c.release.id) == q || normalize(c.name()) == q;
        exact(b).cmp(&exact(a)).then_with(|| a.release.id.cmp(&b.release.id))
    });
    hits
}

/// Ordre de préférence entre deux candidats (Greater = `a` meilleur).
fn better(a: &Candidate, b: &Candidate, lang: &str) -> Ordering {
    version::compare(&a.release.version, &b.release.version)
        .then_with(|| lang_score(a.release, lang).cmp(&lang_score(b.release, lang)))
        .then_with(|| b.repo.config.priority.cmp(&a.repo.config.priority))
}

/// Critères de résolution.
#[derive(Debug, Clone, Default)]
pub struct Selector {
    pub version: Option<VersionReq>,
    pub language: Option<String>,
    pub repo: Option<String>,
}

/// Résout une demande (`firefox`, `Firefox-150.1-fr`, `Firefox`) vers un candidat.
pub fn resolve<'a>(repos: &'a [RepoData], spec: &str, sel: &Selector, default_lang: &str) -> Result<Candidate<'a>> {
    let lang = sel.language.as_deref().unwrap_or(default_lang);
    let spec_l = spec.trim().trim_end_matches(".aupak").to_lowercase();
    let all: Vec<Candidate> = all_candidates(repos)
        .into_iter()
        .filter(|c| sel.repo.as_ref().map(|r| &c.repo.config.name == r).unwrap_or(true))
        .collect();
    // 1. Nom de fichier exact (`Firefox-150.1-fr`).
    let by_file: Vec<&Candidate> = all
        .iter()
        .filter(|c| c.release.file_name.trim_end_matches(".aupak").to_lowercase() == spec_l)
        .collect();
    let pool: Vec<&Candidate> = if !by_file.is_empty() {
        by_file
    } else {
        let by_id: Vec<&Candidate> = all.iter().filter(|c| c.release.id == spec_l).collect();
        if !by_id.is_empty() {
            by_id
        } else {
            all.iter().filter(|c| c.name().to_lowercase() == spec_l).collect()
        }
    };
    if pool.is_empty() {
        let revoked = revoked_versions(repos, &spec_l, sel);
        if !revoked.is_empty() {
            bail!(tr!(
                "« {spec} » : version(s) {} révoquée(s) : installation refusée",
                "\"{spec}\": version(s) {} revoked: installation refused",
                revoked.join(", ")
            ));
        }
        bail!(tr!(
            "aucune application « {spec} » n'est disponible pour ce système (essayez « auxipak search {spec} »)",
            "no application \"{spec}\" is available for this system (try \"auxipak search {spec}\")"
        ));
    }
    let ids: std::collections::BTreeSet<_> = pool.iter().map(|c| (&c.repo.config.name, &c.release.id)).collect();
    if ids.len() > 1 && sel.repo.is_none() {
        let ids: std::collections::BTreeSet<_> = pool.iter().map(|c| &c.release.id).collect();
        if ids.len() > 1 {
            bail!(tr!(
                "« {spec} » est ambigu : {}",
                "\"{spec}\" is ambiguous: {}",
                ids.into_iter().cloned().collect::<Vec<_>>().join(", ")
            ));
        }
    }
    let matching: Vec<&Candidate> = pool
        .into_iter()
        .filter(|c| sel.version.as_ref().map(|r| r.matches(&c.release.version)).unwrap_or(true))
        .filter(|c| sel.language.as_ref().map(|l| lang_score(c.release, l) > 0).unwrap_or(true))
        .collect();
    let revoked: Vec<String> = matching
        .iter()
        .filter(|c| c.is_revoked())
        .map(|c| c.release.version.clone())
        .collect();
    let mut ok: Vec<&Candidate> = matching.into_iter().filter(|c| !c.is_revoked()).collect();
    if ok.is_empty() {
        let mut revoked = revoked;
        revoked.extend(revoked_versions(repos, &spec_l, sel));
        revoked.sort();
        revoked.dedup();
        if !revoked.is_empty() {
            bail!(tr!(
                "« {spec} » : version(s) {} révoquée(s) : installation refusée",
                "\"{spec}\": version(s) {} revoked: installation refused",
                revoked.join(", ")
            ));
        }
        bail!(tr!(
            "« {spec} » : aucune version ne correspond aux critères demandés",
            "\"{spec}\": no version matches the requested criteria"
        ));
    }
    ok.sort_by(|a, b| better(b, a, lang));
    Ok(*ok[0])
}

/// Versions révoquées (liste de révocation authentifiée) correspondant à la demande.
fn revoked_versions(repos: &[RepoData], id: &str, sel: &Selector) -> Vec<String> {
    repos
        .iter()
        .filter(|r| sel.repo.as_ref().map(|n| &r.config.name == n).unwrap_or(true))
        .flat_map(|r| r.revocations.revoked.iter())
        .filter(|rv| rv.id == id && sel.version.as_ref().map(|v| v.matches(&rv.version)).unwrap_or(true))
        .map(|rv| rv.version.clone())
        .collect()
}

/// Meilleure mise à jour disponible pour une application installée.
pub fn best_update<'a>(
    repos: &'a [RepoData],
    id: &str,
    repo: &str,
    installed_version: &str,
    lang: &str,
) -> Option<Candidate<'a>> {
    let mut v: Vec<Candidate> = all_candidates(repos)
        .into_iter()
        .filter(|c| c.release.id == id && c.repo.config.name == repo && !c.is_revoked())
        .filter(|c| version::compare(&c.release.version, installed_version) == Ordering::Greater)
        .collect();
    v.sort_by(|a, b| better(b, a, lang));
    v.into_iter().next()
}
