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
    /// Pré-évaluation automatique par une IA (aucune évaluation humaine).
    Ai(Status),
    /// Dépôt externe : aucune certification AuxiNux possible.
    External,
}

impl DisplayStatus {
    pub fn label(&self) -> String {
        let fr = auxipak_core::i18n::is_fr();
        match self {
            DisplayStatus::Official(s) if fr => s.label_fr().into(),
            DisplayStatus::Official(s) => s.label_en().into(),
            DisplayStatus::Ai(s) if fr => format!("{} (analyse automatique par l'IA)", s.label_fr()),
            DisplayStatus::Ai(s) => format!("{} (automatic AI analysis)", s.label_en()),
            DisplayStatus::External if fr => "Externe (non évalué par AuxiNux)".into(),
            DisplayStatus::External => "External (not reviewed by AuxiNux)".into(),
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
            DisplayStatus::Ai(Status::Verified) => {
                if fr {
                    "vérifié (IA)"
                } else {
                    "verified (AI)"
                }
            }
            DisplayStatus::Ai(_) => {
                if fr {
                    "compat. (IA)"
                } else {
                    "compat. (AI)"
                }
            }
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
        match app {
            Some(a) if a.status == Status::Unreviewed && a.ai_evaluation.is_some() => {
                DisplayStatus::Ai(a.ai_evaluation.as_ref().map(|e| e.status).unwrap_or_default())
            }
            _ => DisplayStatus::Official(app.map(|a| a.status).unwrap_or_default()),
        }
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

    /// Nom affiché dans la langue de l'interface (traduction du manifeste).
    pub fn display_name(&self) -> &str {
        self.app
            .map(|a| a.localized(auxipak_core::i18n::current().code()).0)
            .unwrap_or(&self.release.id)
    }

    /// Résumé dans la langue de l'interface.
    pub fn summary(&self) -> &str {
        self.app
            .map(|a| a.localized(auxipak_core::i18n::current().code()).1)
            .unwrap_or("")
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
                || c.app
                    .map(|a| {
                        normalize(&a.summary).contains(&q)
                            || a.translations.values().any(|t| {
                                normalize(&t.summary).contains(&q)
                                    || t.name.as_deref().map(|n| normalize(n).contains(&q)).unwrap_or(false)
                            })
                    })
                    .unwrap_or(false)
        })
        .collect();
    // Une ligne par (dépôt, application) : la version dans la langue
    // préférée, puis la plus récente (comme pour l'installation).
    hits.sort_by(|a, b| {
        lang_score(b.release, lang)
            .cmp(&lang_score(a.release, lang))
            .then_with(|| better(b, a, lang))
    });
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
    let spec_l = spec.trim().trim_end_matches(".aupak").to_lowercase();
    let all: Vec<Candidate> = all_candidates(repos)
        .into_iter()
        .filter(|c| sel.repo.as_ref().map(|r| &c.repo.config.name == r).unwrap_or(true))
        .collect();
    // `firefox-fr` : identifiant suivi d'une langue publiée pour lui (et qui
    // n'est pas lui-même un identifiant ou un nom) : langue imposée.
    if let Some((id, l)) = split_lang_suffix(&all, &spec_l) {
        let mut forced = sel.clone();
        forced.language = Some(l);
        return resolve(repos, &id, &forced, default_lang);
    }
    let lang = sel.language.as_deref().unwrap_or(default_lang);
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
                "« {spec} » : aucune version installable, version(s) {} révoquée(s) (essayez « auxipak search {spec} »)",
                "\"{spec}\": no installable version, version(s) {} revoked (try \"auxipak search {spec}\")",
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
                "« {spec} » : aucune version installable, version(s) {} révoquée(s) (essayez « auxipak search {spec} »)",
                "\"{spec}\": no installable version, version(s) {} revoked (try \"auxipak search {spec}\")",
                revoked.join(", ")
            ));
        }
        bail!(tr!(
            "« {spec} » : aucune version ne correspond aux critères demandés",
            "\"{spec}\": no version matches the requested criteria"
        ));
    }
    // La langue configurée l'emporte sur le numéro de version : `install
    // firefox` installe la version française pour un client réglé en français,
    // même si la version anglaise est plus récente.
    ok.sort_by(|a, b| {
        lang_score(b.release, lang)
            .cmp(&lang_score(a.release, lang))
            .then_with(|| better(b, a, lang))
    });
    Ok(*ok[0])
}

/// `firefox-fr` → (`firefox`, `fr`) si `firefox-fr` n'est ni un identifiant ni
/// un nom de fichier ou d'application, et si `firefox` a une version publiée
/// dans cette langue (`fr`, `fr-CA`…).
fn split_lang_suffix(all: &[Candidate], spec: &str) -> Option<(String, String)> {
    let known = |c: &Candidate| {
        c.release.id == spec
            || c.name().to_lowercase() == spec
            || c.release.file_name.trim_end_matches(".aupak").to_lowercase() == spec
    };
    if all.iter().any(known) {
        return None;
    }
    let (id, l) = spec.rsplit_once('-')?;
    let published = all.iter().any(|c| {
        c.release.id == id
            && c.release
                .languages
                .iter()
                .any(|x| x.to_lowercase() == l || x.to_lowercase().split('-').next() == Some(l))
    });
    published.then(|| (id.to_string(), l.to_string()))
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
