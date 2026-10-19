//! Index des dépôts AuxiPak.
//!
//! Chaque dépôt hébergé est un dépôt TUF dont les cibles comprennent :
//! - `index.json`       : description du dépôt et liste des sous-index ;
//! - `apps.json`        : métadonnées communes des applications (nom,
//!   éditeur, licence, **statut officiel AuxiNux** attribué par le serveur) ;
//! - `channels/<canal>/<arch>.json` : versions disponibles pour un canal et
//!   une architecture (les paquets `any` figurent dans chaque architecture) ;
//! - `revocations.json` : paquets révoqués ;
//! - `packages/<id>/<version>/<fichier>.apak` et `.apak.sig`.
//!
//! Les métadonnées communes ne sont pas dupliquées dans les sous-index : un
//! client ne télécharge que `index.json`, `apps.json`, `revocations.json` et le
//! sous-index correspondant à son système.
//!
//! L'authenticité, la fraîcheur (expiration) et la protection contre le retour
//! en arrière (numéros de version) sont assurées par les métadonnées TUF
//! (`root`, `timestamp`, `snapshot`, `targets`) qui signent ces fichiers.

use crate::manifest::{Dependency, Mode, Privileges};
use crate::platform::{Arch, Channel, Distribution, Os};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// Version du format des métadonnées d'index.
pub const INDEX_META_VERSION: u32 = 1;

pub const REPO_INDEX_TARGET: &str = "index.json";
pub const APPS_TARGET: &str = "apps.json";
pub const REVOCATIONS_TARGET: &str = "revocations.json";

/// Statut officiel AuxiNux d'une application.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    /// AuxiNux Vérifié : application évaluée et conforme.
    Verified,
    /// AuxiNux Compatible : acceptable, avec réserves documentées.
    Compatible,
    /// Non évalué.
    #[default]
    Unreviewed,
}

impl Status {
    pub fn as_str(&self) -> &'static str {
        match self {
            Status::Verified => "verified",
            Status::Compatible => "compatible",
            Status::Unreviewed => "unreviewed",
        }
    }

    pub fn label_fr(&self) -> &'static str {
        match self {
            Status::Verified => "AuxiNux Vérifié",
            Status::Compatible => "AuxiNux Compatible",
            Status::Unreviewed => "Non évalué",
        }
    }

    pub fn label_en(&self) -> &'static str {
        match self {
            Status::Verified => "AuxiNux Verified",
            Status::Compatible => "AuxiNux Compatible",
            Status::Unreviewed => "Not reviewed",
        }
    }
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Status {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "verified" => Ok(Status::Verified),
            "compatible" => Ok(Status::Compatible),
            "unreviewed" => Ok(Status::Unreviewed),
            o => Err(format!("statut inconnu : {o}")),
        }
    }
}

/// Description d'un dépôt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepositoryInfo {
    pub name: String,
    pub title: String,
    #[serde(default)]
    pub description: String,
    /// Dépôt officiel AuxiNux. Un client n'affiche les statuts officiels que
    /// pour les dépôts qu'il considère lui-même comme officiels (configuration
    /// locale épinglée) : cette valeur seule ne suffit jamais.
    pub official: bool,
}

/// Référence à un sous-index.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelRef {
    pub channel: Channel,
    pub arch: Arch,
    /// Nom de cible TUF du sous-index.
    pub target: String,
    pub releases: usize,
}

/// `index.json` d'un dépôt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepoIndex {
    pub meta_version: u32,
    pub repository: RepositoryInfo,
    pub generated_at: DateTime<Utc>,
    /// Numéro de génération (croissant), redondant avec la version TUF.
    pub generation: u64,
    pub apps: String,
    pub revocations: String,
    pub channels: Vec<ChannelRef>,
}

/// Métadonnées communes d'une application.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppMeta {
    pub id: String,
    pub name: String,
    pub publisher: String,
    pub summary: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub license: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub homepage: Option<String>,
    #[serde(default)]
    pub categories: Vec<String>,
    /// Statut officiel, attribué exclusivement par le serveur.
    pub status: Status,
    /// Réserves ou commentaires de l'évaluation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_note: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evaluated_at: Option<DateTime<Utc>>,
}

/// `apps.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppsIndex {
    pub meta_version: u32,
    pub generated_at: DateTime<Utc>,
    pub apps: Vec<AppMeta>,
}

/// Référence à la signature détachée d'un paquet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureRef {
    /// Nom de cible TUF du document `.apak.sig`.
    pub target: String,
    pub key_id: String,
}

/// Version publiée d'une application pour un canal/architecture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Release {
    pub id: String,
    pub version: String,
    pub languages: Vec<String>,
    pub platform: Os,
    pub distributions: Vec<Distribution>,
    pub architectures: Vec<Arch>,
    /// Nom de fichier du paquet (`Firefox-150.1-fr.apak`).
    pub file_name: String,
    /// Nom de cible TUF du paquet (chemin relatif à `targets/`).
    pub target: String,
    pub size: u64,
    pub sha256: String,
    pub signature: SignatureRef,
    pub published_at: DateTime<Utc>,
    #[serde(default)]
    pub dependencies: Vec<Dependency>,
    pub mode: Mode,
    pub privileges: Privileges,
    #[serde(default)]
    pub uses_scripts: bool,
    #[serde(default)]
    pub revoked: bool,
}

/// `channels/<canal>/<arch>.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelIndex {
    pub meta_version: u32,
    pub channel: Channel,
    pub arch: Arch,
    pub generated_at: DateTime<Utc>,
    pub releases: Vec<Release>,
}

/// Entrée de révocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Revocation {
    pub id: String,
    pub version: String,
    pub sha256: String,
    pub reason: String,
    pub revoked_at: DateTime<Utc>,
}

/// `revocations.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationList {
    pub meta_version: u32,
    pub generated_at: DateTime<Utc>,
    pub revoked: Vec<Revocation>,
}

impl RevocationList {
    pub fn is_revoked(&self, id: &str, version: &str, sha256: &str) -> Option<&Revocation> {
        self.revoked.iter().find(|r| {
            (r.id == id && r.version == version) || (!r.sha256.is_empty() && crate::hash::digest_eq(&r.sha256, sha256))
        })
    }
}

/// Catalogue public `GET /index` : liste des dépôts hébergés par le serveur.
/// Document de découverte ; l'authenticité de chaque dépôt repose sur ses
/// propres métadonnées TUF.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerCatalog {
    pub meta_version: u32,
    pub server: String,
    pub generated_at: DateTime<Utc>,
    pub repositories: Vec<CatalogRepository>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogRepository {
    #[serde(flatten)]
    pub info: RepositoryInfo,
    /// URL de base du dépôt (contient `metadata/` et `targets/`).
    pub url: String,
    pub channels: Vec<ChannelRef>,
}

/// Nom de cible TUF d'un paquet.
pub fn package_target(id: &str, version: &str, file_name: &str) -> String {
    format!("packages/{id}/{version}/{file_name}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_roundtrip() {
        for s in [Status::Verified, Status::Compatible, Status::Unreviewed] {
            assert_eq!(s.as_str().parse::<Status>().unwrap(), s);
        }
        assert_eq!(serde_json::to_string(&Status::Verified).unwrap(), "\"verified\"");
    }

    #[test]
    fn revocation_lookup() {
        let l = RevocationList {
            meta_version: 1,
            generated_at: Utc::now(),
            revoked: vec![Revocation {
                id: "a".into(),
                version: "1.0".into(),
                sha256: "ab".repeat(32),
                reason: "test".into(),
                revoked_at: Utc::now(),
            }],
        };
        assert!(l.is_revoked("a", "1.0", "").is_some());
        assert!(l.is_revoked("b", "2.0", &"ab".repeat(32)).is_some());
        assert!(l.is_revoked("a", "1.1", &"cd".repeat(32)).is_none());
    }
}
