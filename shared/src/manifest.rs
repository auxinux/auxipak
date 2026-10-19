//! Manifeste `instruction.auxipak` (YAML, format 1).
//!
//! Le manifeste est entièrement déclaratif : il ne contient jamais de ligne de
//! commande libre. Chaque méthode d'installation possède des paramètres
//! structurés, validés ici, que le client traduit en appels de processus avec
//! un vecteur d'arguments (aucun interpréteur de commandes n'est invoqué).
//!
//! La validation se fait en trois étapes :
//! 1. validation par le schéma JSON officiel (`schemas/instruction.auxipak.schema.json`) ;
//! 2. désérialisation typée stricte (`deny_unknown_fields`) ;
//! 3. validation sémantique (cohérence mode/méthode/plateforme, chemins, etc.).

use crate::ids;
use crate::platform::{Arch, Distribution, Os, SystemProfile};
use crate::version::{self, VersionReq};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// Nom du fichier manifeste à la racine d'une archive `.apak`.
pub const MANIFEST_FILE: &str = "instruction.auxipak";
/// Version courante du format de manifeste.
pub const MANIFEST_FORMAT: u32 = 1;
/// Taille maximale d'un manifeste.
pub const MAX_MANIFEST_SIZE: usize = 256 * 1024;

/// Racines autorisées pour les destinations du mode `files`.
pub const FILE_DEST_ROOTS: [&str; 3] = ["{app}", "{bin}", "{data}"];
/// Racines autorisées pour les chemins de désinstallation `exe` (Windows).
pub const WINDOWS_PATH_ROOTS: [&str; 4] = ["{program_files}", "{program_files_x86}", "{local_app_data}", "{app}"];

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// Version du format de manifeste (actuellement 1).
    pub format: u32,
    /// Identifiant stable de l'application (`firefox`, `auxipak-demo`).
    pub id: String,
    /// Nom affiché.
    pub name: String,
    /// Version de l'application.
    pub version: String,
    /// Éditeur.
    pub publisher: String,
    /// Description courte (une ligne).
    pub summary: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Licence (identifiant SPDX recommandé, ou `Proprietary`).
    pub license: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub homepage: Option<String>,
    /// Langues de l'application (`fr`, `en`, `mul` pour multilingue).
    pub languages: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub categories: Vec<String>,
    /// Déclaration de l'éditeur sur la vie privée. Purement informative : la
    /// classification officielle est attribuée par le serveur AuxiPak.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub privacy: Option<Privacy>,
    /// Dépendances vers d'autres applications AuxiPak.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dependencies: Vec<Dependency>,
    /// Liste exhaustive des fichiers de l'archive (hors manifeste), avec empreintes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub contents: Vec<ContentEntry>,
    /// Variantes d'installation par plateforme.
    pub targets: Vec<Target>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Privacy {
    pub telemetry: Telemetry,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub data_collected: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Telemetry {
    None,
    OptIn,
    OptOut,
    Mandatory,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Dependency {
    pub id: String,
    #[serde(default = "VersionReq::any")]
    pub version: VersionReq,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContentEntry {
    pub path: String,
    pub sha256: String,
    pub size: u64,
    /// Fichier exécutable (bit `x` appliqué à l'extraction sous Unix).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub executable: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// Délégation à un gestionnaire de paquets natif autorisé.
    Native,
    /// Téléchargement contrôlé depuis une source HTTPS, empreinte obligatoire.
    Remote,
    /// Fichiers fournis dans l'archive.
    Embedded,
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Mode::Native => "native",
            Mode::Remote => "remote",
            Mode::Embedded => "embedded",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Privileges {
    User,
    Admin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Reboot {
    #[default]
    None,
    Recommended,
    Required,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum UpgradeStrategy {
    /// Installer la nouvelle version par-dessus l'ancienne.
    #[default]
    InPlace,
    /// Désinstaller l'ancienne version puis installer la nouvelle.
    RemoveThenInstall,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Upgrade {
    #[serde(default)]
    pub strategy: UpgradeStrategy,
}

/// Gestionnaires natifs autorisés.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Manager {
    /// APT (Debian/Ubuntu uniquement — jamais sur AuxiNuxOS).
    Apt,
    /// Commande système `auxi` d'AuxiNuxOS.
    Auxi,
    /// Mécanisme système de VirtuaOS (adaptateur configurable).
    Virtuaos,
    /// Windows Package Manager.
    Winget,
    /// Homebrew (macOS) — fournisseur tiers, désactivable par politique.
    Brew,
}

impl Manager {
    pub fn as_str(&self) -> &'static str {
        match self {
            Manager::Apt => "apt",
            Manager::Auxi => "auxi",
            Manager::Virtuaos => "virtuaos",
            Manager::Winget => "winget",
            Manager::Brew => "brew",
        }
    }

    /// Distributions sur lesquelles ce gestionnaire est autorisé.
    pub fn allowed_on(&self) -> &'static [Distribution] {
        match self {
            Manager::Apt => &[Distribution::Debian, Distribution::Ubuntu],
            Manager::Auxi => &[Distribution::Auxinuxos],
            Manager::Virtuaos => &[Distribution::Virtuaos],
            Manager::Winget => &[Distribution::Windows],
            Manager::Brew => &[Distribution::Macos],
        }
    }
}

impl fmt::Display for Manager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Origine d'un fichier installateur : intégré (`file`) ou distant (`url` + `sha256`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Source {
    /// Chemin dans l'archive (`payload/...`), mode `embedded`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    /// URL HTTPS, mode `remote`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Empreinte SHA-256 attendue (obligatoire en mode `remote`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// Taille attendue en octets (recommandée en mode `remote`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    /// Hôtes supplémentaires autorisés lors des redirections (l'hôte de `url`
    /// est toujours autorisé).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_hosts: Vec<String>,
    /// Nom du fichier local une fois téléchargé (par défaut : dernier segment de l'URL).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileCopy {
    /// Fichier ou répertoire source dans l'archive (`payload/...`).
    pub source: String,
    /// Destination : `{app}/...`, `{bin}/...` ou `{data}/...`.
    pub destination: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub executable: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum MsiScope {
    #[default]
    Machine,
    User,
}

/// Méthode d'installation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case", deny_unknown_fields)]
pub enum Install {
    PackageManager {
        manager: Manager,
        packages: Vec<String>,
    },
    Deb {
        /// Nom du paquet Debian (champ `Package` du fichier `control`).
        package: String,
        source: Source,
    },
    Msi {
        source: Source,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        product_code: Option<String>,
        #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
        properties: BTreeMap<String, String>,
        #[serde(default)]
        scope: MsiScope,
    },
    Exe {
        source: Source,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        args: Vec<String>,
    },
    Pkg {
        source: Source,
        /// Identifiant du reçu (`pkgutil --pkgs`).
        package_id: String,
    },
    Dmg {
        source: Source,
        /// Nom du bundle `.app` contenu dans l'image.
        app: String,
    },
    Files {
        files: Vec<FileCopy>,
    },
    Script {
        script: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        args: Vec<String>,
    },
}

impl Install {
    pub fn method_name(&self) -> &'static str {
        match self {
            Install::PackageManager { .. } => "package_manager",
            Install::Deb { .. } => "deb",
            Install::Msi { .. } => "msi",
            Install::Exe { .. } => "exe",
            Install::Pkg { .. } => "pkg",
            Install::Dmg { .. } => "dmg",
            Install::Files { .. } => "files",
            Install::Script { .. } => "script",
        }
    }

    pub fn source(&self) -> Option<&Source> {
        match self {
            Install::Deb { source, .. }
            | Install::Msi { source, .. }
            | Install::Exe { source, .. }
            | Install::Pkg { source, .. }
            | Install::Dmg { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Méthode de désinstallation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case", deny_unknown_fields)]
pub enum Remove {
    PackageManager {
        manager: Manager,
        packages: Vec<String>,
    },
    Deb {
        package: String,
    },
    Msi {
        product_code: String,
    },
    Exe {
        /// Chemin de l'exécutable de désinstallation, sous une racine connue.
        path: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        args: Vec<String>,
    },
    Pkg {
        package_id: String,
        /// Chemins à supprimer (sous `/Applications` uniquement).
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        paths: Vec<String>,
    },
    /// Supprime le bundle `.app` installé depuis une image disque.
    App {
        app: String,
    },
    /// Supprime les fichiers enregistrés lors de l'installation.
    Files,
    Script {
        script: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        args: Vec<String>,
    },
}

/// Méthode de détection d'une installation existante.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case", deny_unknown_fields)]
pub enum Detect {
    PackageManager {
        manager: Manager,
        package: String,
    },
    Msi {
        product_code: String,
    },
    Pkg {
        package_id: String,
    },
    App {
        app: String,
    },
    /// Présence de fichiers installés (`{app}/...`, `{bin}/...`).
    Files {
        paths: Vec<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Scripts {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pre_install: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub post_install: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pre_remove: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub post_remove: Option<String>,
}

impl Scripts {
    pub fn all(&self) -> impl Iterator<Item = (&'static str, &String)> {
        [
            ("pre_install", self.pre_install.as_ref()),
            ("post_install", self.post_install.as_ref()),
            ("pre_remove", self.pre_remove.as_ref()),
            ("post_remove", self.post_remove.as_ref()),
        ]
        .into_iter()
        .filter_map(|(k, v)| v.map(|v| (k, v)))
    }

    pub fn is_empty(&self) -> bool {
        self.all().next().is_none()
    }
}

/// Permissions déclarées (informatives, affichées avant installation).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    Network,
    SystemFiles,
    UserFiles,
    Services,
    Autostart,
    Drivers,
    Firewall,
}

fn default_success_codes() -> Vec<i32> {
    vec![0]
}

fn is_default_success(v: &[i32]) -> bool {
    v == [0]
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Target {
    /// Nom court de la variante (`debian`, `windows-x64`…), unique dans le manifeste.
    pub name: String,
    pub platform: Os,
    /// Distributions visées (obligatoire sous Linux).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub distributions: Vec<Distribution>,
    /// Contrainte sur la version du système (`>=12`, `>=10.0.19041`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os_version: Option<VersionReq>,
    pub architectures: Vec<Arch>,
    pub mode: Mode,
    /// Privilèges requis ; déduits de la méthode s'ils sont absents.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub privileges: Option<Privileges>,
    pub install: Install,
    /// Désinstallation ; déduite de la méthode d'installation si absente.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remove: Option<Remove>,
    #[serde(default)]
    pub upgrade: Upgrade,
    #[serde(default)]
    pub reboot: Reboot,
    #[serde(default = "default_success_codes", skip_serializing_if = "is_default_success")]
    pub success_codes: Vec<i32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reboot_codes: Vec<i32>,
    #[serde(default, skip_serializing_if = "Scripts::is_empty")]
    pub scripts: Scripts,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub permissions: Vec<Permission>,
    /// Paquets système requis, installés par le gestionnaire natif.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub native_dependencies: Vec<String>,
    /// Détection d'une installation existante ; déduite si absente.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detect: Option<Detect>,
    /// Délai maximal d'exécution de l'installateur (secondes).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_seconds: Option<u64>,
}

impl Target {
    /// Privilèges effectifs (déclarés ou déduits de la méthode).
    pub fn effective_privileges(&self) -> Privileges {
        if let Some(p) = self.privileges {
            return p;
        }
        match &self.install {
            Install::PackageManager {
                manager: Manager::Winget | Manager::Brew,
                ..
            } => Privileges::User,
            Install::Msi {
                scope: MsiScope::User, ..
            } => Privileges::User,
            Install::Files { .. } | Install::Dmg { .. } => Privileges::User,
            _ => Privileges::Admin,
        }
    }

    /// Procédure de désinstallation effective.
    pub fn effective_remove(&self) -> Option<Remove> {
        if let Some(r) = &self.remove {
            return Some(r.clone());
        }
        match &self.install {
            Install::PackageManager { manager, packages } => Some(Remove::PackageManager {
                manager: *manager,
                packages: packages.clone(),
            }),
            Install::Deb { package, .. } => Some(Remove::Deb {
                package: package.clone(),
            }),
            Install::Msi {
                product_code: Some(pc), ..
            } => Some(Remove::Msi {
                product_code: pc.clone(),
            }),
            Install::Dmg { app, .. } => Some(Remove::App { app: app.clone() }),
            Install::Files { .. } => Some(Remove::Files),
            _ => None,
        }
    }

    /// Méthode de détection effective.
    pub fn effective_detect(&self) -> Option<Detect> {
        if let Some(d) = &self.detect {
            return Some(d.clone());
        }
        match &self.install {
            Install::PackageManager { manager, packages } => packages.first().map(|p| Detect::PackageManager {
                manager: *manager,
                package: p.clone(),
            }),
            Install::Deb { package, .. } => Some(Detect::PackageManager {
                manager: Manager::Apt,
                package: package.clone(),
            }),
            Install::Msi {
                product_code: Some(pc), ..
            } => Some(Detect::Msi {
                product_code: pc.clone(),
            }),
            Install::Pkg { package_id, .. } => Some(Detect::Pkg {
                package_id: package_id.clone(),
            }),
            Install::Dmg { app, .. } => Some(Detect::App { app: app.clone() }),
            Install::Files { files } => Some(Detect::Files {
                paths: files.iter().map(|f| f.destination.clone()).collect(),
            }),
            _ => None,
        }
    }

    /// Cette variante contient-elle des scripts personnalisés ?
    pub fn uses_scripts(&self) -> bool {
        !self.scripts.is_empty()
            || matches!(self.install, Install::Script { .. })
            || matches!(self.remove, Some(Remove::Script { .. }))
    }

    /// Indique si la variante convient au profil donné, sinon pourquoi.
    pub fn matches(&self, p: &SystemProfile) -> Result<MatchQuality, String> {
        if self.platform != p.os {
            return Err(format!("plateforme {} ≠ {}", self.platform, p.os));
        }
        if p.os == Os::Linux && !self.distributions.contains(&p.distribution) {
            return Err(format!(
                "distribution {} non visée ({})",
                p.distribution,
                self.distributions.iter().map(|d| d.as_str()).collect::<Vec<_>>().join(", ")
            ));
        }
        let arch_exact = self.architectures.contains(&p.arch);
        if !arch_exact && !self.architectures.contains(&Arch::Any) {
            return Err(format!("architecture {} non prise en charge", p.arch));
        }
        if let Some(req) = &self.os_version {
            if !req.matches(&p.version) {
                return Err(format!("version du système {} hors de « {} »", p.version, req));
            }
        }
        Ok(MatchQuality {
            arch_exact,
            version_constrained: self.os_version.is_some(),
        })
    }
}

/// Qualité d'une correspondance (utilisée pour départager plusieurs variantes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct MatchQuality {
    pub arch_exact: bool,
    pub version_constrained: bool,
}

/// Erreur ou avertissement de validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Issue {
    pub path: String,
    pub message: String,
    pub fatal: bool,
}

impl fmt::Display for Issue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {} : {}",
            if self.fatal { "ERREUR" } else { "AVERTISSEMENT" },
            self.path,
            self.message
        )
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    #[error("manifeste trop volumineux ({0} octets, maximum {MAX_MANIFEST_SIZE})")]
    TooLarge(usize),
    #[error("YAML invalide : {0}")]
    Yaml(String),
    #[error("manifeste non conforme au schéma :\n{}", .0.join("\n"))]
    Schema(Vec<String>),
    #[error("manifeste invalide :\n{}", .0.iter().filter(|i| i.fatal).map(|i| i.to_string()).collect::<Vec<_>>().join("\n"))]
    Invalid(Vec<Issue>),
}

impl Manifest {
    /// Analyse et valide complètement un manifeste.
    pub fn parse(bytes: &[u8]) -> Result<(Manifest, Vec<Issue>), ManifestError> {
        if bytes.len() > MAX_MANIFEST_SIZE {
            return Err(ManifestError::TooLarge(bytes.len()));
        }
        let text = std::str::from_utf8(bytes).map_err(|e| ManifestError::Yaml(e.to_string()))?;
        Manifest::from_value(parse_yaml_value(text)?)
    }

    /// Valide (schéma, typage strict, règles sémantiques) une valeur issue du YAML.
    pub fn from_value(value: serde_json::Value) -> Result<(Manifest, Vec<Issue>), ManifestError> {
        crate::schema::validate_manifest_value(&value).map_err(ManifestError::Schema)?;
        let manifest: Manifest = serde_json::from_value(value).map_err(|e| ManifestError::Schema(vec![e.to_string()]))?;
        let issues = manifest.validate();
        if issues.iter().any(|i| i.fatal) {
            return Err(ManifestError::Invalid(issues));
        }
        Ok((manifest, issues))
    }

    /// Sérialise en YAML canonique.
    pub fn to_yaml(&self) -> String {
        serde_yaml_ng::to_string(self).expect("sérialisation YAML")
    }

    /// Validation sémantique ; retourne erreurs et avertissements.
    pub fn validate(&self) -> Vec<Issue> {
        let mut v = Validator::default();
        if self.format != MANIFEST_FORMAT {
            v.err(
                "format",
                format!(
                    "version de format {} non prise en charge (attendu {MANIFEST_FORMAT})",
                    self.format
                ),
            );
        }
        if !ids::is_valid_app_id(&self.id) {
            v.err(
                "id",
                "identifiant invalide (minuscules, chiffres, « . », « - », « + », 2 à 64 caractères)",
            );
        }
        if !version::is_valid_version(&self.version) {
            v.err(
                "version",
                "version invalide (doit commencer par un chiffre ; caractères autorisés : alphanumériques et .+-~_)",
            );
        }
        for (field, val, max) in [
            ("name", &self.name, 128usize),
            ("publisher", &self.publisher, 128),
            ("summary", &self.summary, 200),
            ("license", &self.license, 128),
        ] {
            if val.trim().is_empty() {
                v.err(field, "champ obligatoire vide");
            } else if val.chars().count() > max || val.chars().any(|c| c.is_control()) {
                v.err(
                    field,
                    format!("valeur invalide (maximum {max} caractères, sans caractère de contrôle)"),
                );
            }
        }
        if let Some(h) = &self.homepage {
            if !h.starts_with("https://") {
                v.warn("homepage", "la page d'accueil devrait utiliser HTTPS");
            }
        }
        if self.languages.is_empty() {
            v.err("languages", "au moins une langue est requise (« mul » pour multilingue)");
        }
        for (i, l) in self.languages.iter().enumerate() {
            if !ids::is_valid_language(l) {
                v.err(format!("languages[{i}]"), format!("code de langue invalide : {l}"));
            }
        }
        let mut dep_ids = BTreeSet::new();
        for (i, d) in self.dependencies.iter().enumerate() {
            if !ids::is_valid_app_id(&d.id) {
                v.err(format!("dependencies[{i}].id"), "identifiant invalide");
            }
            if d.id == self.id {
                v.err(
                    format!("dependencies[{i}]"),
                    "une application ne peut pas dépendre d'elle-même",
                );
            }
            if !dep_ids.insert(&d.id) {
                v.err(format!("dependencies[{i}]"), "dépendance dupliquée");
            }
        }
        let mut content_paths = BTreeSet::new();
        for (i, c) in self.contents.iter().enumerate() {
            let p = format!("contents[{i}]");
            if !ids::is_safe_relative_path(&c.path) {
                v.err(&p, format!("chemin dangereux ou invalide : {}", c.path));
            } else if !(c.path.starts_with("payload/") || c.path.starts_with("scripts/")) {
                v.err(&p, "les fichiers doivent se trouver dans payload/ ou scripts/");
            }
            if !is_sha256_hex(&c.sha256) {
                v.err(&p, "empreinte SHA-256 invalide (64 caractères hexadécimaux minuscules)");
            }
            if !content_paths.insert(c.path.as_str()) {
                v.err(&p, "chemin dupliqué");
            }
        }
        if self.targets.is_empty() {
            v.err("targets", "au moins une variante est requise");
        }
        let mut names = BTreeSet::new();
        for (i, t) in self.targets.iter().enumerate() {
            if !names.insert(&t.name) {
                v.err(format!("targets[{i}].name"), "nom de variante dupliqué");
            }
            validate_target(&mut v, &format!("targets[{i}]"), t, &content_paths);
        }
        v.issues
    }

    /// Sélectionne la variante correspondant au profil système.
    ///
    /// Une variante doit correspondre exactement à la plateforme, à la
    /// distribution (sous Linux), à l'architecture (ou `any`) et à la contrainte
    /// de version. En cas d'égalité, une architecture exacte est préférée à
    /// `any`, puis une variante dont la version est contrainte, puis l'ordre de
    /// déclaration.
    pub fn select_target(&self, profile: &SystemProfile) -> Result<&Target, String> {
        let mut best: Option<(MatchQuality, &Target)> = None;
        let mut reasons = Vec::new();
        for t in &self.targets {
            match t.matches(profile) {
                Ok(q) => {
                    if best.map(|(bq, _)| q > bq).unwrap_or(true) {
                        best = Some((q, t));
                    }
                }
                Err(e) => reasons.push(format!("{} : {}", t.name, e)),
            }
        }
        best.map(|(_, t)| t).ok_or_else(|| {
            format!(
                "aucune variante de {} {} ne correspond à {} {} ({}) :\n  {}",
                self.id,
                self.version,
                profile.distribution,
                profile.version,
                profile.arch,
                reasons.join("\n  ")
            )
        })
    }

    pub fn content(&self, path: &str) -> Option<&ContentEntry> {
        self.contents.iter().find(|c| c.path == path)
    }

    /// Nom de fichier normalisé : `<Nom>-<version>-<langue>.apak`.
    pub fn suggested_file_name(&self) -> String {
        let name: String = self
            .name
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
            .collect();
        let name = if name.is_empty() { self.id.clone() } else { name };
        let lang = if self.languages.len() == 1 {
            self.languages[0].clone()
        } else {
            "mul".into()
        };
        format!("{}-{}-{}.apak", name, self.version, lang)
    }
}

/// Analyse un texte YAML en valeur générique (sans validation du manifeste).
pub fn parse_yaml_value(text: &str) -> Result<serde_json::Value, ManifestError> {
    if text.len() > MAX_MANIFEST_SIZE {
        return Err(ManifestError::TooLarge(text.len()));
    }
    serde_yaml_ng::from_str(text).map_err(|e| ManifestError::Yaml(e.to_string()))
}

pub fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

#[derive(Default)]
struct Validator {
    issues: Vec<Issue>,
}

impl Validator {
    fn err(&mut self, path: impl Into<String>, msg: impl Into<String>) {
        self.issues.push(Issue {
            path: path.into(),
            message: msg.into(),
            fatal: true,
        });
    }
    fn warn(&mut self, path: impl Into<String>, msg: impl Into<String>) {
        self.issues.push(Issue {
            path: path.into(),
            message: msg.into(),
            fatal: false,
        });
    }
}

fn validate_target(v: &mut Validator, p: &str, t: &Target, contents: &BTreeSet<&str>) {
    if !ids::is_valid_repo_name(&t.name) {
        v.err(
            format!("{p}.name"),
            "nom de variante invalide (minuscules, chiffres, « - », « _ »)",
        );
    }
    if t.architectures.is_empty() {
        v.err(format!("{p}.architectures"), "au moins une architecture est requise");
    }
    if t.architectures.contains(&Arch::Any) && t.architectures.len() > 1 {
        v.err(
            format!("{p}.architectures"),
            "« any » ne peut pas être combiné à d'autres architectures",
        );
    }
    match t.platform {
        Os::Linux => {
            if t.distributions.is_empty() {
                v.err(format!("{p}.distributions"), "obligatoire pour une variante Linux");
            }
            for d in &t.distributions {
                if d.os() != Os::Linux || *d == Distribution::Unknown {
                    v.err(
                        format!("{p}.distributions"),
                        format!("{d} n'est pas une distribution Linux prise en charge"),
                    );
                }
            }
        }
        os => {
            for d in &t.distributions {
                if d.os() != os {
                    v.err(
                        format!("{p}.distributions"),
                        format!("{d} incompatible avec la plateforme {os}"),
                    );
                }
            }
        }
    }
    let target_dists: Vec<Distribution> = if t.platform == Os::Linux {
        t.distributions.clone()
    } else if t.platform == Os::Windows {
        vec![Distribution::Windows]
    } else {
        vec![Distribution::Macos]
    };

    // Cohérence méthode / mode / plateforme.
    let ip = format!("{p}.install");
    match &t.install {
        Install::PackageManager { manager, packages } => {
            if t.mode != Mode::Native {
                v.err(&ip, "la méthode package_manager exige le mode native");
            }
            check_manager(v, &ip, *manager, &target_dists);
            if packages.is_empty() {
                v.err(format!("{ip}.packages"), "au moins un paquet est requis");
            }
            for pk in packages {
                if !ids::is_valid_native_package(pk) {
                    v.err(format!("{ip}.packages"), format!("nom de paquet natif invalide : {pk}"));
                }
            }
        }
        Install::Deb { package, source } => {
            if t.platform != Os::Linux {
                v.err(&ip, "la méthode deb est réservée à Linux");
            }
            if !ids::is_valid_native_package(package) {
                v.err(format!("{ip}.package"), "nom de paquet Debian invalide");
            }
            check_source(v, &ip, t.mode, source, contents, &[".deb"]);
        }
        Install::Msi {
            source,
            product_code,
            properties,
            ..
        } => {
            require_platform(v, &ip, t.platform, Os::Windows, "msi");
            check_source(v, &ip, t.mode, source, contents, &[".msi"]);
            if let Some(pc) = product_code {
                if !ids::is_valid_msi_product_code(pc) {
                    v.err(format!("{ip}.product_code"), "code produit MSI invalide ({GUID})");
                }
            } else if t.remove.is_none() {
                v.warn(
                    format!("{ip}.product_code"),
                    "sans product_code, la désinstallation doit être déclarée explicitement",
                );
            }
            for (k, val) in properties {
                if !ids::is_valid_msi_property(k) || !ids::is_valid_installer_arg(val) {
                    v.err(format!("{ip}.properties"), format!("propriété MSI invalide : {k}"));
                }
            }
        }
        Install::Exe { source, args } => {
            require_platform(v, &ip, t.platform, Os::Windows, "exe");
            check_source(v, &ip, t.mode, source, contents, &[".exe"]);
            check_args(v, &ip, args);
            if t.privileges.is_none() {
                v.warn(
                    format!("{p}.privileges"),
                    "privilèges non déclarés pour un installateur exe (admin supposé)",
                );
            }
        }
        Install::Pkg { source, package_id } => {
            require_platform(v, &ip, t.platform, Os::Macos, "pkg");
            check_source(v, &ip, t.mode, source, contents, &[".pkg"]);
            if !ids::is_valid_reverse_dns(package_id) {
                v.err(format!("{ip}.package_id"), "identifiant de reçu invalide");
            }
        }
        Install::Dmg { source, app } => {
            require_platform(v, &ip, t.platform, Os::Macos, "dmg");
            check_source(v, &ip, t.mode, source, contents, &[".dmg"]);
            if !ids::is_safe_file_name(app) || !app.ends_with(".app") {
                v.err(format!("{ip}.app"), "nom de bundle invalide (ex. « Firefox.app »)");
            }
        }
        Install::Files { files } => {
            if t.mode != Mode::Embedded {
                v.err(&ip, "la méthode files exige le mode embedded");
            }
            if files.is_empty() {
                v.err(format!("{ip}.files"), "au moins un fichier est requis");
            }
            for (i, f) in files.iter().enumerate() {
                let fp = format!("{ip}.files[{i}]");
                if !f.source.starts_with("payload/") || !ids::is_safe_relative_path(&f.source) {
                    v.err(&fp, format!("source invalide : {}", f.source));
                } else if !contents.contains(f.source.as_str())
                    && !contents.iter().any(|c| c.starts_with(&format!("{}/", f.source)))
                {
                    v.err(&fp, format!("source absente de contents : {}", f.source));
                }
                if !is_valid_templated_path(&f.destination, &FILE_DEST_ROOTS) {
                    v.err(
                        &fp,
                        format!(
                            "destination invalide (doit commencer par {{app}}, {{bin}} ou {{data}}) : {}",
                            f.destination
                        ),
                    );
                }
            }
        }
        Install::Script { script, args } => {
            if t.mode != Mode::Embedded {
                v.err(&ip, "la méthode script exige le mode embedded");
            }
            check_script(v, &format!("{ip}.script"), script, t.platform, contents);
            check_args(v, &ip, args);
            if t.remove.is_none() {
                v.err(
                    format!("{p}.remove"),
                    "une installation par script exige une désinstallation explicite",
                );
            }
        }
    }

    // Désinstallation.
    if let Some(r) = &t.remove {
        let rp = format!("{p}.remove");
        match r {
            Remove::PackageManager { manager, packages } => {
                check_manager(v, &rp, *manager, &target_dists);
                for pk in packages {
                    if !ids::is_valid_native_package(pk) {
                        v.err(&rp, format!("nom de paquet natif invalide : {pk}"));
                    }
                }
            }
            Remove::Deb { package } => {
                if t.platform != Os::Linux || !ids::is_valid_native_package(package) {
                    v.err(&rp, "désinstallation deb invalide");
                }
            }
            Remove::Msi { product_code } => {
                require_platform(v, &rp, t.platform, Os::Windows, "msi");
                if !ids::is_valid_msi_product_code(product_code) {
                    v.err(&rp, "code produit MSI invalide");
                }
            }
            Remove::Exe { path, args } => {
                require_platform(v, &rp, t.platform, Os::Windows, "exe");
                if !is_valid_templated_path(path, &WINDOWS_PATH_ROOTS) || !path.to_ascii_lowercase().ends_with(".exe") {
                    v.err(&rp, "chemin de désinstallation invalide (racine {program_files}, {program_files_x86}, {local_app_data} ou {app})");
                }
                check_args(v, &rp, args);
            }
            Remove::Pkg { package_id, paths } => {
                require_platform(v, &rp, t.platform, Os::Macos, "pkg");
                if !ids::is_valid_reverse_dns(package_id) {
                    v.err(&rp, "identifiant de reçu invalide");
                }
                for path in paths {
                    let ok = path
                        .strip_prefix("/Applications/")
                        .map(ids::is_safe_relative_path)
                        .unwrap_or(false);
                    if !ok {
                        v.err(&rp, format!("chemin non autorisé (doit être sous /Applications) : {path}"));
                    }
                }
            }
            Remove::App { app } => {
                require_platform(v, &rp, t.platform, Os::Macos, "app");
                if !ids::is_safe_file_name(app) || !app.ends_with(".app") {
                    v.err(&rp, "nom de bundle invalide");
                }
            }
            Remove::Files => {
                if !matches!(t.install, Install::Files { .. }) {
                    v.err(&rp, "la désinstallation files n'est possible que pour une installation files");
                }
            }
            Remove::Script { script, args } => {
                check_script(v, &format!("{rp}.script"), script, t.platform, contents);
                check_args(v, &rp, args);
            }
        }
    } else if t.effective_remove().is_none() {
        v.err(
            format!("{p}.remove"),
            "aucune procédure de désinstallation ne peut être déduite : déclarez « remove »",
        );
    }

    if let Some(d) = &t.detect {
        let dp = format!("{p}.detect");
        match d {
            Detect::PackageManager { manager, package } => {
                check_manager(v, &dp, *manager, &target_dists);
                if !ids::is_valid_native_package(package) {
                    v.err(&dp, "nom de paquet invalide");
                }
            }
            Detect::Msi { product_code } => {
                if !ids::is_valid_msi_product_code(product_code) {
                    v.err(&dp, "code produit MSI invalide");
                }
            }
            Detect::Pkg { package_id } => {
                if !ids::is_valid_reverse_dns(package_id) {
                    v.err(&dp, "identifiant de reçu invalide");
                }
            }
            Detect::App { app } => {
                if !ids::is_safe_file_name(app) {
                    v.err(&dp, "nom de bundle invalide");
                }
            }
            Detect::Files { paths } => {
                for path in paths {
                    if !is_valid_templated_path(path, &FILE_DEST_ROOTS) {
                        v.err(&dp, format!("chemin invalide : {path}"));
                    }
                }
            }
        }
    }

    for (hook, script) in t.scripts.all() {
        check_script(v, &format!("{p}.scripts.{hook}"), script, t.platform, contents);
    }
    if t.uses_scripts() {
        v.warn(
            p,
            "cette variante utilise des scripts personnalisés : leur exécution exigera une autorisation explicite",
        );
    }
    for nd in &t.native_dependencies {
        if !ids::is_valid_native_package(nd) {
            v.err(
                format!("{p}.native_dependencies"),
                format!("nom de paquet natif invalide : {nd}"),
            );
        }
    }
    if !t.native_dependencies.is_empty() && t.platform != Os::Linux {
        v.err(
            format!("{p}.native_dependencies"),
            "les dépendances natives ne sont prises en charge que sous Linux",
        );
    }
    if t.success_codes.is_empty() {
        v.err(format!("{p}.success_codes"), "au moins un code de succès est requis");
    }
    if let Some(s) = t.timeout_seconds {
        if s == 0 || s > 24 * 3600 {
            v.err(format!("{p}.timeout_seconds"), "délai invalide (1 à 86400 secondes)");
        }
    }
}

fn require_platform(v: &mut Validator, p: &str, actual: Os, expected: Os, what: &str) {
    if actual != expected {
        v.err(p, format!("la méthode {what} est réservée à {expected}"));
    }
}

fn check_manager(v: &mut Validator, p: &str, m: Manager, dists: &[Distribution]) {
    for d in dists {
        if !m.allowed_on().contains(d) {
            v.err(p, format!("le gestionnaire {m} n'est pas autorisé sur {d}"));
        }
    }
}

fn check_args(v: &mut Validator, p: &str, args: &[String]) {
    for a in args {
        if !ids::is_valid_installer_arg(a) {
            v.err(format!("{p}.args"), format!("argument refusé : {a:?}"));
        }
    }
}

fn check_script(v: &mut Validator, p: &str, script: &str, platform: Os, contents: &BTreeSet<&str>) {
    if !script.starts_with("scripts/") || !ids::is_safe_relative_path(script) {
        v.err(p, format!("le script doit se trouver dans scripts/ : {script}"));
        return;
    }
    let ok_ext = match platform {
        Os::Windows => script.ends_with(".ps1"),
        _ => script.ends_with(".sh"),
    };
    if !ok_ext {
        v.err(
            p,
            "extension de script incompatible avec la plateforme (.sh pour Linux/macOS, .ps1 pour Windows)",
        );
    }
    if !contents.contains(script) {
        v.err(p, format!("script absent de contents : {script}"));
    }
}

fn check_source(v: &mut Validator, p: &str, mode: Mode, s: &Source, contents: &BTreeSet<&str>, exts: &[&str]) {
    let sp = format!("{p}.source");
    match mode {
        Mode::Embedded => {
            if s.url.is_some() || s.sha256.is_some() || !s.allowed_hosts.is_empty() || s.file_name.is_some() {
                v.err(&sp, "en mode embedded, seul « file » est autorisé");
            }
            match &s.file {
                None => v.err(&sp, "« file » est obligatoire en mode embedded"),
                Some(f) => {
                    if !f.starts_with("payload/") || !ids::is_safe_relative_path(f) {
                        v.err(&sp, format!("chemin invalide : {f}"));
                    } else if !contents.contains(f.as_str()) {
                        v.err(&sp, format!("fichier absent de contents : {f}"));
                    }
                    if !exts.iter().any(|e| f.to_ascii_lowercase().ends_with(e)) {
                        v.err(&sp, format!("extension attendue : {}", exts.join(", ")));
                    }
                }
            }
        }
        Mode::Remote => {
            if s.file.is_some() {
                v.err(&sp, "« file » est interdit en mode remote");
            }
            match &s.url {
                None => v.err(&sp, "« url » est obligatoire en mode remote"),
                Some(u) => {
                    if let Err(e) = crate::netpolicy::validate_https_url(u) {
                        v.err(&sp, e);
                    }
                }
            }
            match &s.sha256 {
                Some(h) if is_sha256_hex(h) => {}
                _ => v.err(&sp, "« sha256 » valide est obligatoire en mode remote"),
            }
            if s.size.is_none() {
                v.warn(
                    &sp,
                    "taille non déclarée : la limite de téléchargement par défaut s'appliquera",
                );
            }
            for h in &s.allowed_hosts {
                if !crate::netpolicy::is_valid_host(h) {
                    v.err(&sp, format!("hôte invalide : {h}"));
                }
            }
            let name = s.file_name.clone().or_else(|| {
                s.url
                    .as_deref()
                    .and_then(|u| url::Url::parse(u).ok())
                    .and_then(|u| u.path_segments().and_then(|mut seg| seg.next_back().map(|x| x.to_string())))
            });
            match name {
                Some(n) if ids::is_safe_file_name(&n) => {
                    if !exts.iter().any(|e| n.to_ascii_lowercase().ends_with(e)) {
                        v.err(
                            &sp,
                            format!("le fichier téléchargé doit avoir l'extension {}", exts.join(", ")),
                        );
                    }
                }
                _ => v.err(&sp, "nom de fichier local indéterminable : déclarez « file_name »"),
            }
        }
        Mode::Native => v.err(p, "le mode native exige la méthode package_manager"),
    }
}

/// Chemin de la forme `{racine}/sous/chemin` avec une racine autorisée.
pub fn is_valid_templated_path(path: &str, roots: &[&str]) -> bool {
    roots.iter().any(|r| {
        path == *r
            || path
                .strip_prefix(r)
                .and_then(|rest| rest.strip_prefix('/'))
                .map(ids::is_safe_relative_path)
                .unwrap_or(false)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::{linux_profile_from_os_release, parse_os_release};

    pub const DEMO: &str = r#"
format: 1
id: auxipak-demo
name: AuxiPak Demo
version: "1.0.0"
publisher: AuxiNux
summary: Application de démonstration inoffensive
license: GPL-3.0-or-later
languages: [fr, en]
contents:
  - path: payload/auxipak-demo_1.0.0_all.deb
    sha256: "0000000000000000000000000000000000000000000000000000000000000000"
    size: 10
  - path: payload/bin/auxipak-demo
    sha256: "0000000000000000000000000000000000000000000000000000000000000000"
    size: 10
    executable: true
targets:
  - name: debian
    platform: linux
    distributions: [debian, ubuntu]
    architectures: [any]
    mode: embedded
    install:
      method: deb
      package: auxipak-demo
      source:
        file: payload/auxipak-demo_1.0.0_all.deb
  - name: debian-arm
    platform: linux
    distributions: [debian]
    architectures: [arm64]
    os_version: ">=13"
    mode: embedded
    install:
      method: deb
      package: auxipak-demo
      source:
        file: payload/auxipak-demo_1.0.0_all.deb
  - name: auxinuxos
    platform: linux
    distributions: [auxinuxos]
    architectures: [any]
    mode: native
    install:
      method: package_manager
      manager: auxi
      packages: [auxipak-demo]
  - name: portable
    platform: windows
    architectures: [x86_64, arm64]
    mode: embedded
    install:
      method: files
      files:
        - source: payload/bin/auxipak-demo
          destination: "{bin}/auxipak-demo"
"#;

    fn profile(osr: &str, arch: Arch) -> SystemProfile {
        linux_profile_from_os_release(&parse_os_release(osr), arch, false)
    }

    #[test]
    fn parses_demo_manifest() {
        let (m, issues) = Manifest::parse(DEMO.as_bytes()).unwrap();
        assert_eq!(m.id, "auxipak-demo");
        assert_eq!(m.targets.len(), 4);
        assert!(issues.iter().all(|i| !i.fatal));
        // Aller-retour YAML.
        let (m2, _) = Manifest::parse(m.to_yaml().as_bytes()).unwrap();
        assert_eq!(m, m2);
    }

    #[test]
    fn selects_exact_variant() {
        let (m, _) = Manifest::parse(DEMO.as_bytes()).unwrap();
        let deb13_arm = profile("ID=debian\nVERSION_ID=13\n", Arch::Arm64);
        assert_eq!(m.select_target(&deb13_arm).unwrap().name, "debian-arm");
        let deb12_arm = profile("ID=debian\nVERSION_ID=12\n", Arch::Arm64);
        assert_eq!(m.select_target(&deb12_arm).unwrap().name, "debian");
        let ubuntu = profile("ID=ubuntu\nVERSION_ID=24.04\n", Arch::X86_64);
        assert_eq!(m.select_target(&ubuntu).unwrap().name, "debian");
        let aux = profile("ID=auxinuxos\nVERSION_ID=1.0\n", Arch::X86_64);
        assert_eq!(m.select_target(&aux).unwrap().name, "auxinuxos");
        let fedora = profile("ID=fedora\nVERSION_ID=40\n", Arch::X86_64);
        assert!(m.select_target(&fedora).is_err());
        let mac = SystemProfile {
            os: Os::Macos,
            distribution: Distribution::Macos,
            version: "14.5".into(),
            arch: Arch::Arm64,
            raw_id: "macos".into(),
            pretty_name: "macOS".into(),
            immutable: false,
        };
        let err = m.select_target(&mac).unwrap_err();
        assert!(err.contains("aucune variante"));
    }

    #[test]
    fn rejects_unknown_fields_and_free_commands() {
        let bad = DEMO.replace("    mode: native\n", "    mode: native\n    command: \"rm -rf /\"\n");
        assert!(Manifest::parse(bad.as_bytes()).is_err());
    }

    #[test]
    fn rejects_apt_on_auxinuxos() {
        let bad = DEMO.replace("      manager: auxi", "      manager: apt");
        let err = Manifest::parse(bad.as_bytes()).unwrap_err().to_string();
        assert!(err.contains("apt n'est pas autorisé sur auxinuxos"), "{err}");
    }

    #[test]
    fn rejects_path_traversal_and_injection() {
        let bad = DEMO.replace("\"{bin}/auxipak-demo\"", "\"{bin}/../../etc/passwd\"");
        assert!(Manifest::parse(bad.as_bytes()).is_err());
        let bad = DEMO.replace("packages: [auxipak-demo]", "packages: [\"x; rm -rf /\"]");
        assert!(Manifest::parse(bad.as_bytes()).is_err());
        let bad = DEMO.replace("path: payload/bin/auxipak-demo", "path: ../evil");
        assert!(Manifest::parse(bad.as_bytes()).is_err());
    }

    #[test]
    fn remote_requires_sha256_and_https() {
        let remote = r#"
format: 1
id: remote-app
name: Remote
version: "2.0"
publisher: X
summary: test
license: MIT
languages: [en]
targets:
  - name: win
    platform: windows
    architectures: [x86_64]
    mode: remote
    privileges: admin
    install:
      method: msi
      product_code: "{12345678-1234-1234-1234-1234567890AB}"
      source:
        url: https://example.org/app.msi
        sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        size: 1000
"#;
        assert!(Manifest::parse(remote.as_bytes()).is_ok());
        let no_hash = remote.replace(
            "        sha256: \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\n",
            "",
        );
        assert!(Manifest::parse(no_hash.as_bytes()).is_err());
        let http = remote.replace("https://example.org", "http://example.org");
        assert!(Manifest::parse(http.as_bytes()).is_err());
    }

    #[test]
    fn yaml_float_version_is_rejected_by_schema() {
        let bad = DEMO.replace("version: \"1.0.0\"", "version: 1.0");
        match Manifest::parse(bad.as_bytes()) {
            Err(ManifestError::Schema(_)) => {}
            other => panic!("attendu une erreur de schéma : {other:?}"),
        }
    }

    #[test]
    fn script_requires_contents_and_explicit_remove() {
        let s = r#"
format: 1
id: script-app
name: S
version: "1"
publisher: X
summary: t
license: MIT
languages: [fr]
contents:
  - path: scripts/install.sh
    sha256: "0000000000000000000000000000000000000000000000000000000000000000"
    size: 1
targets:
  - name: deb
    platform: linux
    distributions: [debian]
    architectures: [any]
    mode: embedded
    install:
      method: script
      script: scripts/install.sh
"#;
        let err = Manifest::parse(s.as_bytes()).unwrap_err().to_string();
        assert!(err.contains("désinstallation explicite"), "{err}");
    }
}
