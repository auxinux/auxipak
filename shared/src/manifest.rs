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
use crate::tr;
use crate::version::{self, VersionReq};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// Nom du fichier manifeste à la racine d'une archive `.aupak`.
pub const MANIFEST_FILE: &str = "instruction.auxipak";
/// Version courante du format de manifeste.
pub const MANIFEST_FORMAT: u32 = 1;
/// Taille maximale d'un manifeste.
pub const MAX_MANIFEST_SIZE: usize = 256 * 1024;

/// Racines autorisées pour les destinations du mode `files`.
pub const FILE_DEST_ROOTS: [&str; 3] = ["{app}", "{bin}", "{data}"];
/// Racines autorisées pour les chemins de désinstallation `exe` (Windows).
pub const WINDOWS_PATH_ROOTS: [&str; 4] = ["{program_files}", "{program_files_x86}", "{local_app_data}", "{app}"];

/// Textes d'une application dans une autre langue.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Translation {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub summary: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

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
    /// Textes affichés dans d'autres langues (`en`, `fr`…) : nom, résumé et
    /// description. Les champs de premier niveau restent la langue de base.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub translations: BTreeMap<String, Translation>,
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
            return Err(tr!("plateforme {} ≠ {}", "platform {} ≠ {}", self.platform, p.os));
        }
        if p.os == Os::Linux && !self.distributions.contains(&p.distribution) {
            return Err(tr!(
                "distribution {} non visée ({})",
                "distribution {} not targeted ({})",
                p.distribution,
                self.distributions.iter().map(|d| d.as_str()).collect::<Vec<_>>().join(", ")
            ));
        }
        let arch_exact = self.architectures.contains(&p.arch);
        let native = arch_exact || self.architectures.contains(&Arch::Any);
        if !native && !self.architectures.iter().any(|a| a.emulated_on(p.arch, p.os)) {
            return Err(tr!(
                "architecture {} non prise en charge",
                "unsupported architecture {}",
                p.arch
            ));
        }
        if let Some(req) = &self.os_version {
            if !req.matches(&p.version) {
                return Err(tr!(
                    "version du système {} hors de « {} »",
                    "system version {} outside “{}”",
                    p.version,
                    req
                ));
            }
        }
        Ok(MatchQuality {
            native,
            arch_exact,
            version_constrained: self.os_version.is_some(),
        })
    }
}

/// Qualité d'une correspondance (utilisée pour départager plusieurs variantes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct MatchQuality {
    /// Exécution native (et non par émulation x86_64 sur arm64).
    pub native: bool,
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
        let (fr, en) = if self.fatal {
            ("ERREUR", "ERROR")
        } else {
            ("AVERTISSEMENT", "WARNING")
        };
        f.write_str(&tr!("[{fr}] {} : {}", "[{en}] {}: {}", self.path, self.message))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    TooLarge(usize),
    Yaml(String),
    Schema(Vec<String>),
    Invalid(Vec<Issue>),
}

impl fmt::Display for ManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            ManifestError::TooLarge(n) => tr!(
                "manifeste trop volumineux ({n} octets, maximum {MAX_MANIFEST_SIZE})",
                "manifest too large ({n} bytes, maximum {MAX_MANIFEST_SIZE})"
            ),
            ManifestError::Yaml(e) => tr!("YAML invalide : {e}", "invalid YAML: {e}"),
            ManifestError::Schema(v) => tr!(
                "manifeste non conforme au schéma :\n{}",
                "manifest does not match the schema:\n{}",
                v.join("\n")
            ),
            ManifestError::Invalid(v) => tr!(
                "manifeste invalide :\n{}",
                "invalid manifest:\n{}",
                v.iter()
                    .filter(|i| i.fatal)
                    .map(|i| i.to_string())
                    .collect::<Vec<_>>()
                    .join("\n")
            ),
        };
        f.write_str(&s)
    }
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
                tr!(
                    "version de format {} non prise en charge (attendu {MANIFEST_FORMAT})",
                    "unsupported format version {} (expected {MANIFEST_FORMAT})",
                    self.format
                ),
            );
        }
        if !ids::is_valid_app_id(&self.id) {
            v.err(
                "id",
                tr!(
                    "identifiant invalide (minuscules, chiffres, « . », « - », « + », 2 à 64 caractères)",
                    "invalid identifier (lowercase letters, digits, “.”, “-”, “+”, 2 to 64 characters)"
                ),
            );
        }
        if !version::is_valid_version(&self.version) {
            v.err(
                "version",
                tr!(
                    "version invalide (doit commencer par un chiffre ; caractères autorisés : alphanumériques et .+-~_)",
                    "invalid version (must start with a digit; allowed characters: alphanumerics and .+-~_)"
                ),
            );
        }
        for (field, val, max) in [
            ("name", &self.name, 128usize),
            ("publisher", &self.publisher, 128),
            ("summary", &self.summary, 200),
            ("license", &self.license, 128),
        ] {
            if val.trim().is_empty() {
                v.err(field, tr!("champ obligatoire vide", "required field is empty"));
            } else if val.chars().count() > max || val.chars().any(|c| c.is_control()) {
                v.err(
                    field,
                    tr!(
                        "valeur invalide (maximum {max} caractères, sans caractère de contrôle)",
                        "invalid value (at most {max} characters, no control characters)"
                    ),
                );
            }
        }
        if let Some(h) = &self.homepage {
            if !h.starts_with("https://") {
                v.warn(
                    "homepage",
                    tr!("la page d'accueil devrait utiliser HTTPS", "the homepage should use HTTPS"),
                );
            }
        }
        if self.languages.is_empty() {
            v.err(
                "languages",
                tr!(
                    "au moins une langue est requise (« mul » pour multilingue)",
                    "at least one language is required (“mul” for multilingual)"
                ),
            );
        }
        for (i, l) in self.languages.iter().enumerate() {
            if !ids::is_valid_language(l) {
                v.err(
                    format!("languages[{i}]"),
                    tr!("code de langue invalide : {l}", "invalid language code: {l}"),
                );
            }
        }
        for (l, t) in &self.translations {
            let base = format!("translations.{l}");
            if !ids::is_valid_language(l) || l == "mul" {
                v.err(&base, tr!("code de langue invalide : {l}", "invalid language code: {l}"));
            }
            let fields = [
                ("name", t.name.as_deref(), 128usize),
                ("summary", Some(t.summary.as_str()), 200),
            ];
            for (field, val, max) in fields {
                let Some(val) = val else { continue };
                if val.trim().is_empty() {
                    v.err(
                        format!("{base}.{field}"),
                        tr!("champ obligatoire vide", "required field is empty"),
                    );
                } else if val.chars().count() > max || val.chars().any(|c| c.is_control()) {
                    v.err(
                        format!("{base}.{field}"),
                        tr!(
                            "valeur invalide (maximum {max} caractères, sans caractère de contrôle)",
                            "invalid value (at most {max} characters, no control characters)"
                        ),
                    );
                }
            }
            if t.description.as_ref().map(|d| d.chars().count() > 20_000).unwrap_or(false) {
                v.err(
                    format!("{base}.description"),
                    tr!(
                        "description trop longue (20 000 caractères au plus)",
                        "description too long (at most 20,000 characters)"
                    ),
                );
            }
        }
        let mut dep_ids = BTreeSet::new();
        for (i, d) in self.dependencies.iter().enumerate() {
            if !ids::is_valid_app_id(&d.id) {
                v.err(
                    format!("dependencies[{i}].id"),
                    tr!("identifiant invalide", "invalid identifier"),
                );
            }
            if d.id == self.id {
                v.err(
                    format!("dependencies[{i}]"),
                    tr!(
                        "une application ne peut pas dépendre d'elle-même",
                        "an application cannot depend on itself"
                    ),
                );
            }
            if !dep_ids.insert(&d.id) {
                v.err(
                    format!("dependencies[{i}]"),
                    tr!("dépendance dupliquée", "duplicate dependency"),
                );
            }
        }
        let mut content_paths = BTreeSet::new();
        for (i, c) in self.contents.iter().enumerate() {
            let p = format!("contents[{i}]");
            if !ids::is_safe_relative_path(&c.path) {
                v.err(
                    &p,
                    tr!("chemin dangereux ou invalide : {}", "dangerous or invalid path: {}", c.path),
                );
            } else if !(c.path.starts_with("payload/") || c.path.starts_with("scripts/")) {
                v.err(
                    &p,
                    tr!(
                        "les fichiers doivent se trouver dans payload/ ou scripts/",
                        "files must be under payload/ or scripts/"
                    ),
                );
            }
            if !is_sha256_hex(&c.sha256) {
                v.err(
                    &p,
                    tr!(
                        "empreinte SHA-256 invalide (64 caractères hexadécimaux minuscules)",
                        "invalid SHA-256 digest (64 lowercase hexadecimal characters)"
                    ),
                );
            }
            if !content_paths.insert(c.path.as_str()) {
                v.err(&p, tr!("chemin dupliqué", "duplicate path"));
            }
        }
        if self.targets.is_empty() {
            v.err(
                "targets",
                tr!("au moins une variante est requise", "at least one target is required"),
            );
        }
        let mut names = BTreeSet::new();
        for (i, t) in self.targets.iter().enumerate() {
            if !names.insert(&t.name) {
                v.err(
                    format!("targets[{i}].name"),
                    tr!("nom de variante dupliqué", "duplicate target name"),
                );
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
                Err(e) => reasons.push(tr!("{} : {}", "{}: {}", t.name, e)),
            }
        }
        best.map(|(_, t)| t).ok_or_else(|| {
            tr!(
                "aucune variante de {} {} ne correspond à {} {} ({}) :\n  {}",
                "no target of {} {} matches {} {} ({}):\n  {}",
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

    /// Nom de fichier normalisé : `<Nom>-<version>-<langue>.aupak`.
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
        format!("{}-{}-{}.aupak", name, self.version, lang)
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
            tr!(
                "nom de variante invalide (minuscules, chiffres, « - », « _ »)",
                "invalid target name (lowercase letters, digits, “-”, “_”)"
            ),
        );
    }
    if t.architectures.is_empty() {
        v.err(
            format!("{p}.architectures"),
            tr!(
                "au moins une architecture est requise",
                "at least one architecture is required"
            ),
        );
    }
    if t.architectures.contains(&Arch::Any) && t.architectures.len() > 1 {
        v.err(
            format!("{p}.architectures"),
            tr!(
                "« any » ne peut pas être combiné à d'autres architectures",
                "“any” cannot be combined with other architectures"
            ),
        );
    }
    match t.platform {
        Os::Linux => {
            if t.distributions.is_empty() {
                v.err(
                    format!("{p}.distributions"),
                    tr!("obligatoire pour une variante Linux", "required for a Linux target"),
                );
            }
            for d in &t.distributions {
                if d.os() != Os::Linux || *d == Distribution::Unknown {
                    v.err(
                        format!("{p}.distributions"),
                        tr!(
                            "{d} n'est pas une distribution Linux prise en charge",
                            "{d} is not a supported Linux distribution"
                        ),
                    );
                }
            }
        }
        os => {
            for d in &t.distributions {
                if d.os() != os {
                    v.err(
                        format!("{p}.distributions"),
                        tr!(
                            "{d} incompatible avec la plateforme {os}",
                            "{d} is incompatible with platform {os}"
                        ),
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
                v.err(
                    &ip,
                    tr!(
                        "la méthode package_manager exige le mode native",
                        "the package_manager method requires native mode"
                    ),
                );
            }
            check_manager(v, &ip, *manager, &target_dists);
            if packages.is_empty() {
                v.err(
                    format!("{ip}.packages"),
                    tr!("au moins un paquet est requis", "at least one package is required"),
                );
            }
            for pk in packages {
                if !ids::is_valid_native_package(pk) {
                    v.err(
                        format!("{ip}.packages"),
                        tr!("nom de paquet natif invalide : {pk}", "invalid native package name: {pk}"),
                    );
                }
            }
        }
        Install::Deb { package, source } => {
            if t.platform != Os::Linux {
                v.err(
                    &ip,
                    tr!("la méthode deb est réservée à Linux", "the deb method is for Linux only"),
                );
            }
            if t.distributions
                .iter()
                .any(|d| matches!(d, Distribution::Auxinuxos | Distribution::Virtuaos))
            {
                v.warn(
                    &ip,
                    tr!(
                        "sur AuxiNuxOS/VirtuaOS, un .deb ne s'installe que si l'adaptateur système définit install_local_deb \
                         (APT est bloqué) ; préférez package_manager (auxi) ou files",
                        "on AuxiNuxOS/VirtuaOS, a .deb can only be installed if the system adapter defines install_local_deb \
                         (APT is blocked); prefer package_manager (auxi) or files"
                    ),
                );
            }
            if !ids::is_valid_native_package(package) {
                v.err(
                    format!("{ip}.package"),
                    tr!("nom de paquet Debian invalide", "invalid Debian package name"),
                );
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
                    v.err(
                        format!("{ip}.product_code"),
                        tr!("code produit MSI invalide ({{GUID}})", "invalid MSI product code ({{GUID}})"),
                    );
                }
            } else if t.remove.is_none() {
                v.warn(
                    format!("{ip}.product_code"),
                    tr!(
                        "sans product_code, la désinstallation doit être déclarée explicitement",
                        "without product_code, uninstallation must be declared explicitly"
                    ),
                );
            }
            for (k, val) in properties {
                if !ids::is_valid_msi_property(k) || !ids::is_valid_installer_arg(val) {
                    v.err(
                        format!("{ip}.properties"),
                        tr!("propriété MSI invalide : {k}", "invalid MSI property: {k}"),
                    );
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
                    tr!(
                        "privilèges non déclarés pour un installateur exe (admin supposé)",
                        "privileges not declared for an exe installer (admin assumed)"
                    ),
                );
            }
        }
        Install::Pkg { source, package_id } => {
            require_platform(v, &ip, t.platform, Os::Macos, "pkg");
            check_source(v, &ip, t.mode, source, contents, &[".pkg"]);
            if !ids::is_valid_reverse_dns(package_id) {
                v.err(
                    format!("{ip}.package_id"),
                    tr!("identifiant de reçu invalide", "invalid receipt identifier"),
                );
            }
        }
        Install::Dmg { source, app } => {
            require_platform(v, &ip, t.platform, Os::Macos, "dmg");
            check_source(v, &ip, t.mode, source, contents, &[".dmg"]);
            if !ids::is_safe_file_name(app) || !app.ends_with(".app") {
                v.err(
                    format!("{ip}.app"),
                    tr!(
                        "nom de bundle invalide (ex. « Firefox.app »)",
                        "invalid bundle name (e.g. “Firefox.app”)"
                    ),
                );
            }
        }
        Install::Files { files } => {
            if t.mode != Mode::Embedded {
                v.err(
                    &ip,
                    tr!(
                        "la méthode files exige le mode embedded",
                        "the files method requires embedded mode"
                    ),
                );
            }
            if files.is_empty() {
                v.err(
                    format!("{ip}.files"),
                    tr!("au moins un fichier est requis", "at least one file is required"),
                );
            }
            for (i, f) in files.iter().enumerate() {
                let fp = format!("{ip}.files[{i}]");
                if !f.source.starts_with("payload/") || !ids::is_safe_relative_path(&f.source) {
                    v.err(&fp, tr!("source invalide : {}", "invalid source: {}", f.source));
                } else if !contents.contains(f.source.as_str())
                    && !contents.iter().any(|c| c.starts_with(&format!("{}/", f.source)))
                {
                    v.err(
                        &fp,
                        tr!(
                            "source absente de contents : {}",
                            "source missing from contents: {}",
                            f.source
                        ),
                    );
                }
                if !is_valid_templated_path(&f.destination, &FILE_DEST_ROOTS) {
                    v.err(
                        &fp,
                        tr!(
                            "destination invalide (doit commencer par {{app}}, {{bin}} ou {{data}}) : {}",
                            "invalid destination (must start with {{app}}, {{bin}} or {{data}}): {}",
                            f.destination
                        ),
                    );
                }
            }
        }
        Install::Script { script, args } => {
            if t.mode != Mode::Embedded {
                v.err(
                    &ip,
                    tr!(
                        "la méthode script exige le mode embedded",
                        "the script method requires embedded mode"
                    ),
                );
            }
            check_script(v, &format!("{ip}.script"), script, t.platform, contents);
            check_args(v, &ip, args);
            if t.remove.is_none() {
                v.err(
                    format!("{p}.remove"),
                    tr!(
                        "une installation par script exige une désinstallation explicite",
                        "a script installation requires an explicit uninstallation"
                    ),
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
                        v.err(
                            &rp,
                            tr!("nom de paquet natif invalide : {pk}", "invalid native package name: {pk}"),
                        );
                    }
                }
            }
            Remove::Deb { package } => {
                if t.platform != Os::Linux || !ids::is_valid_native_package(package) {
                    v.err(&rp, tr!("désinstallation deb invalide", "invalid deb uninstallation"));
                }
            }
            Remove::Msi { product_code } => {
                require_platform(v, &rp, t.platform, Os::Windows, "msi");
                if !ids::is_valid_msi_product_code(product_code) {
                    v.err(&rp, tr!("code produit MSI invalide", "invalid MSI product code"));
                }
            }
            Remove::Exe { path, args } => {
                require_platform(v, &rp, t.platform, Os::Windows, "exe");
                if !is_valid_templated_path(path, &WINDOWS_PATH_ROOTS) || !path.to_ascii_lowercase().ends_with(".exe") {
                    v.err(&rp, tr!(
                            "chemin de désinstallation invalide (racine {{program_files}}, {{program_files_x86}}, {{local_app_data}} ou {{app}})",
                            "invalid uninstaller path (root {{program_files}}, {{program_files_x86}}, {{local_app_data}} or {{app}})"
                        ));
                }
                check_args(v, &rp, args);
            }
            Remove::Pkg { package_id, paths } => {
                require_platform(v, &rp, t.platform, Os::Macos, "pkg");
                if !ids::is_valid_reverse_dns(package_id) {
                    v.err(&rp, tr!("identifiant de reçu invalide", "invalid receipt identifier"));
                }
                for path in paths {
                    let ok = path
                        .strip_prefix("/Applications/")
                        .map(ids::is_safe_relative_path)
                        .unwrap_or(false);
                    if !ok {
                        v.err(
                            &rp,
                            tr!(
                                "chemin non autorisé (doit être sous /Applications) : {path}",
                                "path not allowed (must be under /Applications): {path}"
                            ),
                        );
                    }
                }
            }
            Remove::App { app } => {
                require_platform(v, &rp, t.platform, Os::Macos, "app");
                if !ids::is_safe_file_name(app) || !app.ends_with(".app") {
                    v.err(&rp, tr!("nom de bundle invalide", "invalid bundle name"));
                }
            }
            Remove::Files => {
                if !matches!(t.install, Install::Files { .. }) {
                    v.err(
                        &rp,
                        tr!(
                            "la désinstallation files n'est possible que pour une installation files",
                            "files uninstallation is only possible for a files installation"
                        ),
                    );
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
            tr!(
                "aucune procédure de désinstallation ne peut être déduite : déclarez « remove »",
                "no uninstallation procedure can be inferred: declare “remove”"
            ),
        );
    }

    if let Some(d) = &t.detect {
        let dp = format!("{p}.detect");
        match d {
            Detect::PackageManager { manager, package } => {
                check_manager(v, &dp, *manager, &target_dists);
                if !ids::is_valid_native_package(package) {
                    v.err(&dp, tr!("nom de paquet invalide", "invalid package name"));
                }
            }
            Detect::Msi { product_code } => {
                if !ids::is_valid_msi_product_code(product_code) {
                    v.err(&dp, tr!("code produit MSI invalide", "invalid MSI product code"));
                }
            }
            Detect::Pkg { package_id } => {
                if !ids::is_valid_reverse_dns(package_id) {
                    v.err(&dp, tr!("identifiant de reçu invalide", "invalid receipt identifier"));
                }
            }
            Detect::App { app } => {
                if !ids::is_safe_file_name(app) {
                    v.err(&dp, tr!("nom de bundle invalide", "invalid bundle name"));
                }
            }
            Detect::Files { paths } => {
                for path in paths {
                    if !is_valid_templated_path(path, &FILE_DEST_ROOTS) {
                        v.err(&dp, tr!("chemin invalide : {path}", "invalid path: {path}"));
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
            tr!(
                "cette variante utilise des scripts personnalisés : leur exécution exigera une autorisation explicite",
                "this target uses custom scripts: running them will require explicit permission"
            ),
        );
    }
    for nd in &t.native_dependencies {
        if !ids::is_valid_native_package(nd) {
            v.err(
                format!("{p}.native_dependencies"),
                tr!("nom de paquet natif invalide : {nd}", "invalid native package name: {nd}"),
            );
        }
    }
    if !t.native_dependencies.is_empty() && t.platform != Os::Linux {
        v.err(
            format!("{p}.native_dependencies"),
            tr!(
                "les dépendances natives ne sont prises en charge que sous Linux",
                "native dependencies are only supported on Linux"
            ),
        );
    }
    if t.success_codes.is_empty() {
        v.err(
            format!("{p}.success_codes"),
            tr!(
                "au moins un code de succès est requis",
                "at least one success code is required"
            ),
        );
    }
    if let Some(s) = t.timeout_seconds {
        if s == 0 || s > 24 * 3600 {
            v.err(
                format!("{p}.timeout_seconds"),
                tr!("délai invalide (1 à 86400 secondes)", "invalid timeout (1 to 86400 seconds)"),
            );
        }
    }
}

fn require_platform(v: &mut Validator, p: &str, actual: Os, expected: Os, what: &str) {
    if actual != expected {
        v.err(
            p,
            tr!(
                "la méthode {what} est réservée à {expected}",
                "the {what} method is for {expected} only"
            ),
        );
    }
}

fn check_manager(v: &mut Validator, p: &str, m: Manager, dists: &[Distribution]) {
    for d in dists {
        if !m.allowed_on().contains(d) {
            v.err(
                p,
                tr!(
                    "le gestionnaire {m} n'est pas autorisé sur {d}",
                    "package manager {m} is not allowed on {d}"
                ),
            );
        }
    }
}

fn check_args(v: &mut Validator, p: &str, args: &[String]) {
    for a in args {
        if !ids::is_valid_installer_arg(a) {
            v.err(
                format!("{p}.args"),
                tr!("argument refusé : {a:?}", "argument rejected: {a:?}"),
            );
        }
    }
}

fn check_script(v: &mut Validator, p: &str, script: &str, platform: Os, contents: &BTreeSet<&str>) {
    if !script.starts_with("scripts/") || !ids::is_safe_relative_path(script) {
        v.err(
            p,
            tr!(
                "le script doit se trouver dans scripts/ : {script}",
                "the script must be under scripts/: {script}"
            ),
        );
        return;
    }
    let ok_ext = match platform {
        Os::Windows => script.ends_with(".ps1"),
        _ => script.ends_with(".sh"),
    };
    if !ok_ext {
        v.err(
            p,
            tr!(
                "extension de script incompatible avec la plateforme (.sh pour Linux/macOS, .ps1 pour Windows)",
                "script extension does not match the platform (.sh for Linux/macOS, .ps1 for Windows)"
            ),
        );
    }
    if !contents.contains(script) {
        v.err(
            p,
            tr!(
                "script absent de contents : {script}",
                "script missing from contents: {script}"
            ),
        );
    }
}

fn check_source(v: &mut Validator, p: &str, mode: Mode, s: &Source, contents: &BTreeSet<&str>, exts: &[&str]) {
    let sp = format!("{p}.source");
    match mode {
        Mode::Embedded => {
            if s.url.is_some() || s.sha256.is_some() || !s.allowed_hosts.is_empty() || s.file_name.is_some() {
                v.err(
                    &sp,
                    tr!(
                        "en mode embedded, seul « file » est autorisé",
                        "in embedded mode, only “file” is allowed"
                    ),
                );
            }
            match &s.file {
                None => v.err(
                    &sp,
                    tr!(
                        "« file » est obligatoire en mode embedded",
                        "“file” is required in embedded mode"
                    ),
                ),
                Some(f) => {
                    if !f.starts_with("payload/") || !ids::is_safe_relative_path(f) {
                        v.err(&sp, tr!("chemin invalide : {f}", "invalid path: {f}"));
                    } else if !contents.contains(f.as_str()) {
                        v.err(
                            &sp,
                            tr!("fichier absent de contents : {f}", "file missing from contents: {f}"),
                        );
                    }
                    if !exts.iter().any(|e| f.to_ascii_lowercase().ends_with(e)) {
                        v.err(&sp, tr!("extension attendue : {}", "expected extension: {}", exts.join(", ")));
                    }
                }
            }
        }
        Mode::Remote => {
            if s.file.is_some() {
                v.err(
                    &sp,
                    tr!("« file » est interdit en mode remote", "“file” is not allowed in remote mode"),
                );
            }
            match &s.url {
                None => v.err(
                    &sp,
                    tr!("« url » est obligatoire en mode remote", "“url” is required in remote mode"),
                ),
                Some(u) => {
                    if let Err(e) = crate::netpolicy::validate_https_url(u) {
                        v.err(&sp, e);
                    }
                }
            }
            match &s.sha256 {
                Some(h) if is_sha256_hex(h) => {}
                _ => v.err(
                    &sp,
                    tr!(
                        "« sha256 » valide est obligatoire en mode remote",
                        "a valid “sha256” is required in remote mode"
                    ),
                ),
            }
            if s.size.is_none() {
                v.warn(
                    &sp,
                    tr!(
                        "taille non déclarée : la limite de téléchargement par défaut s'appliquera",
                        "size not declared: the default download limit will apply"
                    ),
                );
            }
            for h in &s.allowed_hosts {
                if !crate::netpolicy::is_valid_host(h) {
                    v.err(&sp, tr!("hôte invalide : {h}", "invalid host: {h}"));
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
                            tr!(
                                "le fichier téléchargé doit avoir l'extension {}",
                                "the downloaded file must have the extension {}",
                                exts.join(", ")
                            ),
                        );
                    }
                }
                _ => v.err(
                    &sp,
                    tr!(
                        "nom de fichier local indéterminable : déclarez « file_name »",
                        "cannot determine the local file name: declare “file_name”"
                    ),
                ),
            }
        }
        Mode::Native => v.err(
            p,
            tr!(
                "le mode native exige la méthode package_manager",
                "native mode requires the package_manager method"
            ),
        ),
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

    #[test]
    fn translations_are_parsed_and_validated() {
        let yaml = r#"
format: 1
id: demo
name: Démo
version: "1.0"
publisher: X
summary: Résumé en français
license: MIT
languages: [mul]
translations:
  en:
    name: Demo
    summary: English summary
    description: English description
  de:
    summary: Deutsche Zusammenfassung
targets:
  - name: win
    platform: windows
    architectures: [x86_64]
    mode: native
    install: { method: package_manager, manager: winget, packages: [Demo.Demo] }
"#;
        let (m, issues) = Manifest::parse(yaml.as_bytes()).unwrap();
        assert!(issues.iter().all(|i| !i.fatal), "{issues:?}");
        assert_eq!(m.translations["en"].name.as_deref(), Some("Demo"));
        assert_eq!(m.translations["de"].summary, "Deutsche Zusammenfassung");
        // Clé de langue invalide, résumé manquant ou champ inconnu : refusés.
        for bad in [
            yaml.replace("  de:\n", "  deutsch:\n"),
            yaml.replace("    summary: Deutsche Zusammenfassung\n", "    name: X\n"),
            yaml.replace("    description: English description\n", "    tagline: x\n"),
        ] {
            assert!(Manifest::parse(bad.as_bytes()).is_err(), "{bad}");
        }
    }

    #[test]
    fn x86_64_target_matches_arm64_windows_and_macos_by_emulation_only() {
        let yaml = r#"
format: 1
id: demo
name: Demo
version: "1.0"
publisher: X
summary: s
license: MIT
languages: [en]
targets:
  - name: win
    platform: windows
    architectures: [x86_64]
    mode: native
    install: { method: package_manager, manager: winget, packages: [Demo.Demo] }
  - name: deb
    platform: linux
    distributions: [debian]
    architectures: [x86_64]
    mode: native
    install: { method: package_manager, manager: apt, packages: [demo] }
"#;
        let (m, _) = Manifest::parse(yaml.as_bytes()).unwrap();
        let win_arm = SystemProfile {
            os: Os::Windows,
            distribution: Distribution::Windows,
            version: "10.0.26100".into(),
            arch: Arch::Arm64,
            raw_id: String::new(),
            pretty_name: String::new(),
            immutable: false,
        };
        let t = m.select_target(&win_arm).unwrap();
        assert_eq!(t.name, "win");
        assert!(!t.matches(&win_arm).unwrap().native);
        let deb_arm = SystemProfile {
            os: Os::Linux,
            distribution: Distribution::Debian,
            version: "13".into(),
            arch: Arch::Arm64,
            raw_id: String::new(),
            pretty_name: String::new(),
            immutable: false,
        };
        assert!(m.select_target(&deb_arm).is_err(), "pas d'émulation sous Linux");
    }

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
        crate::i18n::set(crate::i18n::Lang::En);
        let err = m.select_target(&mac).unwrap_err();
        assert!(err.contains("no target of"), "{err}");
    }

    #[test]
    fn rejects_unknown_fields_and_free_commands() {
        let bad = DEMO.replace("    mode: native\n", "    mode: native\n    command: \"rm -rf /\"\n");
        assert!(Manifest::parse(bad.as_bytes()).is_err());
    }

    #[test]
    fn rejects_apt_on_auxinuxos() {
        let bad = DEMO.replace("      manager: auxi", "      manager: apt");
        crate::i18n::set(crate::i18n::Lang::En);
        let err = Manifest::parse(bad.as_bytes()).unwrap_err().to_string();
        assert!(err.contains("apt is not allowed on auxinuxos"), "{err}");
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
        crate::i18n::set(crate::i18n::Lang::En);
        let err = Manifest::parse(s.as_bytes()).unwrap_err().to_string();
        assert!(err.contains("explicit uninstallation"), "{err}");
    }
}
