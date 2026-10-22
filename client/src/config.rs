//! Configuration du client (`config.toml`).

use crate::paths::Paths;
use anyhow::{bail, Context, Result};
use auxipak_core::{ids, netpolicy, tr};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const DEFAULT_TTL: u64 = 3600;
pub const OFFICIAL_URL: &str = "https://auxipak.auxinux.ca/repos/official/";

/// Ancres de confiance du dépôt officiel, embarquées à la compilation lorsque
/// `AUXIPAK_OFFICIAL_TRUST_DIR` est défini (voir `build.rs` et docs/SIGNING.md).
pub mod embedded {
    include!(concat!(env!("OUT_DIR"), "/trust_embedded.rs"));
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default = "default_ttl")]
    pub cache_ttl_seconds: u64,
    /// Langue préférée pour le choix des paquets ; à défaut, la langue de
    /// l'interface (`auxipak set lang`, puis langue du système).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
    #[serde(default, rename = "repository")]
    pub repositories: Vec<RepoConfig>,
    #[serde(default)]
    pub adapters: Adapters,
    #[serde(default)]
    pub policy: Policy,
}

fn default_ttl() -> u64 {
    DEFAULT_TTL
}
fn yes() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepoConfig {
    pub name: String,
    pub url: String,
    /// `root.json` TUF de confiance (chemin relatif au répertoire de configuration).
    pub root: PathBuf,
    /// Clés publiques de signature des paquets.
    pub package_keys: PathBuf,
    /// Dépôt officiel AuxiNux : seul un dépôt marqué officiel **dans la
    /// configuration locale** peut afficher les statuts « Vérifié » et
    /// « Compatible ».
    #[serde(default)]
    pub official: bool,
    #[serde(default = "yes")]
    pub enabled: bool,
    /// Autorise l'exécution de scripts personnalisés provenant de ce dépôt
    /// (en plus de l'option explicite `--allow-scripts`).
    #[serde(default)]
    pub allow_scripts: bool,
    #[serde(default = "yes")]
    pub require_signatures: bool,
    /// Développement uniquement : HTTP autorisé vers localhost.
    #[serde(default)]
    pub allow_insecure_localhost: bool,
    #[serde(default)]
    pub priority: i32,
}

/// Adaptateur configurable pour un gestionnaire système dont la syntaxe doit
/// être validée sur le système réel (`auxi` d'AuxiNuxOS, VirtuaOS).
///
/// Chaque commande est un vecteur d'arguments ; `{packages}` est remplacé par
/// la liste (validée) des paquets, `{package}` par un paquet, `{file}` par le
/// chemin d'un fichier local. Aucun interpréteur de commandes n'est utilisé.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct AdapterConfig {
    pub program: String,
    #[serde(default)]
    pub install: Vec<String>,
    #[serde(default)]
    pub remove: Vec<String>,
    /// Commande dont le code de retour 0 signifie « installé ».
    #[serde(default)]
    pub query: Vec<String>,
    /// Installation d'un paquet `.deb` local (si le système le permet).
    #[serde(default)]
    pub install_local_deb: Vec<String>,
    /// Indique que la syntaxe a été validée sur le système réel.
    #[serde(default)]
    pub validated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Adapters {
    #[serde(default = "default_auxi")]
    pub auxi: AdapterConfig,
    #[serde(default)]
    pub virtuaos: AdapterConfig,
}

impl Default for Adapters {
    fn default() -> Self {
        Adapters {
            auxi: default_auxi(),
            virtuaos: AdapterConfig::default(),
        }
    }
}

/// Valeurs par défaut de l'adaptateur `auxi`, vérifiées contre le script
/// `auxi` d'AuxiNux OS 0.3.0 (voir docs/CLI_REFERENCE.md, « Adaptateur auxi ») :
/// - `--yes` (option globale, AVANT la commande) : apt-get -y, debconf non
///   interactif, conffiles conservés ;
/// - `--deb` : jamais Flatpak, plusieurs paquets acceptés à l'installation ;
/// - `uninstall --deb` ne retire que le premier paquet : `{package}`, un appel
///   par paquet ;
/// - un `.deb` local passe par `install --deb CHEMIN_ABSOLU` (apt-get) ;
/// - pas de requête d'état : `query` vide = `dpkg-query -W` direct.
///
/// Un paquet NOUVEAU est refusé par auxi tant que `auxi set deb=true` n'a pas
/// été fait (réglage d'AuxiNux OS, respecté tel quel).
pub fn default_auxi() -> AdapterConfig {
    AdapterConfig {
        program: "auxi".into(),
        install: ["--yes", "install", "--deb", "{packages}"].map(String::from).to_vec(),
        remove: ["--yes", "uninstall", "--deb", "{package}"].map(String::from).to_vec(),
        query: vec![],
        install_local_deb: ["--yes", "install", "--deb", "{file}"].map(String::from).to_vec(),
        validated: true,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// Autorise Homebrew (fournisseur tiers) sur macOS.
    #[serde(default = "yes")]
    pub allow_brew: bool,
    /// Taille maximale d'un paquet téléchargé (octets).
    #[serde(default = "default_max_download")]
    pub max_download_bytes: u64,
}

fn default_max_download() -> u64 {
    32 * 1024 * 1024 * 1024
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            allow_brew: true,
            max_download_bytes: default_max_download(),
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Config {
            cache_ttl_seconds: DEFAULT_TTL,
            language: None,
            repositories: vec![RepoConfig {
                name: "official".into(),
                url: OFFICIAL_URL.into(),
                root: "trust/official/root.json".into(),
                package_keys: "trust/official/package-keys.json".into(),
                official: true,
                enabled: true,
                allow_scripts: false,
                require_signatures: true,
                allow_insecure_localhost: false,
                priority: 0,
            }],
            adapters: Adapters::default(),
            policy: Policy::default(),
        }
    }
}

impl Config {
    pub fn load(paths: &Paths) -> Result<Config> {
        let file = paths.config_file();
        let cfg: Config = if file.exists() {
            let text = std::fs::read_to_string(&file).with_context(|| tr!("lecture de {}", "reading {}", file.display()))?;
            toml::from_str(&text)
                .with_context(|| tr!("configuration invalide : {}", "invalid configuration: {}", file.display()))?
        } else if let Some(sys) = paths
            .system_config_dir
            .as_ref()
            .map(|d| d.join("config.toml"))
            .filter(|f| f.exists())
        {
            let text = std::fs::read_to_string(&sys)?;
            toml::from_str(&text)
                .with_context(|| tr!("configuration invalide : {}", "invalid configuration: {}", sys.display()))?
        } else {
            Config::default()
        };
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn save(&self, paths: &Paths) -> Result<()> {
        self.validate()?;
        let text = toml::to_string_pretty(self)?;
        crate::paths::atomic_write(&paths.config_file(), text.as_bytes())?;
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        if self.cache_ttl_seconds == 0 || self.cache_ttl_seconds > 7 * 24 * 3600 {
            bail!(tr!("cache_ttl_seconds invalide", "invalid cache_ttl_seconds"));
        }
        let mut names = std::collections::BTreeSet::new();
        for r in &self.repositories {
            if !ids::is_valid_repo_name(&r.name) {
                bail!(tr!("nom de dépôt invalide : {}", "invalid repository name: {}", r.name));
            }
            if !names.insert(&r.name) {
                bail!(tr!("dépôt dupliqué : {}", "duplicate repository: {}", r.name));
            }
            netpolicy::validate_repo_url(&r.url, r.allow_insecure_localhost)
                .map_err(|e| anyhow::anyhow!(tr!("dépôt {} : {e}", "repository {}: {e}", r.name)))?;
        }
        for (name, a) in [("auxi", &self.adapters.auxi), ("virtuaos", &self.adapters.virtuaos)] {
            for arg in a.install.iter().chain(&a.remove).chain(&a.query).chain(&a.install_local_deb) {
                if !(arg.starts_with('{') && arg.ends_with('}')) && !ids::is_valid_installer_arg(arg) {
                    bail!(tr!(
                        "adaptateur {name} : argument invalide {arg:?}",
                        "{name} adapter: invalid argument {arg:?}"
                    ));
                }
            }
        }
        Ok(())
    }

    /// Langue retenue pour choisir la variante linguistique d'un paquet.
    pub fn package_language(&self) -> String {
        self.language
            .clone()
            .unwrap_or_else(|| auxipak_core::i18n::current().code().to_string())
    }

    pub fn repo(&self, name: &str) -> Option<&RepoConfig> {
        self.repositories.iter().find(|r| r.name == name)
    }

    pub fn enabled_repos(&self) -> impl Iterator<Item = &RepoConfig> {
        let mut v: Vec<&RepoConfig> = self.repositories.iter().filter(|r| r.enabled).collect();
        v.sort_by_key(|r| r.priority);
        v.into_iter()
    }
}

/// Contenu d'une ancre de confiance (root.json ou package-keys.json).
pub struct TrustMaterial {
    pub root_json: Vec<u8>,
    pub package_keys: auxipak_core::signature::TrustedKeys,
    pub source: String,
}

/// Résout un chemin d'ancre : absolu, relatif au répertoire de configuration,
/// puis à la configuration système.
fn resolve_trust_path(paths: &Paths, p: &Path) -> Option<PathBuf> {
    if p.is_absolute() {
        return p.exists().then(|| p.to_path_buf());
    }
    let local = paths.config_dir.join(p);
    if local.exists() {
        return Some(local);
    }
    paths.system_config_dir.as_ref().map(|d| d.join(p)).filter(|f| f.exists())
}

impl RepoConfig {
    pub fn trust(&self, paths: &Paths) -> Result<TrustMaterial> {
        let root = resolve_trust_path(paths, &self.root);
        let keys = resolve_trust_path(paths, &self.package_keys);
        match (root, keys) {
            (Some(r), Some(k)) => Ok(TrustMaterial {
                root_json: std::fs::read(&r)?,
                package_keys: auxipak_core::signature::TrustedKeys::load(&k)
                    .with_context(|| tr!("clés de paquets invalides : {}", "invalid package keys: {}", k.display()))?,
                source: r.display().to_string(),
            }),
            _ if self.official && self.name == "official" => match (embedded::OFFICIAL_ROOT, embedded::OFFICIAL_PACKAGE_KEYS) {
                (Some(r), Some(k)) => Ok(TrustMaterial {
                    root_json: r.to_vec(),
                    package_keys: serde_json::from_slice(k)?,
                    source: tr!("ancre embarquée dans le client", "trust anchor built into the client"),
                }),
                _ => bail!(tr!(
                    "racine de confiance du dépôt « {} » introuvable ({}). Le dépôt officiel n'est pas encore \
                     initialisé dans ce client : voir docs/SIGNING.md",
                    "trust root of repository \"{}\" not found ({}). The official repository is not yet \
                     initialized in this client: see docs/SIGNING.md",
                    self.name,
                    self.root.display()
                )),
            },
            _ => bail!(tr!(
                "racine de confiance du dépôt « {} » introuvable ({} / {})",
                "trust root of repository \"{}\" not found ({} / {})",
                self.name,
                self.root.display(),
                self.package_keys.display()
            )),
        }
    }
}

/// Valeurs par défaut des adaptateurs, documentées.
pub fn adapter_for(cfg: &Config, manager: auxipak_core::manifest::Manager) -> Option<&AdapterConfig> {
    use auxipak_core::manifest::Manager;
    match manager {
        Manager::Auxi => Some(&cfg.adapters.auxi),
        Manager::Virtuaos => Some(&cfg.adapters.virtuaos),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_valid_and_roundtrips() {
        let c = Config::default();
        c.validate().unwrap();
        let t = toml::to_string_pretty(&c).unwrap();
        let c2: Config = toml::from_str(&t).unwrap();
        assert_eq!(c2.repositories[0].name, "official");
        assert_eq!(c2.cache_ttl_seconds, 3600);
    }

    #[test]
    fn rejects_insecure_repo_urls() {
        let mut c = Config::default();
        c.repositories[0].url = "http://auxipak.auxinux.ca/".into();
        assert!(c.validate().is_err());
        c.repositories[0].url = "http://127.0.0.1:8080/repos/official/".into();
        assert!(c.validate().is_err());
        c.repositories[0].allow_insecure_localhost = true;
        assert!(c.validate().is_ok());
    }

    #[test]
    fn auxi_adapter_defaults_match_auxi_syntax() {
        let a = default_auxi();
        assert!(a.validated);
        assert_eq!(a.install, ["--yes", "install", "--deb", "{packages}"]);
        assert_eq!(a.remove, ["--yes", "uninstall", "--deb", "{package}"]);
        assert_eq!(a.install_local_deb, ["--yes", "install", "--deb", "{file}"]);
        assert!(a.query.is_empty());
        Config::default().validate().unwrap();
    }

    #[test]
    fn deb_conffile_is_valid_and_matches_defaults() {
        // /etc/auxipak/config.toml du paquet .deb (packaging/deb).
        let c: Config = toml::from_str(include_str!("../../packaging/deb/config.toml")).unwrap();
        c.validate().unwrap();
        assert_eq!(c.repositories.len(), 1);
        let r = &c.repositories[0];
        assert_eq!(r.name, "official");
        assert_eq!(r.url, OFFICIAL_URL);
        assert!(r.official && !r.allow_insecure_localhost);
        let (a, d) = (&c.adapters.auxi, default_auxi());
        assert_eq!(a.program, d.program);
        assert_eq!(a.install, d.install);
        assert_eq!(a.remove, d.remove);
        assert_eq!(a.query, d.query);
        assert_eq!(a.install_local_deb, d.install_local_deb);
        assert!(a.validated);
    }

    #[test]
    fn rejects_adapter_injection() {
        let mut c = Config::default();
        c.adapters.auxi.install = vec!["install".into(), "; rm -rf /".into()];
        assert!(c.validate().is_err());
    }
}
