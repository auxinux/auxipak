//! Modèle de plateforme : système d'exploitation, distribution, architecture et
//! canal d'index correspondant.
//!
//! La détection « réelle » (lecture de `/etc/os-release`, API Windows, `sw_vers`)
//! est faite par le client ; ce module contient les types partagés et les
//! fonctions pures (analyse de `os-release`, calcul du canal) afin qu'elles
//! soient testables sur n'importe quel hôte.

use crate::tr;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

/// Famille de système d'exploitation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Os {
    Linux,
    Windows,
    Macos,
}

impl Os {
    pub fn as_str(&self) -> &'static str {
        match self {
            Os::Linux => "linux",
            Os::Windows => "windows",
            Os::Macos => "macos",
        }
    }

    /// Système d'exploitation pour lequel le binaire courant a été compilé.
    pub fn current() -> Option<Os> {
        match std::env::consts::OS {
            "linux" => Some(Os::Linux),
            "windows" => Some(Os::Windows),
            "macos" => Some(Os::Macos),
            _ => None,
        }
    }
}

impl fmt::Display for Os {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Os {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "linux" => Ok(Os::Linux),
            "windows" => Ok(Os::Windows),
            "macos" | "darwin" | "osx" => Ok(Os::Macos),
            other => Err(tr!("système inconnu : {other}", "unknown operating system: {other}")),
        }
    }
}

/// Architecture matérielle. `Any` désigne un paquet indépendant de l'architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Arch {
    #[serde(rename = "x86_64")]
    X86_64,
    Arm64,
    Any,
}

impl Arch {
    pub fn as_str(&self) -> &'static str {
        match self {
            Arch::X86_64 => "x86_64",
            Arch::Arm64 => "arm64",
            Arch::Any => "any",
        }
    }

    /// Architecture pour laquelle le binaire courant a été compilé.
    pub fn current() -> Option<Arch> {
        match std::env::consts::ARCH {
            "x86_64" => Some(Arch::X86_64),
            "aarch64" => Some(Arch::Arm64),
            _ => None,
        }
    }

    /// Indique si un paquet de cette architecture peut s'installer sur `system`.
    pub fn runs_on(&self, system: Arch) -> bool {
        *self == Arch::Any || *self == system
    }

    /// Cette architecture s'exécute-t-elle par émulation sur `system` ?
    /// x86_64 sur arm64 : oui sous Windows 11 et sous macOS (Rosetta 2) ;
    /// jamais sous Linux.
    pub fn emulated_on(&self, system: Arch, os: Os) -> bool {
        *self == Arch::X86_64 && system == Arch::Arm64 && matches!(os, Os::Windows | Os::Macos)
    }
}

impl fmt::Display for Arch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Arch {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "x86_64" | "amd64" | "x64" => Ok(Arch::X86_64),
            "arm64" | "aarch64" => Ok(Arch::Arm64),
            "any" | "all" | "noarch" => Ok(Arch::Any),
            other => Err(format!("architecture inconnue : {other}")),
        }
    }
}

/// Distribution (Linux) ou édition (Windows/macOS) reconnue par AuxiPak.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Distribution {
    Debian,
    Ubuntu,
    Auxinuxos,
    Virtuaos,
    Windows,
    Macos,
    /// Distribution Linux non prise en charge officiellement.
    Unknown,
}

impl Distribution {
    pub fn as_str(&self) -> &'static str {
        match self {
            Distribution::Debian => "debian",
            Distribution::Ubuntu => "ubuntu",
            Distribution::Auxinuxos => "auxinuxos",
            Distribution::Virtuaos => "virtuaos",
            Distribution::Windows => "windows",
            Distribution::Macos => "macos",
            Distribution::Unknown => "unknown",
        }
    }

    pub fn os(&self) -> Os {
        match self {
            Distribution::Windows => Os::Windows,
            Distribution::Macos => Os::Macos,
            _ => Os::Linux,
        }
    }

    /// Famille de paquets natifs associée.
    pub fn family(&self) -> Option<Family> {
        match self {
            Distribution::Debian | Distribution::Ubuntu => Some(Family::Deb),
            _ => None,
        }
    }
}

impl fmt::Display for Distribution {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Distribution {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "debian" => Ok(Distribution::Debian),
            "ubuntu" => Ok(Distribution::Ubuntu),
            "auxinuxos" => Ok(Distribution::Auxinuxos),
            "virtuaos" => Ok(Distribution::Virtuaos),
            "windows" => Ok(Distribution::Windows),
            "macos" => Ok(Distribution::Macos),
            other => Err(format!("distribution inconnue : {other}")),
        }
    }
}

/// Famille de paquets natifs (utilisée pour les cibles partagées Debian/Ubuntu).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Family {
    Deb,
}

/// Canal d'index : chemin logique dans le dépôt (`linux/deb`, `windows`, …).
///
/// Debian et Ubuntu partagent le canal `linux/deb` ; AuxiNuxOS et VirtuaOS ont
/// leur propre canal car leurs mécanismes d'installation diffèrent (système
/// immuable, APT bloqué).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub enum Channel {
    #[serde(rename = "linux/deb")]
    LinuxDeb,
    #[serde(rename = "linux/auxinuxos")]
    LinuxAuxinuxos,
    #[serde(rename = "linux/virtuaos")]
    LinuxVirtuaos,
    #[serde(rename = "windows")]
    Windows,
    #[serde(rename = "macos")]
    Macos,
}

impl Channel {
    pub const ALL: [Channel; 5] = [
        Channel::LinuxDeb,
        Channel::LinuxAuxinuxos,
        Channel::LinuxVirtuaos,
        Channel::Windows,
        Channel::Macos,
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            Channel::LinuxDeb => "linux/deb",
            Channel::LinuxAuxinuxos => "linux/auxinuxos",
            Channel::LinuxVirtuaos => "linux/virtuaos",
            Channel::Windows => "windows",
            Channel::Macos => "macos",
        }
    }

    /// Nom de cible TUF du sous-index de ce canal pour une architecture.
    pub fn index_target(&self, arch: Arch) -> String {
        format!("channels/{}/{}.json", self.as_str(), arch.as_str())
    }

    /// Canal correspondant à une distribution, s'il existe.
    pub fn for_distribution(d: Distribution) -> Option<Channel> {
        match d {
            Distribution::Debian | Distribution::Ubuntu => Some(Channel::LinuxDeb),
            Distribution::Auxinuxos => Some(Channel::LinuxAuxinuxos),
            Distribution::Virtuaos => Some(Channel::LinuxVirtuaos),
            Distribution::Windows => Some(Channel::Windows),
            Distribution::Macos => Some(Channel::Macos),
            Distribution::Unknown => None,
        }
    }

    /// Distributions servies par ce canal.
    pub fn distributions(&self) -> &'static [Distribution] {
        match self {
            Channel::LinuxDeb => &[Distribution::Debian, Distribution::Ubuntu],
            Channel::LinuxAuxinuxos => &[Distribution::Auxinuxos],
            Channel::LinuxVirtuaos => &[Distribution::Virtuaos],
            Channel::Windows => &[Distribution::Windows],
            Channel::Macos => &[Distribution::Macos],
        }
    }
}

impl fmt::Display for Channel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Channel {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Channel::ALL
            .iter()
            .copied()
            .find(|c| c.as_str() == s.trim_matches('/'))
            .ok_or_else(|| format!("canal inconnu : {s}"))
    }
}

/// Profil système détecté et mémorisé par le client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemProfile {
    pub os: Os,
    pub distribution: Distribution,
    /// Version de la distribution (`13`, `24.04`, `10.0.22631`, `14.5`…).
    pub version: String,
    pub arch: Arch,
    /// Identifiant brut du système (champ `ID` d'os-release, etc.).
    pub raw_id: String,
    /// Nom lisible (`PRETTY_NAME`, édition Windows…).
    pub pretty_name: String,
    /// Système de fichiers racine immuable (AuxiNuxOS, VirtuaOS…).
    pub immutable: bool,
}

impl SystemProfile {
    pub fn channel(&self) -> Option<Channel> {
        Channel::for_distribution(self.distribution)
    }

    /// Empreinte servant à détecter un changement important de système.
    pub fn fingerprint(&self) -> String {
        format!(
            "{}|{}|{}|{}",
            self.os,
            self.distribution,
            major_version(&self.version),
            self.arch
        )
    }
}

/// Partie majeure d'une version (`24.04` → `24`, `13` → `13`).
pub fn major_version(v: &str) -> &str {
    v.split(['.', '-', ' ']).next().unwrap_or(v)
}

/// Contenu analysé d'un fichier `os-release`.
pub type OsRelease = BTreeMap<String, String>;

/// Analyse le format `os-release` (clé=valeur, valeurs éventuellement entre guillemets).
pub fn parse_os_release(content: &str) -> OsRelease {
    let mut map = BTreeMap::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let v = v.trim();
        let v = if (v.starts_with('"') && v.ends_with('"') && v.len() >= 2)
            || (v.starts_with('\'') && v.ends_with('\'') && v.len() >= 2)
        {
            &v[1..v.len() - 1]
        } else {
            v
        };
        let v = v.replace("\\\"", "\"").replace("\\\\", "\\");
        map.insert(k.trim().to_string(), v);
    }
    map
}

/// Déduit la distribution à partir d'un `os-release`.
///
/// L'ordre de priorité est : `ID` exact, puis `ID_LIKE`. Une dérivée
/// d'Ubuntu ou de Debian non reconnue est rattachée à sa base uniquement via
/// `ID_LIKE`, ce qui permet d'utiliser le canal `linux/deb`.
pub fn distribution_from_os_release(osr: &OsRelease) -> Distribution {
    let id = osr.get("ID").map(|s| s.to_ascii_lowercase()).unwrap_or_default();
    if let Ok(d) = Distribution::from_str(&id) {
        if d.os() == Os::Linux {
            return d;
        }
    }
    let like = osr.get("ID_LIKE").map(|s| s.to_ascii_lowercase()).unwrap_or_default();
    let likes: Vec<&str> = like.split_whitespace().collect();
    // AuxiNuxOS/VirtuaOS dérivent de Debian mais doivent être reconnus avant
    // la famille générique pour ne jamais utiliser APT directement.
    for candidate in ["auxinuxos", "virtuaos", "ubuntu", "debian"] {
        if likes.contains(&candidate) {
            return Distribution::from_str(candidate).unwrap_or(Distribution::Unknown);
        }
    }
    Distribution::Unknown
}

/// Construit un profil Linux à partir d'un `os-release`.
pub fn linux_profile_from_os_release(osr: &OsRelease, arch: Arch, immutable: bool) -> SystemProfile {
    let distribution = distribution_from_os_release(osr);
    let version = osr
        .get("VERSION_ID")
        .cloned()
        .or_else(|| osr.get("VERSION_CODENAME").cloned())
        .unwrap_or_else(|| "unknown".into());
    SystemProfile {
        os: Os::Linux,
        distribution,
        version,
        arch,
        raw_id: osr.get("ID").cloned().unwrap_or_default(),
        pretty_name: osr
            .get("PRETTY_NAME")
            .or_else(|| osr.get("NAME"))
            .cloned()
            .unwrap_or_else(|| "Linux".into()),
        immutable: immutable || matches!(distribution, Distribution::Auxinuxos | Distribution::Virtuaos),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEBIAN13: &str = r#"PRETTY_NAME="Debian GNU/Linux 13 (trixie)"
NAME="Debian GNU/Linux"
VERSION_ID="13"
VERSION="13 (trixie)"
VERSION_CODENAME=trixie
ID=debian
"#;
    const UBUNTU: &str = "NAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\nID=ubuntu\nID_LIKE=debian\nPRETTY_NAME=\"Ubuntu 24.04.5 LTS\"\n";
    const MINT: &str = "NAME=\"Linux Mint\"\nVERSION_ID=\"22\"\nID=linuxmint\nID_LIKE=\"ubuntu debian\"\n";
    const AUXINUX: &str = "NAME=\"AuxiNuxOS\"\nVERSION_ID=\"1.0\"\nID=auxinuxos\nID_LIKE=debian\n";
    const AUXINUX_DERIVED: &str = "NAME=\"X\"\nVERSION_ID=\"1.0\"\nID=xos\nID_LIKE=\"auxinuxos debian\"\n";
    const FEDORA: &str = "NAME=Fedora\nVERSION_ID=40\nID=fedora\n";

    #[test]
    fn detects_debian_13() {
        let p = linux_profile_from_os_release(&parse_os_release(DEBIAN13), Arch::X86_64, false);
        assert_eq!(p.distribution, Distribution::Debian);
        assert_eq!(p.version, "13");
        assert_eq!(p.channel(), Some(Channel::LinuxDeb));
        assert!(!p.immutable);
        assert_eq!(p.pretty_name, "Debian GNU/Linux 13 (trixie)");
    }

    #[test]
    fn detects_ubuntu_and_derivatives() {
        let p = linux_profile_from_os_release(&parse_os_release(UBUNTU), Arch::Arm64, false);
        assert_eq!(p.distribution, Distribution::Ubuntu);
        assert_eq!(p.version, "24.04");
        let m = linux_profile_from_os_release(&parse_os_release(MINT), Arch::X86_64, false);
        assert_eq!(m.distribution, Distribution::Ubuntu);
        assert_eq!(m.channel(), Some(Channel::LinuxDeb));
    }

    #[test]
    fn detects_auxinuxos_as_immutable_and_never_deb_channel() {
        let p = linux_profile_from_os_release(&parse_os_release(AUXINUX), Arch::X86_64, false);
        assert_eq!(p.distribution, Distribution::Auxinuxos);
        assert!(p.immutable);
        assert_eq!(p.channel(), Some(Channel::LinuxAuxinuxos));
        let d = linux_profile_from_os_release(&parse_os_release(AUXINUX_DERIVED), Arch::X86_64, false);
        assert_eq!(d.distribution, Distribution::Auxinuxos);
    }

    #[test]
    fn unknown_distribution_has_no_channel() {
        let p = linux_profile_from_os_release(&parse_os_release(FEDORA), Arch::X86_64, false);
        assert_eq!(p.distribution, Distribution::Unknown);
        assert_eq!(p.channel(), None);
    }

    #[test]
    fn fingerprint_ignores_minor_version() {
        let mut p = linux_profile_from_os_release(&parse_os_release(UBUNTU), Arch::X86_64, false);
        let f1 = p.fingerprint();
        p.version = "24.10".into();
        assert_eq!(f1, p.fingerprint());
        p.version = "26.04".into();
        assert_ne!(f1, p.fingerprint());
    }

    #[test]
    fn arch_parsing_and_compat() {
        assert_eq!("amd64".parse::<Arch>().unwrap(), Arch::X86_64);
        assert_eq!("aarch64".parse::<Arch>().unwrap(), Arch::Arm64);
        assert!(Arch::Any.runs_on(Arch::Arm64));
        assert!(!Arch::X86_64.runs_on(Arch::Arm64));
        assert!(Arch::X86_64.emulated_on(Arch::Arm64, Os::Windows));
        assert!(Arch::X86_64.emulated_on(Arch::Arm64, Os::Macos));
        assert!(!Arch::X86_64.emulated_on(Arch::Arm64, Os::Linux));
        assert!(!Arch::Arm64.emulated_on(Arch::X86_64, Os::Windows));
    }

    #[test]
    fn channel_roundtrip() {
        for c in Channel::ALL {
            assert_eq!(c.as_str().parse::<Channel>().unwrap(), c);
            let json = serde_json::to_string(&c).unwrap();
            assert_eq!(json, format!("\"{}\"", c.as_str()));
        }
        assert_eq!(Channel::LinuxDeb.index_target(Arch::X86_64), "channels/linux/deb/x86_64.json");
    }
}
