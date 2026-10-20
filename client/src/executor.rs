//! Exécution des outils système.
//!
//! Règles :
//! - jamais d'interpréteur de commandes : programme + vecteur d'arguments ;
//! - outils système désignés par chemin absolu lorsque c'est possible ;
//! - environnement réduit à une liste blanche ;
//! - délai maximal, sortie journalisée, code de retour interprété selon le
//!   manifeste (`success_codes`, `reboot_codes`).
//!
//! Mode simulation (tests uniquement) : si `AUXIPAK_TEST_TOOLS_DIR` est
//! défini, les outils sont cherchés dans ce répertoire. Les installations
//! correspondantes sont marquées `simulated` dans le registre et un
//! avertissement est affiché : elles ne valent jamais validation réelle.

use anyhow::{anyhow, bail, Context, Result};
use auxipak_core::tr;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

/// Outils connus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tool {
    AptGet,
    DpkgQuery,
    Msiexec,
    Reg,
    Winget,
    Installer,
    Pkgutil,
    Hdiutil,
    Ditto,
    Brew,
    Bash,
    PowerShell,
    Tar,
}

impl Tool {
    pub fn name(&self) -> &'static str {
        match self {
            Tool::AptGet => "apt-get",
            Tool::DpkgQuery => "dpkg-query",
            Tool::Msiexec => "msiexec",
            Tool::Reg => "reg",
            Tool::Winget => "winget",
            Tool::Installer => "installer",
            Tool::Pkgutil => "pkgutil",
            Tool::Hdiutil => "hdiutil",
            Tool::Ditto => "ditto",
            Tool::Brew => "brew",
            Tool::Bash => "bash",
            Tool::PowerShell => "powershell",
            Tool::Tar => "tar",
        }
    }

    fn candidates(&self) -> Vec<PathBuf> {
        let sysroot = std::env::var_os("SystemRoot")
            .map(PathBuf::from)
            .unwrap_or_else(|| "C:\\Windows".into());
        match self {
            Tool::AptGet => vec!["/usr/bin/apt-get".into()],
            Tool::DpkgQuery => vec!["/usr/bin/dpkg-query".into()],
            Tool::Msiexec => vec![sysroot.join("System32").join("msiexec.exe")],
            Tool::Reg => vec![sysroot.join("System32").join("reg.exe")],
            Tool::Winget => {
                let mut v = Vec::new();
                if let Some(la) = std::env::var_os("LOCALAPPDATA") {
                    v.push(PathBuf::from(la).join("Microsoft").join("WindowsApps").join("winget.exe"));
                }
                v
            }
            Tool::Installer => vec!["/usr/sbin/installer".into()],
            Tool::Pkgutil => vec!["/usr/sbin/pkgutil".into()],
            Tool::Hdiutil => vec!["/usr/bin/hdiutil".into()],
            Tool::Ditto => vec!["/usr/bin/ditto".into()],
            Tool::Brew => vec!["/opt/homebrew/bin/brew".into(), "/usr/local/bin/brew".into()],
            Tool::Bash => vec!["/bin/bash".into(), "/usr/bin/bash".into()],
            Tool::PowerShell => vec![sysroot
                .join("System32")
                .join("WindowsPowerShell")
                .join("v1.0")
                .join("powershell.exe")],
            // Windows 10 (1803) et plus : bsdtar, qui lit aussi les .zip.
            Tool::Tar => vec![
                "/usr/bin/tar".into(),
                "/bin/tar".into(),
                sysroot.join("System32").join("tar.exe"),
            ],
        }
    }
}

/// Répertoire d'outils simulés (tests), s'il est actif.
pub fn simulation_dir() -> Option<PathBuf> {
    std::env::var_os("AUXIPAK_TEST_TOOLS_DIR")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

pub fn is_simulation() -> bool {
    simulation_dir().is_some()
}

/// Résout le chemin d'un outil.
pub fn resolve(tool: Tool) -> Result<PathBuf> {
    if let Some(dir) = simulation_dir() {
        let p = dir.join(tool.name());
        if p.exists() {
            return Ok(p);
        }
        bail!(tr!("outil simulé absent : {}", "simulated tool missing: {}", p.display()));
    }
    tool.candidates().into_iter().find(|p| p.exists()).ok_or_else(|| {
        anyhow!(tr!(
            "outil système introuvable : {}",
            "system tool not found: {}",
            tool.name()
        ))
    })
}

/// Résout un programme configuré (adaptateurs `auxi`, VirtuaOS) : chemin
/// absolu, ou nom cherché dans les répertoires système standard uniquement.
pub fn resolve_program(program: &str) -> Result<PathBuf> {
    if program.is_empty() {
        bail!(tr!("programme non configuré", "program not configured"));
    }
    if let Some(dir) = simulation_dir() {
        let name = Path::new(program)
            .file_name()
            .context(tr!("programme invalide", "invalid program"))?;
        let p = dir.join(name);
        if p.exists() {
            return Ok(p);
        }
    }
    let p = Path::new(program);
    if p.is_absolute() {
        return if p.exists() {
            Ok(p.to_path_buf())
        } else {
            bail!(tr!("programme introuvable : {program}", "program not found: {program}"))
        };
    }
    if program.contains('/') || program.contains('\\') {
        bail!(tr!(
            "chemin de programme relatif refusé : {program}",
            "relative program path refused: {program}"
        ));
    }
    for d in ["/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local/bin"] {
        let c = Path::new(d).join(program);
        if c.exists() {
            return Ok(c);
        }
    }
    bail!(tr!(
        "programme introuvable dans les répertoires système : {program}",
        "program not found in system directories: {program}"
    ))
}

/// Résultat d'exécution.
#[derive(Debug, Clone)]
pub struct Output {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug, Clone, Default)]
pub struct RunOpts {
    pub cwd: Option<PathBuf>,
    pub env: Vec<(String, String)>,
    pub timeout: Option<Duration>,
}

const ENV_ALLOW: &[&str] = &[
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "LANG",
    "LC_ALL",
    "LC_MESSAGES",
    "TMPDIR",
    "TERM",
    "SystemRoot",
    "windir",
    "SystemDrive",
    "ProgramData",
    "ProgramFiles",
    "ProgramFiles(x86)",
    "ProgramW6432",
    "LOCALAPPDATA",
    "APPDATA",
    "USERPROFILE",
    "TEMP",
    "TMP",
    "PATHEXT",
    "COMPUTERNAME",
    "USERNAME",
    "PROCESSOR_ARCHITECTURE",
    "AUXIPAK_TEST_TOOLS_DIR",
    "AUXIPAK_TEST_LOG",
];

/// Exécute un programme avec un vecteur d'arguments.
pub async fn run(program: &Path, args: &[OsString], opts: &RunOpts) -> Result<Output> {
    let mut cmd = tokio::process::Command::new(program);
    cmd.args(args)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    for (k, v) in std::env::vars_os() {
        if let Some(k) = k.to_str() {
            if ENV_ALLOW.iter().any(|a| a.eq_ignore_ascii_case(k)) {
                cmd.env(k, v);
            }
        }
    }
    for (k, v) in &opts.env {
        cmd.env(k, v);
    }
    if let Some(c) = &opts.cwd {
        cmd.current_dir(c);
    }
    let shown: Vec<String> = args.iter().map(|a| a.to_string_lossy().into_owned()).collect();
    tracing::info!(program = %program.display(), args = ?shown, "{}", tr!("exécution", "running"));
    let child = cmd
        .spawn()
        .with_context(|| tr!("lancement de {}", "starting {}", program.display()))?;
    let timeout = opts.timeout.unwrap_or(Duration::from_secs(3600));
    let out = tokio::time::timeout(timeout, child.wait_with_output()).await.map_err(|_| {
        anyhow!(tr!(
            "délai dépassé ({} s) : {}",
            "timed out ({} s): {}",
            timeout.as_secs(),
            program.display()
        ))
    })??;
    let o = Output {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    };
    tracing::info!(program = %program.display(), code = o.code, stdout = %truncate(&o.stdout), stderr = %truncate(&o.stderr), "{}", tr!("terminé", "finished"));
    Ok(o)
}

fn truncate(s: &str) -> String {
    let t = s.trim();
    if t.len() > 4000 {
        format!("{}…", &t[..t.char_indices().nth(4000).map(|(i, _)| i).unwrap_or(t.len())])
    } else {
        t.to_string()
    }
}

/// Interprétation d'un code de retour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Success,
    SuccessRebootRequired,
    Failure,
}

pub fn verdict(code: i32, success: &[i32], reboot: &[i32]) -> Verdict {
    if reboot.contains(&code) {
        Verdict::SuccessRebootRequired
    } else if success.contains(&code) {
        Verdict::Success
    } else {
        Verdict::Failure
    }
}

pub fn os(s: impl Into<OsString>) -> OsString {
    s.into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdicts() {
        assert_eq!(verdict(0, &[0], &[3010]), Verdict::Success);
        assert_eq!(verdict(3010, &[0], &[3010]), Verdict::SuccessRebootRequired);
        assert_eq!(verdict(1603, &[0], &[3010]), Verdict::Failure);
    }

    #[test]
    fn rejects_relative_program_paths() {
        assert!(resolve_program("../auxi").is_err());
        assert!(resolve_program("").is_err());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn arguments_are_not_interpreted_by_a_shell() {
        // `printf` reçoit littéralement « $(id) ; echo pwned » : aucune expansion.
        let out = run(
            Path::new("/usr/bin/printf"),
            &[os("%s"), os("$(id) ; echo pwned")],
            &RunOpts::default(),
        )
        .await
        .unwrap();
        assert_eq!(out.stdout, "$(id) ; echo pwned");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn environment_is_filtered_and_timeout_enforced() {
        std::env::set_var("AUXIPAK_SECRET_TEST", "x");
        let out = run(Path::new("/usr/bin/env"), &[], &RunOpts::default()).await.unwrap();
        assert!(!out.stdout.contains("AUXIPAK_SECRET_TEST"));
        let r = run(
            Path::new("/bin/sleep"),
            &[os("5")],
            &RunOpts {
                timeout: Some(Duration::from_millis(200)),
                ..Default::default()
            },
        )
        .await;
        assert!(r.is_err());
    }
}
