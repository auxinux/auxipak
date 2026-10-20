//! Projets de paquets : répertoire contenant `instruction.auxipak`,
//! `payload/` et `scripts/`. Utilisé par `auxipak-builder` et par l'API
//! Builder du serveur.

use crate::archive::{self, BuildFile, Inspection, Limits};
use crate::manifest::{Install, Manifest, ManifestError, MANIFEST_FILE};
use crate::platform::{Arch, Distribution, Os, SystemProfile};
use crate::tr;
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Modèle de manifeste pour un nouveau projet.
pub const MANIFEST_TEMPLATE: &str = r#"# Manifeste AuxiPak — voir docs/MANIFEST_SPEC.md
format: 1
id: {id}
name: "{name}"
version: "{version}"
publisher: "{publisher}"
summary: "Description courte de l'application"
license: "{license}"
languages: [{language}]
targets:
  # Exemple : copie de fichiers (fonctionne sans privilèges).
  - name: linux
    platform: linux
    distributions: [debian, ubuntu, auxinuxos, virtuaos]
    architectures: [any]
    mode: embedded
    install:
      method: files
      files:
        - source: payload/bin/{id}
          destination: "{bin}/{id}"
          executable: true
"#;

/// Modèle de manifeste, version anglaise (mêmes clés et valeurs).
pub const MANIFEST_TEMPLATE_EN: &str = r#"# AuxiPak manifest — see docs/MANIFEST_SPEC.md
format: 1
id: {id}
name: "{name}"
version: "{version}"
publisher: "{publisher}"
summary: "Short description of the application"
license: "{license}"
languages: [{language}]
targets:
  # Example: file copy (works without privileges).
  - name: linux
    platform: linux
    distributions: [debian, ubuntu, auxinuxos, virtuaos]
    architectures: [any]
    mode: embedded
    install:
      method: files
      files:
        - source: payload/bin/{id}
          destination: "{bin}/{id}"
          executable: true
"#;

/// Manifeste d'un nouveau projet, commenté dans la langue de l'interface.
pub fn render_template(id: &str, name: &str, version: &str, publisher: &str, language: &str, license: &str) -> String {
    let clean = |s: &str| s.replace(['"', '\n', '\r', '\\'], "");
    let template = if crate::i18n::is_fr() {
        MANIFEST_TEMPLATE
    } else {
        MANIFEST_TEMPLATE_EN
    };
    template
        .replace("{id}", id)
        .replace("{name}", &clean(name))
        .replace("{version}", &clean(version))
        .replace("{publisher}", &clean(publisher))
        .replace("{license}", &clean(license))
        .replace("{language}", &clean(language))
}

/// Fichiers d'un projet : tout ce qui se trouve sous payload/ et scripts/
/// (les fichiers cachés sont ignorés ; les liens symboliques sont refusés).
pub fn project_files(dir: &Path) -> Result<Vec<BuildFile>> {
    let mut out = Vec::new();
    for top in ["payload", "scripts"] {
        let base = dir.join(top);
        if base.is_dir() {
            walk(&base, &format!("{top}/"), &mut out)?;
        }
    }
    Ok(out)
}

fn walk(dir: &Path, prefix: &str, out: &mut Vec<BuildFile>) -> Result<()> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)?.collect::<std::io::Result<_>>()?;
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let name = e.file_name().to_string_lossy().into_owned();
        if name.starts_with('.') {
            continue;
        }
        let ft = e.file_type()?;
        let rel = format!("{prefix}{name}");
        if ft.is_symlink() {
            bail!(tr!(
                "lien symbolique refusé dans le projet : {rel}",
                "symbolic link rejected in the project: {rel}"
            ));
        } else if ft.is_dir() {
            walk(&e.path(), &format!("{rel}/"), out)?;
        } else if ft.is_file() {
            out.push(BuildFile {
                archive_path: rel,
                source: e.path(),
                executable: false,
            });
        }
    }
    Ok(())
}

/// Charge le manifeste source d'un projet et (re)calcule `contents` à partir
/// des fichiers réels.
pub fn load_manifest(dir: &Path) -> Result<(Manifest, Vec<crate::manifest::Issue>)> {
    let text = std::fs::read_to_string(dir.join(MANIFEST_FILE)).with_context(|| {
        tr!(
            "{MANIFEST_FILE} introuvable dans {}",
            "{MANIFEST_FILE} not found in {}",
            dir.display()
        )
    })?;
    manifest_with_contents(&text, &project_files(dir)?)
}

pub fn manifest_with_contents(text: &str, files: &[BuildFile]) -> Result<(Manifest, Vec<crate::manifest::Issue>)> {
    let mut value = crate::manifest::parse_yaml_value(text).map_err(|e| anyhow!("{e}"))?;
    let declared_exec: Vec<String> = value
        .get("contents")
        .and_then(|c| c.as_array())
        .map(|a| {
            a.iter()
                .filter(|e| e.get("executable").and_then(|x| x.as_bool()).unwrap_or(false))
                .filter_map(|e| e.get("path").and_then(|p| p.as_str()).map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let mut contents = Vec::new();
    for f in files {
        let (sha256, size) = crate::hash::sha256_file(&f.source)?;
        let mut entry = serde_json::json!({"path": f.archive_path, "sha256": sha256, "size": size});
        if declared_exec.contains(&f.archive_path) || f.executable {
            entry["executable"] = serde_json::Value::Bool(true);
        }
        contents.push(entry);
    }
    if let Some(obj) = value.as_object_mut() {
        if contents.is_empty() {
            obj.remove("contents");
        } else {
            obj.insert("contents".into(), serde_json::Value::Array(contents));
        }
    }
    Manifest::from_value(value).map_err(|e: ManifestError| anyhow!("{e}"))
}

/// Construit l'archive d'un projet.
pub fn build(dir: &Path, out: &Path) -> Result<(Manifest, Inspection)> {
    if out.extension().and_then(|e| e.to_str()) != Some(archive::PACKAGE_EXTENSION) {
        bail!(tr!(
            "le fichier de sortie doit porter l'extension .aupak",
            "the output file must have the .aupak extension"
        ));
    }
    let (m, _) = load_manifest(dir)?;
    let files = project_files(dir)?;
    archive::build(&m, &files, out).map_err(|e| anyhow!("{e}"))
}

/// Résultat d'un test statique.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Check {
    pub check: String,
    pub ok: bool,
    pub detail: String,
}

/// Profils de référence pour vérifier la sélection des variantes.
pub fn reference_profiles() -> Vec<SystemProfile> {
    let p = |os, d: Distribution, v: &str, a| SystemProfile {
        os,
        distribution: d,
        version: v.into(),
        arch: a,
        raw_id: d.as_str().into(),
        pretty_name: format!("{d} {v}"),
        immutable: matches!(d, Distribution::Auxinuxos | Distribution::Virtuaos),
    };
    use Arch::*;
    vec![
        p(Os::Linux, Distribution::Debian, "12", X86_64),
        p(Os::Linux, Distribution::Debian, "13", X86_64),
        p(Os::Linux, Distribution::Debian, "13", Arm64),
        p(Os::Linux, Distribution::Ubuntu, "22.04", X86_64),
        p(Os::Linux, Distribution::Ubuntu, "24.04", X86_64),
        p(Os::Linux, Distribution::Ubuntu, "24.04", Arm64),
        p(Os::Linux, Distribution::Auxinuxos, "1.0", X86_64),
        p(Os::Linux, Distribution::Virtuaos, "1.0", X86_64),
        p(Os::Windows, Distribution::Windows, "10.0.19045", X86_64),
        p(Os::Windows, Distribution::Windows, "10.0.22631", Arm64),
        p(Os::Macos, Distribution::Macos, "13.6", X86_64),
        p(Os::Macos, Distribution::Macos, "14.5", Arm64),
    ]
}

/// Tests statiques d'un paquet. Aucun installateur ni script n'est exécuté.
/// `external_tools` autorise `dpkg-deb --field` (lecture du fichier control)
/// et `bash -n` (analyse syntaxique sans exécution) lorsqu'ils sont présents.
pub fn static_tests(file: &Path, external_tools: bool) -> Result<Vec<Check>> {
    let mut report = Vec::new();
    let mut push = |check: String, ok: bool, detail: String| report.push(Check { check, ok, detail });
    let insp = match archive::inspect(file, &Limits::default()) {
        Ok(i) => i,
        Err(e) => {
            push(tr!("structure et manifeste", "structure and manifest"), false, e.to_string());
            return Ok(report);
        }
    };
    push(
        tr!("structure et manifeste", "structure and manifest"),
        true,
        tr!("{} entrées", "{} entries", insp.entries.len()),
    );
    let tmp = tempfile::tempdir()?;
    if let Err(e) = archive::extract(file, tmp.path(), &Limits::default()) {
        push(
            tr!("extraction et empreintes", "extraction and digests"),
            false,
            e.to_string(),
        );
        return Ok(report);
    }
    push(
        tr!("extraction et empreintes", "extraction and digests"),
        true,
        tr!("{} octets", "{} bytes", insp.total_unpacked),
    );
    let m = &insp.manifest;
    let mut any = false;
    for p in reference_profiles() {
        let r = m.select_target(&p);
        any |= r.is_ok();
        push(
            tr!(
                "variante pour {} {} {}",
                "target for {} {} {}",
                p.distribution,
                p.version,
                p.arch
            ),
            true,
            match r {
                Ok(t) => format!("→ {}", t.name),
                Err(_) => tr!("aucune (non pris en charge)", "none (not supported)"),
            },
        );
    }
    push(
        tr!(
            "au moins une plateforme de référence couverte",
            "at least one reference platform covered"
        ),
        any,
        String::new(),
    );
    for t in &m.targets {
        if let Install::Deb { package, source } = &t.install {
            if let (Some(f), true) = (&source.file, external_tools) {
                let path = tmp.path().join(f);
                match std::process::Command::new("dpkg-deb")
                    .arg("--field")
                    .arg(&path)
                    .arg("Package")
                    .output()
                {
                    Ok(o) if o.status.success() => {
                        let actual = String::from_utf8_lossy(&o.stdout).trim().to_string();
                        push(
                            tr!("{} : nom du paquet .deb", "{}: .deb package name", t.name),
                            &actual == package,
                            tr!(
                                "control : {actual}, manifeste : {package}",
                                "control: {actual}, manifest: {package}"
                            ),
                        );
                    }
                    _ => push(
                        tr!("{} : contrôle .deb", "{}: .deb check", t.name),
                        true,
                        tr!("dpkg-deb indisponible : non vérifié", "dpkg-deb unavailable: not checked"),
                    ),
                }
            }
        }
        let mut scripts: Vec<String> = t.scripts.all().map(|(_, s)| s.clone()).collect();
        if let Install::Script { script, .. } = &t.install {
            scripts.push(script.clone());
        }
        for s in scripts {
            let path: PathBuf = tmp.path().join(&s);
            if s.ends_with(".sh") && external_tools {
                match std::process::Command::new("bash").arg("-n").arg(&path).output() {
                    Ok(o) => push(
                        tr!("{} : syntaxe de {s}", "{}: syntax of {s}", t.name),
                        o.status.success(),
                        String::from_utf8_lossy(&o.stderr).trim().into(),
                    ),
                    Err(_) => push(
                        tr!("{} : syntaxe de {s}", "{}: syntax of {s}", t.name),
                        true,
                        tr!("bash indisponible : non vérifié", "bash unavailable: not checked"),
                    ),
                }
            } else {
                push(
                    tr!("{} : {s}", "{}: {s}", t.name),
                    true,
                    tr!(
                        "analyse syntaxique non effectuée (examen manuel requis)",
                        "syntax check not performed (manual review required)"
                    ),
                );
            }
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn template_project_builds_and_passes_static_tests() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("payload/bin")).unwrap();
        std::fs::write(
            d.path().join(MANIFEST_FILE),
            render_template("hello", "Hello \"x\"", "1.0", "AuxiNux", "fr", "MIT"),
        )
        .unwrap();
        std::fs::write(d.path().join("payload/bin/hello"), b"#!/bin/sh\necho hi\n").unwrap();
        let out = d.path().join("hello.aupak");
        let (m, insp) = build(d.path(), &out).unwrap();
        assert_eq!(m.name, "Hello x");
        assert_eq!(insp.manifest.contents.len(), 1);
        let checks = static_tests(&out, false).unwrap();
        assert!(checks.iter().all(|c| c.ok), "{checks:?}");
    }

    #[test]
    fn project_rejects_symlinks() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("payload")).unwrap();
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("/etc/passwd", d.path().join("payload/x")).unwrap();
            assert!(project_files(d.path()).is_err());
        }
    }
}
