//! Analyse d'un paquet soumis. Aucun contenu du paquet n'est exécuté : le
//! serveur se limite à l'inspection structurelle, à la validation du
//! manifeste, aux empreintes et à la signature.

use auxipak_core::archive::{self, Inspection, Limits};
use auxipak_core::manifest::{Install, Mode};
use auxipak_core::signature::{KeyPurpose, PackageSignature, TrustedKeys};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Check {
    pub name: String,
    pub ok: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Report {
    pub ok: bool,
    pub checks: Vec<Check>,
    pub warnings: Vec<String>,
    /// Points d'attention pour le relecteur.
    pub review_flags: Vec<String>,
    pub uses_scripts: bool,
    pub targets: Vec<TargetSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetSummary {
    pub name: String,
    pub platform: String,
    pub distributions: Vec<String>,
    pub architectures: Vec<String>,
    pub mode: String,
    pub method: String,
    pub privileges: String,
}

impl Report {
    fn check(&mut self, name: &str, ok: bool, detail: impl Into<String>) {
        self.checks.push(Check {
            name: name.into(),
            ok,
            detail: detail.into(),
        });
    }
}

/// Analyse un fichier `.aupak`.
pub fn analyze(path: &Path) -> (Option<Inspection>, Report) {
    let mut r = Report::default();
    let insp = match archive::inspect(path, &Limits::default()) {
        Ok(i) => i,
        Err(e) => {
            r.check("structure du paquet", false, e.to_string());
            r.ok = false;
            return (None, r);
        }
    };
    r.check(
        "structure du paquet",
        true,
        format!("{} entrées, {} octets décompressés", insp.entries.len(), insp.total_unpacked),
    );
    r.check("manifeste", true, format!("{} {}", insp.manifest.id, insp.manifest.version));
    let m = &insp.manifest;
    r.warnings = insp.warnings.iter().map(|w| w.to_string()).collect();
    for t in &m.targets {
        r.targets.push(TargetSummary {
            name: t.name.clone(),
            platform: t.platform.to_string(),
            distributions: t.distributions.iter().map(|d| d.to_string()).collect(),
            architectures: t.architectures.iter().map(|a| a.to_string()).collect(),
            mode: t.mode.to_string(),
            method: t.install.method_name().into(),
            privileges: format!("{:?}", t.effective_privileges()).to_lowercase(),
        });
        if t.uses_scripts() {
            r.uses_scripts = true;
            r.review_flags
                .push(format!("variante {} : scripts personnalisés à examiner", t.name));
        }
        if t.mode == Mode::Remote {
            if let Some(u) = t.install.source().and_then(|s| s.url.clone()) {
                r.review_flags
                    .push(format!("variante {} : téléchargement distant depuis {u}", t.name));
            }
        }
        if let Install::Exe { .. } = t.install {
            r.review_flags
                .push(format!("variante {} : installateur exe (comportement opaque)", t.name));
        }
        if t.permissions.iter().any(|p| {
            matches!(
                p,
                auxipak_core::manifest::Permission::Drivers | auxipak_core::manifest::Permission::Services
            )
        }) {
            r.review_flags
                .push(format!("variante {} : demande des permissions système étendues", t.name));
        }
    }
    if let Some(p) = &m.privacy {
        if p.telemetry == auxipak_core::manifest::Telemetry::Mandatory {
            r.review_flags.push("télémétrie obligatoire déclarée par l'éditeur".into());
        }
    } else {
        r.review_flags.push("aucune déclaration de vie privée".into());
    }
    let channels: usize = crate::publisher::channel_entries(m).len();
    r.check(
        "couverture des plateformes",
        channels > 0,
        format!("{channels} combinaison(s) canal/architecture"),
    );
    r.ok = r.checks.iter().all(|c| c.ok);
    (Some(insp), r)
}

/// Vérifie une signature détachée contre les clés de confiance.
pub fn check_signature(sig: &PackageSignature, insp: &Inspection, keys: &TrustedKeys) -> Result<String, String> {
    sig.verify(&insp.archive_sha256, insp.archive_size, keys, &[KeyPurpose::PackageSigning])
        .map(|v| v.key_id)
        .map_err(|e| e.to_string())
        .and_then(|k| {
            if sig.payload.package.id != insp.manifest.id || sig.payload.package.version != insp.manifest.version {
                Err("la signature désigne un autre paquet".into())
            } else {
                Ok(k)
            }
        })
}
