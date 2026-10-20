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
    /// Même rapport en français (le rapport principal est en anglais) ; voir
    /// [`localize`]. Absent des rapports enregistrés avant la 1.0.3.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fr: Option<Box<Report>>,
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
    fn check(&mut self, name: String, ok: bool, detail: impl Into<String>) {
        self.checks.push(Check {
            name,
            ok,
            detail: detail.into(),
        });
    }
}

/// Texte français ou anglais selon `fr` (rapport produit dans les deux langues).
macro_rules! t {
    ($fr_flag:expr, $fr:literal, $en:literal $(, $arg:expr)* $(,)?) => {
        if $fr_flag { format!($fr $(, $arg)*) } else { format!($en $(, $arg)*) }
    };
}

/// Rapport rédigé dans une langue (`fr` : français, sinon anglais).
fn build(insp: &Result<Inspection, String>, fr: bool) -> Report {
    let mut r = Report::default();
    let insp = match insp {
        Ok(i) => i,
        Err(e) => {
            r.check(t!(fr, "structure du paquet", "package structure"), false, e.clone());
            r.ok = false;
            return r;
        }
    };
    r.check(
        t!(fr, "structure du paquet", "package structure"),
        true,
        t!(
            fr,
            "{} entrées, {} octets décompressés",
            "{} entries, {} bytes unpacked",
            insp.entries.len(),
            insp.total_unpacked
        ),
    );
    r.check(
        t!(fr, "manifeste", "manifest"),
        true,
        format!("{} {}", insp.manifest.id, insp.manifest.version),
    );
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
            r.review_flags.push(t!(
                fr,
                "variante {} : scripts personnalisés à examiner",
                "variant {}: custom scripts to review",
                t.name
            ));
        }
        if t.mode == Mode::Remote {
            if let Some(u) = t.install.source().and_then(|s| s.url.clone()) {
                r.review_flags.push(t!(
                    fr,
                    "variante {} : téléchargement distant depuis {u}",
                    "variant {}: remote download from {u}",
                    t.name
                ));
            }
        }
        if let Install::Exe { .. } = t.install {
            r.review_flags.push(t!(
                fr,
                "variante {} : installateur exe (comportement opaque)",
                "variant {}: exe installer (opaque behaviour)",
                t.name
            ));
        }
        if t.permissions.iter().any(|p| {
            matches!(
                p,
                auxipak_core::manifest::Permission::Drivers | auxipak_core::manifest::Permission::Services
            )
        }) {
            r.review_flags.push(t!(
                fr,
                "variante {} : demande des permissions système étendues",
                "variant {}: requests extended system permissions",
                t.name
            ));
        }
    }
    if let Some(p) = &m.privacy {
        if p.telemetry == auxipak_core::manifest::Telemetry::Mandatory {
            r.review_flags.push(t!(
                fr,
                "télémétrie obligatoire déclarée par l'éditeur",
                "mandatory telemetry declared by the publisher"
            ));
        }
    } else {
        r.review_flags
            .push(t!(fr, "aucune déclaration de vie privée", "no privacy declaration"));
    }
    let channels: usize = crate::publisher::channel_entries(m).len();
    r.check(
        t!(fr, "couverture des plateformes", "platform coverage"),
        channels > 0,
        t!(
            fr,
            "{channels} combinaison(s) canal/architecture",
            "{channels} channel/architecture combination(s)"
        ),
    );
    r.ok = r.checks.iter().all(|c| c.ok);
    r
}

/// Analyse un fichier `.aupak`. Le rapport est rédigé en anglais, avec sa
/// version française dans `fr` : il s'affiche ensuite dans la langue du
/// lecteur ([`localize`]), quelle que soit celle de l'auteur de la soumission.
pub fn analyze(path: &Path) -> (Option<Inspection>, Report) {
    let insp = archive::inspect(path, &Limits::default()).map_err(|e| e.to_string());
    let mut r = build(&insp, false);
    r.fr = Some(Box::new(build(&insp, true)));
    (insp.ok(), r)
}

/// Rapport enregistré (JSON) dans la langue de la requête en cours.
pub fn localize(v: &mut serde_json::Value) {
    let fr = v.get_mut("fr").map(serde_json::Value::take);
    if let (Some(fr), true) = (fr, auxipak_core::i18n::is_fr()) {
        if fr.is_object() {
            *v = fr;
        }
    }
    if let Some(o) = v.as_object_mut() {
        o.remove("fr");
    }
}

/// Vérifie une signature détachée contre les clés de confiance.
pub fn check_signature(sig: &PackageSignature, insp: &Inspection, keys: &TrustedKeys) -> Result<String, String> {
    sig.verify(&insp.archive_sha256, insp.archive_size, keys, &[KeyPurpose::PackageSigning])
        .map(|v| v.key_id)
        .map_err(|e| e.to_string())
        .and_then(|k| {
            if sig.payload.package.id != insp.manifest.id || sig.payload.package.version != insp.manifest.version {
                Err(auxipak_core::tr!(
                    "la signature désigne un autre paquet",
                    "the signature refers to another package"
                ))
            } else {
                Ok(k)
            }
        })
}
