//! `auxipak-builder` — création, validation, test, signature et soumission de
//! paquets `.apak`.
//!
//! La construction d'un paquet n'entraîne jamais sa publication : la commande
//! `submit` crée une *demande de publication* sur le serveur, qui doit être
//! approuvée par un relecteur autorisé.

use anyhow::{anyhow, bail, Context, Result};
use auxipak_core::archive::{self, Limits};
use auxipak_core::manifest::{Manifest, MANIFEST_FILE};
use auxipak_core::project;
use auxipak_core::signature::{KeyPurpose, PackageRef, PackageSignature, PackageSigner, TrustedKeys};
use auxipak_core::tuf;
use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(Parser)]
#[command(name = "auxipak-builder", version, about = "Constructeur de paquets AuxiPak (.apak)")]
struct Cli {
    /// Sortie JSON (pour l'automatisation : CI, agents).
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Créer un projet de paquet (instruction.auxipak, payload/, scripts/).
    Init {
        dir: PathBuf,
        #[arg(long)]
        id: String,
        #[arg(long)]
        name: String,
        #[arg(long, default_value = "1.0.0")]
        version: String,
        #[arg(long, default_value = "Éditeur inconnu")]
        publisher: String,
        #[arg(long, default_value = "fr")]
        language: String,
        #[arg(long, default_value = "GPL-3.0-or-later")]
        license: String,
    },
    /// Valider un manifeste, un projet ou une archive .apak.
    Validate { path: PathBuf },
    /// Construire une archive .apak normalisée à partir d'un projet.
    Build {
        dir: PathBuf,
        /// Fichier de sortie (par défaut : nom normalisé dans le répertoire courant).
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Tests statiques d'un paquet (aucun installateur ni script n'est exécuté).
    Test { file: PathBuf },
    /// Signer un paquet (document détaché <fichier>.sig).
    Sign {
        file: PathBuf,
        /// Clé privée Ed25519 PKCS#8 PEM.
        #[arg(long, env = "AUXIPAK_SIGNING_KEY")]
        key: PathBuf,
    },
    /// Vérifier la signature d'un paquet avec un fichier de clés publiques.
    VerifySignature {
        file: PathBuf,
        #[arg(long)]
        keys: PathBuf,
    },
    /// Gestion des clés.
    Keys {
        #[command(subcommand)]
        cmd: KeysCmd,
    },
    /// Soumettre un paquet au serveur (crée une demande de publication, jamais une publication directe).
    Submit {
        file: PathBuf,
        /// URL du serveur (ex. https://pak.auxinux.ca).
        #[arg(long, env = "AUXIPAK_SERVER")]
        server: String,
        /// Jeton d'API (variable d'environnement recommandée).
        #[arg(long, env = "AUXIPAK_TOKEN", hide_env_values = true)]
        token: String,
        #[arg(long, default_value = "official")]
        repository: String,
        #[arg(long, default_value = "")]
        note: String,
    },
}

#[derive(Subcommand)]
enum KeysCmd {
    /// Générer une clé de signature de paquets.
    Generate {
        /// Fichier de clé privée à créer (droits 0600).
        #[arg(long)]
        out: PathBuf,
        /// Fichier package-keys.json à créer ou compléter.
        #[arg(long)]
        public: PathBuf,
        #[arg(long, default_value = "AuxiNux")]
        owner: String,
    },
    /// Cérémonie d'initialisation : racine TUF + clés en ligne + clé de paquets.
    InitRepository {
        /// Répertoire de sortie (doit être vide ou inexistant).
        #[arg(long)]
        out: PathBuf,
        #[arg(long, default_value = "AuxiNux")]
        owner: String,
        /// Durée de validité de root.json (jours).
        #[arg(long, default_value_t = 365)]
        root_days: i64,
        /// Environnement de test : l'avertissement de production est omis.
        #[arg(long)]
        dev: bool,
    },
    /// Afficher le contenu d'une racine TUF.
    ShowRoot { root: PathBuf },
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("erreur : {e:#}");
            ExitCode::from(1)
        }
    }
}

fn write_private(path: &Path, data: &str) -> Result<()> {
    auxipak_core::keyset::write_secret(path, data)
}

async fn run(cli: Cli) -> Result<()> {
    match cli.cmd {
        Cmd::Init {
            dir,
            id,
            name,
            version,
            publisher,
            language,
            license,
        } => init(&dir, &id, &name, &version, &publisher, &language, &license),
        Cmd::Validate { path } => validate(&path, cli.json),
        Cmd::Build { dir, output } => {
            let (out, insp) = build(&dir, output.as_deref())?;
            if cli.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "file": out, "id": insp.manifest.id, "version": insp.manifest.version,
                        "sha256": insp.archive_sha256, "size": insp.archive_size, "entries": insp.entries.len(),
                    }))?
                );
            } else {
                println!("Paquet construit : {}", out.display());
                println!(
                    "  {} {} — {} entrées, {} octets",
                    insp.manifest.id,
                    insp.manifest.version,
                    insp.entries.len(),
                    insp.archive_size
                );
                println!("  SHA-256 : {}", insp.archive_sha256);
                println!("  (non publié : utilisez « auxipak-builder submit » pour demander la publication)");
            }
            Ok(())
        }
        Cmd::Test { file } => test(&file, cli.json),
        Cmd::Sign { file, key } => {
            let signer = PackageSigner::load(&key).with_context(|| format!("clé {}", key.display()))?;
            let insp = archive::inspect(&file, &Limits::default()).map_err(|e| anyhow!("{e}"))?;
            let sig = signer.sign(PackageRef {
                id: insp.manifest.id.clone(),
                version: insp.manifest.version.clone(),
                file_name: file.file_name().unwrap().to_string_lossy().into_owned(),
                sha256: insp.archive_sha256.clone(),
                size: insp.archive_size,
            });
            let out = PathBuf::from(format!("{}.sig", file.display()));
            std::fs::write(&out, sig.to_json())?;
            println!("Signature écrite : {} (clé {})", out.display(), signer.key_id());
            Ok(())
        }
        Cmd::VerifySignature { file, keys } => {
            let trust = TrustedKeys::load(&keys)?;
            let (sha, size) = auxipak_core::hash::sha256_file(&file)?;
            let doc = PackageSignature::from_json(&std::fs::read(format!("{}.sig", file.display()))?)?;
            let v = doc.verify(
                &sha,
                size,
                &trust,
                &[KeyPurpose::PackageSigning, KeyPurpose::DeveloperSigning],
            )?;
            println!("Signature valide : clé {} ({}), signée le {}", v.key_id, v.owner, v.signed_at);
            Ok(())
        }
        Cmd::Keys { cmd } => keys(cmd).await,
        Cmd::Submit {
            file,
            server,
            token,
            repository,
            note,
        } => submit(&file, &server, &token, &repository, &note, cli.json).await,
    }
}

fn init(dir: &Path, id: &str, name: &str, version: &str, publisher: &str, language: &str, license: &str) -> Result<()> {
    if !auxipak_core::ids::is_valid_app_id(id) {
        bail!("identifiant invalide : {id}");
    }
    if dir.join(MANIFEST_FILE).exists() {
        bail!("{} contient déjà un manifeste", dir.display());
    }
    std::fs::create_dir_all(dir.join("payload/bin"))?;
    std::fs::create_dir_all(dir.join("scripts"))?;
    let m = project::render_template(id, name, version, publisher, language, license);
    std::fs::write(dir.join(MANIFEST_FILE), m)?;
    let placeholder = dir.join("payload/bin").join(id);
    std::fs::write(&placeholder, format!("#!/bin/sh\necho \"{name} {version}\"\n"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&placeholder, std::fs::Permissions::from_mode(0o755))?;
    }
    println!(
        "Projet créé dans {}. Éditez {MANIFEST_FILE}, puis « auxipak-builder build {} ».",
        dir.display(),
        dir.display()
    );
    Ok(())
}

fn build(dir: &Path, output: Option<&Path>) -> Result<(PathBuf, archive::Inspection)> {
    let (m, warnings) = project::load_manifest(dir)?;
    for w in warnings {
        eprintln!("{w}");
    }
    let out = match output {
        Some(o) => o.to_path_buf(),
        None => PathBuf::from(m.suggested_file_name()),
    };
    let (_, insp) = project::build(dir, &out)?;
    for w in &insp.warnings {
        eprintln!("{w}");
    }
    Ok((out, insp))
}

fn validate(path: &Path, json: bool) -> Result<()> {
    let (manifest, warnings, kind) = if path.is_dir() {
        // Vérification complète avec les fichiers réels, dans un emplacement temporaire.
        let tmp = tempfile::tempdir()?;
        let (m2, insp) = project::build(path, &tmp.path().join("check.apak"))?;
        (m2, insp.warnings, "projet")
    } else if path.extension().and_then(|e| e.to_str()) == Some("apak") {
        let insp = archive::inspect(path, &Limits::default()).map_err(|e| anyhow!("{e}"))?;
        (insp.manifest, insp.warnings, "archive")
    } else {
        let (m, w) = Manifest::parse(&std::fs::read(path)?).map_err(|e| anyhow!("{e}"))?;
        (m, w, "manifeste")
    };
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "valid": true, "kind": kind, "id": manifest.id, "version": manifest.version,
                "warnings": warnings,
            }))?
        );
    } else {
        println!(
            "{kind} valide : {} {} ({} variante(s))",
            manifest.id,
            manifest.version,
            manifest.targets.len()
        );
        for w in warnings {
            println!("{w}");
        }
    }
    Ok(())
}

fn test(file: &Path, json: bool) -> Result<()> {
    let report = project::static_tests(file, true)?;
    let ok = report.iter().all(|c| c.ok);
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({"ok": ok, "checks": report}))?
        );
    } else {
        for c in &report {
            println!("[{}] {} : {}", if c.ok { " OK " } else { "ÉCHEC" }, c.check, c.detail);
        }
        println!("Remarque : tests statiques uniquement ; aucun installateur ni script n'a été exécuté.");
    }
    if !ok {
        bail!("des tests ont échoué");
    }
    Ok(())
}

async fn keys(cmd: KeysCmd) -> Result<()> {
    match cmd {
        KeysCmd::Generate { out, public, owner } => {
            let s = PackageSigner::generate();
            write_private(&out, &s.to_pem())?;
            let mut trust = if public.exists() {
                TrustedKeys::load(&public)?
            } else {
                TrustedKeys::new(vec![])
            };
            trust.keys.push(s.public_info(&owner, KeyPurpose::PackageSigning));
            std::fs::write(&public, serde_json::to_string_pretty(&trust)?)?;
            println!(
                "Clé {} créée : privée {} (à protéger), publique ajoutée à {}",
                s.key_id(),
                out.display(),
                public.display()
            );
            Ok(())
        }
        KeysCmd::InitRepository {
            out,
            owner,
            root_days,
            dev,
        } => {
            let summary = auxipak_core::keyset::generate(&out, &owner, root_days).await?;
            println!("Racine de confiance créée dans {}", out.display());
            println!("  public/root.json, public/package-keys.json : à distribuer (client, serveur)");
            println!("  online/*.pem  : secrets du serveur (montés en lecture seule, jamais dans Git ni dans une image)");
            println!("  offline/root.pem : CLÉ RACINE — à déplacer immédiatement sur un support hors ligne chiffré");
            println!("  empreinte root.json : {}", summary.root_sha256);
            println!("  clé de signature des paquets : {}", summary.package_key_id);
            if !dev {
                println!("Procédure complète : docs/SIGNING.md (cérémonie de clés de production)");
            }
            Ok(())
        }
        KeysCmd::ShowRoot { root } => {
            let s = tuf::check_root_file(&root)?;
            println!("root.json version {} — expire {}", s.version, s.expires);
            for (role, ids, th) in s.roles {
                println!("  {role:<10} seuil {th} : {}", ids.join(", "));
            }
            Ok(())
        }
    }
}

async fn submit(file: &Path, server: &str, token: &str, repository: &str, note: &str, json: bool) -> Result<()> {
    let insp = archive::inspect(file, &Limits::default()).map_err(|e| anyhow!("paquet invalide : {e}"))?;
    let base = url::Url::parse(server)?;
    let local = matches!(base.host_str(), Some("localhost") | Some("127.0.0.1"));
    if base.scheme() != "https" && !(base.scheme() == "http" && local) {
        bail!("HTTPS obligatoire pour la soumission (HTTP accepté uniquement vers localhost)");
    }
    if !auxipak_core::ids::is_valid_repo_name(repository) {
        bail!("dépôt invalide");
    }
    let mut url = base.join("/api/v1/submissions")?;
    url.query_pairs_mut()
        .append_pair("repository", repository)
        .append_pair("file_name", &file.file_name().unwrap().to_string_lossy())
        .append_pair("note", note);
    let f = tokio::fs::File::open(file).await?;
    let body = reqwest::Body::wrap_stream(tokio_util::io::ReaderStream::new(f));
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let resp = client
        .post(url)
        .bearer_auth(token)
        .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
        .header(reqwest::header::CONTENT_LENGTH, insp.archive_size)
        .body(body)
        .send()
        .await?;
    let status = resp.status();
    let text = resp.text().await?;
    if !status.is_success() {
        bail!("le serveur a refusé la soumission ({status}) : {text}");
    }
    let v: serde_json::Value = serde_json::from_str(&text).unwrap_or(serde_json::json!({"raw": text}));
    // Signature détachée éventuelle.
    let sig = PathBuf::from(format!("{}.sig", file.display()));
    if sig.exists() {
        if let Some(id) = v.get("id").and_then(|x| x.as_str()) {
            let u = base.join(&format!("/api/v1/submissions/{id}/signature"))?;
            let r = client.put(u).bearer_auth(token).body(std::fs::read(&sig)?).send().await?;
            if !r.status().is_success() {
                bail!("signature refusée : {}", r.text().await?);
            }
        }
    }
    if json {
        println!("{}", serde_json::to_string_pretty(&v)?);
    } else {
        println!(
            "Demande de publication créée : {} (statut : {}). Elle doit être approuvée par un relecteur.",
            v.get("id").and_then(|x| x.as_str()).unwrap_or("?"),
            v.get("status").and_then(|x| x.as_str()).unwrap_or("?")
        );
    }
    Ok(())
}
