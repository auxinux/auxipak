//! `auxipak-builder` — création, validation, test, signature et soumission de
//! paquets `.aupak`.
//!
//! La construction d'un paquet n'entraîne jamais sa publication : la commande
//! `submit` crée une *demande de publication* sur le serveur, qui doit être
//! approuvée par un relecteur autorisé.

use anyhow::{anyhow, bail, Context, Result};
use auxipak_core::archive::{self, Limits};
use auxipak_core::manifest::{Manifest, MANIFEST_FILE};
use auxipak_core::project;
use auxipak_core::signature::{KeyPurpose, PackageRef, PackageSignature, PackageSigner, TrustedKeys};
use auxipak_core::tr;
use auxipak_core::tuf;
use clap::{CommandFactory, FromArgMatches, Parser, Subcommand};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

mod settings;

#[derive(Parser)]
#[command(name = "auxipak-builder", version, about = "Constructeur de paquets AuxiPak (.aupak)")]
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
        /// Éditeur (défaut : « Éditeur inconnu »).
        #[arg(long)]
        publisher: Option<String>,
        /// Langue du paquet (défaut : langue de l'interface).
        #[arg(long)]
        language: Option<String>,
        #[arg(long, default_value = "GPL-3.0-or-later")]
        license: String,
    },
    /// Valider un manifeste, un projet ou une archive .aupak.
    Validate { path: PathBuf },
    /// Construire une archive .aupak normalisée à partir d'un projet.
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
        /// URL du serveur (sinon AUXIPAK_SERVER, puis « auxipak-builder set server=… »).
        #[arg(long, env = "AUXIPAK_SERVER")]
        server: Option<String>,
        /// Jeton d'API (sinon AUXIPAK_TOKEN, puis « auxipak-builder set token=… »).
        #[arg(long, env = "AUXIPAK_TOKEN", hide_env_values = true)]
        token: Option<String>,
        /// Dépôt cible (défaut : réglage « repository », sinon official).
        #[arg(long)]
        repository: Option<String>,
        #[arg(long, default_value = "")]
        note: String,
    },
    /// Enregistrer des réglages : server, token, repository
    /// (ex. « set server=https://auxipak.auxinux.ca token=apk_… » ; « set token »
    /// sans valeur la demande, hors de l'historique du shell).
    Set {
        #[arg(required = true, value_name = "CLÉ=VALEUR")]
        assignments: Vec<String>,
    },
    /// Supprimer des réglages enregistrés.
    Unset {
        #[arg(required = true, value_name = "CLÉ")]
        keys: Vec<String>,
    },
    /// Afficher les réglages enregistrés (jeton masqué).
    Config,
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
    // Langue : AUXIPAK_LANG, puis « auxipak-builder set lang=… », puis système.
    if std::env::var("AUXIPAK_LANG")
        .ok()
        .and_then(|v| auxipak_core::i18n::Lang::parse(&v))
        .is_none()
    {
        if let Some(l) = settings::Settings::load()
            .ok()
            .and_then(|s| s.lang)
            .and_then(|l| auxipak_core::i18n::Lang::parse(&l))
        {
            auxipak_core::i18n::set(l);
        }
    }
    let mut cmd = Cli::command();
    if !auxipak_core::i18n::is_fr() {
        cmd = english_help(cmd);
    }
    let cli = match Cli::from_arg_matches(&cmd.get_matches()) {
        Ok(c) => c,
        Err(e) => e.exit(),
    };
    match run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{}", tr!("erreur : {e:#}", "error: {e:#}"));
            ExitCode::from(1)
        }
    }
}

/// Aide en anglais : les commentaires de documentation (aide française) sont
/// remplacés par leur traduction.
fn english_help(cmd: clap::Command) -> clap::Command {
    type Table = &'static [(&'static str, &'static str)];
    fn sub(cmd: clap::Command, name: &'static str, about: &'static str, args: Table) -> clap::Command {
        cmd.mut_subcommand(name, |mut c| {
            c = c.about(about);
            for (arg, help) in args {
                c = c.mut_arg(*arg, |a| a.help(*help));
            }
            c
        })
    }
    let mut cmd = cmd
        .about("AuxiPak package builder (.aupak)")
        .mut_arg("json", |a| a.help("JSON output (for automation: CI, agents)"));
    cmd = sub(
        cmd,
        "init",
        "Create a package project (instruction.auxipak, payload/, scripts/)",
        &[
            ("publisher", "Publisher (default: “Unknown publisher”)"),
            ("language", "Package language (default: interface language)"),
        ],
    );
    cmd = sub(cmd, "validate", "Validate a manifest, a project or a .aupak archive", &[]);
    cmd = sub(
        cmd,
        "build",
        "Build a normalized .aupak archive from a project",
        &[("output", "Output file (default: normalized name in the current directory)")],
    );
    cmd = sub(cmd, "test", "Static tests of a package (no installer or script is run)", &[]);
    cmd = sub(
        cmd,
        "sign",
        "Sign a package (detached document <file>.sig)",
        &[("key", "Ed25519 PKCS#8 PEM private key")],
    );
    cmd = sub(
        cmd,
        "verify-signature",
        "Verify a package signature with a public key file",
        &[],
    );
    cmd = sub(
        cmd,
        "submit",
        "Submit a package to the server (creates a publication request, never a direct publication)",
        &[
            (
                "server",
                "Server URL (otherwise AUXIPAK_SERVER, then « auxipak-builder set server=… »)",
            ),
            (
                "token",
                "API token (otherwise AUXIPAK_TOKEN, then « auxipak-builder set token=… »)",
            ),
            (
                "repository",
                "Target repository (default: “repository” setting, otherwise official)",
            ),
        ],
    );
    cmd = sub(
        cmd,
        "set",
        "Save settings: server, token, repository, lang (e.g. « set server=https://auxipak.auxinux.ca token=apk_… »; \
         « set token » without a value prompts for it, keeping it out of the shell history)",
        &[],
    );
    cmd = sub(cmd, "unset", "Delete saved settings", &[]);
    cmd = sub(cmd, "config", "Show saved settings (token masked)", &[]);
    cmd.mut_subcommand("keys", |c| {
        let c = c.about("Key management");
        let c = sub(
            c,
            "generate",
            "Generate a package signing key",
            &[
                ("out", "Private key file to create (mode 0600)"),
                ("public", "package-keys.json file to create or extend"),
            ],
        );
        let c = sub(
            c,
            "init-repository",
            "Initialization ceremony: TUF root + online keys + package key",
            &[
                ("out", "Output directory (must be empty or not exist)"),
                ("root_days", "Validity period of root.json (days)"),
                ("dev", "Test environment: the production warning is omitted"),
            ],
        );
        sub(c, "show-root", "Show the contents of a TUF root", &[])
    })
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
        } => {
            let publisher = publisher.unwrap_or_else(|| tr!("Éditeur inconnu", "Unknown publisher"));
            let language = language.unwrap_or_else(|| auxipak_core::i18n::current().code().to_string());
            init(&dir, &id, &name, &version, &publisher, &language, &license)
        }
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
                println!("{}", tr!("Paquet construit : {}", "Package built: {}", out.display()));
                println!(
                    "{}",
                    tr!(
                        "  {} {} — {} entrées, {} octets",
                        "  {} {} — {} entries, {} bytes",
                        insp.manifest.id,
                        insp.manifest.version,
                        insp.entries.len(),
                        insp.archive_size
                    )
                );
                println!("  SHA-256: {}", insp.archive_sha256);
                println!(
                    "{}",
                    tr!(
                        "  (non publié : utilisez « auxipak-builder submit » pour demander la publication)",
                        "  (not published: use « auxipak-builder submit » to request publication)"
                    )
                );
            }
            Ok(())
        }
        Cmd::Test { file } => test(&file, cli.json),
        Cmd::Sign { file, key } => {
            let signer = PackageSigner::load(&key).with_context(|| tr!("clé {}", "key {}", key.display()))?;
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
            println!(
                "{}",
                tr!(
                    "Signature écrite : {} (clé {})",
                    "Signature written: {} (key {})",
                    out.display(),
                    signer.key_id()
                )
            );
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
            println!(
                "{}",
                tr!(
                    "Signature valide : clé {} ({}), signée le {}",
                    "Valid signature: key {} ({}), signed on {}",
                    v.key_id,
                    v.owner,
                    v.signed_at
                )
            );
            Ok(())
        }
        Cmd::Keys { cmd } => keys(cmd).await,
        Cmd::Submit {
            file,
            server,
            token,
            repository,
            note,
        } => {
            let saved = settings::Settings::load()?;
            let server = server.or(saved.server).with_context(|| {
                tr!(
                    "serveur non défini : auxipak-builder set server=https://…",
                    "server not set: auxipak-builder set server=https://…"
                )
            })?;
            let token = token.or(saved.token).with_context(|| {
                tr!(
                    "jeton non défini : auxipak-builder set token=apk_…",
                    "token not set: auxipak-builder set token=apk_…"
                )
            })?;
            let repository = repository.or(saved.repository).unwrap_or_else(|| "official".into());
            submit(&file, &server, &token, &repository, &note, cli.json).await
        }
        Cmd::Set { assignments } => {
            let mut s = settings::Settings::load()?;
            for a in &assignments {
                let (k, v) = match a.split_once('=') {
                    Some((k, v)) => (k.trim().to_string(), v.to_string()),
                    None => (a.trim().to_string(), settings::read_value(a.trim())?),
                };
                s.set(&k, &v)?;
                // Nouvelle langue : appliquée dès ce message.
                if let Some(l) = s.lang.as_deref().and_then(auxipak_core::i18n::Lang::parse) {
                    if matches!(k.as_str(), "lang" | "language" | "langue") {
                        auxipak_core::i18n::set(l);
                    }
                }
            }
            let p = s.save()?;
            println!("{}", tr!("Réglages enregistrés : {}", "Settings saved: {}", p.display()));
            Ok(())
        }
        Cmd::Unset { keys } => {
            let mut s = settings::Settings::load()?;
            for k in &keys {
                s.unset(k)?;
            }
            let p = s.save()?;
            println!("{}", tr!("Réglages enregistrés : {}", "Settings saved: {}", p.display()));
            Ok(())
        }
        Cmd::Config => {
            let s = settings::Settings::load()?;
            let none = tr!("(non défini)", "(not set)");
            println!("{}", tr!("Fichier    : {}", "File       : {}", settings::path()?.display()));
            println!("server     : {}", s.server.clone().unwrap_or(none.clone()));
            println!(
                "token      : {}",
                s.token.as_deref().map(settings::mask).unwrap_or(none.clone())
            );
            println!(
                "repository : {}",
                s.repository.clone().unwrap_or(tr!("official (défaut)", "official (default)"))
            );
            println!("lang       : {}", auxipak_core::i18n::current().code());
            Ok(())
        }
    }
}

fn init(dir: &Path, id: &str, name: &str, version: &str, publisher: &str, language: &str, license: &str) -> Result<()> {
    if !auxipak_core::ids::is_valid_app_id(id) {
        bail!(tr!("identifiant invalide : {id}", "invalid identifier: {id}"));
    }
    if dir.join(MANIFEST_FILE).exists() {
        bail!(tr!(
            "{} contient déjà un manifeste",
            "{} already contains a manifest",
            dir.display()
        ));
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
        "{}",
        tr!(
            "Projet créé dans {}. Éditez {MANIFEST_FILE}, puis « auxipak-builder build {} ».",
            "Project created in {}. Edit {MANIFEST_FILE}, then run « auxipak-builder build {} ».",
            dir.display(),
            dir.display()
        )
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
        let (m2, insp) = project::build(path, &tmp.path().join("check.aupak"))?;
        (m2, insp.warnings, "projet")
    } else if archive::is_package_path(path) {
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
        let label = match kind {
            "projet" => tr!("projet", "project"),
            "archive" => tr!("archive", "archive"),
            _ => tr!("manifeste", "manifest"),
        };
        println!(
            "{}",
            tr!(
                "{label} valide : {} {} ({} variante(s))",
                "valid {label}: {} {} ({} target(s))",
                manifest.id,
                manifest.version,
                manifest.targets.len()
            )
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
            let status = if c.ok { " OK " } else { &tr!("ÉCHEC", "FAIL") };
            println!("{}", tr!("[{status}] {} : {}", "[{status}] {}: {}", c.check, c.detail));
        }
        println!(
            "{}",
            tr!(
                "Remarque : tests statiques uniquement ; aucun installateur ni script n'a été exécuté.",
                "Note: static tests only; no installer or script was run."
            )
        );
    }
    if !ok {
        bail!(tr!("des tests ont échoué", "some tests failed"));
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
                "{}",
                tr!(
                    "Clé {} créée : privée {} (à protéger), publique ajoutée à {}",
                    "Key {} created: private {} (keep it safe), public added to {}",
                    s.key_id(),
                    out.display(),
                    public.display()
                )
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
            println!(
                "{}",
                tr!("Racine de confiance créée dans {}", "Trust root created in {}", out.display())
            );
            println!(
                "{}",
                tr!(
                    "  public/root.json, public/package-keys.json : à distribuer (client, serveur)",
                    "  public/root.json, public/package-keys.json: to distribute (client, server)"
                )
            );
            println!(
                "{}",
                tr!(
                    "  online/*.pem  : secrets du serveur (montés en lecture seule, jamais dans Git ni dans une image)",
                    "  online/*.pem: server secrets (mounted read-only, never in Git or in an image)"
                )
            );
            println!(
                "{}",
                tr!(
                    "  offline/root.pem : CLÉ RACINE — à déplacer immédiatement sur un support hors ligne chiffré",
                    "  offline/root.pem: ROOT KEY — move it immediately to an encrypted offline medium"
                )
            );
            println!(
                "{}",
                tr!("  empreinte root.json : {}", "  root.json digest: {}", summary.root_sha256)
            );
            println!(
                "{}",
                tr!(
                    "  clé de signature des paquets : {}",
                    "  package signing key: {}",
                    summary.package_key_id
                )
            );
            if !dev {
                println!(
                    "{}",
                    tr!(
                        "Procédure complète : docs/SIGNING.md (cérémonie de clés de production)",
                        "Full procedure: docs/SIGNING.md (production key ceremony)"
                    )
                );
            }
            Ok(())
        }
        KeysCmd::ShowRoot { root } => {
            let s = tuf::check_root_file(&root)?;
            println!(
                "{}",
                tr!(
                    "root.json version {} — expire {}",
                    "root.json version {} — expires {}",
                    s.version,
                    s.expires
                )
            );
            for (role, ids, th) in s.roles {
                println!(
                    "{}",
                    tr!(
                        "  {role:<10} seuil {th} : {}",
                        "  {role:<10} threshold {th}: {}",
                        ids.join(", ")
                    )
                );
            }
            Ok(())
        }
    }
}

async fn submit(file: &Path, server: &str, token: &str, repository: &str, note: &str, json: bool) -> Result<()> {
    let insp =
        archive::inspect(file, &Limits::default()).map_err(|e| anyhow!(tr!("paquet invalide : {e}", "invalid package: {e}")))?;
    let base = settings::check_server(server)?;
    if !auxipak_core::ids::is_valid_repo_name(repository) {
        bail!(tr!("dépôt invalide", "invalid repository"));
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
        .header(reqwest::header::ACCEPT_LANGUAGE, auxipak_core::i18n::current().code())
        .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
        .header(reqwest::header::CONTENT_LENGTH, insp.archive_size)
        .body(body)
        .send()
        .await?;
    let status = resp.status();
    let text = resp.text().await?;
    if !status.is_success() {
        bail!(tr!(
            "le serveur a refusé la soumission ({status}) : {text}",
            "the server rejected the submission ({status}): {text}"
        ));
    }
    let v: serde_json::Value = serde_json::from_str(&text).unwrap_or(serde_json::json!({"raw": text}));
    // Signature détachée éventuelle.
    let sig = PathBuf::from(format!("{}.sig", file.display()));
    if sig.exists() {
        if let Some(id) = v.get("id").and_then(|x| x.as_str()) {
            let u = base.join(&format!("/api/v1/submissions/{id}/signature"))?;
            let r = client
                .put(u)
                .bearer_auth(token)
                .header(reqwest::header::ACCEPT_LANGUAGE, auxipak_core::i18n::current().code())
                .body(std::fs::read(&sig)?)
                .send()
                .await?;
            if !r.status().is_success() {
                bail!(tr!("signature refusée : {}", "signature rejected: {}", r.text().await?));
            }
        }
    }
    if json {
        println!("{}", serde_json::to_string_pretty(&v)?);
    } else {
        println!(
            "{}",
            tr!(
                "Demande de publication créée : {} (statut : {}). Elle doit être approuvée par un relecteur.",
                "Publication request created: {} (status: {}). It must be approved by a reviewer.",
                v.get("id").and_then(|x| x.as_str()).unwrap_or("?"),
                v.get("status").and_then(|x| x.as_str()).unwrap_or("?")
            )
        );
    }
    Ok(())
}
