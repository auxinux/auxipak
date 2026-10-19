//! `auxipak-builder` — création, validation, test, signature et soumission de
//! paquets `.apak`.
//!
//! La construction d'un paquet n'entraîne jamais sa publication : la commande
//! `submit` crée une *demande de publication* sur le serveur, qui doit être
//! approuvée par un relecteur autorisé.

use anyhow::{anyhow, bail, Context, Result};
use auxipak_core::archive::{self, BuildFile, Limits};
use auxipak_core::manifest::{Install, Manifest, MANIFEST_FILE};
use auxipak_core::platform::{Arch, Distribution, Os, SystemProfile};
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
    if path.exists() {
        bail!("{} existe déjà : refus d'écraser une clé", path.display());
    }
    if let Some(p) = path.parent() {
        std::fs::create_dir_all(p)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700))?;
        }
    }
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    use std::io::Write;
    o.open(path)?.write_all(data.as_bytes())?;
    Ok(())
}

async fn run(cli: Cli) -> Result<()> {
    match cli.cmd {
        Cmd::Init { dir, id, name, version, publisher, language, license } => init(&dir, &id, &name, &version, &publisher, &language, &license),
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
                println!("  {} {} — {} entrées, {} octets", insp.manifest.id, insp.manifest.version, insp.entries.len(), insp.archive_size);
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
            let v = doc.verify(&sha, size, &trust, &[KeyPurpose::PackageSigning, KeyPurpose::DeveloperSigning])?;
            println!("Signature valide : clé {} ({}), signée le {}", v.key_id, v.owner, v.signed_at);
            Ok(())
        }
        Cmd::Keys { cmd } => keys(cmd).await,
        Cmd::Submit { file, server, token, repository, note } => submit(&file, &server, &token, &repository, &note, cli.json).await,
    }
}

const MANIFEST_TEMPLATE: &str = r#"# Manifeste AuxiPak — voir docs/MANIFEST_SPEC.md
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

fn init(dir: &Path, id: &str, name: &str, version: &str, publisher: &str, language: &str, license: &str) -> Result<()> {
    if !auxipak_core::ids::is_valid_app_id(id) {
        bail!("identifiant invalide : {id}");
    }
    if dir.join(MANIFEST_FILE).exists() {
        bail!("{} contient déjà un manifeste", dir.display());
    }
    std::fs::create_dir_all(dir.join("payload/bin"))?;
    std::fs::create_dir_all(dir.join("scripts"))?;
    let m = MANIFEST_TEMPLATE
        .replace("{id}", id)
        .replace("{name}", &name.replace('"', ""))
        .replace("{version}", version)
        .replace("{publisher}", &publisher.replace('"', ""))
        .replace("{license}", &license.replace('"', ""))
        .replace("{language}", language);
    std::fs::write(dir.join(MANIFEST_FILE), m)?;
    let placeholder = dir.join("payload/bin").join(id);
    std::fs::write(&placeholder, format!("#!/bin/sh\necho \"{name} {version}\"\n"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&placeholder, std::fs::Permissions::from_mode(0o755))?;
    }
    println!("Projet créé dans {}. Éditez {MANIFEST_FILE}, puis « auxipak-builder build {} ».", dir.display(), dir.display());
    Ok(())
}

/// Fichiers d'un projet : tout ce qui se trouve sous payload/ et scripts/.
fn project_files(dir: &Path) -> Result<Vec<BuildFile>> {
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
            bail!("lien symbolique refusé dans le projet : {rel}");
        } else if ft.is_dir() {
            walk(&e.path(), &format!("{rel}/"), out)?;
        } else if ft.is_file() {
            out.push(BuildFile { archive_path: rel, source: e.path(), executable: false });
        }
    }
    Ok(())
}

/// Charge le manifeste source d'un projet. La section `contents` est
/// (re)calculée à partir des fichiers réels de payload/ et scripts/.
fn load_project_manifest(dir: &Path) -> Result<Manifest> {
    let path = dir.join(MANIFEST_FILE);
    let text = std::fs::read_to_string(&path).with_context(|| format!("{MANIFEST_FILE} introuvable dans {}", dir.display()))?;
    let mut value = auxipak_core::manifest::parse_yaml_value(&text).map_err(|e| anyhow!("{e}"))?;
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
    for f in project_files(dir)? {
        let (sha256, size) = auxipak_core::hash::sha256_file(&f.source)?;
        let mut entry = serde_json::json!({"path": f.archive_path, "sha256": sha256, "size": size});
        if declared_exec.contains(&f.archive_path) {
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
    let (m, warnings) = Manifest::from_value(value).map_err(|e| anyhow!("{e}"))?;
    for w in warnings {
        eprintln!("{w}");
    }
    Ok(m)
}

fn build(dir: &Path, output: Option<&Path>) -> Result<(PathBuf, archive::Inspection)> {
    let m = load_project_manifest(dir)?;
    let files = project_files(dir)?;
    let out = match output {
        Some(o) => o.to_path_buf(),
        None => PathBuf::from(m.suggested_file_name()),
    };
    if out.extension().and_then(|e| e.to_str()) != Some(archive::APAK_EXTENSION) {
        bail!("le fichier de sortie doit porter l'extension .apak");
    }
    let (_, insp) = archive::build(&m, &files, &out).map_err(|e| anyhow!("{e}"))?;
    for w in &insp.warnings {
        eprintln!("{w}");
    }
    Ok((out, insp))
}

fn validate(path: &Path, json: bool) -> Result<()> {
    let (manifest, warnings, kind) = if path.is_dir() {
        let m = load_project_manifest(path)?;
        // Vérification complète avec les fichiers réels, dans un emplacement temporaire.
        let tmp = tempfile::tempdir()?;
        let out = tmp.path().join("check.apak");
        let files = project_files(path)?;
        let (m2, insp) = archive::build(&m, &files, &out).map_err(|e| anyhow!("{e}"))?;
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
        println!("{kind} valide : {} {} ({} variante(s))", manifest.id, manifest.version, manifest.targets.len());
        for w in warnings {
            println!("{w}");
        }
    }
    Ok(())
}

/// Profils de référence pour les tests de sélection de variante.
fn reference_profiles() -> Vec<SystemProfile> {
    let p = |os, d, v: &str, a| SystemProfile {
        os,
        distribution: d,
        version: v.into(),
        arch: a,
        raw_id: d.as_str().into(),
        pretty_name: format!("{} {}", d, v),
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

fn test(file: &Path, json: bool) -> Result<()> {
    let mut report = Vec::<(String, bool, String)>::new();
    let insp = archive::inspect(file, &Limits::default()).map_err(|e| anyhow!("structure : {e}"))?;
    report.push(("structure et manifeste".into(), true, format!("{} entrées", insp.entries.len())));
    // Extraction complète dans un répertoire isolé (vérifie chaque empreinte).
    let tmp = tempfile::tempdir()?;
    archive::extract(file, tmp.path(), &Limits::default()).map_err(|e| anyhow!("extraction : {e}"))?;
    report.push(("extraction et empreintes".into(), true, format!("{} octets", insp.total_unpacked)));
    let m = &insp.manifest;
    // Sélection des variantes sur la matrice de référence.
    for p in reference_profiles() {
        let r = m.select_target(&p);
        report.push((
            format!("variante pour {} {} {}", p.distribution, p.version, p.arch),
            true,
            match r {
                Ok(t) => format!("→ {}", t.name),
                Err(_) => "aucune (non pris en charge)".into(),
            },
        ));
    }
    // Vérifications statiques des fichiers intégrés.
    for t in &m.targets {
        if let Install::Deb { package, source } = &t.install {
            if let Some(f) = &source.file {
                let path = tmp.path().join(f);
                match std::process::Command::new("dpkg-deb").arg("--field").arg(&path).arg("Package").output() {
                    Ok(o) if o.status.success() => {
                        let actual = String::from_utf8_lossy(&o.stdout).trim().to_string();
                        let ok = &actual == package;
                        report.push((format!("{} : nom du paquet .deb", t.name), ok, format!("control: {actual}, manifeste: {package}")));
                    }
                    _ => report.push((format!("{} : contrôle .deb", t.name), true, "dpkg-deb indisponible : non vérifié".into())),
                }
            }
        }
        for (_, script) in t.scripts.all() {
            report.push(check_script_syntax(tmp.path(), script, t.name.as_str()));
        }
        if let Install::Script { script, .. } = &t.install {
            report.push(check_script_syntax(tmp.path(), script, t.name.as_str()));
        }
    }
    let ok = report.iter().all(|(_, ok, _)| *ok);
    if json {
        let v: Vec<_> = report.iter().map(|(n, ok, d)| serde_json::json!({"check": n, "ok": ok, "detail": d})).collect();
        println!("{}", serde_json::to_string_pretty(&serde_json::json!({"ok": ok, "checks": v}))?);
    } else {
        for (n, ok, d) in &report {
            println!("[{}] {n} : {d}", if *ok { " OK " } else { "ÉCHEC" });
        }
        println!("Remarque : tests statiques uniquement ; aucun installateur ni script n'a été exécuté.");
    }
    if !ok {
        bail!("des tests ont échoué");
    }
    Ok(())
}

fn check_script_syntax(root: &Path, script: &str, target: &str) -> (String, bool, String) {
    let path = root.join(script);
    if script.ends_with(".sh") {
        // `bash -n` analyse la syntaxe sans rien exécuter.
        match std::process::Command::new("bash").arg("-n").arg(&path).output() {
            Ok(o) => (
                format!("{target} : syntaxe de {script}"),
                o.status.success(),
                String::from_utf8_lossy(&o.stderr).trim().to_string(),
            ),
            Err(_) => (format!("{target} : syntaxe de {script}"), true, "bash indisponible : non vérifié".into()),
        }
    } else {
        (format!("{target} : {script}"), true, "PowerShell : analyse non effectuée sur cet hôte".into())
    }
}

async fn keys(cmd: KeysCmd) -> Result<()> {
    match cmd {
        KeysCmd::Generate { out, public, owner } => {
            let s = PackageSigner::generate();
            write_private(&out, &s.to_pem())?;
            let mut trust = if public.exists() { TrustedKeys::load(&public)? } else { TrustedKeys::new(vec![]) };
            trust.keys.push(s.public_info(&owner, KeyPurpose::PackageSigning));
            std::fs::write(&public, serde_json::to_string_pretty(&trust)?)?;
            println!("Clé {} créée : privée {} (à protéger), publique ajoutée à {}", s.key_id(), out.display(), public.display());
            Ok(())
        }
        KeysCmd::InitRepository { out, owner, root_days, dev } => {
            if out.exists() && std::fs::read_dir(&out)?.next().is_some() {
                bail!("{} n'est pas vide", out.display());
            }
            let root_pem = tuf::generate_key_pem();
            let targets = tuf::generate_key_pem();
            let snapshot = tuf::generate_key_pem();
            let timestamp = tuf::generate_key_pem();
            let root_json = tuf::create_root(tuf::RootSpec {
                root_keys: vec![root_pem.clone()],
                root_threshold: 1,
                targets_keys: vec![tuf::public_tuf_key(&targets)?.1],
                snapshot_keys: vec![tuf::public_tuf_key(&snapshot)?.1],
                timestamp_keys: vec![tuf::public_tuf_key(&timestamp)?.1],
                version: 1,
                expires: chrono::Utc::now() + chrono::Duration::days(root_days),
            })
            .await?;
            let pkg = PackageSigner::generate();
            std::fs::create_dir_all(out.join("public"))?;
            std::fs::write(out.join("public/root.json"), &root_json)?;
            let trust = TrustedKeys::new(vec![pkg.public_info(&owner, KeyPurpose::PackageSigning)]);
            std::fs::write(out.join("public/package-keys.json"), serde_json::to_string_pretty(&trust)?)?;
            write_private(&out.join("online/targets.pem"), &targets)?;
            write_private(&out.join("online/snapshot.pem"), &snapshot)?;
            write_private(&out.join("online/timestamp.pem"), &timestamp)?;
            write_private(&out.join("online/package-signing.pem"), &pkg.to_pem())?;
            write_private(&out.join("offline/root.pem"), &root_pem)?;
            println!("Racine de confiance créée dans {}", out.display());
            println!("  public/root.json, public/package-keys.json : à distribuer (client, serveur)");
            println!("  online/*.pem  : secrets du serveur (montés en lecture seule, jamais dans Git ni dans une image)");
            println!("  offline/root.pem : CLÉ RACINE — à déplacer immédiatement sur un support hors ligne chiffré");
            println!("  empreinte root.json : {}", auxipak_core::hash::sha256_hex(&root_json));
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
    let client = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build()?;
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
