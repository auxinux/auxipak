//! Tests d'intégration du client `auxipak` contre un dépôt TUF local
//! (`file://`), construit avec les mêmes bibliothèques que le serveur.
//!
//! Le profil système est imposé (AuxiNuxOS x86_64) : seule la *détection* est
//! simulée ; les installations (méthode `files`), les vérifications TUF, les
//! signatures et le registre sont réels. Aucun installateur tiers n'est
//! exécuté ; le seul script exécuté est un script de test inoffensif écrit
//! par ce fichier.

use auxipak_core::archive::{self, Limits};
use auxipak_core::index::{AppMeta, RepositoryInfo, Revocation, Status};
use auxipak_core::repogen::{PublishedPackage, RepoContent};
use auxipak_core::signature::{PackageRef, PackageSigner};
use auxipak_core::tuf::{self, PemKeySource, PublishSpec};
use chrono::{Duration, Utc};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use tough::key_source::KeySource;

const PROFILE: &str = r#"{"os":"linux","distribution":"auxinuxos","version":"1.0","arch":"x86_64","raw_id":"auxinuxos","pretty_name":"AuxiNuxOS 1.0 (test)","immutable":true}"#;

struct Fixture {
    dir: tempfile::TempDir,
    generation: u64,
    packages: Vec<PublishedPackage>,
    apps: Vec<AppMeta>,
    revoked: Vec<Revocation>,
    ttl: u64,
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Runtime::new().unwrap()
}

impl Fixture {
    fn new() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        rt().block_on(auxipak_core::keyset::generate(&dir.path().join("keys"), "Test", 30))
            .unwrap();
        let f = Fixture {
            dir,
            generation: 0,
            packages: vec![],
            apps: vec![],
            revoked: vec![],
            ttl: 3600,
        };
        f.write_config();
        f
    }

    fn p(&self, rel: &str) -> PathBuf {
        self.dir.path().join(rel)
    }

    fn home(&self) -> PathBuf {
        self.p("home")
    }

    fn repo(&self) -> PathBuf {
        self.p("repo")
    }

    fn write_config(&self) {
        let trust = self.home().join("config/trust/official");
        std::fs::create_dir_all(&trust).unwrap();
        std::fs::copy(self.p("keys/public/root.json"), trust.join("root.json")).unwrap();
        std::fs::copy(self.p("keys/public/package-keys.json"), trust.join("package-keys.json")).unwrap();
        let url = url::Url::from_directory_path(self.repo()).unwrap();
        std::fs::write(
            self.home().join("config/config.toml"),
            format!(
                "cache_ttl_seconds = {}\n\n[[repository]]\nname = \"official\"\nurl = \"{url}\"\nroot = \"trust/official/root.json\"\npackage_keys = \"trust/official/package-keys.json\"\nofficial = true\n",
                self.ttl
            ),
        )
        .unwrap();
    }

    /// Construit, signe et ajoute un paquet au contenu du dépôt.
    fn add(&mut self, yaml: &str, files: &[(&str, &[u8])], signer: Option<&PackageSigner>) -> PathBuf {
        let proj = self.p(&format!("proj-{}", self.packages.len()));
        std::fs::create_dir_all(&proj).unwrap();
        std::fs::write(proj.join("instruction.auxipak"), yaml).unwrap();
        for (path, data) in files {
            let f = proj.join(path);
            std::fs::create_dir_all(f.parent().unwrap()).unwrap();
            std::fs::write(&f, data).unwrap();
        }
        let out = self.p(&format!("pkg-{}.aupak", self.packages.len()));
        auxipak_core::project::build(&proj, &out).unwrap();
        self.add_file(&out, signer)
    }

    /// Ajoute une archive existante (éventuellement malveillante) au dépôt.
    fn add_file(&mut self, pkg: &Path, signer: Option<&PackageSigner>) -> PathBuf {
        let default = PackageSigner::load(&self.p("keys/online/package-signing.pem")).unwrap();
        let signer = signer.unwrap_or(&default);
        let (sha256, size) = auxipak_core::hash::sha256_file(pkg).unwrap();
        // Le manifeste est lu sans validation de l'archive (cas malveillants).
        let manifest = match archive::inspect(pkg, &Limits::default()) {
            Ok(i) => i.manifest,
            Err(_) => {
                let mut r = sevenz::reader(pkg);
                auxipak_core::manifest::Manifest::parse(&r.read_file("instruction.auxipak").unwrap())
                    .unwrap()
                    .0
            }
        };
        let file_name = format!("{}-{}.aupak", manifest.id, manifest.version);
        let sig = signer.sign(PackageRef {
            id: manifest.id.clone(),
            version: manifest.version.clone(),
            file_name: file_name.clone(),
            sha256: sha256.clone(),
            size,
        });
        let sig_path = PathBuf::from(format!("{}.sig", pkg.display()));
        std::fs::write(&sig_path, sig.to_json()).unwrap();
        if !self.apps.iter().any(|a| a.id == manifest.id) {
            self.apps.push(AppMeta {
                id: manifest.id.clone(),
                name: manifest.name.clone(),
                publisher: manifest.publisher.clone(),
                summary: manifest.summary.clone(),
                description: None,
                license: manifest.license.clone(),
                homepage: None,
                categories: vec![],
                status: Status::Verified,
                status_note: None,
                evaluated_at: None,
                translations: manifest.translations.clone(),
                ai_evaluation: None,
            });
        }
        self.packages.push(PublishedPackage {
            uses_scripts: manifest.targets.iter().any(|t| t.uses_scripts()),
            manifest,
            file_name,
            package_path: pkg.to_path_buf(),
            signature_path: sig_path,
            size,
            sha256,
            signature_key_id: signer.key_id().into(),
            published_at: Utc::now(),
        });
        pkg.to_path_buf()
    }

    /// Signe et publie le dépôt (remplace le précédent).
    fn publish_with(&mut self, timestamp_expires: chrono::DateTime<Utc>) {
        self.generation += 1;
        let src = self.p(&format!("src-{}", self.generation));
        std::fs::create_dir_all(&src).unwrap();
        let content = RepoContent {
            info: RepositoryInfo {
                name: "official".into(),
                title: "Test".into(),
                description: String::new(),
                official: true,
            },
            generation: self.generation,
            packages: self.packages.clone(),
            apps: self.apps.clone(),
            revoked: self.revoked.clone(),
        };
        let targets = auxipak_core::repogen::write_indexes(&content, &src, Utc::now()).unwrap();
        let out = self.p(&format!("gen-{}", self.generation));
        let keys: Vec<Box<dyn KeySource>> = ["targets", "snapshot", "timestamp"]
            .iter()
            .map(|r| {
                Box::new(PemKeySource {
                    path: self.p(&format!("keys/online/{r}.pem")),
                }) as Box<dyn KeySource>
            })
            .collect();
        rt().block_on(tuf::publish(PublishSpec {
            root_path: self.p("keys/public/root.json"),
            keys,
            targets,
            version: self.generation,
            targets_expires: Utc::now() + Duration::days(30),
            snapshot_expires: Utc::now() + Duration::days(7),
            timestamp_expires,
            out_dir: out.clone(),
            previous_roots: vec![],
        }))
        .unwrap();
        let _ = std::fs::remove_dir_all(self.repo());
        copy_dir(&out, &self.repo());
    }

    fn publish(&mut self) {
        self.publish_with(Utc::now() + Duration::hours(24));
    }

    fn run(&self, args: &[&str]) -> Output {
        self.run_env(args, &[])
    }

    fn run_env(&self, args: &[&str], env: &[(&str, &str)]) -> Output {
        self.command(args, env).output().unwrap()
    }

    fn command(&self, args: &[&str], env: &[(&str, &str)]) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_auxipak"));
        c.args(args)
            .env("AUXIPAK_HOME", self.home())
            .env("AUXIPAK_PROFILE_OVERRIDE", PROFILE)
            .env("AUXIPAK_ASSUME_ELEVATED", "0")
            // Les vérifications portent sur les messages français ; l'anglais
            // (langue par défaut) est vérifié par `interface_language`.
            .env("AUXIPAK_LANG", "fr")
            .env_remove("AUXIPAK_TEST_TOOLS_DIR");
        for (k, v) in env {
            c.env(k, v);
        }
        c
    }

    fn ok(&self, args: &[&str]) -> String {
        let o = self.run(args);
        let text = format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
        assert!(o.status.success(), "auxipak {args:?} a échoué :\n{text}");
        text
    }

    fn fails(&self, args: &[&str]) -> String {
        let o = self.run(args);
        let text = format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
        assert!(!o.status.success(), "auxipak {args:?} aurait dû échouer :\n{text}");
        text
    }

    fn installed_bin(&self, name: &str) -> PathBuf {
        self.home().join("bin").join(name)
    }
}

mod sevenz {
    pub fn reader(p: &std::path::Path) -> sevenz_rust2::ArchiveReader<std::fs::File> {
        sevenz_rust2::ArchiveReader::new(std::fs::File::open(p).unwrap(), sevenz_rust2::Password::empty()).unwrap()
    }
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap() {
        let e = e.unwrap();
        if e.file_type().unwrap().is_dir() {
            copy_dir(&e.path(), &to.join(e.file_name()));
        } else {
            std::fs::copy(e.path(), to.join(e.file_name())).unwrap();
        }
    }
}

fn manifest(id: &str, version: &str, extra_target: &str, top: &str) -> String {
    format!(
        r#"format: 1
id: {id}
name: "App {id}"
version: "{version}"
publisher: Test
summary: "Application de test {id}"
license: MIT
languages: [fr]
{top}targets:
  - name: aux
    platform: linux
    distributions: [auxinuxos]
    architectures: [any]
    mode: embedded
{extra_target}    install:
      method: files
      files:
        - source: payload/bin/{id}
          destination: "{{bin}}/{id}"
          executable: true
"#
    )
}

fn script(id: &str, version: &str) -> Vec<u8> {
    format!("#!/bin/sh\necho {id} {version}\n").into_bytes()
}

fn simple(f: &mut Fixture, id: &str, version: &str) {
    let m = manifest(id, version, "", "");
    f.add(&m, &[(&format!("payload/bin/{id}"), &script(id, version))], None);
}

#[test]
fn install_list_upgrade_remove_with_cache() {
    let mut f = Fixture::new();
    simple(&mut f, "hello", "1.0.0");
    f.publish();
    // Premier lancement : profil enregistré, index synchronisé.
    let out = f.ok(&["search", "hello"]);
    assert!(out.contains("hello") && out.contains("1.0.0"), "{out}");
    assert!(f.home().join("state/profile.json").exists());
    assert!(
        out.contains("vérifié"),
        "statut officiel affiché pour un dépôt officiel : {out}"
    );
    f.ok(&["install", "hello"]);
    assert_eq!(std::fs::read(f.installed_bin("hello")).unwrap(), script("hello", "1.0.0"));
    let list = f.ok(&["list", "--check"]);
    assert!(
        list.contains("hello") && list.contains("installed") && !list.contains("absente"),
        "{list}"
    );
    assert!(f.ok(&["install", "hello"]).contains("déjà installé"));

    // Nouvelle version : le cache est encore frais, la recherche ne la voit pas…
    simple(&mut f, "hello", "1.1.0");
    f.publish();
    assert!(!f.ok(&["search", "hello"]).contains("1.1.0"));
    // … jusqu'à « update », qui force la synchronisation.
    let upd = f.ok(&["update"]);
    assert!(upd.contains("Cache à jour") && !upd.contains("génération"), "{upd}");
    let upd = f.ok(&["update", "--verbose"]);
    assert!(upd.contains("génération 2") && upd.contains("Cache déjà à jour"), "{upd}");
    assert!(f.ok(&["search", "hello"]).contains("1.1.0"));
    let up = f.ok(&["upgrade", "hello"]);
    assert!(up.contains("1.0.0 → 1.1.0"), "{up}");
    assert_eq!(std::fs::read(f.installed_bin("hello")).unwrap(), script("hello", "1.1.0"));
    assert!(f.ok(&["upgrade"]).contains("est à jour"));
    let info = f.ok(&["info", "hello"]);
    assert!(info.contains("SHA-256") && info.contains("AuxiNux Vérifié"), "{info}");

    f.ok(&["remove", "hello"]);
    assert!(!f.installed_bin("hello").exists());
    assert!(f.ok(&["list"]).contains("Aucune application"));
    let up = f.ok(&["upgrade", "--no-self"]);
    assert!(up.contains("rien à mettre à niveau"), "{up}");
    f.ok(&["clean", "--all"]);
    assert!(!f.home().join("cache/repos").exists());
}

#[test]
fn offline_search_uses_validated_cache_but_install_requires_fresh_index() {
    let mut f = Fixture::new();
    f.ttl = 1;
    f.write_config();
    simple(&mut f, "hello", "1.0.0");
    f.publish();
    f.ok(&["update"]);
    std::fs::rename(f.repo(), f.p("repo-away")).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(1500));
    // Cache expiré, dépôt inaccessible : la recherche fonctionne hors ligne en le signalant.
    let out = f.ok(&["search", "hello"]);
    assert!(out.contains("hello") && out.contains("dernier index validé"), "{out}");
    // L'installation refuse un index expiré (révocations potentiellement manquées).
    f.fails(&["install", "hello"]);
    assert!(!f.installed_bin("hello").exists());
}

#[test]
fn rejects_expired_index() {
    let mut f = Fixture::new();
    simple(&mut f, "hello", "1.0.0");
    f.publish_with(Utc::now() - Duration::minutes(5));
    let out = f.fails(&["update"]);
    assert!(out.to_lowercase().contains("expired") || out.contains("refusées"), "{out}");
    f.fails(&["install", "hello"]);
}

#[test]
fn rejects_tampered_index_and_rollback() {
    let mut f = Fixture::new();
    simple(&mut f, "hello", "1.0.0");
    f.publish();
    let gen1 = f.p("gen-1");
    // Index falsifié : le fichier ne correspond plus à l'empreinte signée.
    let ch = f.repo().join("targets/channels/linux/auxinuxos/x86_64.json");
    let text = std::fs::read_to_string(&ch).unwrap().replace("\"hello\"", "\"hellx\"");
    std::fs::write(&ch, text).unwrap();
    let out = f.fails(&["update"]);
    assert!(out.contains("vérification TUF") || out.contains("refusées"), "{out}");
    // Restauration, publication d'une génération 2 puis tentative de retour vers la génération 1.
    let _ = std::fs::remove_dir_all(f.repo());
    simple(&mut f, "hello", "1.1.0");
    f.publish();
    f.ok(&["update"]);
    let _ = std::fs::remove_dir_all(f.repo());
    copy_dir(&gen1, &f.repo());
    let out = f.fails(&["update"]);
    assert!(out.to_lowercase().contains("version") || out.contains("refusées"), "{out}");
}

#[test]
fn rejects_wrong_sha256_and_invalid_signature() {
    let mut f = Fixture::new();
    simple(&mut f, "hello", "1.0.0");
    let attacker = PackageSigner::generate();
    let m = manifest("evil", "1.0.0", "", "");
    f.add(&m, &[("payload/bin/evil", &script("evil", "1.0.0"))], Some(&attacker));
    f.publish();
    f.ok(&["update"]);
    // Signature par une clé non reconnue.
    let out = f.fails(&["install", "evil"]);
    assert!(out.contains("signature"), "{out}");
    assert!(!f.installed_bin("evil").exists());
    // Paquet remplacé sur le dépôt après publication : empreinte incorrecte.
    let target = f.repo().join("targets/packages/hello/1.0.0/hello-1.0.0.aupak");
    let mut data = std::fs::read(&target).unwrap();
    let last = data.len() - 1;
    data[last] ^= 0xff;
    std::fs::write(&target, data).unwrap();
    let out = f.fails(&["install", "hello"]);
    assert!(out.contains("intégrité") || out.contains("SHA-256"), "{out}");
    assert!(!f.installed_bin("hello").exists());
}

#[test]
fn rejects_revoked_package() {
    let mut f = Fixture::new();
    simple(&mut f, "hello", "1.0.0");
    f.publish();
    f.ok(&["install", "hello"]);
    let sha = f.packages[0].sha256.clone();
    f.packages.clear();
    f.revoked.push(Revocation {
        id: "hello".into(),
        version: "1.0.0".into(),
        sha256: sha,
        reason: "test".into(),
        revoked_at: Utc::now(),
    });
    f.publish();
    f.ok(&["update"]);
    // La version installée est signalée comme révoquée.
    let list = f.ok(&["list"]);
    assert!(list.contains("RÉVOQUÉE"), "{list}");
    f.ok(&["remove", "hello"]);
    let out = f.fails(&["install", "hello"]);
    assert!(out.contains("révoqu"), "{out}");
}

#[test]
fn rejects_malicious_archive() {
    let mut f = Fixture::new();
    let m = manifest("trav", "1.0.0", "", "").replace(
        "targets:",
        &format!(
            "contents:\n  - path: payload/bin/trav\n    sha256: \"{}\"\n    size: 1\ntargets:",
            auxipak_core::hash::sha256_hex(b"x")
        ),
    );
    let evil = f.p("evil.aupak");
    archive::write_raw_7z(
        &evil,
        vec![
            (
                sevenz_rust2::ArchiveEntry::new_file("instruction.auxipak"),
                Some(m.into_bytes()),
            ),
            (sevenz_rust2::ArchiveEntry::new_file("payload/bin/trav"), Some(b"x".to_vec())),
            (
                sevenz_rust2::ArchiveEntry::new_file("payload/../../../escape"),
                Some(b"pwned".to_vec()),
            ),
        ],
    )
    .unwrap();
    f.add_file(&evil, None);
    f.publish();
    f.ok(&["update"]);
    let out = f.fails(&["install", "trav"]);
    assert!(out.contains("paquet refusé"), "{out}");
    assert!(!f.dir.path().join("escape").exists());
    // Vérification locale : refus également.
    let out = f.fails(&["verify", evil.to_str().unwrap()]);
    assert!(out.contains("INVALIDE"), "{out}");
}

#[cfg(unix)]
#[test]
fn scripts_require_explicit_authorization() {
    let mut f = Fixture::new();
    let m = manifest("scripted", "1.0.0", "    scripts:\n      post_install: scripts/post.sh\n", "");
    // Script de test inoffensif : écrit un marqueur dans le répertoire de données du test.
    let post = b"#!/bin/sh\nmkdir -p \"$AUXIPAK_DATA_DIR\" && echo ok > \"$AUXIPAK_DATA_DIR/marker\"\n";
    f.add(
        &m,
        &[("payload/bin/scripted", &script("scripted", "1")), ("scripts/post.sh", post)],
        None,
    );
    f.publish();
    f.ok(&["update"]);
    // « search » et « info » n'exécutent jamais de script.
    f.ok(&["search", "scripted"]);
    assert!(f.ok(&["info", "scripted"]).contains("OUI"));
    let out = f.fails(&["install", "scripted"]);
    assert!(out.contains("--allow-scripts"), "{out}");
    let marker = f.home().join("data/scripted/marker");
    assert!(!marker.exists() && !f.installed_bin("scripted").exists());
    f.ok(&["install", "scripted", "--allow-scripts"]);
    assert!(marker.exists(), "le script autorisé doit s'exécuter");
}

#[test]
fn admin_privileges_are_required_when_declared() {
    let mut f = Fixture::new();
    let m = manifest("priv", "1.0.0", "    privileges: admin\n", "");
    f.add(&m, &[("payload/bin/priv", &script("priv", "1"))], None);
    f.publish();
    f.ok(&["update"]);
    let out = f.fails(&["install", "priv"]);
    let hint = if cfg!(windows) { "administrateur" } else { "sudo" };
    assert!(out.contains("droits d'administration") && out.contains(hint), "{out}");
    assert!(!f.installed_bin("priv").exists());
}

#[test]
fn dependencies_are_installed_first_and_protected() {
    let mut f = Fixture::new();
    simple(&mut f, "libdemo", "1.0.0");
    let m = manifest(
        "appdemo",
        "2.0.0",
        "",
        "dependencies:\n  - id: libdemo\n    version: \">=1.0\"\n",
    );
    f.add(&m, &[("payload/bin/appdemo", &script("appdemo", "2"))], None);
    f.publish();
    f.ok(&["update"]);
    let out = f.ok(&["install", "appdemo"]);
    assert!(
        out.find("libdemo").unwrap() < out.rfind("appdemo 2.0.0 installé").unwrap(),
        "{out}"
    );
    assert!(f.installed_bin("libdemo").exists() && f.installed_bin("appdemo").exists());
    // Une dépendance utilisée n'est jamais supprimée implicitement.
    let out = f.fails(&["remove", "libdemo"]);
    assert!(out.contains("requis par"), "{out}");
    let out = f.ok(&["remove", "appdemo", "--autoremove"]);
    assert!(out.contains("libdemo"), "{out}");
    assert!(!f.installed_bin("libdemo").exists());
}

#[test]
fn partial_failure_is_rolled_back_and_foreign_files_are_never_overwritten() {
    let mut f = Fixture::new();
    let m = r#"format: 1
id: twofiles
name: "Two files"
version: "1.0.0"
publisher: Test
summary: "Deux fichiers"
license: MIT
languages: [fr]
targets:
  - name: aux
    platform: linux
    distributions: [auxinuxos]
    architectures: [any]
    mode: embedded
    install:
      method: files
      files:
        - source: payload/a
          destination: "{bin}/twofiles-a"
        - source: payload/b
          destination: "{bin}/twofiles-b"
"#;
    f.add(m, &[("payload/a", b"a"), ("payload/b", b"b")], None);
    f.publish();
    f.ok(&["update"]);
    // Un fichier étranger occupe la seconde destination.
    std::fs::create_dir_all(f.home().join("bin")).unwrap();
    std::fs::write(f.installed_bin("twofiles-b"), b"fichier de l'utilisateur").unwrap();
    let out = f.fails(&["install", "twofiles"]);
    assert!(out.contains("n'est pas géré par AuxiPak"), "{out}");
    assert_eq!(
        std::fs::read(f.installed_bin("twofiles-b")).unwrap(),
        b"fichier de l'utilisateur"
    );
    assert!(
        !f.installed_bin("twofiles-a").exists(),
        "le premier fichier copié doit être retiré"
    );
    assert!(f.ok(&["list"]).contains("Aucune application"));
    assert!(std::fs::read_dir(f.home().join("state/transactions"))
        .unwrap()
        .next()
        .is_none());
}

#[test]
fn interrupted_install_is_recovered_by_repair() {
    let mut f = Fixture::new();
    simple(&mut f, "hello", "1.0.0");
    f.publish();
    f.ok(&["update"]);
    // Interruption brutale après la copie des fichiers, avant l'enregistrement.
    let o = f.run_env(&["install", "hello"], &[("AUXIPAK_TEST_CRASH_AT", "after_install")]);
    assert!(!o.status.success());
    assert!(f.installed_bin("hello").exists());
    let list = f.ok(&["list"]);
    assert!(list.contains("interrompue") && list.contains("Aucune application"), "{list}");
    let rep = f.ok(&["repair"]);
    assert!(rep.contains("récupérée"), "{rep}");
    let list = f.ok(&["list"]);
    assert!(list.contains("hello") && list.contains("recovered"), "{list}");
    f.ok(&["remove", "hello"]);
    assert!(!f.installed_bin("hello").exists());

    // Interruption avant toute modification : simple nettoyage.
    let o = f.run_env(&["install", "hello"], &[("AUXIPAK_TEST_CRASH_AT", "after_extract")]);
    assert!(!o.status.success());
    let rep = f.ok(&["repair"]);
    assert!(rep.contains("nettoyé"), "{rep}");
    assert!(!f.installed_bin("hello").exists());
}

#[test]
fn external_repositories_cannot_claim_official_status() {
    let mut f = Fixture::new();
    simple(&mut f, "hello", "1.0.0");
    f.publish();
    // Même dépôt, ajouté comme dépôt externe : le statut « vérifié » de l'index est ignoré.
    let cfg = f.home().join("config/config.toml");
    let text = std::fs::read_to_string(&cfg)
        .unwrap()
        .replace("official = true", "official = false");
    std::fs::write(&cfg, text).unwrap();
    let out = f.ok(&["search", "hello"]);
    assert!(out.contains("externe") && !out.contains("vérifié"), "{out}");
}

#[test]
fn repo_management_rejects_insecure_urls() {
    let f = Fixture::new();
    let out = f.fails(&[
        "repo",
        "add",
        "http://example.org/repo",
        "--name",
        "ext",
        "--trust-on-first-use",
    ]);
    assert!(out.contains("HTTPS"), "{out}");
    let root = f.p("keys/public/root.json");
    let keys = f.p("keys/public/package-keys.json");
    let url = url::Url::from_directory_path(f.repo()).unwrap();
    f.ok(&[
        "repo",
        "add",
        url.as_str(),
        "--name",
        "ext",
        "--root",
        root.to_str().unwrap(),
        "--keys",
        keys.to_str().unwrap(),
    ]);
    let list = f.ok(&["repo", "list"]);
    assert!(list.contains("ext") && list.contains("EXTERNE"), "{list}");
    f.ok(&["repo", "remove", "ext"]);
    assert!(!f.ok(&["repo", "list"]).contains("ext "));
}

/// SIMULATION : la commande `auxi` d'AuxiNuxOS n'existe pas sur l'hôte de
/// test. Un faux programme enregistre les arguments reçus afin de vérifier
/// que l'adaptateur transmet des arguments structurés (aucun shell) et que
/// l'installation est marquée « simulée » dans le registre. Cela ne valide
/// pas la syntaxe réelle de `auxi` (à confirmer sur AuxiNuxOS).
#[cfg(unix)]
#[test]
fn auxi_adapter_passes_structured_arguments_simulated() {
    use std::os::unix::fs::PermissionsExt;
    let mut f = Fixture::new();
    let m = r#"format: 1
id: firefox
name: Firefox
version: "150.1"
publisher: Mozilla
summary: Navigateur
license: MPL-2.0
languages: [fr]
targets:
  - name: aux
    platform: linux
    distributions: [auxinuxos]
    architectures: [any]
    mode: native
    install: { method: package_manager, manager: auxi, packages: [firefox] }
"#;
    f.add(m, &[], None);
    f.publish();
    f.ok(&["update"]);
    let tools = f.p("tools");
    std::fs::create_dir_all(&tools).unwrap();
    let log = f.p("auxi.log");
    let deb_on = f.p("apps.conf");
    std::fs::write(&deb_on, "DEB_APPS=1\n").unwrap();
    let fake = tools.join("auxi");
    std::fs::write(
        &fake,
        "#!/bin/sh\nfor a in \"$@\"; do printf '[%s]' \"$a\"; done >> \"$AUXIPAK_TEST_LOG\"\necho >> \"$AUXIPAK_TEST_LOG\"\n",
    )
    .unwrap();
    std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
    let env = [
        ("AUXIPAK_TEST_TOOLS_DIR", tools.to_str().unwrap()),
        ("AUXIPAK_TEST_LOG", log.to_str().unwrap()),
        // Réglage DEB déjà actif : pas d'aller-retour « auxi set » ici.
        ("AUXIPAK_TEST_APPS_CONF", deb_on.to_str().unwrap()),
        ("AUXIPAK_ASSUME_ELEVATED", "1"),
    ];
    let o = f.run_env(&["install", "firefox"], &env);
    let text = format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
    assert!(o.status.success(), "{text}");
    assert!(text.contains("MODE SIMULATION"), "{text}");
    assert_eq!(
        std::fs::read_to_string(&log).unwrap().trim(),
        "[--yes][install][--deb][firefox]"
    );
    let list = f.run_env(&["list"], &env);
    assert!(String::from_utf8_lossy(&list.stdout).contains("installed*"));
    let o = f.run_env(&["remove", "firefox"], &env);
    assert!(o.status.success());
    assert!(std::fs::read_to_string(&log)
        .unwrap()
        .contains("[--yes][uninstall][--deb][firefox]"));
}

/// AuxiNux OS 0.3.0 (Debian 13) sans variante propre : la variante Debian du
/// catalogue (canal linux/deb) s'applique, APT remplacé par `auxi`.
/// SIMULATION (faux `auxi`, comme ci-dessus).
#[cfg(unix)]
#[test]
fn auxinuxos_installs_debian_variant_through_auxi_simulated() {
    use std::os::unix::fs::PermissionsExt;
    const AUX13: &str = r#"{"os":"linux","distribution":"auxinuxos","version":"13","arch":"x86_64","raw_id":"debian","pretty_name":"AuxiNux OS 0.3.0","immutable":true}"#;
    let mut f = Fixture::new();
    let m = r#"format: 1
id: vlc
name: VLC
version: "3.0.21"
publisher: VideoLAN
summary: Lecteur multimédia
license: GPL-2.0-or-later
languages: [fr]
targets:
  - name: debian
    platform: linux
    distributions: [debian]
    os_version: ">=12"
    architectures: [x86_64]
    mode: native
    install: { method: package_manager, manager: apt, packages: [vlc, vlc-plugin-base] }
"#;
    f.add(m, &[], None);
    f.publish();
    let tools = f.p("tools");
    std::fs::create_dir_all(&tools).unwrap();
    let log = f.p("auxi.log");
    let deb_on = f.p("apps.conf");
    std::fs::write(&deb_on, "DEB_APPS=1\n").unwrap();
    let fake = tools.join("auxi");
    std::fs::write(
        &fake,
        "#!/bin/sh\nfor a in \"$@\"; do printf '[%s]' \"$a\"; done >> \"$AUXIPAK_TEST_LOG\"\necho >> \"$AUXIPAK_TEST_LOG\"\n",
    )
    .unwrap();
    std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
    let env = [
        ("AUXIPAK_PROFILE_OVERRIDE", AUX13),
        ("AUXIPAK_TEST_TOOLS_DIR", tools.to_str().unwrap()),
        ("AUXIPAK_TEST_LOG", log.to_str().unwrap()),
        // Réglage DEB déjà actif : pas d'aller-retour « auxi set » ici.
        ("AUXIPAK_TEST_APPS_CONF", deb_on.to_str().unwrap()),
        ("AUXIPAK_ASSUME_ELEVATED", "1"),
    ];
    let o = f.run_env(&["update"], &env);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let o = f.run_env(&["search", "vlc"], &env);
    assert!(String::from_utf8_lossy(&o.stdout).contains("vlc"), "{o:?}");
    let o = f.run_env(&["install", "vlc"], &env);
    let text = format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
    assert!(o.status.success(), "{text}");
    assert_eq!(
        std::fs::read_to_string(&log).unwrap().trim(),
        "[--yes][install][--deb][vlc][vlc-plugin-base]"
    );
    let o = f.run_env(&["remove", "vlc"], &env);
    assert!(o.status.success(), "{o:?}");
    // auxi uninstall --deb ne retire que le premier paquet : un appel chacun.
    let log = std::fs::read_to_string(&log).unwrap();
    assert!(log.contains("[--yes][uninstall][--deb][vlc]\n"), "{log}");
    assert!(log.contains("[--yes][uninstall][--deb][vlc-plugin-base]\n"), "{log}");
}

/// Dépôt avec des applications à variante Debian (apt), profil AuxiNux OS
/// 0.3.0, faux `auxi` qui journalise ses appels et tient le réglage DEB
/// (`set deb=true|false`) dans un faux apps.conf. Fichier `tools/fail` : les
/// installations échouent (l'environnement des sous-processus est filtré).
#[cfg(unix)]
struct DebToggleBench {
    f: Fixture,
    tools: PathBuf,
    log: PathBuf,
    conf: PathBuf,
}

#[cfg(unix)]
impl DebToggleBench {
    fn new(apps: &[&str]) -> DebToggleBench {
        use std::os::unix::fs::PermissionsExt;
        let mut f = Fixture::new();
        for id in apps {
            let m = format!(
                "format: 1\nid: {id}\nname: {id}\nversion: \"1.0\"\npublisher: X\nsummary: Essai\nlicense: MIT\nlanguages: [fr]\n\
                 targets:\n  - name: debian\n    platform: linux\n    distributions: [debian]\n    architectures: [x86_64]\n    \
                 mode: native\n    install: {{ method: package_manager, manager: apt, packages: [{id}] }}\n"
            );
            f.add(&m, &[], None);
        }
        f.publish();
        let tools = f.p("tools");
        std::fs::create_dir_all(&tools).unwrap();
        let log = f.p("auxi.log");
        let conf = f.p("apps.conf");
        std::fs::write(
            tools.join("auxi"),
            "#!/bin/sh\nfor a in \"$@\"; do printf '[%s]' \"$a\"; done >> \"$AUXIPAK_TEST_LOG\"\necho >> \"$AUXIPAK_TEST_LOG\"\n\
             case \"$1 $2\" in\n  'set deb=true') echo DEB_APPS=1 > \"$AUXIPAK_TEST_APPS_CONF\"; echo bavard ;;\n  \
             'set deb=false') echo DEB_APPS=0 > \"$AUXIPAK_TEST_APPS_CONF\"; echo bavard ;;\n  \
             *) [ \"$2\" = install ] && [ -e \"$(dirname \"$0\")/slow\" ] && sleep 20\n     \
             [ -e \"$(dirname \"$0\")/fail\" ] && [ \"$2\" = install ] && exit 1 ;;\nesac\nexit 0\n",
        )
        .unwrap();
        std::fs::set_permissions(tools.join("auxi"), std::fs::Permissions::from_mode(0o755)).unwrap();
        DebToggleBench { f, tools, log, conf }
    }

    fn env(&self) -> [(&'static str, String); 5] {
        [
            ("AUXIPAK_PROFILE_OVERRIDE", r#"{"os":"linux","distribution":"auxinuxos","version":"13","arch":"x86_64","raw_id":"debian","pretty_name":"AuxiNux OS 0.3.0","immutable":true}"#.into()),
            ("AUXIPAK_TEST_TOOLS_DIR", self.tools.to_str().unwrap().into()),
            ("AUXIPAK_TEST_LOG", self.log.to_str().unwrap().into()),
            ("AUXIPAK_TEST_APPS_CONF", self.conf.to_str().unwrap().into()),
            ("AUXIPAK_ASSUME_ELEVATED", "1".into()),
        ]
    }

    fn run(&self, args: &[&str], fail: bool) -> (bool, String) {
        let owned = self.env();
        let env: Vec<(&str, &str)> = owned.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let flag = self.tools.join("fail");
        if fail {
            std::fs::write(&flag, "").unwrap();
        } else {
            let _ = std::fs::remove_file(&flag);
        }
        let o = self.f.run_env(args, &env);
        let text = format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
        (o.status.success(), text)
    }

    fn calls(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    fn marker(&self) -> PathBuf {
        self.f.home().join("state/deb-temporaire")
    }
}

/// DEB désactivé : activé une seule fois pour tout le lot, puis remis à
/// désactivé ; rien pour la désinstallation. SIMULATION (faux `auxi`).
#[cfg(unix)]
#[test]
fn auxi_deb_setting_enabled_once_for_a_batch_then_disabled_simulated() {
    let b = DebToggleBench::new(&["app-a", "app-b"]);
    assert!(b.run(&["update"], false).0);
    let (ok, text) = b.run(&["install", "app-a", "app-b"], false);
    assert!(ok, "{text}");
    assert_eq!(
        b.calls(),
        "[set][deb=true]\n[--yes][install][--deb][app-a]\n[--yes][install][--deb][app-b]\n[set][deb=false]\n"
    );
    assert!(text.contains("activée le temps de l'opération"), "{text}");
    assert!(text.contains("remise à désactivée"), "{text}");
    assert!(!text.contains("bavard"), "sortie de « auxi set » réaffichée : {text}");
    assert_eq!(std::fs::read_to_string(&b.conf).unwrap(), "DEB_APPS=0\n");
    assert!(!b.marker().exists());
    // Désinstallation : jamais de réglage DEB.
    std::fs::remove_file(&b.log).unwrap();
    assert!(b.run(&["remove", "app-a"], false).0);
    assert_eq!(b.calls(), "[--yes][uninstall][--deb][app-a]\n");
}

/// DEB déjà actif : aucun `auxi set`, ni avant ni après.
#[cfg(unix)]
#[test]
fn auxi_deb_setting_left_alone_when_already_enabled_simulated() {
    let b = DebToggleBench::new(&["app-a"]);
    std::fs::write(&b.conf, "DEB_APPS=1\n").unwrap();
    assert!(b.run(&["update"], false).0);
    let (ok, text) = b.run(&["install", "app-a"], false);
    assert!(ok, "{text}");
    assert_eq!(b.calls(), "[--yes][install][--deb][app-a]\n");
    assert_eq!(std::fs::read_to_string(&b.conf).unwrap(), "DEB_APPS=1\n");
    assert!(!b.marker().exists());
}

/// Échec de l'installation : le réglage est remis à désactivé quand même.
#[cfg(unix)]
#[test]
fn auxi_deb_setting_disabled_even_when_install_fails_simulated() {
    let b = DebToggleBench::new(&["app-a"]);
    assert!(b.run(&["update"], false).0);
    let (ok, text) = b.run(&["install", "app-a"], true);
    assert!(!ok, "{text}");
    assert_eq!(
        b.calls(),
        "[set][deb=true]\n[--yes][install][--deb][app-a]\n[set][deb=false]\n"
    );
    assert_eq!(std::fs::read_to_string(&b.conf).unwrap(), "DEB_APPS=0\n");
    assert!(!b.marker().exists());
}

/// Témoin résiduel (plantage pendant la fenêtre) : remis à désactivé au
/// lancement suivant, témoin supprimé.
#[cfg(unix)]
#[test]
fn auxi_deb_setting_restored_from_leftover_marker_simulated() {
    let b = DebToggleBench::new(&["app-a"]);
    std::fs::write(&b.conf, "DEB_APPS=1\n").unwrap();
    std::fs::create_dir_all(b.marker().parent().unwrap()).unwrap();
    std::fs::write(b.marker(), b.tools.join("auxi").to_str().unwrap()).unwrap();
    let (ok, text) = b.run(&["list"], false);
    assert!(ok, "{text}");
    assert!(text.contains("interrompue"), "{text}");
    assert_eq!(b.calls(), "[set][deb=false]\n");
    assert_eq!(std::fs::read_to_string(&b.conf).unwrap(), "DEB_APPS=0\n");
    assert!(!b.marker().exists());
    // Plus rien au lancement suivant.
    assert!(b.run(&["list"], false).0);
    assert_eq!(b.calls(), "[set][deb=false]\n");
}

/// SIGTERM pendant la fenêtre (installation en cours) : remise à désactivé
/// avant la sortie, témoin supprimé.
#[cfg(unix)]
#[test]
fn auxi_deb_setting_disabled_on_sigterm_simulated() {
    let b = DebToggleBench::new(&["app-a"]);
    assert!(b.run(&["update"], false).0);
    std::fs::write(b.tools.join("slow"), "").unwrap();
    let owned = b.env();
    let env: Vec<(&str, &str)> = owned.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let mut child =
        b.f.command(&["install", "app-a"], &env)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
    let start = std::time::Instant::now();
    while !b.calls().contains("[install]") {
        assert!(start.elapsed().as_secs() < 30, "installation jamais lancée : {}", b.calls());
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert!(b.marker().exists());
    let k = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .unwrap();
    assert!(k.success());
    let st = child.wait().unwrap();
    assert!(!st.success());
    assert!(start.elapsed().as_secs() < 15, "la sortie a attendu la fin de l'installation");
    assert!(b.calls().ends_with("[set][deb=false]\n"), "{}", b.calls());
    assert_eq!(std::fs::read_to_string(&b.conf).unwrap(), "DEB_APPS=0\n");
    assert!(!b.marker().exists());
}

#[test]
fn interface_language() {
    let f = Fixture::new();
    let en = &[("AUXIPAK_LANG", "en")];
    // Anglais par défaut, français sur demande (variable, puis « auxipak set lang »).
    let o = f.run_env(&["list"], en);
    assert!(String::from_utf8_lossy(&o.stdout).contains("No application installed by AuxiPak."));
    let o = f.run(&["list"]);
    assert!(String::from_utf8_lossy(&o.stdout).contains("Aucune application installée par AuxiPak."));
    let o = f.run_env(&["--help"], en);
    let help = String::from_utf8_lossy(&o.stdout);
    assert!(
        help.contains("Install one or more applications") && help.contains("native mechanisms"),
        "{help}"
    );
    let o = f.run_env(&["install", "--help"], en);
    assert!(String::from_utf8_lossy(&o.stdout).contains("Explicitly allow the package's custom scripts"));
    let o = f.run(&["install", "--help"]);
    assert!(String::from_utf8_lossy(&o.stdout).contains("Autoriser explicitement les scripts"));
    // Préférence enregistrée, utilisée sans variable d'environnement.
    let mut c = Command::new(env!("CARGO_BIN_EXE_auxipak"));
    let run = |c: &mut Command, args: &[&str]| {
        let o = c
            .args(args)
            .env("AUXIPAK_HOME", f.home())
            .env("AUXIPAK_PROFILE_OVERRIDE", PROFILE)
            .env_remove("AUXIPAK_LANG")
            .env_remove("LC_ALL")
            .env_remove("LC_MESSAGES")
            .env("LANG", "C")
            .output()
            .unwrap();
        String::from_utf8_lossy(&o.stdout).to_string()
    };
    assert!(run(&mut c, &["list"]).contains("No application"));
    let mut c = Command::new(env!("CARGO_BIN_EXE_auxipak"));
    assert!(run(&mut c, &["set", "lang", "FR"]).contains("Langue : français"));
    let mut c = Command::new(env!("CARGO_BIN_EXE_auxipak"));
    assert!(run(&mut c, &["list"]).contains("Aucune application"));
    let mut c = Command::new(env!("CARGO_BIN_EXE_auxipak"));
    assert!(run(&mut c, &["set", "lang=en"]).contains("Language: English"));
    let mut c = Command::new(env!("CARGO_BIN_EXE_auxipak"));
    assert!(run(&mut c, &["list"]).contains("No application"));
}

#[test]
fn language_choice_and_forced_language_suffix() {
    let mut f = Fixture::new();
    // Même application en deux langues ; l'anglaise est plus récente.
    let fr = manifest("hello", "1.0.0", "", "");
    f.add(&fr, &[("payload/bin/hello", &script("hello", "fr 1.0.0"))], None);
    let en = manifest("hello", "1.0.1", "", "").replace("languages: [fr]", "languages: [en]");
    f.add(&en, &[("payload/bin/hello", &script("hello", "en 1.0.1"))], None);
    f.publish();
    let bin = || std::fs::read(f.installed_bin("hello")).unwrap();

    // Client en français : la version française, malgré une anglaise plus récente.
    f.ok(&["install", "hello"]);
    assert_eq!(bin(), script("hello", "fr 1.0.0"));
    f.ok(&["remove", "hello"]);

    // Client en anglais : la version anglaise.
    let o = f.run_env(&["install", "hello"], &[("AUXIPAK_LANG", "en")]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert_eq!(bin(), script("hello", "en 1.0.1"));
    f.ok(&["remove", "hello"]);

    // « hello-en » impose la langue, quelle que soit celle du client.
    f.ok(&["install", "hello-en"]);
    assert_eq!(bin(), script("hello", "en 1.0.1"));
    f.ok(&["remove", "hello"]);
    f.ok(&["install", "hello-fr"]);
    assert_eq!(bin(), script("hello", "fr 1.0.0"));

    // Langue non publiée : pas d'alias, application inconnue.
    assert!(f.fails(&["install", "hello-de"]).contains("aucune application"));
}

#[test]
fn install_and_remove_several_applications() {
    let mut f = Fixture::new();
    simple(&mut f, "alpha", "1.0.0");
    simple(&mut f, "beta", "1.0.0");
    let m = manifest("gamma", "1.0.0", "", "dependencies:\n  - id: alpha\n");
    f.add(&m, &[("payload/bin/gamma", &script("gamma", "1.0.0"))], None);
    f.publish();

    // Plusieurs applications en une commande.
    f.ok(&["install", "alpha", "beta"]);
    assert!(f.installed_bin("alpha").exists() && f.installed_bin("beta").exists());

    // Une application inconnue n'empêche pas les autres ; le code de sortie le signale.
    let out = f.fails(&["install", "inconnue", "gamma"]);
    assert!(
        out.contains("inconnue") && out.contains("1 application(s) sur 2 en échec"),
        "{out}"
    );
    assert!(f.installed_bin("gamma").exists());

    // --version n'a de sens que pour une seule application.
    assert!(f
        .fails(&["install", "alpha", "beta", "--version", "1.0.0"])
        .contains("une seule application"));

    // Désinstallation groupée : alpha, requise par gamma, est retirée après elle.
    f.ok(&["remove", "alpha", "gamma", "beta"]);
    for id in ["alpha", "beta", "gamma"] {
        assert!(!f.installed_bin(id).exists(), "{id}");
    }
    assert!(f.ok(&["list"]).contains("Aucune application"));
}

#[test]
fn conflicting_application_names_its_owner() {
    let mut f = Fixture::new();
    simple(&mut f, "navigo-esr", "1.0.0");
    // Même destination (et donc même détection) que navigo-esr.
    let m = manifest("navigo", "2.0.0", "", "").replace(
        "        - source: payload/bin/navigo\n          destination: \"{bin}/navigo\"",
        "        - source: payload/bin/navigo\n          destination: \"{bin}/navigo-esr\"",
    );
    f.add(&m, &[("payload/bin/navigo", &script("navigo", "2.0.0"))], None);
    f.publish();
    f.ok(&["install", "navigo-esr"]);
    let out = f.fails(&["install", "navigo"]);
    assert!(out.contains("auxipak remove navigo-esr"), "{out}");
}

#[test]
fn search_shows_texts_in_the_interface_language() {
    let mut f = Fixture::new();
    let m = manifest(
        "hello",
        "1.0.0",
        "",
        "translations:\n  en:\n    name: Hello EN\n    summary: English summary of hello\n",
    );
    f.add(&m, &[("payload/bin/hello", &script("hello", "1.0.0"))], None);
    f.publish();
    let fr = f.ok(&["search", "hello"]);
    assert!(
        fr.contains("Application de test hello") && !fr.contains("English summary"),
        "{fr}"
    );
    let o = f.run_env(&["search", "hello"], &[("AUXIPAK_LANG", "en")]);
    let en = String::from_utf8_lossy(&o.stdout);
    assert!(en.contains("English summary of hello") && en.contains("Hello EN"), "{en}");
    // La recherche porte aussi sur les traductions.
    assert!(f.ok(&["search", "english"]).contains("hello"));
}

#[test]
fn ai_pre_assessment_is_labelled_until_a_human_reviews() {
    let mut f = Fixture::new();
    simple(&mut f, "hello", "1.0.0");
    let app = f.apps.iter_mut().find(|a| a.id == "hello").unwrap();
    app.status = Status::Unreviewed;
    app.ai_evaluation = Some(auxipak_core::index::AiEvaluation {
        status: Status::Compatible,
        notes: [
            ("fr".to_string(), "Télémétrie activée par défaut".to_string()),
            ("en".to_string(), "Telemetry enabled by default".to_string()),
        ]
        .into(),
        sources: vec!["https://example.org/privacy".into()],
        evaluated_at: Utc::now(),
    });
    f.publish();
    let s = f.ok(&["search", "hello"]);
    assert!(s.contains("compat. (IA)"), "{s}");
    let i = f.ok(&["info", "hello"]);
    assert!(
        i.contains("AuxiNux Compatible (analyse automatique par l'IA)")
            && i.contains("Télémétrie activée par défaut (analyse automatique par l'IA)")
            && i.contains("pas encore vérifié par un relecteur humain"),
        "{i}"
    );
    let o = f.run_env(&["info", "hello"], &[("AUXIPAK_LANG", "en")]);
    let en = String::from_utf8_lossy(&o.stdout);
    assert!(en.contains("Telemetry enabled by default (automatic AI analysis)"), "{en}");
    // Une évaluation humaine l'emporte : plus de mention IA.
    let app = f.apps.iter_mut().find(|a| a.id == "hello").unwrap();
    app.status = Status::Verified;
    f.publish();
    f.ok(&["update"]);
    let i = f.ok(&["info", "hello"]);
    assert!(i.contains("AuxiNux Vérifié") && !i.contains("IA"), "{i}");
}
