//! Format d'archive `.aupak` (version 1).
//!
//! Un `.aupak` est une archive 7z **normalisée** :
//! - compression LZMA2 (ou stockage sans compression), non solide, sans chiffrement ;
//! - entrées triées, `instruction.auxipak` en premier, chemins en `/` ;
//! - aucune date, aucun attribut de lien symbolique, aucun « anti-item » ;
//! - seuls `instruction.auxipak`, `payload/**` et `scripts/**` sont admis ;
//! - chaque fichier (hors manifeste) est déclaré dans `contents` avec sa
//!   taille et son SHA-256, et inversement.
//!
//! L'extraction n'utilise jamais les fonctions d'extraction automatique de la
//! bibliothèque 7z : chaque entrée est validée, écrite avec `create_new` dans
//! un répertoire privé fraîchement créé, comptée et hachée à la volée.

use crate::hash::{digest_eq, sha256_file, HashingWriter};
use crate::ids;
use crate::manifest::{ContentEntry, Install, Issue, Manifest, ManifestError, MANIFEST_FILE, MAX_MANIFEST_SIZE};
use crate::tr;
use sevenz_rust2::{ArchiveEntry, ArchiveReader, ArchiveWriter, EncoderConfiguration, EncoderMethod, Password};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

/// Version du format d'archive.
pub const AUPAK_FORMAT_VERSION: u32 = 1;
/// Extension obligatoire.
/// Extension des paquets AuxiPak.
pub const PACKAGE_EXTENSION: &str = "aupak";
/// Ancienne extension (avant la 1.0.3), toujours acceptée en lecture.
pub const LEGACY_EXTENSION: &str = "apak";

/// Le chemin porte-t-il une extension de paquet (actuelle ou ancienne) ?
pub fn is_package_path(p: &std::path::Path) -> bool {
    matches!(
        p.extension().and_then(|e| e.to_str()),
        Some(PACKAGE_EXTENSION | LEGACY_EXTENSION)
    )
}

/// Nom de fichier de paquet (actuel ou ancien).
pub fn is_package_name(name: &str) -> bool {
    is_package_path(std::path::Path::new(name))
}

const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
const FILE_ATTRIBUTE_UNIX_EXTENSION: u32 = 0x8000;
const S_IFMT: u32 = 0o170000;
const S_IFREG: u32 = 0o100000;
const S_IFDIR: u32 = 0o040000;

/// Limites appliquées à l'inspection et à l'extraction.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub max_entries: usize,
    /// Taille totale décompressée maximale.
    pub max_total_size: u64,
    /// Taille maximale d'une entrée.
    pub max_entry_size: u64,
    /// Rapport maximal taille décompressée / taille de l'archive (bombe de
    /// décompression), appliqué au-delà de 64 Mio décompressés.
    pub max_ratio: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_entries: 20_000,
            max_total_size: 32 * 1024 * 1024 * 1024,
            max_entry_size: 16 * 1024 * 1024 * 1024,
            max_ratio: 1_000,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ApakError {
    Archive(String),
    UnsafeEntry { path: String, reason: String },
    Limit(String),
    MissingManifest,
    Manifest(ManifestError),
    Contents(String),
    Integrity(String),
    Io(#[from] io::Error),
}

impl From<ManifestError> for ApakError {
    fn from(e: ManifestError) -> Self {
        ApakError::Manifest(e)
    }
}

impl std::fmt::Display for ApakError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            ApakError::Archive(e) => tr!("archive illisible : {e}", "unreadable archive: {e}"),
            ApakError::UnsafeEntry { path, reason } => {
                tr!("entrée refusée « {path} » : {reason}", "entry rejected “{path}”: {reason}")
            }
            ApakError::Limit(e) => tr!("limite dépassée : {e}", "limit exceeded: {e}"),
            ApakError::MissingManifest => tr!(
                "manifeste absent ({MANIFEST_FILE} est obligatoire)",
                "manifest missing ({MANIFEST_FILE} is required)"
            ),
            ApakError::Manifest(e) => e.to_string(),
            ApakError::Contents(e) => tr!(
                "contenu incohérent avec le manifeste : {e}",
                "contents do not match the manifest: {e}"
            ),
            ApakError::Integrity(e) => tr!("intégrité : {e}", "integrity: {e}"),
            ApakError::Io(e) => tr!("entrée/sortie : {e}", "I/O: {e}"),
        };
        f.write_str(&s)
    }
}

impl From<sevenz_rust2::Error> for ApakError {
    fn from(e: sevenz_rust2::Error) -> Self {
        ApakError::Archive(e.to_string())
    }
}

/// Entrée d'archive validée.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryInfo {
    pub path: String,
    pub size: u64,
    pub is_dir: bool,
}

/// Résultat de l'inspection d'une archive.
#[derive(Debug, Clone)]
pub struct Inspection {
    pub manifest: Manifest,
    pub manifest_bytes: Vec<u8>,
    pub warnings: Vec<Issue>,
    pub entries: Vec<EntryInfo>,
    pub archive_size: u64,
    pub archive_sha256: String,
    pub total_unpacked: u64,
}

fn unsafe_entry(path: &str, reason: impl Into<String>) -> ApakError {
    ApakError::UnsafeEntry {
        path: path.to_string(),
        reason: reason.into(),
    }
}

/// Valide les métadonnées d'une entrée (nom, type, attributs).
fn check_entry(e: &ArchiveEntry) -> Result<EntryInfo, ApakError> {
    let path = e.name().to_string();
    if e.is_anti_item() {
        return Err(unsafe_entry(
            &path,
            tr!("anti-item 7z interdit", "7z anti-items are not allowed"),
        ));
    }
    if !ids::is_safe_relative_path(&path) {
        return Err(unsafe_entry(
            &path,
            tr!(
                "chemin absolu, traversée de répertoire ou nom interdit",
                "absolute path, directory traversal or forbidden name"
            ),
        ));
    }
    if e.has_windows_attributes {
        let a = e.windows_attributes();
        if a & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(unsafe_entry(
                &path,
                tr!(
                    "point d'analyse/lien symbolique interdit",
                    "reparse points/symbolic links are not allowed"
                ),
            ));
        }
        if a & FILE_ATTRIBUTE_UNIX_EXTENSION != 0 {
            let kind = (a >> 16) & S_IFMT;
            let ok = kind == 0 || (kind == S_IFREG && !e.is_directory()) || (kind == S_IFDIR && e.is_directory());
            if !ok {
                return Err(unsafe_entry(
                    &path,
                    tr!(
                        "type de fichier spécial interdit (lien symbolique, périphérique…)",
                        "special file types are not allowed (symbolic link, device…)"
                    ),
                ));
            }
        }
    }
    let top = path.split('/').next().unwrap_or("");
    let allowed = if e.is_directory() {
        top == "payload" || top == "scripts"
    } else {
        path == MANIFEST_FILE || (top == "payload" || top == "scripts") && path.contains('/')
    };
    if !allowed {
        return Err(unsafe_entry(
            &path,
            tr!(
                "seuls instruction.auxipak, payload/ et scripts/ sont autorisés",
                "only instruction.auxipak, payload/ and scripts/ are allowed"
            ),
        ));
    }
    Ok(EntryInfo {
        path,
        size: if e.is_directory() { 0 } else { e.size() },
        is_dir: e.is_directory(),
    })
}

fn open_reader(path: &Path) -> Result<ArchiveReader<File>, ApakError> {
    let f = File::open(path)?;
    ArchiveReader::new(f, Password::empty()).map_err(|e| ApakError::Archive(e.to_string()))
}

/// Inspecte une archive sans rien extraire ni exécuter : validation des
/// entrées, des limites, du manifeste et de la cohérence avec `contents`.
pub fn inspect(path: &Path, limits: &Limits) -> Result<Inspection, ApakError> {
    let (archive_sha256, archive_size) = sha256_file(path)?;
    let mut reader = open_reader(path)?;
    let files = reader.archive().files.clone();
    if files.len() > limits.max_entries {
        return Err(ApakError::Limit(tr!(
            "{} entrées (maximum {})",
            "{} entries (maximum {})",
            files.len(),
            limits.max_entries
        )));
    }
    let mut entries = Vec::with_capacity(files.len());
    let mut seen = BTreeSet::new();
    let mut total = 0u64;
    for f in &files {
        let info = check_entry(f)?;
        // Les doublons (y compris par différence de casse) permettraient
        // d'écraser un fichier vérifié sur les systèmes insensibles à la casse.
        if !seen.insert(info.path.to_lowercase()) {
            return Err(unsafe_entry(&info.path, tr!("entrée dupliquée", "duplicate entry")));
        }
        if info.size > limits.max_entry_size {
            return Err(ApakError::Limit(tr!(
                "entrée {} trop volumineuse ({} octets)",
                "entry {} too large ({} bytes)",
                info.path,
                info.size
            )));
        }
        total = total.saturating_add(info.size);
        entries.push(info);
    }
    if total > limits.max_total_size {
        return Err(ApakError::Limit(tr!(
            "taille décompressée totale {total} > {}",
            "total uncompressed size {total} > {}",
            limits.max_total_size
        )));
    }
    if total > 64 * 1024 * 1024 && total / archive_size.max(1) > limits.max_ratio {
        return Err(ApakError::Limit(tr!(
            "taux de compression suspect ({}:1), bombe de décompression probable",
            "suspicious compression ratio ({}:1), likely decompression bomb",
            total / archive_size.max(1)
        )));
    }
    // Méthodes de compression autorisées (pas de chiffrement ni de filtre exotique).
    for e in entries.iter().filter(|e| !e.is_dir) {
        let mut methods = Vec::new();
        reader.file_compression_methods(&e.path, &mut methods)?;
        for m in methods {
            let id = m.id();
            if id != EncoderMethod::ID_LZMA2 && id != EncoderMethod::ID_LZMA && id != EncoderMethod::ID_COPY {
                return Err(unsafe_entry(
                    &e.path,
                    tr!(
                        "méthode de compression non autorisée : {}",
                        "compression method not allowed: {}",
                        m.name()
                    ),
                ));
            }
        }
    }
    let m_entry = entries
        .iter()
        .find(|e| e.path == MANIFEST_FILE)
        .ok_or(ApakError::MissingManifest)?;
    if m_entry.size as usize > MAX_MANIFEST_SIZE {
        return Err(ApakError::Limit(tr!("manifeste trop volumineux", "manifest too large")));
    }
    let manifest_bytes = reader.read_file(MANIFEST_FILE)?;
    let (manifest, warnings) = Manifest::parse(&manifest_bytes)?;
    check_contents(&manifest, &entries)?;
    Ok(Inspection {
        manifest,
        manifest_bytes,
        warnings,
        entries,
        archive_size,
        archive_sha256,
        total_unpacked: total,
    })
}

/// Vérifie la correspondance exacte entre les fichiers de l'archive et `contents`.
fn check_contents(m: &Manifest, entries: &[EntryInfo]) -> Result<(), ApakError> {
    let declared: BTreeMap<&str, &ContentEntry> = m.contents.iter().map(|c| (c.path.as_str(), c)).collect();
    let mut present = BTreeSet::new();
    for e in entries.iter().filter(|e| !e.is_dir && e.path != MANIFEST_FILE) {
        match declared.get(e.path.as_str()) {
            None => {
                return Err(ApakError::Contents(tr!(
                    "fichier non déclaré : {}",
                    "undeclared file: {}",
                    e.path
                )))
            }
            Some(c) if c.size != e.size => {
                return Err(ApakError::Contents(tr!(
                    "taille de {} : {} déclarés, {} dans l'archive",
                    "size of {}: {} declared, {} in the archive",
                    e.path,
                    c.size,
                    e.size
                )))
            }
            Some(_) => {
                present.insert(e.path.as_str());
            }
        }
    }
    for c in &m.contents {
        if !present.contains(c.path.as_str()) {
            return Err(ApakError::Contents(tr!(
                "fichier déclaré absent de l'archive : {}",
                "declared file missing from the archive: {}",
                c.path
            )));
        }
    }
    Ok(())
}

/// Extrait une archive dans `dest` (répertoire existant et vide), en vérifiant
/// chaque fichier contre le manifeste. Rien n'est exécuté.
pub fn extract(path: &Path, dest: &Path, limits: &Limits) -> Result<Inspection, ApakError> {
    let insp = inspect(path, limits)?;
    if fs::read_dir(dest)?.next().is_some() {
        return Err(ApakError::Io(io::Error::other(tr!(
            "le répertoire de destination n'est pas vide",
            "the destination directory is not empty"
        ))));
    }
    let dest = dest.canonicalize()?;
    let declared: BTreeMap<String, ContentEntry> = insp.manifest.contents.iter().map(|c| (c.path.clone(), c.clone())).collect();
    let mut reader = open_reader(path)?;
    let mut written_total = 0u64;
    let mut extracted = BTreeSet::new();
    let mut failure: Option<ApakError> = None;
    let manifest_bytes = insp.manifest_bytes.clone();

    reader.for_each_entries(|entry, data| {
        let result = (|| -> Result<(), ApakError> {
            let info = check_entry(entry)?;
            let target = safe_join(&dest, &info.path)?;
            if info.is_dir {
                fs::create_dir_all(&target)?;
                return Ok(());
            }
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
                // Le répertoire parent doit rester dans la destination (aucun
                // lien symbolique n'est jamais créé, mais on vérifie quand même).
                if !parent.canonicalize()?.starts_with(&dest) {
                    return Err(unsafe_entry(
                        &info.path,
                        tr!("sortie du répertoire d'extraction", "escapes the extraction directory"),
                    ));
                }
            }
            let (expected_size, expected_sha, executable) = if info.path == MANIFEST_FILE {
                (manifest_bytes.len() as u64, crate::hash::sha256_hex(&manifest_bytes), false)
            } else {
                let c = declared
                    .get(&info.path)
                    .ok_or_else(|| ApakError::Contents(tr!("fichier non déclaré : {}", "undeclared file: {}", info.path)))?;
                (c.size, c.sha256.clone(), c.executable)
            };
            if written_total + expected_size > limits.max_total_size {
                return Err(ApakError::Limit(tr!("taille totale extraite", "total extracted size")));
            }
            let file = create_new_private(&target)?;
            let mut w = HashingWriter::new(file, expected_size);
            io::copy(data, &mut w).map_err(|e| ApakError::Integrity(tr!("{} : {e}", "{}: {e}", info.path)))?;
            let (file, sha, size) = w.finish();
            file.sync_all()?;
            if size != expected_size || !digest_eq(&sha, &expected_sha) {
                return Err(ApakError::Integrity(tr!(
                    "{} : empreinte ou taille incorrecte (attendu {expected_sha}, obtenu {sha})",
                    "{}: wrong digest or size (expected {expected_sha}, got {sha})",
                    info.path
                )));
            }
            set_executable(&target, executable)?;
            written_total += size;
            extracted.insert(info.path);
            Ok(())
        })();
        match result {
            Ok(()) => Ok(true),
            Err(e) => {
                failure = Some(e);
                Ok(false)
            }
        }
    })?;
    if let Some(e) = failure {
        return Err(e);
    }
    for c in &insp.manifest.contents {
        if !extracted.contains(&c.path) {
            return Err(ApakError::Contents(tr!(
                "fichier non extrait : {}",
                "file not extracted: {}",
                c.path
            )));
        }
    }
    Ok(insp)
}

/// Joint un chemin d'archive validé à la destination, composant par composant.
fn safe_join(dest: &Path, rel: &str) -> Result<PathBuf, ApakError> {
    if !ids::is_safe_relative_path(rel) {
        return Err(unsafe_entry(rel, tr!("chemin dangereux", "dangerous path")));
    }
    let mut p = dest.to_path_buf();
    for c in rel.split('/') {
        p.push(c);
    }
    Ok(p)
}

fn create_new_private(path: &Path) -> io::Result<File> {
    let mut o = OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    o.open(path)
}

fn set_executable(path: &Path, executable: bool) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = if executable { 0o700 } else { 0o600 };
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    }
    #[cfg(not(unix))]
    {
        let _ = (path, executable);
    }
    Ok(())
}

/// Fichier à intégrer dans une archive.
#[derive(Debug, Clone)]
pub struct BuildFile {
    /// Chemin dans l'archive (`payload/...` ou `scripts/...`).
    pub archive_path: String,
    /// Fichier source sur disque.
    pub source: PathBuf,
    pub executable: bool,
}

/// Construit une archive `.aupak` normalisée. Les entrées `contents` du
/// manifeste sont recalculées à partir des fichiers fournis. Retourne le
/// manifeste final et l'inspection de l'archive produite.
pub fn build(manifest: &Manifest, files: &[BuildFile], out: &Path) -> Result<(Manifest, Inspection), ApakError> {
    let mut m = manifest.clone();
    let mut sorted: Vec<&BuildFile> = files.iter().collect();
    sorted.sort_by(|a, b| a.archive_path.cmp(&b.archive_path));
    let mut contents = Vec::new();
    let mut seen = BTreeSet::new();
    for f in &sorted {
        let p = &f.archive_path;
        if !ids::is_safe_relative_path(p) || !(p.starts_with("payload/") || p.starts_with("scripts/")) {
            return Err(unsafe_entry(
                p,
                tr!(
                    "chemin d'archive invalide (payload/ ou scripts/ requis)",
                    "invalid archive path (payload/ or scripts/ required)"
                ),
            ));
        }
        if !seen.insert(p.to_lowercase()) {
            return Err(unsafe_entry(p, tr!("entrée dupliquée", "duplicate entry")));
        }
        let meta = fs::symlink_metadata(&f.source)?;
        if !meta.file_type().is_file() {
            return Err(unsafe_entry(
                p,
                tr!(
                    "la source doit être un fichier ordinaire (pas de lien symbolique)",
                    "the source must be a regular file (not a symbolic link)"
                ),
            ));
        }
        let (sha256, size) = sha256_file(&f.source)?;
        let executable = f.executable || p.ends_with(".sh") || is_unix_executable(&meta) || executable_in_manifest(&m, p);
        contents.push(ContentEntry {
            path: p.clone(),
            sha256,
            size,
            executable,
        });
    }
    m.contents = contents;
    let yaml = m.to_yaml();
    // Validation complète (schéma + sémantique) du manifeste final.
    let (parsed, _) = Manifest::parse(yaml.as_bytes())?;

    let parent = out.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let tmp = tempfile::Builder::new().prefix(".aupak-build-").tempfile_in(parent)?;
    {
        let file = tmp.reopen()?;
        let mut w = ArchiveWriter::new(file)?;
        w.set_encrypt_header(false);
        w.set_content_methods(vec![EncoderConfiguration::new(EncoderMethod::LZMA2)]);
        w.push_archive_entry(ArchiveEntry::new_file(MANIFEST_FILE), Some(yaml.as_bytes()))?;
        for f in &sorted {
            let src = File::open(&f.source)?;
            w.push_archive_entry(ArchiveEntry::new_file(&f.archive_path), Some(src))?;
        }
        let file = w.finish()?;
        file.sync_all()?;
    }
    tmp.persist(out).map_err(|e| ApakError::Io(e.error))?;
    let insp = inspect(out, &Limits::default())?;
    Ok((parsed, insp))
}

fn executable_in_manifest(m: &Manifest, path: &str) -> bool {
    m.contents.iter().any(|c| c.path == path && c.executable)
        || m.targets.iter().any(|t| match &t.install {
            Install::Files { files } => files.iter().any(|f| f.source == path && f.executable),
            _ => false,
        })
}

#[cfg(unix)]
fn is_unix_executable(meta: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn is_unix_executable(_meta: &fs::Metadata) -> bool {
    false
}

/// Lit uniquement le manifeste d'une archive (après inspection complète).
pub fn read_manifest(path: &Path) -> Result<Manifest, ApakError> {
    Ok(inspect(path, &Limits::default())?.manifest)
}

/// Écrit des entrées brutes dans une archive 7z, sans aucune validation.
/// Réservé aux tests (fabrication d'archives malveillantes) et aux outils.
pub fn write_raw_7z(out: &Path, entries: Vec<(ArchiveEntry, Option<Vec<u8>>)>) -> Result<(), ApakError> {
    let file = File::create(out)?;
    let mut w = ArchiveWriter::new(file)?;
    w.set_encrypt_header(false);
    for (e, data) in entries {
        match data {
            Some(d) => w.push_archive_entry(e, Some(d.as_slice()))?,
            None => w.push_archive_entry::<&[u8]>(e, None)?,
        };
    }
    let mut f = w.finish()?;
    f.flush()?;
    Ok(())
}

/// Lit intégralement un petit fichier (utilitaire de test).
pub fn read_all(mut r: impl Read) -> io::Result<Vec<u8>> {
    let mut v = Vec::new();
    r.read_to_end(&mut v)?;
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extensions_de_paquet() {
        assert!(is_package_name("Firefox-158.0-fr.aupak"));
        assert!(is_package_name("Firefox-158.0-fr.apak"), "ancienne extension toujours acceptée");
        assert!(!is_package_name("x.pkg") && !is_package_name("x.aupak.sig") && !is_package_name("aupak"));
    }

    const MANIFEST: &str = r#"
format: 1
id: test-app
name: Test App
version: "1.0.0"
publisher: AuxiNux
summary: test
license: MIT
languages: [fr]
targets:
  - name: portable
    platform: linux
    distributions: [debian, ubuntu]
    architectures: [any]
    mode: embedded
    install:
      method: files
      files:
        - source: payload/bin/hello
          destination: "{bin}/hello"
          executable: true
"#;

    fn build_sample(dir: &Path) -> PathBuf {
        let src = dir.join("hello");
        fs::write(&src, b"#!/bin/sh\necho bonjour\n").unwrap();
        let (m, _) = Manifest::parse(MANIFEST.replace("targets:", "contents:\n  - path: payload/bin/hello\n    sha256: \"0000000000000000000000000000000000000000000000000000000000000000\"\n    size: 0\ntargets:").as_bytes()).unwrap();
        let out = dir.join("Test-1.0.0-fr.aupak");
        build(
            &m,
            &[BuildFile {
                archive_path: "payload/bin/hello".into(),
                source: src,
                executable: true,
            }],
            &out,
        )
        .unwrap();
        out
    }

    #[test]
    fn build_inspect_extract_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let pkg = build_sample(dir.path());
        let insp = inspect(&pkg, &Limits::default()).unwrap();
        assert_eq!(insp.manifest.id, "test-app");
        assert_eq!(insp.manifest.contents.len(), 1);
        assert!(insp.manifest.contents[0].executable);
        let out = dir.path().join("x");
        fs::create_dir(&out).unwrap();
        extract(&pkg, &out, &Limits::default()).unwrap();
        assert_eq!(fs::read(out.join("payload/bin/hello")).unwrap(), b"#!/bin/sh\necho bonjour\n");
        assert!(out.join(MANIFEST_FILE).exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(out.join("payload/bin/hello")).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
    }

    #[test]
    fn build_is_deterministic() {
        let d1 = tempfile::tempdir().unwrap();
        let d2 = tempfile::tempdir().unwrap();
        let a = fs::read(build_sample(d1.path())).unwrap();
        let b = fs::read(build_sample(d2.path())).unwrap();
        assert_eq!(crate::hash::sha256_hex(&a), crate::hash::sha256_hex(&b));
    }

    #[test]
    fn manifest_only_package_is_valid() {
        let dir = tempfile::tempdir().unwrap();
        let native = r#"
format: 1
id: firefox
name: Firefox
version: "150.1"
publisher: Mozilla
summary: Navigateur
license: MPL-2.0
languages: [fr]
targets:
  - name: debian
    platform: linux
    distributions: [debian, ubuntu]
    architectures: [any]
    mode: native
    install: { method: package_manager, manager: apt, packages: [firefox-esr] }
"#;
        let (m, _) = Manifest::parse(native.as_bytes()).unwrap();
        let out = dir.path().join("Firefox-150.1-fr.aupak");
        let (_, insp) = build(&m, &[], &out).unwrap();
        assert_eq!(insp.entries.len(), 1);
    }

    fn raw(dir: &Path, entries: Vec<(ArchiveEntry, Option<Vec<u8>>)>) -> PathBuf {
        let p = dir.join("evil.aupak");
        write_raw_7z(&p, entries).unwrap();
        p
    }

    fn manifest_entry() -> (ArchiveEntry, Option<Vec<u8>>) {
        (ArchiveEntry::new_file(MANIFEST_FILE), Some(MANIFEST.as_bytes().to_vec()))
    }

    #[test]
    fn rejects_path_traversal() {
        let dir = tempfile::tempdir().unwrap();
        for name in ["../evil", "payload/../../evil", "/etc/passwd", "payload/..\\evil", "C:/evil"] {
            let p = raw(
                dir.path(),
                vec![manifest_entry(), (ArchiveEntry::new_file(name), Some(b"x".to_vec()))],
            );
            let err = inspect(&p, &Limits::default()).unwrap_err();
            assert!(matches!(err, ApakError::UnsafeEntry { .. }), "{name}: {err}");
        }
    }

    #[test]
    fn rejects_symlink_entries() {
        let dir = tempfile::tempdir().unwrap();
        let mut link = ArchiveEntry::new_file("payload/link");
        link.has_windows_attributes = true;
        link.windows_attributes = FILE_ATTRIBUTE_UNIX_EXTENSION | ((0o120777u32) << 16);
        let p = raw(dir.path(), vec![manifest_entry(), (link, Some(b"/etc/passwd".to_vec()))]);
        assert!(matches!(inspect(&p, &Limits::default()), Err(ApakError::UnsafeEntry { .. })));

        let mut reparse = ArchiveEntry::new_file("payload/reparse");
        reparse.has_windows_attributes = true;
        reparse.windows_attributes = FILE_ATTRIBUTE_REPARSE_POINT;
        let p = raw(dir.path(), vec![manifest_entry(), (reparse, Some(b"x".to_vec()))]);
        assert!(matches!(inspect(&p, &Limits::default()), Err(ApakError::UnsafeEntry { .. })));
    }

    #[test]
    fn rejects_unexpected_top_level_and_duplicates() {
        let dir = tempfile::tempdir().unwrap();
        let p = raw(
            dir.path(),
            vec![manifest_entry(), (ArchiveEntry::new_file("autorun.sh"), Some(b"x".to_vec()))],
        );
        assert!(matches!(inspect(&p, &Limits::default()), Err(ApakError::UnsafeEntry { .. })));
        let p = raw(
            dir.path(),
            vec![
                manifest_entry(),
                (ArchiveEntry::new_file("payload/a"), Some(b"x".to_vec())),
                (ArchiveEntry::new_file("payload/A"), Some(b"y".to_vec())),
            ],
        );
        assert!(matches!(inspect(&p, &Limits::default()), Err(ApakError::UnsafeEntry { .. })));
    }

    #[test]
    fn rejects_missing_manifest_and_undeclared_files() {
        let dir = tempfile::tempdir().unwrap();
        let p = raw(dir.path(), vec![(ArchiveEntry::new_file("payload/a"), Some(b"x".to_vec()))]);
        assert!(matches!(inspect(&p, &Limits::default()), Err(ApakError::MissingManifest)));
        let manifest = MANIFEST.replace(
            "targets:",
            &format!(
                "contents:\n  - path: payload/bin/hello\n    sha256: \"{}\"\n    size: 1\ntargets:",
                crate::hash::sha256_hex(b"x")
            ),
        );
        let p = raw(
            dir.path(),
            vec![
                (ArchiveEntry::new_file(MANIFEST_FILE), Some(manifest.clone().into_bytes())),
                (ArchiveEntry::new_file("payload/bin/hello"), Some(b"x".to_vec())),
                (ArchiveEntry::new_file("payload/smuggled"), Some(b"y".to_vec())),
            ],
        );
        assert!(matches!(inspect(&p, &Limits::default()), Err(ApakError::Contents(_))));
        // Fichier déclaré mais absent.
        let p = raw(
            dir.path(),
            vec![(ArchiveEntry::new_file(MANIFEST_FILE), Some(manifest.into_bytes()))],
        );
        assert!(matches!(inspect(&p, &Limits::default()), Err(ApakError::Contents(_))));
    }

    #[test]
    fn rejects_decompression_bomb() {
        let dir = tempfile::tempdir().unwrap();
        let zeros = vec![0u8; 80 * 1024 * 1024];
        let manifest = MANIFEST.replace(
            "targets:",
            &format!(
                "contents:\n  - path: payload/bin/hello\n    sha256: \"{}\"\n    size: {}\ntargets:",
                crate::hash::sha256_hex(&zeros),
                zeros.len()
            ),
        );
        let p = raw(
            dir.path(),
            vec![
                (ArchiveEntry::new_file(MANIFEST_FILE), Some(manifest.into_bytes())),
                (ArchiveEntry::new_file("payload/bin/hello"), Some(zeros)),
            ],
        );
        let err = inspect(&p, &Limits::default()).unwrap_err();
        assert!(matches!(err, ApakError::Limit(_)), "{err}");
        // Limite de taille totale.
        let small = Limits {
            max_total_size: 1024,
            ..Limits::default()
        };
        assert!(matches!(inspect(&p, &small), Err(ApakError::Limit(_))));
    }

    #[test]
    fn extraction_detects_tampered_content_hash() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = MANIFEST.replace(
            "targets:",
            &format!(
                "contents:\n  - path: payload/bin/hello\n    sha256: \"{}\"\n    size: 4\ntargets:",
                crate::hash::sha256_hex(b"good")
            ),
        );
        let p = raw(
            dir.path(),
            vec![
                (ArchiveEntry::new_file(MANIFEST_FILE), Some(manifest.into_bytes())),
                (ArchiveEntry::new_file("payload/bin/hello"), Some(b"evil".to_vec())),
            ],
        );
        let out = dir.path().join("out");
        fs::create_dir(&out).unwrap();
        assert!(matches!(extract(&p, &out, &Limits::default()), Err(ApakError::Integrity(_))));
    }

    #[test]
    fn extraction_requires_empty_destination() {
        let dir = tempfile::tempdir().unwrap();
        let pkg = build_sample(dir.path());
        let out = dir.path().join("o");
        fs::create_dir(&out).unwrap();
        fs::write(out.join("x"), b"").unwrap();
        assert!(extract(&pkg, &out, &Limits::default()).is_err());
    }

    #[test]
    fn rejects_non_7z_and_truncated_files() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("x.aupak");
        fs::write(&p, b"PK\x03\x04 not a 7z").unwrap();
        assert!(matches!(inspect(&p, &Limits::default()), Err(ApakError::Archive(_))));
        let good = fs::read(build_sample(dir.path())).unwrap();
        fs::write(&p, &good[..good.len() / 2]).unwrap();
        assert!(inspect(&p, &Limits::default()).is_err());
    }
}
