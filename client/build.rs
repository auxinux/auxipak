//! Embarque optionnellement les ancres de confiance du dépôt officiel.
//!
//! Si la variable `AUXIPAK_OFFICIAL_TRUST_DIR` désigne un répertoire contenant
//! `root.json` et `package-keys.json` (publics, issus de la cérémonie
//! d'initialisation des clés), ils sont intégrés au binaire. Sinon, le client
//! cherche ces fichiers dans sa configuration (`trust/official/`).

use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-env-changed=AUXIPAK_OFFICIAL_TRUST_DIR");
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("trust_embedded.rs");
    let mut code = String::new();
    match std::env::var("AUXIPAK_OFFICIAL_TRUST_DIR").ok().filter(|s| !s.is_empty()) {
        Some(dir) => {
            let dir = PathBuf::from(dir);
            let root = dir.join("root.json");
            let keys = dir.join("package-keys.json");
            assert!(
                root.exists() && keys.exists(),
                "AUXIPAK_OFFICIAL_TRUST_DIR doit contenir root.json et package-keys.json"
            );
            println!("cargo:rerun-if-changed={}", root.display());
            println!("cargo:rerun-if-changed={}", keys.display());
            code.push_str(&format!(
                "pub const OFFICIAL_ROOT: Option<&[u8]> = Some(include_bytes!({:?}));\n",
                root.canonicalize().unwrap()
            ));
            code.push_str(&format!(
                "pub const OFFICIAL_PACKAGE_KEYS: Option<&[u8]> = Some(include_bytes!({:?}));\n",
                keys.canonicalize().unwrap()
            ));
        }
        None => {
            code.push_str("pub const OFFICIAL_ROOT: Option<&[u8]> = None;\n");
            code.push_str("pub const OFFICIAL_PACKAGE_KEYS: Option<&[u8]> = None;\n");
        }
    }
    std::fs::write(out, code).unwrap();
}
