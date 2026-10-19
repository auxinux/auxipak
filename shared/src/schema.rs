//! Schéma JSON officiel du manifeste, embarqué dans le binaire.

use serde_json::Value;
use std::sync::OnceLock;

/// Texte du schéma JSON (`schemas/instruction.auxipak.schema.json`).
pub const MANIFEST_SCHEMA: &str = include_str!("../../schemas/instruction.auxipak.schema.json");

fn validator() -> &'static jsonschema::Validator {
    static V: OnceLock<jsonschema::Validator> = OnceLock::new();
    V.get_or_init(|| {
        let schema: Value = serde_json::from_str(MANIFEST_SCHEMA).expect("schéma JSON valide");
        jsonschema::validator_for(&schema).expect("schéma compilable")
    })
}

/// Valide une valeur (issue du YAML) contre le schéma du manifeste.
pub fn validate_manifest_value(v: &Value) -> Result<(), Vec<String>> {
    let errors: Vec<String> = validator()
        .iter_errors(v)
        .map(|e| {
            let path = e.instance_path().to_string();
            format!("{} : {}", if path.is_empty() { "/".to_string() } else { path }, e)
        })
        .collect();
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}
