//! Signatures de paquets `.apak`.
//!
//! Une signature est un document JSON détaché (`<fichier>.apak.sig`) : le
//! format `.apak` n'est donc jamais modifié par la signature, ce qui permet
//! d'ajouter plus tard des chaînes de certificats (autorité AuxiNux CA,
//! `ca.auxinux.ca`) sans rupture.
//!
//! Algorithme V1 : Ed25519 (`ed25519-dalek`). Le message signé est
//! `AUXIPAK-SIGNATURE-V1\n` suivi de la sérialisation JSON déterministe de
//! [`SignedPayload`] (structure à champs ordonnés, sans table de hachage).
//!
//! Important : une signature atteste l'**origine** et l'**intégrité** d'un
//! paquet. Elle ne dit rien de sa conformité aux valeurs AuxiNux
//! (« Vérifié », « Compatible ») : cette évaluation est un mécanisme distinct,
//! attribué par le serveur.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chrono::{DateTime, Utc};
use ed25519_dalek::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

pub const SIGNATURE_FORMAT: &str = "auxipak-signature/1";
const DOMAIN: &[u8] = b"AUXIPAK-SIGNATURE-V1\n";

#[derive(Debug, thiserror::Error)]
pub enum SignatureError {
    #[error("format de signature non pris en charge : {0}")]
    Format(String),
    #[error("clé de signature inconnue : {0}")]
    UnknownKey(String),
    #[error("clé {0} révoquée")]
    RevokedKey(String),
    #[error("clé {0} hors de sa période de validité")]
    KeyNotValid(String),
    #[error("usage de clé incorrect pour {0}")]
    WrongPurpose(String),
    #[error("la signature ne correspond pas au paquet : {0}")]
    Mismatch(String),
    #[error("signature cryptographique invalide")]
    BadSignature,
    #[error("clé invalide : {0}")]
    Key(String),
    #[error("entrée/sortie : {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON : {0}")]
    Json(#[from] serde_json::Error),
}

/// Usage d'une clé publique.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KeyPurpose {
    /// Signature des paquets officiels (clé de publication AuxiPak).
    PackageSigning,
    /// Signature par un développeur (préparation phase 2).
    DeveloperSigning,
}

/// Clé publique de confiance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKeyInfo {
    pub key_id: String,
    pub algorithm: String,
    /// Clé publique brute encodée en base64.
    pub public_key: String,
    pub purpose: KeyPurpose,
    pub owner: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_after: Option<DateTime<Utc>>,
    #[serde(default)]
    pub revoked: bool,
}

impl PublicKeyInfo {
    pub fn verifying_key(&self) -> Result<VerifyingKey, SignatureError> {
        if self.algorithm != "ed25519" {
            return Err(SignatureError::Key(format!(
                "algorithme non pris en charge : {}",
                self.algorithm
            )));
        }
        let raw = B64.decode(&self.public_key).map_err(|e| SignatureError::Key(e.to_string()))?;
        let arr: [u8; 32] = raw
            .try_into()
            .map_err(|_| SignatureError::Key("longueur de clé invalide".into()))?;
        let vk = VerifyingKey::from_bytes(&arr).map_err(|e| SignatureError::Key(e.to_string()))?;
        if key_id_for(&vk) != self.key_id {
            return Err(SignatureError::Key(format!(
                "identifiant de clé incohérent : {}",
                self.key_id
            )));
        }
        Ok(vk)
    }
}

/// Ensemble de clés publiques de confiance (`package-keys.json`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustedKeys {
    pub format: String,
    pub keys: Vec<PublicKeyInfo>,
}

impl TrustedKeys {
    pub const FORMAT: &'static str = "auxipak-trusted-keys/1";

    pub fn new(keys: Vec<PublicKeyInfo>) -> Self {
        TrustedKeys {
            format: Self::FORMAT.into(),
            keys,
        }
    }

    pub fn load(path: &Path) -> Result<Self, SignatureError> {
        let t: TrustedKeys = serde_json::from_slice(&std::fs::read(path)?)?;
        if t.format != Self::FORMAT {
            return Err(SignatureError::Format(t.format));
        }
        Ok(t)
    }

    pub fn find(&self, key_id: &str) -> Option<&PublicKeyInfo> {
        self.keys.iter().find(|k| k.key_id == key_id)
    }
}

/// Identifiant d'une clé : 32 premiers caractères hexadécimaux du SHA-256 de
/// la clé publique brute.
pub fn key_id_for(vk: &VerifyingKey) -> String {
    hex::encode(Sha256::digest(vk.as_bytes()))[..32].to_string()
}

/// Paire de clés de signature de paquets.
pub struct PackageSigner {
    key: SigningKey,
    key_id: String,
}

impl PackageSigner {
    /// Génère une nouvelle clé (à n'utiliser que dans une procédure
    /// d'initialisation contrôlée ou pour les tests).
    pub fn generate() -> Self {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let key_id = key_id_for(&key.verifying_key());
        PackageSigner { key, key_id }
    }

    /// Charge une clé privée PKCS#8 PEM (`-----BEGIN PRIVATE KEY-----`).
    pub fn from_pem(pem: &str) -> Result<Self, SignatureError> {
        let key = SigningKey::from_pkcs8_pem(pem).map_err(|e| SignatureError::Key(e.to_string()))?;
        let key_id = key_id_for(&key.verifying_key());
        Ok(PackageSigner { key, key_id })
    }

    pub fn load(path: &Path) -> Result<Self, SignatureError> {
        Self::from_pem(&std::fs::read_to_string(path)?)
    }

    pub fn to_pem(&self) -> String {
        self.key
            .to_pkcs8_pem(Default::default())
            .expect("encodage PKCS#8")
            .to_string()
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn public_info(&self, owner: &str, purpose: KeyPurpose) -> PublicKeyInfo {
        PublicKeyInfo {
            key_id: self.key_id.clone(),
            algorithm: "ed25519".into(),
            public_key: B64.encode(self.key.verifying_key().as_bytes()),
            purpose,
            owner: owner.into(),
            not_before: None,
            not_after: None,
            revoked: false,
        }
    }

    /// Signe un paquet décrit par ses métadonnées et son empreinte.
    pub fn sign(&self, package: PackageRef) -> PackageSignature {
        let payload = SignedPayload {
            format: SIGNATURE_FORMAT.into(),
            algorithm: "ed25519".into(),
            key_id: self.key_id.clone(),
            package,
            signed_at: Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        };
        let sig = self.key.sign(&payload.message());
        PackageSignature {
            payload,
            certificate_chain: Vec::new(),
            signature: B64.encode(sig.to_bytes()),
        }
    }
}

/// Paquet signé.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageRef {
    pub id: String,
    pub version: String,
    pub file_name: String,
    pub sha256: String,
    pub size: u64,
}

/// Partie signée du document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedPayload {
    pub format: String,
    pub algorithm: String,
    pub key_id: String,
    pub package: PackageRef,
    pub signed_at: String,
}

impl SignedPayload {
    fn message(&self) -> Vec<u8> {
        let mut m = DOMAIN.to_vec();
        m.extend_from_slice(&serde_json::to_vec(self).expect("sérialisation JSON"));
        m
    }
}

/// Document de signature détaché (`.apak.sig`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageSignature {
    #[serde(flatten)]
    pub payload: SignedPayload,
    /// Chaîne de certificats (réservée à la phase 2, vide en V1).
    #[serde(default)]
    pub certificate_chain: Vec<String>,
    pub signature: String,
}

/// Résultat d'une vérification réussie.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSignature {
    pub key_id: String,
    pub owner: String,
    pub signed_at: String,
}

impl PackageSignature {
    pub fn from_json(bytes: &[u8]) -> Result<Self, SignatureError> {
        if bytes.len() > 64 * 1024 {
            return Err(SignatureError::Format("document de signature trop volumineux".into()));
        }
        Ok(serde_json::from_slice(bytes)?)
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("sérialisation JSON")
    }

    /// Vérifie la signature contre l'empreinte réelle du fichier et un
    /// ensemble de clés de confiance.
    pub fn verify(
        &self,
        actual_sha256: &str,
        actual_size: u64,
        trust: &TrustedKeys,
        purposes: &[KeyPurpose],
    ) -> Result<VerifiedSignature, SignatureError> {
        let p = &self.payload;
        if p.format != SIGNATURE_FORMAT || p.algorithm != "ed25519" {
            return Err(SignatureError::Format(format!("{} / {}", p.format, p.algorithm)));
        }
        let key = trust
            .find(&p.key_id)
            .ok_or_else(|| SignatureError::UnknownKey(p.key_id.clone()))?;
        if key.revoked {
            return Err(SignatureError::RevokedKey(key.key_id.clone()));
        }
        if !purposes.contains(&key.purpose) {
            return Err(SignatureError::WrongPurpose(key.key_id.clone()));
        }
        let signed_at = DateTime::parse_from_rfc3339(&p.signed_at)
            .map_err(|e| SignatureError::Format(format!("date de signature : {e}")))?
            .with_timezone(&Utc);
        if key.not_before.map(|nb| signed_at < nb).unwrap_or(false) || key.not_after.map(|na| signed_at > na).unwrap_or(false) {
            return Err(SignatureError::KeyNotValid(key.key_id.clone()));
        }
        if !crate::hash::digest_eq(&p.package.sha256, actual_sha256) {
            return Err(SignatureError::Mismatch("empreinte SHA-256".into()));
        }
        if p.package.size != actual_size {
            return Err(SignatureError::Mismatch("taille".into()));
        }
        let vk = key.verifying_key()?;
        let raw = B64.decode(&self.signature).map_err(|_| SignatureError::BadSignature)?;
        let sig = Signature::from_slice(&raw).map_err(|_| SignatureError::BadSignature)?;
        vk.verify(&p.message(), &sig).map_err(|_| SignatureError::BadSignature)?;
        Ok(VerifiedSignature {
            key_id: key.key_id.clone(),
            owner: key.owner.clone(),
            signed_at: p.signed_at.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkg() -> PackageRef {
        PackageRef {
            id: "auxipak-demo".into(),
            version: "1.0.0".into(),
            file_name: "AuxiPakDemo-1.0.0-mul.apak".into(),
            sha256: "ab".repeat(32),
            size: 1234,
        }
    }

    #[test]
    fn sign_and_verify() {
        let s = PackageSigner::generate();
        let trust = TrustedKeys::new(vec![s.public_info("AuxiNux", KeyPurpose::PackageSigning)]);
        let sig = s.sign(pkg());
        let json = sig.to_json();
        let parsed = PackageSignature::from_json(json.as_bytes()).unwrap();
        let v = parsed
            .verify(&"ab".repeat(32), 1234, &trust, &[KeyPurpose::PackageSigning])
            .unwrap();
        assert_eq!(v.owner, "AuxiNux");
    }

    #[test]
    fn pem_roundtrip() {
        let s = PackageSigner::generate();
        let s2 = PackageSigner::from_pem(&s.to_pem()).unwrap();
        assert_eq!(s.key_id(), s2.key_id());
    }

    #[test]
    fn rejects_tampering() {
        let s = PackageSigner::generate();
        let trust = TrustedKeys::new(vec![s.public_info("AuxiNux", KeyPurpose::PackageSigning)]);
        let sig = s.sign(pkg());
        let purposes = [KeyPurpose::PackageSigning];
        // Mauvais fichier.
        assert!(matches!(
            sig.verify(&"cd".repeat(32), 1234, &trust, &purposes),
            Err(SignatureError::Mismatch(_))
        ));
        assert!(matches!(
            sig.verify(&"ab".repeat(32), 1, &trust, &purposes),
            Err(SignatureError::Mismatch(_))
        ));
        // Métadonnées modifiées après signature (ex. nouvelle version).
        let mut forged = sig.clone();
        forged.payload.package.version = "9.9.9".into();
        assert!(matches!(
            forged.verify(&"ab".repeat(32), 1234, &trust, &purposes),
            Err(SignatureError::BadSignature)
        ));
        // Signature altérée.
        let mut bad = sig.clone();
        let mut raw = B64.decode(&bad.signature).unwrap();
        raw[0] ^= 1;
        bad.signature = B64.encode(raw);
        assert!(matches!(
            bad.verify(&"ab".repeat(32), 1234, &trust, &purposes),
            Err(SignatureError::BadSignature)
        ));
    }

    #[test]
    fn rejects_unknown_revoked_and_wrong_purpose_keys() {
        let s = PackageSigner::generate();
        let other = PackageSigner::generate();
        let sig = s.sign(pkg());
        let purposes = [KeyPurpose::PackageSigning];
        let trust_other = TrustedKeys::new(vec![other.public_info("X", KeyPurpose::PackageSigning)]);
        assert!(matches!(
            sig.verify(&"ab".repeat(32), 1234, &trust_other, &purposes),
            Err(SignatureError::UnknownKey(_))
        ));
        let mut revoked = s.public_info("AuxiNux", KeyPurpose::PackageSigning);
        revoked.revoked = true;
        assert!(matches!(
            sig.verify(&"ab".repeat(32), 1234, &TrustedKeys::new(vec![revoked]), &purposes),
            Err(SignatureError::RevokedKey(_))
        ));
        let dev = TrustedKeys::new(vec![s.public_info("Dev", KeyPurpose::DeveloperSigning)]);
        assert!(matches!(
            sig.verify(&"ab".repeat(32), 1234, &dev, &purposes),
            Err(SignatureError::WrongPurpose(_))
        ));
        let mut expired = s.public_info("AuxiNux", KeyPurpose::PackageSigning);
        expired.not_after = Some(Utc::now() - chrono::Duration::days(1));
        assert!(matches!(
            sig.verify(&"ab".repeat(32), 1234, &TrustedKeys::new(vec![expired]), &purposes),
            Err(SignatureError::KeyNotValid(_))
        ));
    }

    #[test]
    fn key_id_must_match_public_key() {
        let s = PackageSigner::generate();
        let mut info = s.public_info("AuxiNux", KeyPurpose::PackageSigning);
        info.key_id = "0".repeat(32);
        assert!(info.verifying_key().is_err());
    }
}
