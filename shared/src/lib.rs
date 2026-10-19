//! # auxipak-core
//!
//! Bibliothèque commune au client `auxipak`, au constructeur
//! `auxipak-builder` et au serveur `auxipak-server` :
//!
//! - [`platform`] : modèle de plateforme et analyse d'`os-release` ;
//! - [`version`] : comparaison et contraintes de versions ;
//! - [`ids`] : validation des identifiants (barrière anti-injection) ;
//! - [`manifest`] : manifeste `instruction.auxipak` ;
//! - [`archive`] : format `.apak` (7z normalisé) et extraction sécurisée ;
//! - [`signature`] : signatures Ed25519 détachées des paquets ;
//! - [`index`] : index des dépôts ;
//! - [`tuf`] : métadonnées de dépôt TUF (via `tough`) ;
//! - [`netpolicy`] : validation des URL et redirections.

pub mod archive;
pub mod hash;
pub mod ids;
pub mod index;
pub mod keyset;
pub mod manifest;
pub mod netpolicy;
pub mod platform;
pub mod project;
pub mod repogen;
pub mod schema;
pub mod signature;
pub mod tuf;
pub mod version;

/// Version de la bibliothèque (identique pour tous les composants).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
