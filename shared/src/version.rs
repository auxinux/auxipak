//! Comparaison de versions et contraintes de versions.
//!
//! Les applications utilisent des schémas de versions hétérogènes (`150.1`,
//! `1.0.0-beta.2`, `24.04`, `10.0.22631`). L'algorithme retenu est celui de
//! Debian (`dpkg --compare-versions`, sans époque ni révision) : alternance de
//! segments non numériques et numériques, le tilde `~` étant trié avant tout
//! (`1.0~rc1 < 1.0`). Il est déterministe et identique sur toutes les
//! plateformes.

use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::fmt;

/// Compare deux chaînes de version.
pub fn compare(a: &str, b: &str) -> Ordering {
    let (mut a, mut b) = (a.as_bytes(), b.as_bytes());
    loop {
        if a.is_empty() && b.is_empty() {
            return Ordering::Equal;
        }
        // Segment non numérique.
        let (na, ra) = split_while(a, |c| !c.is_ascii_digit());
        let (nb, rb) = split_while(b, |c| !c.is_ascii_digit());
        let ord = compare_non_digit(na, nb);
        if ord != Ordering::Equal {
            return ord;
        }
        // Segment numérique.
        let (da, ra) = split_while(ra, |c| c.is_ascii_digit());
        let (db, rb) = split_while(rb, |c| c.is_ascii_digit());
        let ord = compare_digits(da, db);
        if ord != Ordering::Equal {
            return ord;
        }
        a = ra;
        b = rb;
    }
}

fn split_while(s: &[u8], f: impl Fn(u8) -> bool) -> (&[u8], &[u8]) {
    let n = s.iter().take_while(|c| f(**c)).count();
    s.split_at(n)
}

fn char_order(c: Option<u8>) -> i32 {
    match c {
        Some(b'~') => -1,
        None => 0,
        Some(c) if c.is_ascii_alphabetic() => c as i32,
        Some(c) => c as i32 + 256,
    }
}

fn compare_non_digit(a: &[u8], b: &[u8]) -> Ordering {
    let n = a.len().max(b.len());
    for i in 0..n {
        let oa = char_order(a.get(i).copied());
        let ob = char_order(b.get(i).copied());
        if oa != ob {
            return oa.cmp(&ob);
        }
    }
    Ordering::Equal
}

fn compare_digits(a: &[u8], b: &[u8]) -> Ordering {
    let a = trim_zeros(a);
    let b = trim_zeros(b);
    a.len().cmp(&b.len()).then_with(|| a.cmp(b))
}

fn trim_zeros(s: &[u8]) -> &[u8] {
    let n = s.iter().take_while(|c| **c == b'0').count();
    &s[n..]
}

/// Valide la syntaxe d'une version : caractères alphanumériques et `.+-~_`,
/// commençant par un chiffre.
pub fn is_valid_version(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= 64
        && v.as_bytes()[0].is_ascii_digit()
        && v
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'+' | b'-' | b'~' | b'_'))
}

/// Opérateur d'une contrainte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Eq,
    Ge,
    Gt,
    Le,
    Lt,
}

/// Contrainte de version (`>=1.0, <2.0`, `=1.2.3`, `*`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionReq {
    raw: String,
    clauses: Vec<(Op, String)>,
}

impl VersionReq {
    pub fn any() -> Self {
        VersionReq { raw: "*".into(), clauses: vec![] }
    }

    pub fn parse(s: &str) -> Result<Self, String> {
        let raw = s.trim().to_string();
        if raw.is_empty() || raw == "*" {
            return Ok(VersionReq::any());
        }
        let mut clauses = Vec::new();
        for part in raw.split(',') {
            let p = part.trim();
            let (op, rest) = if let Some(r) = p.strip_prefix(">=") {
                (Op::Ge, r)
            } else if let Some(r) = p.strip_prefix("<=") {
                (Op::Le, r)
            } else if let Some(r) = p.strip_prefix('>') {
                (Op::Gt, r)
            } else if let Some(r) = p.strip_prefix('<') {
                (Op::Lt, r)
            } else if let Some(r) = p.strip_prefix('=') {
                (Op::Eq, r)
            } else {
                (Op::Eq, p)
            };
            let v = rest.trim();
            if !is_valid_version(v) {
                return Err(format!("contrainte de version invalide : « {part} »"));
            }
            clauses.push((op, v.to_string()));
        }
        Ok(VersionReq { raw, clauses })
    }

    pub fn matches(&self, version: &str) -> bool {
        self.clauses.iter().all(|(op, v)| {
            let o = compare(version, v);
            match op {
                Op::Eq => o == Ordering::Equal,
                Op::Ge => o != Ordering::Less,
                Op::Gt => o == Ordering::Greater,
                Op::Le => o != Ordering::Greater,
                Op::Lt => o == Ordering::Less,
            }
        })
    }

    pub fn as_str(&self) -> &str {
        &self.raw
    }
}

impl fmt::Display for VersionReq {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.raw)
    }
}

impl Serialize for VersionReq {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.raw)
    }
}

impl<'de> Deserialize<'de> for VersionReq {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        VersionReq::parse(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use Ordering::*;

    #[test]
    fn compares_like_dpkg() {
        let cases = [
            ("1.0", "1.0", Equal),
            ("1.0", "1.1", Less),
            ("1.10", "1.9", Greater),
            ("150.1", "150.0.1", Greater),
            ("1.0~rc1", "1.0", Less),
            ("1.0", "1.0a", Less),
            ("1.0.0", "1.0", Greater),
            ("01.2", "1.2", Equal),
            ("2.0", "10.0", Less),
            ("1.1.0", "1.0.0", Greater),
            ("24.04", "22.04", Greater),
        ];
        for (a, b, o) in cases {
            assert_eq!(compare(a, b), o, "{a} vs {b}");
            assert_eq!(compare(b, a), o.reverse(), "{b} vs {a}");
        }
    }

    #[test]
    fn requirements() {
        let r = VersionReq::parse(">=1.0, <2.0").unwrap();
        assert!(r.matches("1.0"));
        assert!(r.matches("1.9.9"));
        assert!(!r.matches("2.0"));
        assert!(!r.matches("0.9"));
        assert!(VersionReq::parse("*").unwrap().matches("0.0.1"));
        assert!(VersionReq::parse("=1.2").unwrap().matches("1.2"));
        assert!(VersionReq::parse("1.2").unwrap().matches("1.2"));
        assert!(VersionReq::parse(">=12").unwrap().matches("13"));
        assert!(!VersionReq::parse(">=12").unwrap().matches("11"));
        assert!(VersionReq::parse(">=1.0; rm -rf /").is_err());
    }

    #[test]
    fn version_syntax() {
        assert!(is_valid_version("150.1"));
        assert!(is_valid_version("1.0.0-beta.2"));
        assert!(!is_valid_version("v1"));
        assert!(!is_valid_version("1.0 && x"));
        assert!(!is_valid_version("../1"));
    }
}
