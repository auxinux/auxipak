//! Calculs d'empreintes SHA-256.

use sha2::{Digest, Sha256};
use std::io::{self, Read, Write};
use std::path::Path;

/// SHA-256 hexadécimal (minuscules) d'un tampon.
pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// SHA-256 et taille d'un fichier, lu par blocs.
pub fn sha256_file(path: &Path) -> io::Result<(String, u64)> {
    let f = std::fs::File::open(path)?;
    sha256_reader(f)
}

pub fn sha256_reader(mut r: impl Read) -> io::Result<(String, u64)> {
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 256 * 1024];
    let mut total = 0u64;
    loop {
        let n = r.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
        total += n as u64;
    }
    Ok((hex::encode(h.finalize()), total))
}

/// Écrivain qui calcule l'empreinte et la taille de ce qui le traverse, et
/// refuse de dépasser une limite.
pub struct HashingWriter<W: Write> {
    inner: W,
    hasher: Sha256,
    written: u64,
    limit: u64,
}

impl<W: Write> HashingWriter<W> {
    pub fn new(inner: W, limit: u64) -> Self {
        HashingWriter { inner, hasher: Sha256::new(), written: 0, limit }
    }

    pub fn finish(self) -> (W, String, u64) {
        (self.inner, hex::encode(self.hasher.finalize()), self.written)
    }

    pub fn written(&self) -> u64 {
        self.written
    }
}

impl<W: Write> Write for HashingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.written + buf.len() as u64 > self.limit {
            return Err(io::Error::other(format!(
                "limite de taille dépassée ({} octets)",
                self.limit
            )));
        }
        let n = self.inner.write(buf)?;
        self.hasher.update(&buf[..n]);
        self.written += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Comparaison en temps constant de deux empreintes hexadécimales.
pub fn digest_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x.to_ascii_lowercase() ^ y.to_ascii_lowercase())) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vector() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn hashing_writer_enforces_limit() {
        let mut w = HashingWriter::new(Vec::new(), 4);
        assert!(w.write_all(b"abc").is_ok());
        assert!(w.write_all(b"de").is_err());
    }

    #[test]
    fn digest_comparison() {
        assert!(digest_eq("ABcd", "abcd"));
        assert!(!digest_eq("abcd", "abce"));
        assert!(!digest_eq("abcd", "abc"));
    }
}
