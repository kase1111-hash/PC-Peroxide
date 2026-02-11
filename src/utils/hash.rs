//! Hash calculation utilities.

use crate::core::error::{Error, Result};
use md5::{Digest, Md5};
use sha2::Sha256;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

/// Buffer size for reading files (64KB).
const BUFFER_SIZE: usize = 64 * 1024;

/// Hash results for a file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileHashes {
    /// SHA256 hash (primary)
    pub sha256: String,
    /// MD5 hash (for compatibility)
    pub md5: String,
    /// File size in bytes
    pub size: u64,
}

/// Hash calculator for files.
pub struct HashCalculator;

impl HashCalculator {
    /// Calculate SHA256 hash of a file.
    pub fn sha256_file(path: &Path) -> Result<String> {
        let file = File::open(path).map_err(|e| Error::file_read(path, e))?;
        let mut reader = BufReader::with_capacity(BUFFER_SIZE, file);
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; BUFFER_SIZE];

        loop {
            let bytes_read = reader
                .read(&mut buffer)
                .map_err(|e| Error::file_read(path, e))?;
            if bytes_read == 0 {
                break;
            }
            hasher.update(&buffer[..bytes_read]);
        }

        Ok(hex::encode(hasher.finalize()))
    }

    /// Calculate MD5 hash of a file.
    pub fn md5_file(path: &Path) -> Result<String> {
        let file = File::open(path).map_err(|e| Error::file_read(path, e))?;
        let mut reader = BufReader::with_capacity(BUFFER_SIZE, file);
        let mut hasher = Md5::new();
        let mut buffer = [0u8; BUFFER_SIZE];

        loop {
            let bytes_read = reader
                .read(&mut buffer)
                .map_err(|e| Error::file_read(path, e))?;
            if bytes_read == 0 {
                break;
            }
            hasher.update(&buffer[..bytes_read]);
        }

        Ok(hex::encode(hasher.finalize()))
    }

    /// Calculate both SHA256 and MD5 hashes of a file in a single pass.
    pub fn hash_file(path: &Path) -> Result<FileHashes> {
        let file = File::open(path).map_err(|e| Error::file_read(path, e))?;
        let metadata = file.metadata().map_err(|e| Error::file_read(path, e))?;
        let size = metadata.len();

        let mut reader = BufReader::with_capacity(BUFFER_SIZE, file);
        let mut sha256_hasher = Sha256::new();
        let mut md5_hasher = Md5::new();
        let mut buffer = [0u8; BUFFER_SIZE];

        loop {
            let bytes_read = reader
                .read(&mut buffer)
                .map_err(|e| Error::file_read(path, e))?;
            if bytes_read == 0 {
                break;
            }
            sha256_hasher.update(&buffer[..bytes_read]);
            md5_hasher.update(&buffer[..bytes_read]);
        }

        Ok(FileHashes {
            sha256: hex::encode(sha256_hasher.finalize()),
            md5: hex::encode(md5_hasher.finalize()),
            size,
        })
    }

    /// Calculate SHA256 hash of bytes.
    pub fn sha256_bytes(data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hex::encode(hasher.finalize())
    }

    /// Calculate MD5 hash of bytes.
    pub fn md5_bytes(data: &[u8]) -> String {
        let mut hasher = Md5::new();
        hasher.update(data);
        hex::encode(hasher.finalize())
    }

    /// Verify a file matches an expected SHA256 hash.
    pub fn verify_sha256(path: &Path, expected: &str) -> Result<bool> {
        let actual = Self::sha256_file(path)?;
        Ok(actual.eq_ignore_ascii_case(expected))
    }

    /// Verify a file matches an expected MD5 hash.
    pub fn verify_md5(path: &Path, expected: &str) -> Result<bool> {
        let actual = Self::md5_file(path)?;
        Ok(actual.eq_ignore_ascii_case(expected))
    }
}

/// Trait for hash computation (for extensibility).
pub trait Hasher {
    /// Compute hash of bytes.
    fn hash_bytes(&self, data: &[u8]) -> String;

    /// Compute hash of a file.
    fn hash_file(&self, path: &Path) -> Result<String>;
}

/// SHA256 hasher implementation.
pub struct Sha256Hasher;

impl Hasher for Sha256Hasher {
    fn hash_bytes(&self, data: &[u8]) -> String {
        HashCalculator::sha256_bytes(data)
    }

    fn hash_file(&self, path: &Path) -> Result<String> {
        HashCalculator::sha256_file(path)
    }
}

/// MD5 hasher implementation.
pub struct Md5Hasher;

impl Hasher for Md5Hasher {
    fn hash_bytes(&self, data: &[u8]) -> String {
        HashCalculator::md5_bytes(data)
    }

    fn hash_file(&self, path: &Path) -> Result<String> {
        HashCalculator::md5_file(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_sha256_bytes() {
        // Test vector: SHA256("hello")
        let hash = HashCalculator::sha256_bytes(b"hello");
        assert_eq!(
            hash,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn test_md5_bytes() {
        // Test vector: MD5("hello")
        let hash = HashCalculator::md5_bytes(b"hello");
        assert_eq!(hash, "5d41402abc4b2a76b9719d911017c592");
    }

    #[test]
    fn test_hash_file() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(b"test content").unwrap();

        let hashes = HashCalculator::hash_file(file.path()).unwrap();
        assert!(!hashes.sha256.is_empty());
        assert!(!hashes.md5.is_empty());
        assert_eq!(hashes.size, 12);
    }

    #[test]
    fn test_verify_hash() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(b"hello").unwrap();

        let valid = HashCalculator::verify_sha256(
            file.path(),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
        )
        .unwrap();
        assert!(valid);

        let invalid = HashCalculator::verify_sha256(file.path(), "invalid_hash").unwrap();
        assert!(!invalid);
    }
}
