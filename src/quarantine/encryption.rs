//! AES-256-GCM encryption for quarantine vault.
//!
//! This module provides secure encryption and decryption for quarantined files
//! using AES-256-GCM (Galois/Counter Mode) which provides both confidentiality
//! and authenticity.

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use rand::RngCore;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;

use crate::core::error::{Error, Result};

/// Size of the AES-256 key in bytes
const KEY_SIZE: usize = 32;
/// Size of the GCM nonce in bytes
const NONCE_SIZE: usize = 12;
/// Magic bytes to identify encrypted vault files
const VAULT_MAGIC: &[u8] = b"PCPX";
/// Current vault format version
const VAULT_VERSION: u8 = 1;

/// Encryption manager for quarantine operations.
#[derive(Clone)]
pub struct EncryptionManager {
    /// The encryption key (derived or stored securely)
    key: [u8; KEY_SIZE],
}

impl EncryptionManager {
    /// Create a new encryption manager with a random key.
    pub fn new() -> Self {
        let mut key = [0u8; KEY_SIZE];
        OsRng.fill_bytes(&mut key);
        Self { key }
    }

    /// Create an encryption manager from an existing key.
    pub fn from_key(key: [u8; KEY_SIZE]) -> Self {
        Self { key }
    }

    /// Create an encryption manager from a key file.
    ///
    /// If the key file doesn't exist, generates a new key and saves it.
    pub fn from_key_file(path: &Path) -> Result<Self> {
        if path.exists() {
            let mut file = File::open(path).map_err(|e| Error::file_read(path, e))?;
            let mut key = [0u8; KEY_SIZE];
            file.read_exact(&mut key)
                .map_err(|e| Error::file_read(path, e))?;
            Ok(Self { key })
        } else {
            let manager = Self::new();
            manager.save_key(path)?;
            Ok(manager)
        }
    }

    /// Save the encryption key to a file.
    ///
    /// On Unix systems, the file is created with mode 0600 (owner read/write only).
    /// On Windows, the file inherits default permissions from the parent directory.
    pub fn save_key(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| Error::DirectoryAccess {
                path: parent.to_path_buf(),
                source: e,
            })?;
        }

        let mut file = File::create(path).map_err(|e| Error::file_write(path, e))?;
        file.write_all(&self.key)
            .map_err(|e| Error::file_write(path, e))?;

        // Set restrictive permissions on the key file
        Self::set_key_file_permissions(path)?;

        Ok(())
    }

    /// Set restrictive permissions on the key file.
    #[cfg(unix)]
    fn set_key_file_permissions(path: &Path) -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let permissions = std::fs::Permissions::from_mode(0o600);
        fs::set_permissions(path, permissions).map_err(|e| Error::file_write(path, e))?;
        Ok(())
    }

    /// Set restrictive permissions on the key file (Windows stub).
    #[cfg(not(unix))]
    fn set_key_file_permissions(_path: &Path) -> Result<()> {
        // On Windows, file permissions are handled differently through ACLs.
        // The file is created with inherited permissions from the parent directory.
        // For enhanced security on Windows, consider using the windows-acl crate.
        Ok(())
    }

    /// Get the encryption key bytes.
    pub fn key_bytes(&self) -> &[u8; KEY_SIZE] {
        &self.key
    }

    /// Encrypt data using AES-256-GCM.
    ///
    /// Returns the encrypted data with a prepended nonce.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let key = Key::<Aes256Gcm>::from_slice(&self.key);
        let cipher = Aes256Gcm::new(key);

        // Generate random nonce
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt the data
        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| Error::Encryption(format!("Encryption failed: {}", e)))?;

        // Combine nonce + ciphertext
        let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend(ciphertext);

        Ok(result)
    }

    /// Decrypt data that was encrypted with [encrypt].
    ///
    /// Expects the nonce to be prepended to the ciphertext.
    pub fn decrypt(&self, encrypted: &[u8]) -> Result<Vec<u8>> {
        if encrypted.len() < NONCE_SIZE {
            return Err(Error::Decryption("Data too short".to_string()));
        }

        let key = Key::<Aes256Gcm>::from_slice(&self.key);
        let cipher = Aes256Gcm::new(key);

        // Split nonce and ciphertext
        let (nonce_bytes, ciphertext) = encrypted.split_at(NONCE_SIZE);
        let nonce = Nonce::from_slice(nonce_bytes);

        // Decrypt the data
        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| Error::Decryption(format!("Decryption failed: {}", e)))?;

        Ok(plaintext)
    }

    /// Encrypt a file and write to the vault format.
    ///
    /// Vault format:
    /// - 4 bytes: Magic ("PCPX")
    /// - 1 byte: Version
    /// - 8 bytes: Original file size (little endian)
    /// - 12 bytes: Nonce
    /// - N bytes: Encrypted data
    /// - 16 bytes: GCM authentication tag (included in encrypted data)
    pub fn encrypt_file(&self, source: &Path, dest: &Path) -> Result<()> {
        // Read source file
        let plaintext = fs::read(source).map_err(|e| Error::file_read(source, e))?;
        let original_size = plaintext.len() as u64;

        // Encrypt the data
        let encrypted = self.encrypt(&plaintext)?;

        // Create vault file with header
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent).map_err(|e| Error::DirectoryAccess {
                path: parent.to_path_buf(),
                source: e,
            })?;
        }

        let mut file = File::create(dest).map_err(|e| Error::file_write(dest, e))?;

        // Write header
        file.write_all(VAULT_MAGIC)
            .map_err(|e| Error::file_write(dest, e))?;
        file.write_all(&[VAULT_VERSION])
            .map_err(|e| Error::file_write(dest, e))?;
        file.write_all(&original_size.to_le_bytes())
            .map_err(|e| Error::file_write(dest, e))?;

        // Write encrypted data
        file.write_all(&encrypted)
            .map_err(|e| Error::file_write(dest, e))?;

        Ok(())
    }

    /// Decrypt a vault file and write the original content.
    pub fn decrypt_file(&self, source: &Path, dest: &Path) -> Result<()> {
        let data = fs::read(source).map_err(|e| Error::file_read(source, e))?;

        // Parse header
        let header_size = VAULT_MAGIC.len() + 1 + 8; // magic + version + size
        if data.len() < header_size {
            return Err(Error::Decryption(
                "Invalid vault file: too short".to_string(),
            ));
        }

        // Verify magic
        if &data[..VAULT_MAGIC.len()] != VAULT_MAGIC {
            return Err(Error::Decryption(
                "Invalid vault file: bad magic".to_string(),
            ));
        }

        // Check version
        let version = data[VAULT_MAGIC.len()];
        if version != VAULT_VERSION {
            return Err(Error::Decryption(format!(
                "Unsupported vault version: {}",
                version
            )));
        }

        // Get original size (for verification)
        let size_offset = VAULT_MAGIC.len() + 1;
        let mut size_bytes = [0u8; 8];
        size_bytes.copy_from_slice(&data[size_offset..size_offset + 8]);
        let _original_size = u64::from_le_bytes(size_bytes);

        // Decrypt the data
        let encrypted = &data[header_size..];
        let plaintext = self.decrypt(encrypted)?;

        // Write decrypted file
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent).map_err(|e| Error::DirectoryAccess {
                path: parent.to_path_buf(),
                source: e,
            })?;
        }

        fs::write(dest, &plaintext).map_err(|e| Error::file_write(dest, e))?;

        Ok(())
    }
}

impl Default for EncryptionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_encrypt_decrypt() {
        let manager = EncryptionManager::new();
        let plaintext = b"Hello, World! This is a test message.";

        let encrypted = manager.encrypt(plaintext).unwrap();
        assert_ne!(encrypted, plaintext);
        assert!(encrypted.len() > plaintext.len()); // Includes nonce + tag

        let decrypted = manager.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_empty() {
        let manager = EncryptionManager::new();
        let plaintext = b"";

        let encrypted = manager.encrypt(plaintext).unwrap();
        let decrypted = manager.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_large_data() {
        let manager = EncryptionManager::new();
        let plaintext: Vec<u8> = (0..10000).map(|i| (i % 256) as u8).collect();

        let encrypted = manager.encrypt(&plaintext).unwrap();
        let decrypted = manager.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_invalid_data() {
        let manager = EncryptionManager::new();

        // Too short
        let result = manager.decrypt(&[0u8; 5]);
        assert!(result.is_err());

        // Invalid ciphertext (random garbage)
        let mut invalid = vec![0u8; 100];
        OsRng.fill_bytes(&mut invalid);
        let result = manager.decrypt(&invalid);
        assert!(result.is_err());
    }

    #[test]
    fn test_different_keys_fail() {
        let manager1 = EncryptionManager::new();
        let manager2 = EncryptionManager::new();

        let plaintext = b"Secret message";
        let encrypted = manager1.encrypt(plaintext).unwrap();

        // Decrypting with different key should fail
        let result = manager2.decrypt(&encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_key_persistence() {
        let temp_dir = TempDir::new().unwrap();
        let key_path = temp_dir.path().join("test.key");

        // Create and save key
        let manager1 = EncryptionManager::new();
        manager1.save_key(&key_path).unwrap();

        // Load key
        let manager2 = EncryptionManager::from_key_file(&key_path).unwrap();

        // Should be able to decrypt with loaded key
        let plaintext = b"Test message";
        let encrypted = manager1.encrypt(plaintext).unwrap();
        let decrypted = manager2.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_file() {
        let temp_dir = TempDir::new().unwrap();
        let source = temp_dir.path().join("source.txt");
        let vault = temp_dir.path().join("vault.qvault");
        let restored = temp_dir.path().join("restored.txt");

        // Create source file
        let content = b"This is the file content to encrypt.";
        fs::write(&source, content).unwrap();

        // Encrypt
        let manager = EncryptionManager::new();
        manager.encrypt_file(&source, &vault).unwrap();

        // Verify vault file exists and is different
        assert!(vault.exists());
        let vault_content = fs::read(&vault).unwrap();
        assert_ne!(&vault_content[..], content);
        assert!(vault_content.starts_with(VAULT_MAGIC));

        // Decrypt
        manager.decrypt_file(&vault, &restored).unwrap();

        // Verify restored content
        let restored_content = fs::read(&restored).unwrap();
        assert_eq!(restored_content, content);
    }

    #[test]
    fn test_decrypt_invalid_vault() {
        let temp_dir = TempDir::new().unwrap();
        let invalid_vault = temp_dir.path().join("invalid.qvault");
        let dest = temp_dir.path().join("dest.txt");

        // Write invalid vault file
        fs::write(&invalid_vault, b"Not a valid vault").unwrap();

        let manager = EncryptionManager::new();
        let result = manager.decrypt_file(&invalid_vault, &dest);
        assert!(result.is_err());
    }
}
