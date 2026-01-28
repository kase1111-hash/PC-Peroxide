//! Quarantine vault manager.
//!
//! The vault is the main interface for quarantine operations, combining:
//! - AES-256-GCM encryption
//! - SQLite metadata storage
//! - Secure file operations

use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;

use super::{
    encryption::EncryptionManager,
    get_quarantine_path,
    metadata::{QuarantineItem, QuarantineMetadata},
    operations::SecureOperations,
    QuarantineResult, RestoreResult, ITEMS_DIR, VAULT_EXTENSION,
};
use crate::core::error::{Error, Result};

/// Quarantine vault manager.
///
/// Handles quarantine, restore, and deletion operations for malicious files.
pub struct QuarantineVault {
    /// Base path for the quarantine vault
    base_path: PathBuf,
    /// Encryption manager
    encryption: EncryptionManager,
    /// Metadata database
    metadata: QuarantineMetadata,
    /// Secure file operations
    operations: SecureOperations,
}

impl QuarantineVault {
    /// Create or open a quarantine vault at the default location.
    pub fn open_default() -> Result<Self> {
        Self::open(&get_quarantine_path())
    }

    /// Create or open a quarantine vault at the specified path.
    pub fn open(base_path: &Path) -> Result<Self> {
        // Create directory structure
        fs::create_dir_all(base_path).map_err(|e| Error::DirectoryAccess {
            path: base_path.to_path_buf(),
            source: e,
        })?;

        let items_path = base_path.join(ITEMS_DIR);
        fs::create_dir_all(&items_path).map_err(|e| Error::DirectoryAccess {
            path: items_path.clone(),
            source: e,
        })?;

        // Initialize encryption (load or create key)
        let key_path = base_path.join("vault.key");
        let encryption = EncryptionManager::from_key_file(&key_path)?;

        // Initialize metadata database
        let db_path = base_path.join("vault.db");
        let metadata = QuarantineMetadata::open(&db_path)?;

        Ok(Self {
            base_path: base_path.to_path_buf(),
            encryption,
            metadata,
            operations: SecureOperations::new(),
        })
    }

    /// Get the base path of the vault.
    pub fn base_path(&self) -> &Path {
        &self.base_path
    }

    /// Get the path to the items directory.
    pub fn items_path(&self) -> PathBuf {
        self.base_path.join(ITEMS_DIR)
    }

    /// Quarantine a file.
    ///
    /// This will:
    /// 1. Calculate the file hash
    /// 2. Encrypt the file and store it in the vault
    /// 3. Record metadata in the database
    /// 4. Delete the original file (if delete_original is true)
    pub fn quarantine(
        &self,
        path: &Path,
        detection_name: &str,
        category: &str,
        severity: u8,
        delete_original: bool,
    ) -> QuarantineResult {
        // Validate source file
        if !path.exists() {
            return QuarantineResult::failure(
                path.to_path_buf(),
                "File does not exist".to_string(),
            );
        }

        // Calculate hash
        let hash = match self.calculate_hash(path) {
            Ok(h) => h,
            Err(e) => {
                return QuarantineResult::failure(
                    path.to_path_buf(),
                    format!("Failed to calculate hash: {}", e),
                );
            }
        };

        // Check if already quarantined
        match self.metadata.exists_by_hash(&hash) {
            Ok(true) => {
                return QuarantineResult::failure(
                    path.to_path_buf(),
                    "File already quarantined".to_string(),
                );
            }
            Err(e) => {
                return QuarantineResult::failure(
                    path.to_path_buf(),
                    format!("Database error: {}", e),
                );
            }
            _ => {}
        }

        // Get file size
        let file_size = match fs::metadata(path) {
            Ok(m) => m.len(),
            Err(e) => {
                return QuarantineResult::failure(
                    path.to_path_buf(),
                    format!("Failed to read file metadata: {}", e),
                );
            }
        };

        // Generate unique ID
        let id = Uuid::new_v4().to_string();
        let vault_filename = format!("{}.{}", id, VAULT_EXTENSION);
        let vault_path = self.items_path().join(&vault_filename);

        // Encrypt and store
        if let Err(e) = self.encryption.encrypt_file(path, &vault_path) {
            return QuarantineResult::failure(
                path.to_path_buf(),
                format!("Encryption failed: {}", e),
            );
        }

        // Create metadata entry
        let item = QuarantineItem::new(
            id.clone(),
            path.to_path_buf(),
            vault_filename,
            hash,
            file_size,
            detection_name.to_string(),
            category.to_string(),
            severity,
        );

        // Store metadata
        if let Err(e) = self.metadata.add(&item) {
            // Clean up vault file on failure
            if let Err(cleanup_err) = fs::remove_file(&vault_path) {
                log::warn!(
                    "Failed to clean up vault file {:?} after metadata error: {}",
                    vault_path,
                    cleanup_err
                );
            }
            return QuarantineResult::failure(
                path.to_path_buf(),
                format!("Failed to store metadata: {}", e),
            );
        }

        // Delete original file if requested
        if delete_original {
            if let Err(e) = self.operations.secure_delete(path) {
                // Log but don't fail the quarantine
                log::warn!("Failed to delete original file: {}", e);
            }
        }

        QuarantineResult::success(id, path.to_path_buf(), vault_path)
    }

    /// Restore a quarantined file to its original location.
    pub fn restore(&self, id: &str) -> RestoreResult {
        self.restore_to(id, None)
    }

    /// Restore a quarantined file to a specific location.
    pub fn restore_to(&self, id: &str, dest: Option<&Path>) -> RestoreResult {
        // Get item metadata
        let item = match self.metadata.get(id) {
            Ok(Some(item)) => item,
            Ok(None) => {
                return RestoreResult::failure(
                    id.to_string(),
                    "Quarantine item not found".to_string(),
                );
            }
            Err(e) => {
                return RestoreResult::failure(id.to_string(), format!("Database error: {}", e));
            }
        };

        if !item.restorable {
            return RestoreResult::failure(
                id.to_string(),
                "Item is not restorable (may have been deleted)".to_string(),
            );
        }

        let vault_path = self.items_path().join(&item.vault_filename);
        if !vault_path.exists() {
            return RestoreResult::failure(
                id.to_string(),
                "Vault file not found".to_string(),
            );
        }

        // Determine destination path
        let restore_path = dest
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| item.original_path.clone());

        // Decrypt and restore
        if let Err(e) = self.encryption.decrypt_file(&vault_path, &restore_path) {
            return RestoreResult::failure(
                id.to_string(),
                format!("Decryption failed: {}", e),
            );
        }

        // Remove from quarantine
        if let Err(e) = self.metadata.remove(id) {
            log::warn!("Failed to remove metadata after restore: {}", e);
        }

        // Delete vault file
        if let Err(e) = fs::remove_file(&vault_path) {
            log::warn!("Failed to delete vault file after restore: {}", e);
        }

        RestoreResult::success(id.to_string(), restore_path)
    }

    /// Permanently delete a quarantined item.
    pub fn delete(&self, id: &str) -> Result<()> {
        // Get item metadata
        let item = self
            .metadata
            .get(id)?
            .ok_or_else(|| Error::QuarantineItemNotFound(id.to_string()))?;

        // Delete vault file
        let vault_path = self.items_path().join(&item.vault_filename);
        if vault_path.exists() {
            self.operations.secure_delete(&vault_path)?;
        }

        // Remove from database
        self.metadata.remove(id)?;

        Ok(())
    }

    /// List all quarantined items.
    pub fn list(&self) -> Result<Vec<QuarantineItem>> {
        self.metadata.list()
    }

    /// Get a quarantined item by ID.
    pub fn get(&self, id: &str) -> Result<Option<QuarantineItem>> {
        self.metadata.get(id)
    }

    /// Get the count of quarantined items.
    pub fn count(&self) -> Result<usize> {
        self.metadata.count()
    }

    /// Get the total size of quarantined items.
    pub fn total_size(&self) -> Result<u64> {
        self.metadata.total_size()
    }

    /// Check if a file hash is already quarantined.
    pub fn is_quarantined(&self, hash: &str) -> Result<bool> {
        self.metadata.exists_by_hash(hash)
    }

    /// Calculate SHA-256 hash of a file.
    fn calculate_hash(&self, path: &Path) -> Result<String> {
        let data = fs::read(path).map_err(|e| Error::file_read(path, e))?;
        let mut hasher = Sha256::new();
        hasher.update(&data);
        Ok(hex::encode(hasher.finalize()))
    }

    /// Get vault statistics.
    pub fn stats(&self) -> Result<VaultStats> {
        let items = self.list()?;
        let total_count = items.len();
        let total_original_size = items.iter().map(|i| i.original_size).sum();

        // Calculate actual vault size
        let vault_size = self.calculate_vault_size()?;

        // Count by category
        let mut categories: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();
        for item in &items {
            *categories.entry(item.category.clone()).or_insert(0) += 1;
        }

        Ok(VaultStats {
            total_count,
            total_original_size,
            vault_size,
            categories,
        })
    }

    /// Calculate the actual disk size of the vault.
    fn calculate_vault_size(&self) -> Result<u64> {
        let mut size = 0u64;
        let items_path = self.items_path();

        if items_path.exists() {
            for entry in fs::read_dir(&items_path)
                .map_err(|e| Error::DirectoryAccess {
                    path: items_path.clone(),
                    source: e,
                })?
                .flatten()
            {
                if let Ok(metadata) = entry.metadata() {
                    size += metadata.len();
                }
            }
        }

        Ok(size)
    }
}

/// Statistics about the quarantine vault.
#[derive(Debug, Clone)]
pub struct VaultStats {
    /// Total number of quarantined items
    pub total_count: usize,
    /// Total size of original files
    pub total_original_size: u64,
    /// Actual size of vault files on disk
    pub vault_size: u64,
    /// Count of items by category
    pub categories: std::collections::HashMap<String, usize>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_test_file(dir: &Path, name: &str, content: &[u8]) -> PathBuf {
        let path = dir.join(name);
        fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn test_vault_open() {
        let temp_dir = TempDir::new().unwrap();
        let vault = QuarantineVault::open(temp_dir.path()).unwrap();

        assert_eq!(vault.count().unwrap(), 0);
        assert!(vault.items_path().exists());
    }

    #[test]
    fn test_quarantine_and_restore() {
        let temp_dir = TempDir::new().unwrap();
        let vault_dir = temp_dir.path().join("vault");
        let files_dir = temp_dir.path().join("files");
        fs::create_dir_all(&files_dir).unwrap();

        let vault = QuarantineVault::open(&vault_dir).unwrap();

        // Create test file
        let content = b"Malicious content here";
        let file_path = create_test_file(&files_dir, "malware.exe", content);

        // Quarantine it
        let result = vault.quarantine(
            &file_path,
            "TestMalware",
            "trojan",
            75,
            true, // Delete original
        );

        assert!(result.success);
        assert!(!file_path.exists()); // Original deleted
        assert_eq!(vault.count().unwrap(), 1);

        // Restore it
        let restore_result = vault.restore(&result.id);
        assert!(restore_result.success);
        assert!(file_path.exists()); // Restored
        assert_eq!(fs::read(&file_path).unwrap(), content);
        assert_eq!(vault.count().unwrap(), 0);
    }

    #[test]
    fn test_quarantine_keep_original() {
        let temp_dir = TempDir::new().unwrap();
        let vault_dir = temp_dir.path().join("vault");
        let files_dir = temp_dir.path().join("files");
        fs::create_dir_all(&files_dir).unwrap();

        let vault = QuarantineVault::open(&vault_dir).unwrap();

        let content = b"Test content";
        let file_path = create_test_file(&files_dir, "test.exe", content);

        let result = vault.quarantine(
            &file_path,
            "TestVirus",
            "virus",
            50,
            false, // Keep original
        );

        assert!(result.success);
        assert!(file_path.exists()); // Original still exists
    }

    #[test]
    fn test_quarantine_duplicate() {
        let temp_dir = TempDir::new().unwrap();
        let vault_dir = temp_dir.path().join("vault");
        let files_dir = temp_dir.path().join("files");
        fs::create_dir_all(&files_dir).unwrap();

        let vault = QuarantineVault::open(&vault_dir).unwrap();

        let content = b"Duplicate content";
        let file1 = create_test_file(&files_dir, "file1.exe", content);
        let file2 = create_test_file(&files_dir, "file2.exe", content);

        // Quarantine first
        let result1 = vault.quarantine(&file1, "Test", "test", 50, false);
        assert!(result1.success);

        // Try to quarantine duplicate
        let result2 = vault.quarantine(&file2, "Test", "test", 50, false);
        assert!(!result2.success);
        assert!(result2.error.unwrap().contains("already quarantined"));
    }

    #[test]
    fn test_quarantine_nonexistent() {
        let temp_dir = TempDir::new().unwrap();
        let vault = QuarantineVault::open(temp_dir.path()).unwrap();

        let result = vault.quarantine(
            Path::new("/nonexistent/file.exe"),
            "Test",
            "test",
            50,
            false,
        );

        assert!(!result.success);
    }

    #[test]
    fn test_restore_to_different_path() {
        let temp_dir = TempDir::new().unwrap();
        let vault_dir = temp_dir.path().join("vault");
        let files_dir = temp_dir.path().join("files");
        let restore_dir = temp_dir.path().join("restored");
        fs::create_dir_all(&files_dir).unwrap();
        fs::create_dir_all(&restore_dir).unwrap();

        let vault = QuarantineVault::open(&vault_dir).unwrap();

        let content = b"Content to restore elsewhere";
        let file_path = create_test_file(&files_dir, "original.exe", content);

        let result = vault.quarantine(&file_path, "Test", "test", 50, true);
        assert!(result.success);

        let new_path = restore_dir.join("restored.exe");
        let restore_result = vault.restore_to(&result.id, Some(&new_path));

        assert!(restore_result.success);
        assert!(new_path.exists());
        assert!(!file_path.exists()); // Original was deleted during quarantine
        assert_eq!(fs::read(&new_path).unwrap(), content);
    }

    #[test]
    fn test_delete_quarantined() {
        let temp_dir = TempDir::new().unwrap();
        let vault_dir = temp_dir.path().join("vault");
        let files_dir = temp_dir.path().join("files");
        fs::create_dir_all(&files_dir).unwrap();

        let vault = QuarantineVault::open(&vault_dir).unwrap();

        let file_path = create_test_file(&files_dir, "delete_me.exe", b"Content");

        let result = vault.quarantine(&file_path, "Test", "test", 50, true);
        assert!(result.success);
        assert_eq!(vault.count().unwrap(), 1);

        // Delete from quarantine
        vault.delete(&result.id).unwrap();
        assert_eq!(vault.count().unwrap(), 0);

        // Vault file should be gone
        assert!(!result.vault_path.exists());
    }

    #[test]
    fn test_vault_stats() {
        let temp_dir = TempDir::new().unwrap();
        let vault_dir = temp_dir.path().join("vault");
        let files_dir = temp_dir.path().join("files");
        fs::create_dir_all(&files_dir).unwrap();

        let vault = QuarantineVault::open(&vault_dir).unwrap();

        create_test_file(&files_dir, "virus.exe", b"Virus content");
        create_test_file(&files_dir, "trojan.exe", b"Trojan content here");
        create_test_file(&files_dir, "pup.exe", b"PUP");

        vault.quarantine(
            &files_dir.join("virus.exe"),
            "Virus.Test",
            "virus",
            90,
            false,
        );
        vault.quarantine(
            &files_dir.join("trojan.exe"),
            "Trojan.Test",
            "trojan",
            80,
            false,
        );
        vault.quarantine(
            &files_dir.join("pup.exe"),
            "PUP.Test",
            "pup",
            30,
            false,
        );

        let stats = vault.stats().unwrap();
        assert_eq!(stats.total_count, 3);
        assert_eq!(*stats.categories.get("virus").unwrap_or(&0), 1);
        assert_eq!(*stats.categories.get("trojan").unwrap_or(&0), 1);
        assert_eq!(*stats.categories.get("pup").unwrap_or(&0), 1);
    }

    #[test]
    fn test_list_items() {
        let temp_dir = TempDir::new().unwrap();
        let vault_dir = temp_dir.path().join("vault");
        let files_dir = temp_dir.path().join("files");
        fs::create_dir_all(&files_dir).unwrap();

        let vault = QuarantineVault::open(&vault_dir).unwrap();

        create_test_file(&files_dir, "file1.exe", b"Content 1");
        create_test_file(&files_dir, "file2.exe", b"Content 2");

        vault.quarantine(&files_dir.join("file1.exe"), "Test1", "test", 50, false);
        vault.quarantine(&files_dir.join("file2.exe"), "Test2", "test", 60, false);

        let items = vault.list().unwrap();
        assert_eq!(items.len(), 2);
    }
}
