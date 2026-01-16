//! Quarantine metadata database using SQLite.
//!
//! Tracks all quarantined items with their original paths, detection info,
//! timestamps, and vault file locations.

use chrono::{DateTime, Utc};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::core::error::{Error, Result};

/// Metadata for a quarantined item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineItem {
    /// Unique identifier (UUID)
    pub id: String,
    /// Original file path
    pub original_path: PathBuf,
    /// Filename of the vault file (without path)
    pub vault_filename: String,
    /// SHA-256 hash of the original file
    pub hash_sha256: String,
    /// Original file size in bytes
    pub original_size: u64,
    /// Detection reason/threat name
    pub detection_name: String,
    /// Detection category (virus, trojan, pup, etc.)
    pub category: String,
    /// Severity score (0-100)
    pub severity: u8,
    /// When the file was quarantined
    pub quarantine_time: DateTime<Utc>,
    /// Whether the item can be restored
    pub restorable: bool,
    /// Additional notes
    pub notes: Option<String>,
}

impl QuarantineItem {
    /// Create a new quarantine item.
    pub fn new(
        id: String,
        original_path: PathBuf,
        vault_filename: String,
        hash_sha256: String,
        original_size: u64,
        detection_name: String,
        category: String,
        severity: u8,
    ) -> Self {
        Self {
            id,
            original_path,
            vault_filename,
            hash_sha256,
            original_size,
            detection_name,
            category,
            severity,
            quarantine_time: Utc::now(),
            restorable: true,
            notes: None,
        }
    }

    /// Set notes for the item.
    pub fn with_notes(mut self, notes: String) -> Self {
        self.notes = Some(notes);
        self
    }

    /// Mark the item as non-restorable.
    pub fn non_restorable(mut self) -> Self {
        self.restorable = false;
        self
    }
}

/// Quarantine metadata database manager.
pub struct QuarantineMetadata {
    conn: Connection,
}

impl QuarantineMetadata {
    /// Create or open the quarantine metadata database.
    pub fn open(db_path: &Path) -> Result<Self> {
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| Error::DirectoryAccess {
                path: parent.to_path_buf(),
                source: e,
            })?;
        }

        let conn = Connection::open(db_path)?;
        let metadata = Self { conn };
        metadata.initialize()?;
        Ok(metadata)
    }

    /// Create an in-memory database (for testing).
    #[cfg(test)]
    pub fn in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        let metadata = Self { conn };
        metadata.initialize()?;
        Ok(metadata)
    }

    /// Initialize the database schema.
    fn initialize(&self) -> Result<()> {
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS quarantine_items (
                id TEXT PRIMARY KEY,
                original_path TEXT NOT NULL,
                vault_filename TEXT NOT NULL,
                hash_sha256 TEXT NOT NULL,
                original_size INTEGER NOT NULL,
                detection_name TEXT NOT NULL,
                category TEXT NOT NULL,
                severity INTEGER NOT NULL,
                quarantine_time TEXT NOT NULL,
                restorable INTEGER NOT NULL DEFAULT 1,
                notes TEXT
            )",
            [],
        )?;

        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_quarantine_hash ON quarantine_items(hash_sha256)",
            [],
        )?;

        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_quarantine_time ON quarantine_items(quarantine_time)",
            [],
        )?;

        Ok(())
    }

    /// Add a new quarantined item to the database.
    pub fn add(&self, item: &QuarantineItem) -> Result<()> {
        self.conn.execute(
            "INSERT INTO quarantine_items
             (id, original_path, vault_filename, hash_sha256, original_size,
              detection_name, category, severity, quarantine_time, restorable, notes)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                item.id,
                item.original_path.to_string_lossy(),
                item.vault_filename,
                item.hash_sha256,
                item.original_size as i64,
                item.detection_name,
                item.category,
                item.severity,
                item.quarantine_time.to_rfc3339(),
                item.restorable as i32,
                item.notes,
            ],
        )?;
        Ok(())
    }

    /// Get a quarantine item by ID.
    pub fn get(&self, id: &str) -> Result<Option<QuarantineItem>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, original_path, vault_filename, hash_sha256, original_size,
                    detection_name, category, severity, quarantine_time, restorable, notes
             FROM quarantine_items WHERE id = ?1",
        )?;

        let result = stmt.query_row([id], |row| {
            Ok(QuarantineItem {
                id: row.get(0)?,
                original_path: PathBuf::from(row.get::<_, String>(1)?),
                vault_filename: row.get(2)?,
                hash_sha256: row.get(3)?,
                original_size: row.get::<_, i64>(4)? as u64,
                detection_name: row.get(5)?,
                category: row.get(6)?,
                severity: row.get::<_, i32>(7)? as u8,
                quarantine_time: DateTime::parse_from_rfc3339(&row.get::<_, String>(8)?)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
                restorable: row.get::<_, i32>(9)? != 0,
                notes: row.get(10)?,
            })
        });

        match result {
            Ok(item) => Ok(Some(item)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Get a quarantine item by hash.
    pub fn get_by_hash(&self, hash: &str) -> Result<Option<QuarantineItem>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, original_path, vault_filename, hash_sha256, original_size,
                    detection_name, category, severity, quarantine_time, restorable, notes
             FROM quarantine_items WHERE hash_sha256 = ?1 LIMIT 1",
        )?;

        let result = stmt.query_row([hash], |row| {
            Ok(QuarantineItem {
                id: row.get(0)?,
                original_path: PathBuf::from(row.get::<_, String>(1)?),
                vault_filename: row.get(2)?,
                hash_sha256: row.get(3)?,
                original_size: row.get::<_, i64>(4)? as u64,
                detection_name: row.get(5)?,
                category: row.get(6)?,
                severity: row.get::<_, i32>(7)? as u8,
                quarantine_time: DateTime::parse_from_rfc3339(&row.get::<_, String>(8)?)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
                restorable: row.get::<_, i32>(9)? != 0,
                notes: row.get(10)?,
            })
        });

        match result {
            Ok(item) => Ok(Some(item)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// List all quarantined items.
    pub fn list(&self) -> Result<Vec<QuarantineItem>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, original_path, vault_filename, hash_sha256, original_size,
                    detection_name, category, severity, quarantine_time, restorable, notes
             FROM quarantine_items ORDER BY quarantine_time DESC",
        )?;

        let items = stmt
            .query_map([], |row| {
                Ok(QuarantineItem {
                    id: row.get(0)?,
                    original_path: PathBuf::from(row.get::<_, String>(1)?),
                    vault_filename: row.get(2)?,
                    hash_sha256: row.get(3)?,
                    original_size: row.get::<_, i64>(4)? as u64,
                    detection_name: row.get(5)?,
                    category: row.get(6)?,
                    severity: row.get::<_, i32>(7)? as u8,
                    quarantine_time: DateTime::parse_from_rfc3339(&row.get::<_, String>(8)?)
                        .map(|dt| dt.with_timezone(&Utc))
                        .unwrap_or_else(|_| Utc::now()),
                    restorable: row.get::<_, i32>(9)? != 0,
                    notes: row.get(10)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;

        Ok(items)
    }

    /// List items by category.
    pub fn list_by_category(&self, category: &str) -> Result<Vec<QuarantineItem>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, original_path, vault_filename, hash_sha256, original_size,
                    detection_name, category, severity, quarantine_time, restorable, notes
             FROM quarantine_items WHERE category = ?1 ORDER BY quarantine_time DESC",
        )?;

        let items = stmt
            .query_map([category], |row| {
                Ok(QuarantineItem {
                    id: row.get(0)?,
                    original_path: PathBuf::from(row.get::<_, String>(1)?),
                    vault_filename: row.get(2)?,
                    hash_sha256: row.get(3)?,
                    original_size: row.get::<_, i64>(4)? as u64,
                    detection_name: row.get(5)?,
                    category: row.get(6)?,
                    severity: row.get::<_, i32>(7)? as u8,
                    quarantine_time: DateTime::parse_from_rfc3339(&row.get::<_, String>(8)?)
                        .map(|dt| dt.with_timezone(&Utc))
                        .unwrap_or_else(|_| Utc::now()),
                    restorable: row.get::<_, i32>(9)? != 0,
                    notes: row.get(10)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;

        Ok(items)
    }

    /// Mark an item as restored (removed from quarantine).
    pub fn remove(&self, id: &str) -> Result<bool> {
        let rows = self.conn.execute(
            "DELETE FROM quarantine_items WHERE id = ?1",
            [id],
        )?;
        Ok(rows > 0)
    }

    /// Update item notes.
    pub fn update_notes(&self, id: &str, notes: Option<&str>) -> Result<bool> {
        let rows = self.conn.execute(
            "UPDATE quarantine_items SET notes = ?1 WHERE id = ?2",
            params![notes, id],
        )?;
        Ok(rows > 0)
    }

    /// Mark an item as non-restorable (e.g., after deletion).
    pub fn mark_deleted(&self, id: &str) -> Result<bool> {
        let rows = self.conn.execute(
            "UPDATE quarantine_items SET restorable = 0 WHERE id = ?1",
            [id],
        )?;
        Ok(rows > 0)
    }

    /// Get count of quarantined items.
    pub fn count(&self) -> Result<usize> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM quarantine_items",
            [],
            |row| row.get(0),
        )?;
        Ok(count as usize)
    }

    /// Get total size of quarantined items.
    pub fn total_size(&self) -> Result<u64> {
        let size: i64 = self.conn.query_row(
            "SELECT COALESCE(SUM(original_size), 0) FROM quarantine_items",
            [],
            |row| row.get(0),
        )?;
        Ok(size as u64)
    }

    /// Check if a file hash already exists in quarantine.
    pub fn exists_by_hash(&self, hash: &str) -> Result<bool> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM quarantine_items WHERE hash_sha256 = ?1",
            [hash],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_item(id: &str) -> QuarantineItem {
        QuarantineItem::new(
            id.to_string(),
            PathBuf::from("/test/path/malware.exe"),
            format!("{}.qvault", id),
            "a".repeat(64),
            1024,
            "Trojan.Generic".to_string(),
            "trojan".to_string(),
            80,
        )
    }

    #[test]
    fn test_open_in_memory() {
        let metadata = QuarantineMetadata::in_memory().unwrap();
        assert_eq!(metadata.count().unwrap(), 0);
    }

    #[test]
    fn test_add_and_get() {
        let metadata = QuarantineMetadata::in_memory().unwrap();
        let item = create_test_item("test-id-1");

        metadata.add(&item).unwrap();
        assert_eq!(metadata.count().unwrap(), 1);

        let retrieved = metadata.get("test-id-1").unwrap().unwrap();
        assert_eq!(retrieved.id, "test-id-1");
        assert_eq!(retrieved.detection_name, "Trojan.Generic");
        assert_eq!(retrieved.severity, 80);
    }

    #[test]
    fn test_get_nonexistent() {
        let metadata = QuarantineMetadata::in_memory().unwrap();
        let result = metadata.get("nonexistent").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_get_by_hash() {
        let metadata = QuarantineMetadata::in_memory().unwrap();
        let item = create_test_item("test-hash-1");
        let hash = item.hash_sha256.clone();

        metadata.add(&item).unwrap();

        let retrieved = metadata.get_by_hash(&hash).unwrap().unwrap();
        assert_eq!(retrieved.id, "test-hash-1");
    }

    #[test]
    fn test_list() {
        let metadata = QuarantineMetadata::in_memory().unwrap();

        metadata.add(&create_test_item("id-1")).unwrap();
        metadata.add(&create_test_item("id-2")).unwrap();
        metadata.add(&create_test_item("id-3")).unwrap();

        let items = metadata.list().unwrap();
        assert_eq!(items.len(), 3);
    }

    #[test]
    fn test_list_by_category() {
        let metadata = QuarantineMetadata::in_memory().unwrap();

        let mut item1 = create_test_item("cat-1");
        item1.category = "virus".to_string();
        metadata.add(&item1).unwrap();

        let mut item2 = create_test_item("cat-2");
        item2.category = "trojan".to_string();
        metadata.add(&item2).unwrap();

        let mut item3 = create_test_item("cat-3");
        item3.category = "virus".to_string();
        metadata.add(&item3).unwrap();

        let viruses = metadata.list_by_category("virus").unwrap();
        assert_eq!(viruses.len(), 2);

        let trojans = metadata.list_by_category("trojan").unwrap();
        assert_eq!(trojans.len(), 1);
    }

    #[test]
    fn test_remove() {
        let metadata = QuarantineMetadata::in_memory().unwrap();
        metadata.add(&create_test_item("remove-me")).unwrap();
        assert_eq!(metadata.count().unwrap(), 1);

        let removed = metadata.remove("remove-me").unwrap();
        assert!(removed);
        assert_eq!(metadata.count().unwrap(), 0);
    }

    #[test]
    fn test_remove_nonexistent() {
        let metadata = QuarantineMetadata::in_memory().unwrap();
        let removed = metadata.remove("nonexistent").unwrap();
        assert!(!removed);
    }

    #[test]
    fn test_update_notes() {
        let metadata = QuarantineMetadata::in_memory().unwrap();
        metadata.add(&create_test_item("notes-test")).unwrap();

        metadata.update_notes("notes-test", Some("Updated notes")).unwrap();

        let item = metadata.get("notes-test").unwrap().unwrap();
        assert_eq!(item.notes, Some("Updated notes".to_string()));
    }

    #[test]
    fn test_mark_deleted() {
        let metadata = QuarantineMetadata::in_memory().unwrap();
        let item = create_test_item("delete-test");
        metadata.add(&item).unwrap();

        let marked = metadata.mark_deleted("delete-test").unwrap();
        assert!(marked);

        let retrieved = metadata.get("delete-test").unwrap().unwrap();
        assert!(!retrieved.restorable);
    }

    #[test]
    fn test_total_size() {
        let metadata = QuarantineMetadata::in_memory().unwrap();

        let mut item1 = create_test_item("size-1");
        item1.original_size = 1000;
        metadata.add(&item1).unwrap();

        let mut item2 = create_test_item("size-2");
        item2.original_size = 2500;
        metadata.add(&item2).unwrap();

        assert_eq!(metadata.total_size().unwrap(), 3500);
    }

    #[test]
    fn test_exists_by_hash() {
        let metadata = QuarantineMetadata::in_memory().unwrap();
        let item = create_test_item("hash-exists");
        let hash = item.hash_sha256.clone();

        assert!(!metadata.exists_by_hash(&hash).unwrap());

        metadata.add(&item).unwrap();

        assert!(metadata.exists_by_hash(&hash).unwrap());
    }

    #[test]
    fn test_item_with_notes() {
        let item = create_test_item("with-notes").with_notes("Test notes".to_string());
        assert_eq!(item.notes, Some("Test notes".to_string()));
    }

    #[test]
    fn test_item_non_restorable() {
        let item = create_test_item("non-restorable").non_restorable();
        assert!(!item.restorable);
    }
}
