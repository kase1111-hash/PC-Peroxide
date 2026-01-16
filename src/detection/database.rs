//! SQLite signature database manager.

use crate::core::config::Config;
use crate::core::error::{Error, Result};
use crate::core::types::{Severity, ThreatCategory};
use crate::detection::signature::{
    DatabaseInfo, RemediationAction, Signature, SignatureFile, SignatureType,
};
use rusqlite::{params, Connection, OptionalExtension};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// SQL schema version for migrations.
const SCHEMA_VERSION: u32 = 1;

/// SQLite database manager for signatures.
pub struct SignatureDatabase {
    conn: Arc<Mutex<Connection>>,
    path: PathBuf,
}

impl SignatureDatabase {
    /// Open or create a signature database at the given path.
    pub fn open(path: &Path) -> Result<Self> {
        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                Error::Database(format!("Failed to create database directory: {}", e))
            })?;
        }

        let conn = Connection::open(path).map_err(|e| {
            Error::Database(format!("Failed to open database: {}", e))
        })?;

        let db = Self {
            conn: Arc::new(Mutex::new(conn)),
            path: path.to_path_buf(),
        };

        db.initialize_schema()?;
        Ok(db)
    }

    /// Open the default signature database.
    pub fn open_default() -> Result<Self> {
        let path = Config::data_dir().join("signatures.db");
        Self::open(&path)
    }

    /// Initialize database schema.
    fn initialize_schema(&self) -> Result<()> {
        let conn = self.conn.lock().map_err(|e| {
            Error::Database(format!("Failed to acquire database lock: {}", e))
        })?;

        // Create metadata table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )",
            [],
        )
        .map_err(|e| Error::Database(format!("Failed to create metadata table: {}", e)))?;

        // Check schema version
        let version: Option<u32> = conn
            .query_row(
                "SELECT value FROM metadata WHERE key = 'schema_version'",
                [],
                |row| row.get::<_, String>(0).map(|s| s.parse().unwrap_or(0)),
            )
            .optional()
            .map_err(|e| Error::Database(format!("Failed to query schema version: {}", e)))?;

        if version.unwrap_or(0) < SCHEMA_VERSION {
            self.migrate_schema(&conn, version.unwrap_or(0))?;
        }

        Ok(())
    }

    /// Migrate database schema.
    fn migrate_schema(&self, conn: &Connection, from_version: u32) -> Result<()> {
        log::info!(
            "Migrating database schema from version {} to {}",
            from_version,
            SCHEMA_VERSION
        );

        if from_version < 1 {
            // Initial schema creation
            conn.execute_batch(
                "
                -- Main signatures table
                CREATE TABLE IF NOT EXISTS signatures (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    sig_type TEXT NOT NULL,
                    hash_sha256 TEXT,
                    hash_md5 TEXT,
                    pattern TEXT,
                    pattern_offset TEXT,
                    severity TEXT NOT NULL,
                    category TEXT NOT NULL,
                    description TEXT,
                    remediation TEXT NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                -- Index for fast hash lookups
                CREATE INDEX IF NOT EXISTS idx_signatures_sha256
                    ON signatures(hash_sha256) WHERE hash_sha256 IS NOT NULL;

                CREATE INDEX IF NOT EXISTS idx_signatures_md5
                    ON signatures(hash_md5) WHERE hash_md5 IS NOT NULL;

                CREATE INDEX IF NOT EXISTS idx_signatures_type
                    ON signatures(sig_type);

                CREATE INDEX IF NOT EXISTS idx_signatures_enabled
                    ON signatures(enabled);

                -- Tags table for signature metadata
                CREATE TABLE IF NOT EXISTS signature_tags (
                    signature_id TEXT NOT NULL,
                    tag TEXT NOT NULL,
                    PRIMARY KEY (signature_id, tag),
                    FOREIGN KEY (signature_id) REFERENCES signatures(id) ON DELETE CASCADE
                );

                -- Version history table
                CREATE TABLE IF NOT EXISTS version_history (
                    version TEXT PRIMARY KEY,
                    imported_at TEXT NOT NULL,
                    signature_count INTEGER NOT NULL
                );
                ",
            )
            .map_err(|e| Error::Database(format!("Failed to create schema: {}", e)))?;
        }

        // Update schema version
        conn.execute(
            "INSERT OR REPLACE INTO metadata (key, value) VALUES ('schema_version', ?1)",
            params![SCHEMA_VERSION.to_string()],
        )
        .map_err(|e| Error::Database(format!("Failed to update schema version: {}", e)))?;

        Ok(())
    }

    /// Insert or update a signature.
    pub fn upsert_signature(&self, sig: &Signature) -> Result<()> {
        let conn = self.conn.lock().map_err(|e| {
            Error::Database(format!("Failed to acquire database lock: {}", e))
        })?;

        let now = chrono::Utc::now().to_rfc3339();

        conn.execute(
            "INSERT INTO signatures (
                id, name, sig_type, hash_sha256, hash_md5, pattern, pattern_offset,
                severity, category, description, remediation, enabled, created_at, updated_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?13)
            ON CONFLICT(id) DO UPDATE SET
                name = excluded.name,
                sig_type = excluded.sig_type,
                hash_sha256 = excluded.hash_sha256,
                hash_md5 = excluded.hash_md5,
                pattern = excluded.pattern,
                pattern_offset = excluded.pattern_offset,
                severity = excluded.severity,
                category = excluded.category,
                description = excluded.description,
                remediation = excluded.remediation,
                enabled = excluded.enabled,
                updated_at = excluded.updated_at",
            params![
                sig.id,
                sig.name,
                sig.sig_type.as_str(),
                sig.hash_sha256,
                sig.hash_md5,
                sig.pattern,
                sig.offset,
                sig.severity.as_str(),
                sig.category.as_str(),
                sig.description,
                sig.remediation.as_str(),
                sig.enabled as i32,
                now,
            ],
        )
        .map_err(|e| Error::Database(format!("Failed to upsert signature: {}", e)))?;

        // Update tags
        conn.execute(
            "DELETE FROM signature_tags WHERE signature_id = ?1",
            params![sig.id],
        )
        .map_err(|e| Error::Database(format!("Failed to clear signature tags: {}", e)))?;

        for tag in &sig.tags {
            conn.execute(
                "INSERT INTO signature_tags (signature_id, tag) VALUES (?1, ?2)",
                params![sig.id, tag],
            )
            .map_err(|e| Error::Database(format!("Failed to insert signature tag: {}", e)))?;
        }

        Ok(())
    }

    /// Get a signature by ID.
    pub fn get_signature(&self, id: &str) -> Result<Option<Signature>> {
        let conn = self.conn.lock().map_err(|e| {
            Error::Database(format!("Failed to acquire database lock: {}", e))
        })?;

        let sig = conn
            .query_row(
                "SELECT id, name, sig_type, hash_sha256, hash_md5, pattern, pattern_offset,
                        severity, category, description, remediation, enabled
                 FROM signatures WHERE id = ?1",
                params![id],
                |row| self.row_to_signature(row),
            )
            .optional()
            .map_err(|e| Error::Database(format!("Failed to query signature: {}", e)))?;

        if let Some(mut sig) = sig {
            // Load tags
            let mut stmt = conn
                .prepare("SELECT tag FROM signature_tags WHERE signature_id = ?1")
                .map_err(|e| Error::Database(format!("Failed to prepare tags query: {}", e)))?;

            let tags: Vec<String> = stmt
                .query_map(params![id], |row| row.get(0))
                .map_err(|e| Error::Database(format!("Failed to query tags: {}", e)))?
                .filter_map(|r| r.ok())
                .collect();

            sig.tags = tags;
            Ok(Some(sig))
        } else {
            Ok(None)
        }
    }

    /// Look up a signature by SHA256 hash.
    pub fn lookup_sha256(&self, hash: &str) -> Result<Option<Signature>> {
        let conn = self.conn.lock().map_err(|e| {
            Error::Database(format!("Failed to acquire database lock: {}", e))
        })?;

        let hash_lower = hash.to_lowercase();

        conn.query_row(
            "SELECT id, name, sig_type, hash_sha256, hash_md5, pattern, pattern_offset,
                    severity, category, description, remediation, enabled
             FROM signatures
             WHERE hash_sha256 = ?1 AND enabled = 1",
            params![hash_lower],
            |row| self.row_to_signature(row),
        )
        .optional()
        .map_err(|e| Error::Database(format!("Failed to lookup SHA256: {}", e)))
    }

    /// Look up a signature by MD5 hash.
    pub fn lookup_md5(&self, hash: &str) -> Result<Option<Signature>> {
        let conn = self.conn.lock().map_err(|e| {
            Error::Database(format!("Failed to acquire database lock: {}", e))
        })?;

        let hash_lower = hash.to_lowercase();

        conn.query_row(
            "SELECT id, name, sig_type, hash_sha256, hash_md5, pattern, pattern_offset,
                    severity, category, description, remediation, enabled
             FROM signatures
             WHERE hash_md5 = ?1 AND enabled = 1",
            params![hash_lower],
            |row| self.row_to_signature(row),
        )
        .optional()
        .map_err(|e| Error::Database(format!("Failed to lookup MD5: {}", e)))
    }

    /// Look up by either SHA256 or MD5.
    pub fn lookup_hash(&self, sha256: &str, md5: &str) -> Result<Option<Signature>> {
        // Try SHA256 first (preferred)
        if let Some(sig) = self.lookup_sha256(sha256)? {
            return Ok(Some(sig));
        }
        // Fall back to MD5
        self.lookup_md5(md5)
    }

    /// Get all pattern-based signatures.
    pub fn get_pattern_signatures(&self) -> Result<Vec<Signature>> {
        let conn = self.conn.lock().map_err(|e| {
            Error::Database(format!("Failed to acquire database lock: {}", e))
        })?;

        let mut stmt = conn
            .prepare(
                "SELECT id, name, sig_type, hash_sha256, hash_md5, pattern, pattern_offset,
                        severity, category, description, remediation, enabled
                 FROM signatures
                 WHERE sig_type = 'pattern' AND enabled = 1",
            )
            .map_err(|e| Error::Database(format!("Failed to prepare query: {}", e)))?;

        let sigs: Vec<Signature> = stmt
            .query_map([], |row| self.row_to_signature(row))
            .map_err(|e| Error::Database(format!("Failed to query patterns: {}", e)))?
            .filter_map(|r| r.ok())
            .collect();

        Ok(sigs)
    }

    /// Convert a database row to a Signature.
    fn row_to_signature(&self, row: &rusqlite::Row) -> rusqlite::Result<Signature> {
        let sig_type_str: String = row.get(2)?;
        let severity_str: String = row.get(7)?;
        let category_str: String = row.get(8)?;
        let remediation_str: String = row.get(10)?;

        Ok(Signature {
            id: row.get(0)?,
            name: row.get(1)?,
            sig_type: SignatureType::parse(&sig_type_str).unwrap_or(SignatureType::Hash),
            hash_sha256: row.get(3)?,
            hash_md5: row.get(4)?,
            pattern: row.get(5)?,
            offset: row.get(6)?,
            severity: Severity::parse(&severity_str).unwrap_or(Severity::Medium),
            category: ThreatCategory::parse(&category_str).unwrap_or(ThreatCategory::Unknown),
            description: row.get(9)?,
            remediation: RemediationAction::parse(&remediation_str)
                .unwrap_or(RemediationAction::Quarantine),
            enabled: row.get::<_, i32>(11)? != 0,
            tags: Vec::new(), // Loaded separately
        })
    }

    /// Import signatures from a SignatureFile.
    pub fn import(&self, file: &SignatureFile) -> Result<ImportResult> {
        let mut imported = 0;
        let mut skipped = 0;
        let mut errors = Vec::new();

        for sig in &file.signatures {
            match self.upsert_signature(sig) {
                Ok(()) => imported += 1,
                Err(e) => {
                    errors.push(format!("{}: {}", sig.id, e));
                    skipped += 1;
                }
            }
        }

        // Record version
        {
            let conn = self.conn.lock().map_err(|e| {
                Error::Database(format!("Failed to acquire database lock: {}", e))
            })?;

            conn.execute(
                "INSERT OR REPLACE INTO version_history (version, imported_at, signature_count)
                 VALUES (?1, ?2, ?3)",
                params![
                    file.version,
                    chrono::Utc::now().to_rfc3339(),
                    imported as i64
                ],
            )
            .map_err(|e| Error::Database(format!("Failed to record version: {}", e)))?;

            // Update current version in metadata
            conn.execute(
                "INSERT OR REPLACE INTO metadata (key, value) VALUES ('current_version', ?1)",
                params![file.version],
            )
            .map_err(|e| Error::Database(format!("Failed to update version: {}", e)))?;
        }

        Ok(ImportResult {
            imported,
            skipped,
            errors,
            version: file.version.clone(),
        })
    }

    /// Import signatures from a JSON file.
    pub fn import_file(&self, path: &Path) -> Result<ImportResult> {
        let file = SignatureFile::load(path)?;
        self.import(&file)
    }

    /// Get database information.
    pub fn info(&self) -> Result<DatabaseInfo> {
        let conn = self.conn.lock().map_err(|e| {
            Error::Database(format!("Failed to acquire database lock: {}", e))
        })?;

        let signature_count: u64 = conn
            .query_row("SELECT COUNT(*) FROM signatures", [], |row| row.get(0))
            .map_err(|e| Error::Database(format!("Failed to count signatures: {}", e)))?;

        let hash_count: u64 = conn
            .query_row(
                "SELECT COUNT(*) FROM signatures WHERE sig_type = 'hash'",
                [],
                |row| row.get(0),
            )
            .map_err(|e| Error::Database(format!("Failed to count hash signatures: {}", e)))?;

        let pattern_count: u64 = conn
            .query_row(
                "SELECT COUNT(*) FROM signatures WHERE sig_type = 'pattern'",
                [],
                |row| row.get(0),
            )
            .map_err(|e| Error::Database(format!("Failed to count pattern signatures: {}", e)))?;

        let version: String = conn
            .query_row(
                "SELECT value FROM metadata WHERE key = 'current_version'",
                [],
                |row| row.get(0),
            )
            .unwrap_or_else(|_| "0.0.0".to_string());

        let last_updated: Option<chrono::DateTime<chrono::Utc>> = conn
            .query_row(
                "SELECT imported_at FROM version_history ORDER BY imported_at DESC LIMIT 1",
                [],
                |row| {
                    let s: String = row.get(0)?;
                    Ok(chrono::DateTime::parse_from_rfc3339(&s)
                        .ok()
                        .map(|dt| dt.with_timezone(&chrono::Utc)))
                },
            )
            .unwrap_or(None);

        Ok(DatabaseInfo {
            version,
            signature_count,
            hash_count,
            pattern_count,
            last_updated,
            created_at: chrono::Utc::now(), // TODO: Store actual creation time
        })
    }

    /// Delete a signature by ID.
    pub fn delete_signature(&self, id: &str) -> Result<bool> {
        let conn = self.conn.lock().map_err(|e| {
            Error::Database(format!("Failed to acquire database lock: {}", e))
        })?;

        let affected = conn
            .execute("DELETE FROM signatures WHERE id = ?1", params![id])
            .map_err(|e| Error::Database(format!("Failed to delete signature: {}", e)))?;

        Ok(affected > 0)
    }

    /// Enable or disable a signature.
    pub fn set_enabled(&self, id: &str, enabled: bool) -> Result<bool> {
        let conn = self.conn.lock().map_err(|e| {
            Error::Database(format!("Failed to acquire database lock: {}", e))
        })?;

        let affected = conn
            .execute(
                "UPDATE signatures SET enabled = ?1, updated_at = ?2 WHERE id = ?3",
                params![enabled as i32, chrono::Utc::now().to_rfc3339(), id],
            )
            .map_err(|e| Error::Database(format!("Failed to update signature: {}", e)))?;

        Ok(affected > 0)
    }

    /// Clear all signatures from the database.
    pub fn clear(&self) -> Result<u64> {
        let conn = self.conn.lock().map_err(|e| {
            Error::Database(format!("Failed to acquire database lock: {}", e))
        })?;

        let count: u64 = conn
            .query_row("SELECT COUNT(*) FROM signatures", [], |row| row.get(0))
            .map_err(|e| Error::Database(format!("Failed to count signatures: {}", e)))?;

        conn.execute("DELETE FROM signatures", [])
            .map_err(|e| Error::Database(format!("Failed to clear signatures: {}", e)))?;

        conn.execute("DELETE FROM signature_tags", [])
            .map_err(|e| Error::Database(format!("Failed to clear tags: {}", e)))?;

        Ok(count)
    }

    /// Get the database file path.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Result of importing signatures.
#[derive(Debug)]
pub struct ImportResult {
    /// Number of signatures imported
    pub imported: usize,
    /// Number of signatures skipped
    pub skipped: usize,
    /// Error messages for skipped signatures
    pub errors: Vec<String>,
    /// Version imported
    pub version: String,
}

impl std::fmt::Display for ImportResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Imported {} signatures (skipped: {}) - version {}",
            self.imported, self.skipped, self.version
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn test_db() -> SignatureDatabase {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.db");
        // Keep dir alive by leaking it (for tests only)
        std::mem::forget(dir);
        SignatureDatabase::open(&path).unwrap()
    }

    #[test]
    fn test_database_creation() {
        let db = test_db();
        let info = db.info().unwrap();
        assert_eq!(info.signature_count, 0);
    }

    #[test]
    fn test_signature_crud() {
        let db = test_db();

        // Create
        let sig = Signature::new_hash(
            "TEST-001",
            "Test.Malware",
            "abc123def456",
            Severity::High,
            ThreatCategory::Trojan,
            "Test malware",
        );
        db.upsert_signature(&sig).unwrap();

        // Read
        let loaded = db.get_signature("TEST-001").unwrap().unwrap();
        assert_eq!(loaded.name, "Test.Malware");

        // Update
        let mut updated_sig = sig.clone();
        updated_sig.name = "Test.Malware.Updated".to_string();
        db.upsert_signature(&updated_sig).unwrap();

        let loaded = db.get_signature("TEST-001").unwrap().unwrap();
        assert_eq!(loaded.name, "Test.Malware.Updated");

        // Delete
        assert!(db.delete_signature("TEST-001").unwrap());
        assert!(db.get_signature("TEST-001").unwrap().is_none());
    }

    #[test]
    fn test_hash_lookup() {
        let db = test_db();

        let sig = Signature::new_hash(
            "HASH-001",
            "Hash.Test",
            "deadbeef1234",
            Severity::Critical,
            ThreatCategory::Ransomware,
            "Test hash signature",
        );
        db.upsert_signature(&sig).unwrap();

        // Lookup should work (case insensitive)
        let found = db.lookup_sha256("DEADBEEF1234").unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().id, "HASH-001");

        // Non-existent hash
        let not_found = db.lookup_sha256("notexist").unwrap();
        assert!(not_found.is_none());
    }

    #[test]
    fn test_import() {
        let db = test_db();

        let mut file = SignatureFile::new("2025.01.15");
        file.add(Signature::new_hash(
            "IMP-001",
            "Import.Test1",
            "hash1",
            Severity::Low,
            ThreatCategory::Adware,
            "Test 1",
        ));
        file.add(Signature::new_hash(
            "IMP-002",
            "Import.Test2",
            "hash2",
            Severity::Medium,
            ThreatCategory::Spyware,
            "Test 2",
        ));

        let result = db.import(&file).unwrap();
        assert_eq!(result.imported, 2);
        assert_eq!(result.skipped, 0);

        let info = db.info().unwrap();
        assert_eq!(info.signature_count, 2);
        assert_eq!(info.version, "2025.01.15");
    }
}
