//! Whitelist management for false positive handling.
//!
//! Allows users to exclude files from detection based on:
//! - File hash (SHA-256)
//! - File path patterns
//! - Detection name patterns

use chrono::{DateTime, Utc};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::core::error::{Error, Result};
use crate::core::types::Detection;
use crate::utils::hash::HashCalculator;

/// Type of whitelist entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WhitelistType {
    /// Whitelist by SHA-256 hash
    Hash,
    /// Whitelist by file path pattern (glob)
    Path,
    /// Whitelist by detection name pattern
    Detection,
}

impl WhitelistType {
    /// Convert to database string.
    fn to_db(self) -> &'static str {
        match self {
            Self::Hash => "hash",
            Self::Path => "path",
            Self::Detection => "detection",
        }
    }

    /// Parse from database string.
    fn from_db(s: &str) -> Option<Self> {
        match s {
            "hash" => Some(Self::Hash),
            "path" => Some(Self::Path),
            "detection" => Some(Self::Detection),
            _ => None,
        }
    }
}

/// A whitelist entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhitelistEntry {
    /// Unique identifier
    pub id: String,
    /// Type of whitelist
    pub whitelist_type: WhitelistType,
    /// The pattern or hash to match
    pub pattern: String,
    /// User-provided reason for whitelisting
    pub reason: String,
    /// When the entry was created
    pub created_at: DateTime<Utc>,
    /// Whether the entry is active
    pub active: bool,
}

impl WhitelistEntry {
    /// Create a new whitelist entry.
    pub fn new(id: String, whitelist_type: WhitelistType, pattern: String, reason: String) -> Self {
        Self {
            id,
            whitelist_type,
            pattern,
            reason,
            created_at: Utc::now(),
            active: true,
        }
    }

    /// Create a hash-based whitelist entry.
    pub fn by_hash(id: String, hash: String, reason: String) -> Self {
        Self::new(id, WhitelistType::Hash, hash, reason)
    }

    /// Create a path-based whitelist entry.
    pub fn by_path(id: String, path_pattern: String, reason: String) -> Self {
        Self::new(id, WhitelistType::Path, path_pattern, reason)
    }

    /// Create a detection-based whitelist entry.
    pub fn by_detection(id: String, detection_pattern: String, reason: String) -> Self {
        Self::new(id, WhitelistType::Detection, detection_pattern, reason)
    }
}

/// Whitelist manager.
pub struct WhitelistManager {
    conn: Connection,
}

impl WhitelistManager {
    /// Default location of the whitelist database.
    pub fn default_path() -> PathBuf {
        super::get_quarantine_path().join("whitelist.db")
    }

    /// Open or create the whitelist database.
    pub fn open(db_path: &Path) -> Result<Self> {
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| Error::DirectoryAccess {
                path: parent.to_path_buf(),
                source: e,
            })?;
        }

        let conn = Connection::open(db_path)?;
        let manager = Self { conn };
        manager.initialize()?;
        Ok(manager)
    }

    /// Open the whitelist to change it. SQLite quietly opens a file it cannot
    /// write read-only, which is fine for checking entries (scans, listing)
    /// but would only fail on the first change; refuse it up front instead.
    pub fn open_writable(db_path: &Path) -> Result<Self> {
        let manager = Self::open(db_path)?;
        if manager.conn.is_readonly(rusqlite::DatabaseName::Main)? {
            return Err(Error::DatabaseReadOnly {
                path: db_path.to_path_buf(),
            });
        }
        Ok(manager)
    }

    /// Create an in-memory database (for testing).
    #[cfg(test)]
    pub fn in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        let manager = Self { conn };
        manager.initialize()?;
        Ok(manager)
    }

    /// Initialize the database schema.
    fn initialize(&self) -> Result<()> {
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS whitelist (
                id TEXT PRIMARY KEY,
                whitelist_type TEXT NOT NULL,
                pattern TEXT NOT NULL,
                reason TEXT NOT NULL,
                created_at TEXT NOT NULL,
                active INTEGER NOT NULL DEFAULT 1
            )",
            [],
        )?;

        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_whitelist_type ON whitelist(whitelist_type)",
            [],
        )?;

        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_whitelist_pattern ON whitelist(pattern)",
            [],
        )?;

        Ok(())
    }

    /// Add a new whitelist entry.
    pub fn add(&self, entry: &WhitelistEntry) -> Result<()> {
        self.conn.execute(
            "INSERT INTO whitelist (id, whitelist_type, pattern, reason, created_at, active)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                entry.id,
                entry.whitelist_type.to_db(),
                entry.pattern,
                entry.reason,
                entry.created_at.to_rfc3339(),
                entry.active as i32,
            ],
        )?;
        Ok(())
    }

    /// Get a whitelist entry by ID.
    pub fn get(&self, id: &str) -> Result<Option<WhitelistEntry>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, whitelist_type, pattern, reason, created_at, active
             FROM whitelist WHERE id = ?1",
        )?;

        let result = stmt.query_row([id], |row| {
            let type_str: String = row.get(1)?;
            Ok(WhitelistEntry {
                id: row.get(0)?,
                whitelist_type: WhitelistType::from_db(&type_str).unwrap_or_else(|| {
                    log::warn!("Unknown whitelist type '{}', skipping entry", type_str);
                    WhitelistType::Hash
                }),
                pattern: row.get(2)?,
                reason: row.get(3)?,
                created_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(4)?)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
                active: row.get::<_, i32>(5)? != 0,
            })
        });

        match result {
            Ok(entry) => Ok(Some(entry)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// List all whitelist entries.
    pub fn list(&self) -> Result<Vec<WhitelistEntry>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, whitelist_type, pattern, reason, created_at, active
             FROM whitelist ORDER BY created_at DESC",
        )?;

        let entries = stmt
            .query_map([], |row| {
                let type_str: String = row.get(1)?;
                Ok(WhitelistEntry {
                    id: row.get(0)?,
                    whitelist_type: WhitelistType::from_db(&type_str)
                        .unwrap_or(WhitelistType::Hash),
                    pattern: row.get(2)?,
                    reason: row.get(3)?,
                    created_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(4)?)
                        .map(|dt| dt.with_timezone(&Utc))
                        .unwrap_or_else(|_| Utc::now()),
                    active: row.get::<_, i32>(5)? != 0,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;

        Ok(entries)
    }

    /// List active whitelist entries of a specific type.
    pub fn list_by_type(&self, whitelist_type: WhitelistType) -> Result<Vec<WhitelistEntry>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, whitelist_type, pattern, reason, created_at, active
             FROM whitelist WHERE whitelist_type = ?1 AND active = 1
             ORDER BY created_at DESC",
        )?;

        let entries = stmt
            .query_map([whitelist_type.to_db()], |row| {
                let type_str: String = row.get(1)?;
                Ok(WhitelistEntry {
                    id: row.get(0)?,
                    whitelist_type: WhitelistType::from_db(&type_str)
                        .unwrap_or(WhitelistType::Hash),
                    pattern: row.get(2)?,
                    reason: row.get(3)?,
                    created_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(4)?)
                        .map(|dt| dt.with_timezone(&Utc))
                        .unwrap_or_else(|_| Utc::now()),
                    active: row.get::<_, i32>(5)? != 0,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;

        Ok(entries)
    }

    /// Remove a whitelist entry.
    pub fn remove(&self, id: &str) -> Result<bool> {
        let rows = self
            .conn
            .execute("DELETE FROM whitelist WHERE id = ?1", [id])?;
        Ok(rows > 0)
    }

    /// Disable a whitelist entry (soft delete).
    pub fn disable(&self, id: &str) -> Result<bool> {
        let rows = self
            .conn
            .execute("UPDATE whitelist SET active = 0 WHERE id = ?1", [id])?;
        Ok(rows > 0)
    }

    /// Enable a whitelist entry.
    pub fn enable(&self, id: &str) -> Result<bool> {
        let rows = self
            .conn
            .execute("UPDATE whitelist SET active = 1 WHERE id = ?1", [id])?;
        Ok(rows > 0)
    }

    /// Check if a hash is whitelisted (case-insensitive).
    pub fn is_hash_whitelisted(&self, hash: &str) -> Result<bool> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM whitelist
             WHERE whitelist_type = 'hash' AND lower(pattern) = lower(?1) AND active = 1",
            [hash],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    /// Check if a path matches any path whitelist patterns.
    pub fn is_path_whitelisted(&self, path: &Path) -> Result<bool> {
        let path_str = path.to_string_lossy().to_string();

        // Get all active path patterns
        let patterns = self.list_by_type(WhitelistType::Path)?;

        for entry in patterns {
            if Self::matches_glob(&entry.pattern, &path_str) {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Check if a detection name matches any detection whitelist patterns.
    pub fn is_detection_whitelisted(&self, detection_name: &str) -> Result<bool> {
        let patterns = self.list_by_type(WhitelistType::Detection)?;

        for entry in patterns {
            if Self::matches_pattern(&entry.pattern, detection_name) {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Check if any active entry suppresses a detection.
    ///
    /// Hash entries are compared against the detection's hash (for an archive,
    /// the hash of the matching member) and against the hash of the file itself.
    pub fn is_whitelisted(&self, detection: &Detection) -> Result<bool> {
        if self.is_path_whitelisted(&detection.path)?
            || self.is_detection_whitelisted(&detection.threat_name)?
        {
            return Ok(true);
        }

        if let Some(ref hash) = detection.sha256 {
            if self.is_hash_whitelisted(hash)? {
                return Ok(true);
            }
        }

        if self.list_by_type(WhitelistType::Hash)?.is_empty() {
            return Ok(false);
        }
        match HashCalculator::sha256_file(&detection.path) {
            Ok(hash) => self.is_hash_whitelisted(&hash),
            Err(_) => Ok(false),
        }
    }

    /// Simple glob matching (* and ?).
    fn matches_glob(pattern: &str, text: &str) -> bool {
        let pattern_lower = pattern.to_lowercase();
        let text_lower = text.to_lowercase();
        Self::glob_match(&pattern_lower, &text_lower)
    }

    /// Iterative glob matching implementation using two-pointer / DP approach.
    /// Avoids exponential backtracking from recursive wildcard expansion.
    fn glob_match(pattern: &str, text: &str) -> bool {
        let p: Vec<char> = pattern.chars().collect();
        let t: Vec<char> = text.chars().collect();
        let (plen, tlen) = (p.len(), t.len());

        let mut pi = 0; // pattern index
        let mut ti = 0; // text index
        let mut star_pi: Option<usize> = None; // position of last '*' in pattern
        let mut star_ti = 0; // text position when last '*' was encountered

        while ti < tlen {
            if pi < plen && (p[pi] == '?' || p[pi] == t[ti]) {
                // Exact match or single-char wildcard
                pi += 1;
                ti += 1;
            } else if pi < plen && p[pi] == '*' {
                // Record star position and try matching zero chars first
                star_pi = Some(pi);
                star_ti = ti;
                pi += 1;
            } else if let Some(sp) = star_pi {
                // Backtrack: let the last '*' match one more character
                star_ti += 1;
                ti = star_ti;
                pi = sp + 1;
            } else {
                return false;
            }
        }

        // Consume trailing '*' in pattern
        while pi < plen && p[pi] == '*' {
            pi += 1;
        }

        pi == plen
    }

    /// Simple wildcard pattern matching.
    fn matches_pattern(pattern: &str, text: &str) -> bool {
        Self::matches_glob(pattern, text)
    }

    /// Get count of whitelist entries.
    pub fn count(&self) -> Result<usize> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM whitelist", [], |row| row.get(0))?;
        Ok(count as usize)
    }

    /// Get count of active whitelist entries.
    pub fn count_active(&self) -> Result<usize> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM whitelist WHERE active = 1",
            [],
            |row| row.get(0),
        )?;
        Ok(count as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_entry() {
        let entry = WhitelistEntry::by_hash(
            "test-id".to_string(),
            "abc123".to_string(),
            "False positive".to_string(),
        );

        assert_eq!(entry.id, "test-id");
        assert_eq!(entry.whitelist_type, WhitelistType::Hash);
        assert_eq!(entry.pattern, "abc123");
        assert!(entry.active);
    }

    #[test]
    fn test_add_and_get() {
        let manager = WhitelistManager::in_memory().unwrap();
        let entry = WhitelistEntry::by_hash(
            "hash-1".to_string(),
            "deadbeef".to_string(),
            "Test reason".to_string(),
        );

        manager.add(&entry).unwrap();

        let retrieved = manager.get("hash-1").unwrap().unwrap();
        assert_eq!(retrieved.pattern, "deadbeef");
        assert_eq!(retrieved.reason, "Test reason");
    }

    #[test]
    fn test_list() {
        let manager = WhitelistManager::in_memory().unwrap();

        manager
            .add(&WhitelistEntry::by_hash(
                "1".to_string(),
                "hash1".to_string(),
                "".to_string(),
            ))
            .unwrap();
        manager
            .add(&WhitelistEntry::by_path(
                "2".to_string(),
                "*.tmp".to_string(),
                "".to_string(),
            ))
            .unwrap();
        manager
            .add(&WhitelistEntry::by_detection(
                "3".to_string(),
                "PUP.*".to_string(),
                "".to_string(),
            ))
            .unwrap();

        let entries = manager.list().unwrap();
        assert_eq!(entries.len(), 3);
    }

    #[test]
    fn test_list_by_type() {
        let manager = WhitelistManager::in_memory().unwrap();

        manager
            .add(&WhitelistEntry::by_hash(
                "1".to_string(),
                "hash1".to_string(),
                "".to_string(),
            ))
            .unwrap();
        manager
            .add(&WhitelistEntry::by_hash(
                "2".to_string(),
                "hash2".to_string(),
                "".to_string(),
            ))
            .unwrap();
        manager
            .add(&WhitelistEntry::by_path(
                "3".to_string(),
                "*.tmp".to_string(),
                "".to_string(),
            ))
            .unwrap();

        let hashes = manager.list_by_type(WhitelistType::Hash).unwrap();
        assert_eq!(hashes.len(), 2);

        let paths = manager.list_by_type(WhitelistType::Path).unwrap();
        assert_eq!(paths.len(), 1);
    }

    #[test]
    fn test_remove() {
        let manager = WhitelistManager::in_memory().unwrap();

        manager
            .add(&WhitelistEntry::by_hash(
                "remove-me".to_string(),
                "hash".to_string(),
                "".to_string(),
            ))
            .unwrap();

        assert_eq!(manager.count().unwrap(), 1);
        manager.remove("remove-me").unwrap();
        assert_eq!(manager.count().unwrap(), 0);
    }

    #[test]
    fn test_disable_enable() {
        let manager = WhitelistManager::in_memory().unwrap();

        manager
            .add(&WhitelistEntry::by_hash(
                "toggle".to_string(),
                "hash".to_string(),
                "".to_string(),
            ))
            .unwrap();

        assert!(manager.is_hash_whitelisted("hash").unwrap());

        manager.disable("toggle").unwrap();
        assert!(!manager.is_hash_whitelisted("hash").unwrap());

        manager.enable("toggle").unwrap();
        assert!(manager.is_hash_whitelisted("hash").unwrap());
    }

    #[test]
    fn test_is_hash_whitelisted() {
        let manager = WhitelistManager::in_memory().unwrap();

        manager
            .add(&WhitelistEntry::by_hash(
                "1".to_string(),
                "whitelisted_hash".to_string(),
                "".to_string(),
            ))
            .unwrap();

        assert!(manager.is_hash_whitelisted("whitelisted_hash").unwrap());
        assert!(!manager.is_hash_whitelisted("other_hash").unwrap());
    }

    #[test]
    fn test_is_path_whitelisted() {
        let manager = WhitelistManager::in_memory().unwrap();

        manager
            .add(&WhitelistEntry::by_path(
                "1".to_string(),
                "*.tmp".to_string(),
                "".to_string(),
            ))
            .unwrap();
        manager
            .add(&WhitelistEntry::by_path(
                "2".to_string(),
                "/safe/dir/*".to_string(),
                "".to_string(),
            ))
            .unwrap();

        assert!(manager.is_path_whitelisted(Path::new("test.tmp")).unwrap());
        assert!(manager
            .is_path_whitelisted(Path::new("/safe/dir/file.exe"))
            .unwrap());
        assert!(!manager
            .is_path_whitelisted(Path::new("malware.exe"))
            .unwrap());
    }

    #[test]
    fn test_is_detection_whitelisted() {
        let manager = WhitelistManager::in_memory().unwrap();

        manager
            .add(&WhitelistEntry::by_detection(
                "1".to_string(),
                "PUP.*".to_string(),
                "".to_string(),
            ))
            .unwrap();
        manager
            .add(&WhitelistEntry::by_detection(
                "2".to_string(),
                "Adware.Generic".to_string(),
                "".to_string(),
            ))
            .unwrap();

        assert!(manager.is_detection_whitelisted("PUP.Generic").unwrap());
        assert!(manager.is_detection_whitelisted("PUP.Toolbar").unwrap());
        assert!(manager.is_detection_whitelisted("Adware.Generic").unwrap());
        assert!(!manager.is_detection_whitelisted("Trojan.Generic").unwrap());
    }

    #[test]
    fn test_glob_matching() {
        // Exact match (case-insensitive)
        assert!(WhitelistManager::matches_glob("test", "test"));
        assert!(WhitelistManager::matches_glob("test", "TEST")); // Case-insensitive matching

        // Wildcard *
        assert!(WhitelistManager::matches_glob("*.exe", "malware.exe"));
        assert!(WhitelistManager::matches_glob("test*", "testing"));
        assert!(WhitelistManager::matches_glob("*test*", "a_test_file"));

        // Single char ?
        assert!(WhitelistManager::matches_glob("te?t", "test"));
        assert!(WhitelistManager::matches_glob("te?t", "text"));
        assert!(!WhitelistManager::matches_glob("te?t", "teest"));

        // Combined
        assert!(WhitelistManager::matches_glob("*.t?p", "file.tmp"));
        assert!(WhitelistManager::matches_glob("*.t?p", "file.txp"));
    }

    #[test]
    fn test_count() {
        let manager = WhitelistManager::in_memory().unwrap();

        assert_eq!(manager.count().unwrap(), 0);
        assert_eq!(manager.count_active().unwrap(), 0);

        manager
            .add(&WhitelistEntry::by_hash(
                "1".to_string(),
                "hash".to_string(),
                "".to_string(),
            ))
            .unwrap();
        manager
            .add(&WhitelistEntry::by_hash(
                "2".to_string(),
                "hash2".to_string(),
                "".to_string(),
            ))
            .unwrap();

        assert_eq!(manager.count().unwrap(), 2);
        assert_eq!(manager.count_active().unwrap(), 2);

        manager.disable("1").unwrap();
        assert_eq!(manager.count().unwrap(), 2);
        assert_eq!(manager.count_active().unwrap(), 1);
    }

    #[test]
    fn test_is_whitelisted_detection() {
        use crate::core::types::{DetectionMethod, Severity, ThreatCategory};
        use std::io::Write;

        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(b"flagged content").unwrap();
        let detection = Detection::new(
            file.path().to_path_buf(),
            "Trojan.Test",
            Severity::High,
            ThreatCategory::Trojan,
            DetectionMethod::Yara,
        );

        let manager = WhitelistManager::in_memory().unwrap();
        assert!(!manager.is_whitelisted(&detection).unwrap());

        // A hash entry matches the file's own hash even when the detection
        // carries none, and regardless of hex case.
        let hash = HashCalculator::sha256_file(file.path()).unwrap();
        manager
            .add(&WhitelistEntry::by_hash(
                "h".to_string(),
                hash.to_uppercase(),
                "".to_string(),
            ))
            .unwrap();
        assert!(manager.is_whitelisted(&detection).unwrap());
        manager.disable("h").unwrap();
        assert!(!manager.is_whitelisted(&detection).unwrap());

        manager
            .add(&WhitelistEntry::by_detection(
                "d".to_string(),
                "trojan.*".to_string(),
                "".to_string(),
            ))
            .unwrap();
        assert!(manager.is_whitelisted(&detection).unwrap());
        manager.disable("d").unwrap();

        let pattern = format!("{}*", file.path().parent().unwrap().display());
        manager
            .add(&WhitelistEntry::by_path(
                "p".to_string(),
                pattern,
                "".to_string(),
            ))
            .unwrap();
        assert!(manager.is_whitelisted(&detection).unwrap());
    }

    #[test]
    fn test_whitelist_type_conversion() {
        assert_eq!(WhitelistType::Hash.to_db(), "hash");
        assert_eq!(WhitelistType::Path.to_db(), "path");
        assert_eq!(WhitelistType::Detection.to_db(), "detection");

        assert_eq!(WhitelistType::from_db("hash"), Some(WhitelistType::Hash));
        assert_eq!(WhitelistType::from_db("path"), Some(WhitelistType::Path));
        assert_eq!(
            WhitelistType::from_db("detection"),
            Some(WhitelistType::Detection)
        );
        assert_eq!(WhitelistType::from_db("invalid"), None);
    }

    #[test]
    fn test_read_only_whitelist_is_still_checked() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("whitelist.db");
        let hash = "ab".repeat(32);
        WhitelistManager::open_writable(&db_path)
            .unwrap()
            .add(&WhitelistEntry::by_hash(
                "1".to_string(),
                hash.clone(),
                "test".to_string(),
            ))
            .unwrap();

        let mut perms = std::fs::metadata(&db_path).unwrap().permissions();
        perms.set_readonly(true);
        std::fs::set_permissions(&db_path, perms.clone()).unwrap();
        // Root (or an administrator) can write regardless; nothing to test
        if std::fs::OpenOptions::new()
            .write(true)
            .open(&db_path)
            .is_err()
        {
            // Scans can still honour the entries...
            let manager = WhitelistManager::open(&db_path).unwrap();
            assert!(manager.is_hash_whitelisted(&hash).unwrap());
            // ...but changing it is refused up front
            let err = WhitelistManager::open_writable(&db_path)
                .err()
                .expect("refused");
            assert!(matches!(err, Error::DatabaseReadOnly { .. }), "{}", err);
        }

        #[allow(clippy::permissions_set_readonly_false)]
        perms.set_readonly(false);
        std::fs::set_permissions(&db_path, perms).unwrap();
    }
}
