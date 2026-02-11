//! Scan result persistence and history management.

use crate::core::error::{Error, Result};
use crate::core::types::{
    Detection, DetectionMethod, ScanStatus, ScanSummary, ScanType, Severity, ThreatCategory,
};
use chrono::{DateTime, TimeZone, Utc};
use rusqlite::{params, Connection, OptionalExtension};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Default database filename for scan results.
const DEFAULT_RESULTS_DB: &str = "scan_results.db";

/// Scan result storage and history manager.
pub struct ScanResultStore {
    conn: Mutex<Connection>,
}

impl ScanResultStore {
    /// Open or create a scan result store at the given path.
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path).map_err(|e| Error::DatabaseInit(e.to_string()))?;
        let store = Self {
            conn: Mutex::new(conn),
        };
        store.init_schema()?;
        Ok(store)
    }

    /// Open the default scan result store.
    pub fn open_default() -> Result<Self> {
        let data_dir = crate::core::config::Config::data_dir();
        std::fs::create_dir_all(&data_dir).map_err(|e| Error::DirectoryAccess {
            path: data_dir.clone(),
            source: e,
        })?;
        Self::open(&data_dir.join(DEFAULT_RESULTS_DB))
    }

    /// Initialize the database schema.
    fn init_schema(&self) -> Result<()> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| Error::lock_poisoned("scan results database"))?;

        conn.execute_batch(
            r#"
            -- Scan summaries table
            CREATE TABLE IF NOT EXISTS scans (
                scan_id TEXT PRIMARY KEY,
                scan_type TEXT NOT NULL,
                start_time INTEGER NOT NULL,
                end_time INTEGER,
                status TEXT NOT NULL,
                files_scanned INTEGER NOT NULL DEFAULT 0,
                directories_scanned INTEGER NOT NULL DEFAULT 0,
                bytes_scanned INTEGER NOT NULL DEFAULT 0,
                threats_found INTEGER NOT NULL DEFAULT 0,
                threats_quarantined INTEGER NOT NULL DEFAULT 0,
                threats_deleted INTEGER NOT NULL DEFAULT 0,
                errors INTEGER NOT NULL DEFAULT 0
            );

            -- Detections table
            CREATE TABLE IF NOT EXISTS detections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                path TEXT NOT NULL,
                threat_name TEXT NOT NULL,
                severity TEXT NOT NULL,
                category TEXT NOT NULL,
                method TEXT NOT NULL,
                description TEXT,
                sha256 TEXT,
                score INTEGER NOT NULL DEFAULT 0,
                detected_at INTEGER NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
            );

            -- Indexes for faster queries
            CREATE INDEX IF NOT EXISTS idx_scans_start_time ON scans(start_time DESC);
            CREATE INDEX IF NOT EXISTS idx_detections_scan_id ON detections(scan_id);
            CREATE INDEX IF NOT EXISTS idx_detections_path ON detections(path);
            CREATE INDEX IF NOT EXISTS idx_detections_sha256 ON detections(sha256);
            "#,
        )
        .map_err(|e| Error::DatabaseInit(e.to_string()))?;

        Ok(())
    }

    /// Save a scan summary and its detections.
    pub fn save_scan(&self, summary: &ScanSummary) -> Result<()> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| Error::lock_poisoned("scan results database"))?;

        // Insert or update scan summary
        conn.execute(
            r#"
            INSERT OR REPLACE INTO scans
            (scan_id, scan_type, start_time, end_time, status, files_scanned,
             directories_scanned, bytes_scanned, threats_found, threats_quarantined,
             threats_deleted, errors)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
            "#,
            params![
                summary.scan_id,
                scan_type_to_str(summary.scan_type),
                summary.start_time.timestamp(),
                summary.end_time.map(|t| t.timestamp()),
                scan_status_to_str(summary.status),
                summary.files_scanned,
                summary.directories_scanned,
                summary.bytes_scanned,
                summary.threats_found,
                summary.threats_quarantined,
                summary.threats_deleted,
                summary.errors,
            ],
        )
        .map_err(|e| Error::Database(e.to_string()))?;

        // Delete existing detections for this scan (in case of update)
        conn.execute(
            "DELETE FROM detections WHERE scan_id = ?1",
            params![summary.scan_id],
        )
        .map_err(|e| Error::Database(e.to_string()))?;

        // Insert detections
        for detection in &summary.detections {
            conn.execute(
                r#"
                INSERT INTO detections
                (scan_id, path, threat_name, severity, category, method,
                 description, sha256, score, detected_at)
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
                "#,
                params![
                    summary.scan_id,
                    detection.path.to_string_lossy(),
                    detection.threat_name,
                    detection.severity.as_str(),
                    detection.category.as_str(),
                    detection_method_to_str(detection.method),
                    detection.description,
                    detection.sha256,
                    detection.score,
                    Utc::now().timestamp(),
                ],
            )
            .map_err(|e| Error::Database(e.to_string()))?;
        }

        Ok(())
    }

    /// Load a scan summary by ID.
    pub fn load_scan(&self, scan_id: &str) -> Result<Option<ScanSummary>> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| Error::lock_poisoned("scan results database"))?;

        let scan = conn
            .query_row(
                r#"
                SELECT scan_id, scan_type, start_time, end_time, status, files_scanned,
                       directories_scanned, bytes_scanned, threats_found, threats_quarantined,
                       threats_deleted, errors
                FROM scans WHERE scan_id = ?1
                "#,
                params![scan_id],
                |row| {
                    Ok(ScanSummary {
                        scan_id: row.get(0)?,
                        scan_type: scan_type_from_str(&row.get::<_, String>(1)?),
                        start_time: Utc.timestamp_opt(row.get(2)?, 0).unwrap(),
                        end_time: row
                            .get::<_, Option<i64>>(3)?
                            .map(|t| Utc.timestamp_opt(t, 0).unwrap()),
                        status: scan_status_from_str(&row.get::<_, String>(4)?),
                        files_scanned: row.get(5)?,
                        directories_scanned: row.get(6)?,
                        bytes_scanned: row.get(7)?,
                        threats_found: row.get(8)?,
                        threats_quarantined: row.get(9)?,
                        threats_deleted: row.get(10)?,
                        errors: row.get(11)?,
                        detections: Vec::new(),
                    })
                },
            )
            .optional()
            .map_err(|e| Error::Database(e.to_string()))?;

        match scan {
            Some(mut summary) => {
                // Load detections
                summary.detections = self.load_detections_internal(&conn, scan_id)?;
                Ok(Some(summary))
            }
            None => Ok(None),
        }
    }

    /// Load detections for a scan.
    fn load_detections_internal(&self, conn: &Connection, scan_id: &str) -> Result<Vec<Detection>> {
        let mut stmt = conn
            .prepare(
                r#"
                SELECT path, threat_name, severity, category, method, description, sha256, score
                FROM detections WHERE scan_id = ?1
                "#,
            )
            .map_err(|e| Error::Database(e.to_string()))?;

        let detections = stmt
            .query_map(params![scan_id], |row| {
                Ok(Detection {
                    path: PathBuf::from(row.get::<_, String>(0)?),
                    threat_name: row.get(1)?,
                    severity: Severity::parse(&row.get::<_, String>(2)?)
                        .unwrap_or(Severity::Medium),
                    category: ThreatCategory::parse(&row.get::<_, String>(3)?)
                        .unwrap_or(ThreatCategory::Unknown),
                    method: detection_method_from_str(&row.get::<_, String>(4)?),
                    description: row.get(5)?,
                    sha256: row.get(6)?,
                    score: row.get(7)?,
                })
            })
            .map_err(|e| Error::Database(e.to_string()))?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::Database(e.to_string()))?;

        Ok(detections)
    }

    /// Get recent scan history.
    pub fn get_recent_scans(&self, limit: usize) -> Result<Vec<ScanSummary>> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| Error::lock_poisoned("scan results database"))?;

        let mut stmt = conn
            .prepare(
                r#"
                SELECT scan_id, scan_type, start_time, end_time, status, files_scanned,
                       directories_scanned, bytes_scanned, threats_found, threats_quarantined,
                       threats_deleted, errors
                FROM scans ORDER BY start_time DESC LIMIT ?1
                "#,
            )
            .map_err(|e| Error::Database(e.to_string()))?;

        let scans = stmt
            .query_map(params![limit as i64], |row| {
                Ok(ScanSummary {
                    scan_id: row.get(0)?,
                    scan_type: scan_type_from_str(&row.get::<_, String>(1)?),
                    start_time: Utc.timestamp_opt(row.get(2)?, 0).unwrap(),
                    end_time: row
                        .get::<_, Option<i64>>(3)?
                        .map(|t| Utc.timestamp_opt(t, 0).unwrap()),
                    status: scan_status_from_str(&row.get::<_, String>(4)?),
                    files_scanned: row.get(5)?,
                    directories_scanned: row.get(6)?,
                    bytes_scanned: row.get(7)?,
                    threats_found: row.get(8)?,
                    threats_quarantined: row.get(9)?,
                    threats_deleted: row.get(10)?,
                    errors: row.get(11)?,
                    detections: Vec::new(),
                })
            })
            .map_err(|e| Error::Database(e.to_string()))?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::Database(e.to_string()))?;

        Ok(scans)
    }

    /// Get all detections from scan history matching a hash.
    pub fn find_by_hash(&self, sha256: &str) -> Result<Vec<Detection>> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| Error::lock_poisoned("scan results database"))?;

        let mut stmt = conn
            .prepare(
                r#"
                SELECT path, threat_name, severity, category, method, description, sha256, score
                FROM detections WHERE sha256 = ?1
                "#,
            )
            .map_err(|e| Error::Database(e.to_string()))?;

        let detections = stmt
            .query_map(params![sha256], |row| {
                Ok(Detection {
                    path: PathBuf::from(row.get::<_, String>(0)?),
                    threat_name: row.get(1)?,
                    severity: Severity::parse(&row.get::<_, String>(2)?)
                        .unwrap_or(Severity::Medium),
                    category: ThreatCategory::parse(&row.get::<_, String>(3)?)
                        .unwrap_or(ThreatCategory::Unknown),
                    method: detection_method_from_str(&row.get::<_, String>(4)?),
                    description: row.get(5)?,
                    sha256: row.get(6)?,
                    score: row.get(7)?,
                })
            })
            .map_err(|e| Error::Database(e.to_string()))?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::Database(e.to_string()))?;

        Ok(detections)
    }

    /// Delete old scan records.
    pub fn cleanup_old_scans(&self, days_to_keep: u32) -> Result<u64> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| Error::lock_poisoned("scan results database"))?;
        let cutoff = Utc::now().timestamp() - (days_to_keep as i64 * 24 * 60 * 60);

        let deleted = conn
            .execute("DELETE FROM scans WHERE start_time < ?1", params![cutoff])
            .map_err(|e| Error::Database(e.to_string()))?;

        Ok(deleted as u64)
    }

    /// Get total scan statistics.
    pub fn get_statistics(&self) -> Result<ScanStatistics> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| Error::lock_poisoned("scan results database"))?;

        let stats = conn
            .query_row(
                r#"
                SELECT
                    COUNT(*) as total_scans,
                    COALESCE(SUM(files_scanned), 0) as total_files,
                    COALESCE(SUM(bytes_scanned), 0) as total_bytes,
                    COALESCE(SUM(threats_found), 0) as total_threats,
                    MAX(start_time) as last_scan
                FROM scans
                "#,
                [],
                |row| {
                    Ok(ScanStatistics {
                        total_scans: row.get(0)?,
                        total_files_scanned: row.get(1)?,
                        total_bytes_scanned: row.get(2)?,
                        total_threats_found: row.get(3)?,
                        last_scan_time: row
                            .get::<_, Option<i64>>(4)?
                            .map(|t| Utc.timestamp_opt(t, 0).unwrap()),
                    })
                },
            )
            .map_err(|e| Error::Database(e.to_string()))?;

        Ok(stats)
    }
}

/// Aggregate scan statistics.
#[derive(Debug, Clone, Default)]
pub struct ScanStatistics {
    /// Total number of scans performed
    pub total_scans: u64,
    /// Total files scanned across all scans
    pub total_files_scanned: u64,
    /// Total bytes scanned
    pub total_bytes_scanned: u64,
    /// Total threats found
    pub total_threats_found: u64,
    /// Last scan time
    pub last_scan_time: Option<DateTime<Utc>>,
}

// Helper functions for type conversion

fn scan_type_to_str(st: ScanType) -> &'static str {
    match st {
        ScanType::Quick => "quick",
        ScanType::Full => "full",
        ScanType::Custom => "custom",
        ScanType::Memory => "memory",
        ScanType::Registry => "registry",
        ScanType::BootTime => "boottime",
    }
}

fn scan_type_from_str(s: &str) -> ScanType {
    match s.to_lowercase().as_str() {
        "quick" => ScanType::Quick,
        "full" => ScanType::Full,
        "custom" => ScanType::Custom,
        "memory" => ScanType::Memory,
        "registry" => ScanType::Registry,
        "boottime" => ScanType::BootTime,
        _ => ScanType::Custom,
    }
}

fn scan_status_to_str(status: ScanStatus) -> &'static str {
    match status {
        ScanStatus::Pending => "pending",
        ScanStatus::Running => "running",
        ScanStatus::Paused => "paused",
        ScanStatus::Completed => "completed",
        ScanStatus::Cancelled => "cancelled",
        ScanStatus::Failed => "failed",
    }
}

fn scan_status_from_str(s: &str) -> ScanStatus {
    match s.to_lowercase().as_str() {
        "pending" => ScanStatus::Pending,
        "running" => ScanStatus::Running,
        "paused" => ScanStatus::Paused,
        "completed" => ScanStatus::Completed,
        "cancelled" => ScanStatus::Cancelled,
        "failed" => ScanStatus::Failed,
        _ => ScanStatus::Pending,
    }
}

fn detection_method_to_str(method: DetectionMethod) -> &'static str {
    match method {
        DetectionMethod::Signature => "signature",
        DetectionMethod::Pattern => "pattern",
        DetectionMethod::Yara => "yara",
        DetectionMethod::Heuristic => "heuristic",
        DetectionMethod::Behavioral => "behavioral",
        DetectionMethod::Cloud => "cloud",
    }
}

fn detection_method_from_str(s: &str) -> DetectionMethod {
    match s.to_lowercase().as_str() {
        "signature" => DetectionMethod::Signature,
        "pattern" => DetectionMethod::Pattern,
        "yara" => DetectionMethod::Yara,
        "heuristic" => DetectionMethod::Heuristic,
        "behavioral" => DetectionMethod::Behavioral,
        "cloud" => DetectionMethod::Cloud,
        _ => DetectionMethod::Signature,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn test_store() -> ScanResultStore {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test_results.db");
        std::mem::forget(dir);
        ScanResultStore::open(&path).unwrap()
    }

    #[test]
    fn test_save_and_load_scan() {
        let store = test_store();

        let mut summary = ScanSummary::new(ScanType::Quick);
        summary.files_scanned = 100;
        summary.threats_found = 2;
        summary.complete();

        // Add detection
        let detection = Detection::new(
            PathBuf::from("/test/malware.exe"),
            "Test.Malware",
            Severity::High,
            ThreatCategory::Trojan,
            DetectionMethod::Signature,
        )
        .with_sha256("abc123");
        summary.detections.push(detection);

        store.save_scan(&summary).unwrap();

        let loaded = store.load_scan(&summary.scan_id).unwrap().unwrap();
        assert_eq!(loaded.scan_id, summary.scan_id);
        assert_eq!(loaded.files_scanned, 100);
        assert_eq!(loaded.threats_found, 2);
        assert_eq!(loaded.detections.len(), 1);
        assert_eq!(loaded.detections[0].threat_name, "Test.Malware");
    }

    #[test]
    fn test_recent_scans() {
        let store = test_store();

        // Create multiple scans
        for i in 0..5 {
            let mut summary = ScanSummary::new(ScanType::Quick);
            summary.files_scanned = i * 10;
            summary.complete();
            store.save_scan(&summary).unwrap();
        }

        let recent = store.get_recent_scans(3).unwrap();
        assert_eq!(recent.len(), 3);
    }

    #[test]
    fn test_find_by_hash() {
        let store = test_store();

        let mut summary = ScanSummary::new(ScanType::Quick);
        let detection = Detection::new(
            PathBuf::from("/test/file.exe"),
            "Test.Malware",
            Severity::High,
            ThreatCategory::Trojan,
            DetectionMethod::Signature,
        )
        .with_sha256("deadbeef123456");
        summary.detections.push(detection);
        store.save_scan(&summary).unwrap();

        let found = store.find_by_hash("deadbeef123456").unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].sha256, Some("deadbeef123456".to_string()));

        let not_found = store.find_by_hash("nonexistent").unwrap();
        assert!(not_found.is_empty());
    }

    #[test]
    fn test_statistics() {
        let store = test_store();

        let mut summary = ScanSummary::new(ScanType::Quick);
        summary.files_scanned = 100;
        summary.bytes_scanned = 1000000;
        summary.threats_found = 5;
        summary.complete();
        store.save_scan(&summary).unwrap();

        let stats = store.get_statistics().unwrap();
        assert_eq!(stats.total_scans, 1);
        assert_eq!(stats.total_files_scanned, 100);
        assert_eq!(stats.total_threats_found, 5);
    }
}
