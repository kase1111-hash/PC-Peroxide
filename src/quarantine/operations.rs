//! Secure file operations for quarantine.
//!
//! Provides:
//! - Secure file deletion with overwrite
//! - Safe file moving with ownership handling
//! - Process termination before file operations
//! - Locked file handling

use rand::RngCore;
use std::fs::{self, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;

use crate::core::error::{Error, Result};

/// Number of overwrite passes for secure deletion.
const SECURE_DELETE_PASSES: usize = 3;

/// Secure file operations manager.
pub struct SecureOperations {
    /// Number of overwrite passes for secure deletion
    overwrite_passes: usize,
}

impl SecureOperations {
    /// Create a new secure operations manager with default settings.
    pub fn new() -> Self {
        Self {
            overwrite_passes: SECURE_DELETE_PASSES,
        }
    }

    /// Create a secure operations manager with custom overwrite passes.
    pub fn with_passes(passes: usize) -> Self {
        Self {
            overwrite_passes: passes.max(1),
        }
    }

    /// Securely delete a file by overwriting with random data before deletion.
    ///
    /// This method:
    /// 1. Opens the file for writing
    /// 2. Overwrites the content with random data (multiple passes)
    /// 3. Renames the file to a random name
    /// 4. Deletes the renamed file
    pub fn secure_delete(&self, path: &Path) -> Result<()> {
        if !path.exists() {
            return Ok(()); // Already deleted
        }

        // Get file size
        let metadata = fs::metadata(path).map_err(|e| Error::file_read(path, e))?;
        let file_size = metadata.len() as usize;

        if file_size > 0 {
            // Overwrite with random data
            for _pass in 0..self.overwrite_passes {
                self.overwrite_with_random(path, file_size)?;
            }
        }

        // Rename to random name before deletion
        let random_name = self.generate_random_filename();
        let random_path = path
            .parent()
            .unwrap_or(Path::new("."))
            .join(&random_name);

        fs::rename(path, &random_path).map_err(|e| Error::FileDelete {
            path: path.to_path_buf(),
            source: e,
        })?;

        // Delete the renamed file
        fs::remove_file(&random_path).map_err(|e| Error::FileDelete {
            path: path.to_path_buf(),
            source: e,
        })?;

        Ok(())
    }

    /// Overwrite a file with random data.
    fn overwrite_with_random(&self, path: &Path, size: usize) -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .open(path)
            .map_err(|e| Error::file_write(path, e))?;

        // Write random data in chunks
        const CHUNK_SIZE: usize = 8192;
        let mut rng = rand::thread_rng();
        let mut buffer = vec![0u8; CHUNK_SIZE.min(size)];
        let mut remaining = size;

        file.seek(SeekFrom::Start(0))
            .map_err(|e| Error::file_write(path, e))?;

        while remaining > 0 {
            let write_size = remaining.min(CHUNK_SIZE);
            rng.fill_bytes(&mut buffer[..write_size]);
            file.write_all(&buffer[..write_size])
                .map_err(|e| Error::file_write(path, e))?;
            remaining -= write_size;
        }

        file.sync_all().map_err(|e| Error::file_write(path, e))?;

        Ok(())
    }

    /// Generate a random filename for deletion.
    fn generate_random_filename(&self) -> String {
        let mut rng = rand::thread_rng();
        let mut bytes = [0u8; 16];
        rng.fill_bytes(&mut bytes);
        hex::encode(bytes)
    }

    /// Simple delete without secure overwrite.
    pub fn simple_delete(&self, path: &Path) -> Result<()> {
        if path.exists() {
            fs::remove_file(path).map_err(|e| Error::FileDelete {
                path: path.to_path_buf(),
                source: e,
            })?;
        }
        Ok(())
    }

    /// Move a file safely with copy-then-delete semantics.
    ///
    /// This is safer than rename across filesystems.
    pub fn safe_move(&self, source: &Path, dest: &Path) -> Result<()> {
        // Ensure destination directory exists
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent).map_err(|e| Error::DirectoryAccess {
                path: parent.to_path_buf(),
                source: e,
            })?;
        }

        // Try rename first (fast path for same filesystem)
        if fs::rename(source, dest).is_ok() {
            return Ok(());
        }

        // Fall back to copy-then-delete
        fs::copy(source, dest).map_err(|e| Error::file_write(dest, e))?;

        // Verify copy
        let source_size = fs::metadata(source)
            .map_err(|e| Error::file_read(source, e))?
            .len();
        let dest_size = fs::metadata(dest)
            .map_err(|e| Error::file_read(dest, e))?
            .len();

        if source_size != dest_size {
            // Copy failed, remove partial dest
            let _ = fs::remove_file(dest);
            return Err(Error::Internal(
                "File copy verification failed".to_string(),
            ));
        }

        // Delete source
        fs::remove_file(source).map_err(|e| Error::FileDelete {
            path: source.to_path_buf(),
            source: e,
        })?;

        Ok(())
    }

    /// Check if a file is locked by another process.
    ///
    /// On Windows, tries to open with exclusive access.
    /// On Unix, always returns false (files are not locked the same way).
    #[cfg(target_os = "windows")]
    pub fn is_file_locked(&self, path: &Path) -> bool {
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .is_err()
    }

    #[cfg(not(target_os = "windows"))]
    pub fn is_file_locked(&self, _path: &Path) -> bool {
        false
    }

    /// Try to acquire exclusive access to a file.
    ///
    /// On Windows, this may require terminating processes that hold the file open.
    pub fn try_acquire_access(&self, path: &Path) -> Result<()> {
        if !path.exists() {
            return Err(Error::PathNotFound(path.to_path_buf()));
        }

        // Try to open for writing
        let result = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path);

        match result {
            Ok(_) => Ok(()),
            Err(e) => Err(Error::PermissionDenied {
                path: path.to_path_buf(),
                source: e,
            }),
        }
    }

    /// Get file permissions/attributes info.
    pub fn get_file_info(&self, path: &Path) -> Result<FileInfo> {
        let metadata = fs::metadata(path).map_err(|e| Error::file_read(path, e))?;

        Ok(FileInfo {
            size: metadata.len(),
            readonly: metadata.permissions().readonly(),
            is_file: metadata.is_file(),
            is_dir: metadata.is_dir(),
        })
    }

    /// Remove readonly attribute from a file.
    #[cfg(target_os = "windows")]
    pub fn remove_readonly(&self, path: &Path) -> Result<()> {
        use std::os::windows::fs::OpenOptionsExt;

        let mut perms = fs::metadata(path)
            .map_err(|e| Error::file_read(path, e))?
            .permissions();

        perms.set_readonly(false);
        fs::set_permissions(path, perms).map_err(|e| Error::file_write(path, e))?;

        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    pub fn remove_readonly(&self, path: &Path) -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let mut perms = fs::metadata(path)
            .map_err(|e| Error::file_read(path, e))?
            .permissions();

        // Add write permission
        let mode = perms.mode() | 0o200;
        perms.set_mode(mode);
        fs::set_permissions(path, perms).map_err(|e| Error::file_write(path, e))?;

        Ok(())
    }
}

impl Default for SecureOperations {
    fn default() -> Self {
        Self::new()
    }
}

/// Information about a file.
#[derive(Debug, Clone)]
pub struct FileInfo {
    /// File size in bytes
    pub size: u64,
    /// Whether the file is read-only
    pub readonly: bool,
    /// Whether this is a regular file
    pub is_file: bool,
    /// Whether this is a directory
    pub is_dir: bool,
}

/// Terminate a process by PID.
///
/// This is used to release file handles before deletion.
#[cfg(target_os = "windows")]
pub fn terminate_process(pid: u32) -> Result<()> {
    use std::process::Command;

    let output = Command::new("taskkill")
        .args(["/F", "/PID", &pid.to_string()])
        .output()
        .map_err(|e| Error::ProcessTermination {
            pid,
            reason: e.to_string(),
        })?;

    if output.status.success() {
        Ok(())
    } else {
        Err(Error::ProcessTermination {
            pid,
            reason: String::from_utf8_lossy(&output.stderr).to_string(),
        })
    }
}

#[cfg(target_os = "linux")]
pub fn terminate_process(pid: u32) -> Result<()> {
    use std::process::Command;

    let output = Command::new("kill")
        .args(["-9", &pid.to_string()])
        .output()
        .map_err(|e| Error::ProcessTermination {
            pid,
            reason: e.to_string(),
        })?;

    if output.status.success() {
        Ok(())
    } else {
        Err(Error::ProcessTermination {
            pid,
            reason: String::from_utf8_lossy(&output.stderr).to_string(),
        })
    }
}

#[cfg(target_os = "macos")]
pub fn terminate_process(pid: u32) -> Result<()> {
    use std::process::Command;

    let output = Command::new("kill")
        .args(["-9", &pid.to_string()])
        .output()
        .map_err(|e| Error::ProcessTermination {
            pid,
            reason: e.to_string(),
        })?;

    if output.status.success() {
        Ok(())
    } else {
        Err(Error::ProcessTermination {
            pid,
            reason: String::from_utf8_lossy(&output.stderr).to_string(),
        })
    }
}

#[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
pub fn terminate_process(pid: u32) -> Result<()> {
    Err(Error::NotSupported(
        "Process termination not supported on this platform".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_secure_delete() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test_delete.txt");

        // Create test file
        fs::write(&file_path, b"This is test content to delete").unwrap();
        assert!(file_path.exists());

        // Secure delete
        let ops = SecureOperations::new();
        ops.secure_delete(&file_path).unwrap();

        assert!(!file_path.exists());
    }

    #[test]
    fn test_secure_delete_nonexistent() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("nonexistent.txt");

        let ops = SecureOperations::new();
        // Should not error on nonexistent file
        ops.secure_delete(&file_path).unwrap();
    }

    #[test]
    fn test_simple_delete() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("simple_delete.txt");

        fs::write(&file_path, b"Test content").unwrap();
        assert!(file_path.exists());

        let ops = SecureOperations::new();
        ops.simple_delete(&file_path).unwrap();

        assert!(!file_path.exists());
    }

    #[test]
    fn test_safe_move() {
        let temp_dir = TempDir::new().unwrap();
        let source = temp_dir.path().join("source.txt");
        let dest = temp_dir.path().join("subdir").join("dest.txt");

        let content = b"Content to move";
        fs::write(&source, content).unwrap();

        let ops = SecureOperations::new();
        ops.safe_move(&source, &dest).unwrap();

        assert!(!source.exists());
        assert!(dest.exists());
        assert_eq!(fs::read(&dest).unwrap(), content);
    }

    #[test]
    fn test_get_file_info() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("info_test.txt");

        let content = b"Test content for info";
        fs::write(&file_path, content).unwrap();

        let ops = SecureOperations::new();
        let info = ops.get_file_info(&file_path).unwrap();

        assert_eq!(info.size, content.len() as u64);
        assert!(info.is_file);
        assert!(!info.is_dir);
    }

    #[test]
    fn test_is_file_locked() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("lock_test.txt");

        fs::write(&file_path, b"Test").unwrap();

        let ops = SecureOperations::new();
        // File should not be locked on most systems
        let _locked = ops.is_file_locked(&file_path);
        // Just check it doesn't panic
    }

    #[test]
    fn test_remove_readonly() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("readonly_test.txt");

        fs::write(&file_path, b"Test").unwrap();

        // Make readonly
        let mut perms = fs::metadata(&file_path).unwrap().permissions();
        perms.set_readonly(true);
        fs::set_permissions(&file_path, perms).unwrap();

        let ops = SecureOperations::new();
        ops.remove_readonly(&file_path).unwrap();

        let perms = fs::metadata(&file_path).unwrap().permissions();
        assert!(!perms.readonly());
    }

    #[test]
    fn test_custom_passes() {
        let ops = SecureOperations::with_passes(5);
        assert_eq!(ops.overwrite_passes, 5);

        let ops = SecureOperations::with_passes(0);
        assert_eq!(ops.overwrite_passes, 1); // Minimum 1
    }

    #[test]
    fn test_try_acquire_access() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("access_test.txt");

        fs::write(&file_path, b"Test").unwrap();

        let ops = SecureOperations::new();
        ops.try_acquire_access(&file_path).unwrap();
    }

    #[test]
    fn test_try_acquire_nonexistent() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("nonexistent.txt");

        let ops = SecureOperations::new();
        let result = ops.try_acquire_access(&file_path);
        assert!(result.is_err());
    }
}
