//! Archive extraction and scanning support.

use crate::core::error::{Error, Result};
use std::fs::File;
use std::io::{Read, Seek};
use std::path::{Path, PathBuf};
use zip::ZipArchive;

/// Maximum file size to extract from archive (100 MB default).
const MAX_EXTRACT_SIZE: u64 = 100 * 1024 * 1024;

/// Maximum number of files to process from a single archive.
const MAX_ARCHIVE_FILES: usize = 10000;

/// Maximum decompression ratio (to prevent zip bombs).
const MAX_COMPRESSION_RATIO: f64 = 100.0;

/// Represents a file extracted from an archive.
#[derive(Debug, Clone)]
pub struct ArchivedFile {
    /// Name of the file within the archive
    pub name: String,
    /// Full path within the archive (including directories)
    pub path: PathBuf,
    /// Compressed size
    pub compressed_size: u64,
    /// Uncompressed size
    pub uncompressed_size: u64,
    /// File content (if extracted)
    pub content: Option<Vec<u8>>,
    /// Whether this entry is a directory
    pub is_dir: bool,
}

impl ArchivedFile {
    /// Get the file extension.
    pub fn extension(&self) -> Option<&str> {
        self.path.extension().and_then(|e| e.to_str())
    }

    /// Check if this file should be scanned based on extension.
    pub fn should_scan(&self) -> bool {
        if self.is_dir {
            return false;
        }

        // Check extension
        if let Some(ext) = self.extension() {
            let ext_lower = ext.to_lowercase();
            matches!(
                ext_lower.as_str(),
                "exe" | "dll" | "sys" | "scr" | "com" | "bat" | "cmd" | "ps1" | "vbs" | "js"
                    | "jse" | "vbe" | "wsf" | "wsh" | "msi" | "jar" | "hta" | "lnk" | "pif"
                    | "doc" | "docm" | "xls" | "xlsm" | "ppt" | "pptm" | "pdf"
            )
        } else {
            // No extension - might still be executable
            true
        }
    }

    /// Calculate compression ratio.
    pub fn compression_ratio(&self) -> f64 {
        if self.compressed_size == 0 {
            return 0.0;
        }
        self.uncompressed_size as f64 / self.compressed_size as f64
    }
}

/// Archive scanner for extracting and scanning archive contents.
pub struct ArchiveScanner {
    max_extract_size: u64,
    max_files: usize,
    max_depth: u8,
    current_depth: u8,
}

impl Default for ArchiveScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl ArchiveScanner {
    /// Create a new archive scanner with default settings.
    pub fn new() -> Self {
        Self {
            max_extract_size: MAX_EXTRACT_SIZE,
            max_files: MAX_ARCHIVE_FILES,
            max_depth: 3,
            current_depth: 0,
        }
    }

    /// Set maximum file size to extract.
    pub fn with_max_size(mut self, size: u64) -> Self {
        self.max_extract_size = size;
        self
    }

    /// Set maximum number of files to process.
    pub fn with_max_files(mut self, count: usize) -> Self {
        self.max_files = count;
        self
    }

    /// Set maximum nesting depth for nested archives.
    pub fn with_max_depth(mut self, depth: u8) -> Self {
        self.max_depth = depth;
        self
    }

    /// Check if we can descend into nested archives.
    pub fn can_descend(&self) -> bool {
        self.current_depth < self.max_depth
    }

    /// Create a scanner for nested archive scanning.
    pub fn nested(&self) -> Self {
        Self {
            max_extract_size: self.max_extract_size,
            max_files: self.max_files,
            max_depth: self.max_depth,
            current_depth: self.current_depth + 1,
        }
    }

    /// List files in a ZIP archive without extracting.
    pub fn list_zip(&self, path: &Path) -> Result<Vec<ArchivedFile>> {
        let file = File::open(path).map_err(|e| Error::file_read(path, e))?;
        self.list_zip_reader(file, path)
    }

    /// List files from a ZIP reader.
    fn list_zip_reader<R: Read + Seek>(&self, reader: R, source_path: &Path) -> Result<Vec<ArchivedFile>> {
        let mut archive = ZipArchive::new(reader).map_err(|e| Error::ArchiveError {
            path: source_path.to_path_buf(),
            source: Box::new(e),
        })?;

        let mut files = Vec::new();
        let file_count = archive.len().min(self.max_files);

        for i in 0..file_count {
            let entry = archive.by_index(i).map_err(|e| Error::ArchiveError {
                path: source_path.to_path_buf(),
                source: Box::new(e),
            })?;

            let name = entry.name().to_string();
            let path = PathBuf::from(&name);
            let is_dir = entry.is_dir();
            let compressed_size = entry.compressed_size();
            let uncompressed_size = entry.size();

            files.push(ArchivedFile {
                name,
                path,
                compressed_size,
                uncompressed_size,
                content: None,
                is_dir,
            });
        }

        Ok(files)
    }

    /// Extract and scan files from a ZIP archive.
    pub fn scan_zip<F>(&self, path: &Path, mut callback: F) -> Result<Vec<ArchivedFile>>
    where
        F: FnMut(&ArchivedFile) -> Result<()>,
    {
        let file = File::open(path).map_err(|e| Error::file_read(path, e))?;
        let mut archive = ZipArchive::new(file).map_err(|e| Error::ArchiveError {
            path: path.to_path_buf(),
            source: Box::new(e),
        })?;

        let mut files = Vec::new();
        let file_count = archive.len().min(self.max_files);

        for i in 0..file_count {
            let mut entry = archive.by_index(i).map_err(|e| Error::ArchiveError {
                path: path.to_path_buf(),
                source: Box::new(e),
            })?;

            let name = entry.name().to_string();
            let entry_path = PathBuf::from(&name);
            let is_dir = entry.is_dir();
            let compressed_size = entry.compressed_size();
            let uncompressed_size = entry.size();

            // Check for zip bomb
            let ratio = if compressed_size > 0 {
                uncompressed_size as f64 / compressed_size as f64
            } else {
                0.0
            };

            if ratio > MAX_COMPRESSION_RATIO {
                log::warn!(
                    "Suspicious compression ratio ({:.1}x) in {:?}: {}",
                    ratio,
                    path,
                    name
                );
                continue;
            }

            // Skip if too large
            if uncompressed_size > self.max_extract_size {
                log::trace!("Skipping large file in archive: {} ({} bytes)", name, uncompressed_size);
                continue;
            }

            let mut archived_file = ArchivedFile {
                name,
                path: entry_path,
                compressed_size,
                uncompressed_size,
                content: None,
                is_dir,
            };

            // Extract content if it should be scanned
            if !is_dir && archived_file.should_scan() && uncompressed_size > 0 {
                let mut content = Vec::with_capacity(uncompressed_size as usize);
                if entry.read_to_end(&mut content).is_ok() {
                    archived_file.content = Some(content);
                }
            }

            // Call the callback for processing
            callback(&archived_file)?;

            files.push(archived_file);
        }

        Ok(files)
    }

    /// Extract a single file from a ZIP archive by name.
    pub fn extract_file(&self, archive_path: &Path, file_name: &str) -> Result<Vec<u8>> {
        let file = File::open(archive_path).map_err(|e| Error::file_read(archive_path, e))?;
        let mut archive = ZipArchive::new(file).map_err(|e| Error::ArchiveError {
            path: archive_path.to_path_buf(),
            source: Box::new(e),
        })?;

        let mut entry = archive.by_name(file_name).map_err(|e| Error::ArchiveError {
            path: archive_path.to_path_buf(),
            source: Box::new(e),
        })?;

        if entry.size() > self.max_extract_size {
            return Err(Error::ArchiveError {
                path: archive_path.to_path_buf(),
                source: Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "File too large to extract",
                )),
            });
        }

        let mut content = Vec::with_capacity(entry.size() as usize);
        entry.read_to_end(&mut content).map_err(|e| Error::ArchiveError {
            path: archive_path.to_path_buf(),
            source: Box::new(e),
        })?;

        Ok(content)
    }

    /// Check if a path is a supported archive format.
    pub fn is_supported_archive(path: &Path) -> bool {
        if let Some(ext) = path.extension() {
            matches!(
                ext.to_string_lossy().to_lowercase().as_str(),
                "zip" | "jar" | "docx" | "xlsx" | "pptx" | "apk" | "xpi"
            )
        } else {
            false
        }
    }

    /// Get archive type from path.
    pub fn archive_type(path: &Path) -> Option<ArchiveType> {
        if let Some(ext) = path.extension() {
            match ext.to_string_lossy().to_lowercase().as_str() {
                "zip" | "jar" | "docx" | "xlsx" | "pptx" | "apk" | "xpi" => Some(ArchiveType::Zip),
                "rar" => Some(ArchiveType::Rar),
                "7z" => Some(ArchiveType::SevenZip),
                "tar" => Some(ArchiveType::Tar),
                "gz" | "tgz" => Some(ArchiveType::Gzip),
                _ => None,
            }
        } else {
            None
        }
    }
}

/// Type of archive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveType {
    Zip,
    Rar,
    SevenZip,
    Tar,
    Gzip,
}

impl std::fmt::Display for ArchiveType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ArchiveType::Zip => write!(f, "ZIP"),
            ArchiveType::Rar => write!(f, "RAR"),
            ArchiveType::SevenZip => write!(f, "7-Zip"),
            ArchiveType::Tar => write!(f, "TAR"),
            ArchiveType::Gzip => write!(f, "GZIP"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Write};

    fn create_test_zip() -> Vec<u8> {
        let mut buffer = Cursor::new(Vec::new());
        {
            let mut zip = zip::ZipWriter::new(&mut buffer);
            let options = zip::write::FileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);

            zip.start_file("test.txt", options).unwrap();
            zip.write_all(b"Hello, World!").unwrap();

            zip.start_file("script.bat", options).unwrap();
            zip.write_all(b"@echo off\necho test").unwrap();

            zip.finish().unwrap();
        }
        buffer.into_inner()
    }

    #[test]
    fn test_list_zip() {
        let zip_data = create_test_zip();
        let scanner = ArchiveScanner::new();

        // Write to temp file
        let temp_dir = tempfile::tempdir().unwrap();
        let zip_path = temp_dir.path().join("test.zip");
        std::fs::write(&zip_path, &zip_data).unwrap();

        let files = scanner.list_zip(&zip_path).unwrap();
        assert_eq!(files.len(), 2);

        let names: Vec<&str> = files.iter().map(|f| f.name.as_str()).collect();
        assert!(names.contains(&"test.txt"));
        assert!(names.contains(&"script.bat"));
    }

    #[test]
    fn test_should_scan() {
        let exe_file = ArchivedFile {
            name: "malware.exe".to_string(),
            path: PathBuf::from("malware.exe"),
            compressed_size: 100,
            uncompressed_size: 200,
            content: None,
            is_dir: false,
        };
        assert!(exe_file.should_scan());

        let txt_file = ArchivedFile {
            name: "readme.txt".to_string(),
            path: PathBuf::from("readme.txt"),
            compressed_size: 50,
            uncompressed_size: 100,
            content: None,
            is_dir: false,
        };
        assert!(!txt_file.should_scan());

        let dir_entry = ArchivedFile {
            name: "folder/".to_string(),
            path: PathBuf::from("folder/"),
            compressed_size: 0,
            uncompressed_size: 0,
            content: None,
            is_dir: true,
        };
        assert!(!dir_entry.should_scan());
    }

    #[test]
    fn test_archive_type_detection() {
        assert_eq!(
            ArchiveScanner::archive_type(Path::new("file.zip")),
            Some(ArchiveType::Zip)
        );
        assert_eq!(
            ArchiveScanner::archive_type(Path::new("file.rar")),
            Some(ArchiveType::Rar)
        );
        assert_eq!(
            ArchiveScanner::archive_type(Path::new("file.7z")),
            Some(ArchiveType::SevenZip)
        );
        assert_eq!(
            ArchiveScanner::archive_type(Path::new("file.txt")),
            None
        );
    }

    #[test]
    fn test_compression_ratio() {
        let file = ArchivedFile {
            name: "test.exe".to_string(),
            path: PathBuf::from("test.exe"),
            compressed_size: 100,
            uncompressed_size: 1000,
            content: None,
            is_dir: false,
        };
        assert!((file.compression_ratio() - 10.0).abs() < 0.01);
    }
}
