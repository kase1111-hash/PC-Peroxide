//! File type detection using magic bytes and extensions.

use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

/// Maximum bytes to read for magic detection.
const MAGIC_BYTES_SIZE: usize = 16;

/// Detected file type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileType {
    /// Windows executable (PE format)
    Executable,
    /// Dynamic link library
    Dll,
    /// Windows driver
    Driver,
    /// Microsoft installer
    Msi,
    /// Java archive
    Jar,
    /// ZIP archive
    Zip,
    /// RAR archive
    Rar,
    /// 7-Zip archive
    SevenZip,
    /// GZIP compressed
    Gzip,
    /// TAR archive
    Tar,
    /// PDF document
    Pdf,
    /// Microsoft Office document (legacy)
    OfficeOle,
    /// Microsoft Office document (modern XML)
    OfficeXml,
    /// Batch script
    Batch,
    /// PowerShell script
    PowerShell,
    /// VBScript
    VbScript,
    /// JavaScript
    JavaScript,
    /// ELF binary (Linux)
    Elf,
    /// Mach-O binary (macOS)
    MachO,
    /// Windows shortcut
    Lnk,
    /// HTML document
    Html,
    /// XML document
    Xml,
    /// Plain text
    Text,
    /// Binary data (unknown format)
    Binary,
    /// Unknown type
    Unknown,
}

impl FileType {
    /// Check if this file type is potentially dangerous.
    pub fn is_executable(&self) -> bool {
        matches!(
            self,
            FileType::Executable
                | FileType::Dll
                | FileType::Driver
                | FileType::Msi
                | FileType::Jar
                | FileType::Batch
                | FileType::PowerShell
                | FileType::VbScript
                | FileType::JavaScript
                | FileType::Elf
                | FileType::MachO
                | FileType::Lnk
        )
    }

    /// Check if this file type is an archive.
    pub fn is_archive(&self) -> bool {
        matches!(
            self,
            FileType::Zip
                | FileType::Rar
                | FileType::SevenZip
                | FileType::Gzip
                | FileType::Tar
                | FileType::Jar
        )
    }

    /// Check if this file type is a document that can contain macros.
    pub fn is_macro_capable(&self) -> bool {
        matches!(
            self,
            FileType::OfficeOle | FileType::OfficeXml | FileType::Pdf
        )
    }

    /// Get MIME type string.
    pub fn mime_type(&self) -> &'static str {
        match self {
            FileType::Executable | FileType::Dll | FileType::Driver => {
                "application/vnd.microsoft.portable-executable"
            }
            FileType::Msi => "application/x-msi",
            FileType::Jar => "application/java-archive",
            FileType::Zip => "application/zip",
            FileType::Rar => "application/vnd.rar",
            FileType::SevenZip => "application/x-7z-compressed",
            FileType::Gzip => "application/gzip",
            FileType::Tar => "application/x-tar",
            FileType::Pdf => "application/pdf",
            FileType::OfficeOle => "application/msword",
            FileType::OfficeXml => "application/vnd.openxmlformats-officedocument",
            FileType::Batch => "application/x-bat",
            FileType::PowerShell => "application/x-powershell",
            FileType::VbScript => "text/vbscript",
            FileType::JavaScript => "text/javascript",
            FileType::Elf => "application/x-executable",
            FileType::MachO => "application/x-mach-binary",
            FileType::Lnk => "application/x-ms-shortcut",
            FileType::Html => "text/html",
            FileType::Xml => "application/xml",
            FileType::Text => "text/plain",
            FileType::Binary | FileType::Unknown => "application/octet-stream",
        }
    }
}

impl std::fmt::Display for FileType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FileType::Executable => write!(f, "Windows Executable"),
            FileType::Dll => write!(f, "Dynamic Link Library"),
            FileType::Driver => write!(f, "Windows Driver"),
            FileType::Msi => write!(f, "Windows Installer"),
            FileType::Jar => write!(f, "Java Archive"),
            FileType::Zip => write!(f, "ZIP Archive"),
            FileType::Rar => write!(f, "RAR Archive"),
            FileType::SevenZip => write!(f, "7-Zip Archive"),
            FileType::Gzip => write!(f, "GZIP Compressed"),
            FileType::Tar => write!(f, "TAR Archive"),
            FileType::Pdf => write!(f, "PDF Document"),
            FileType::OfficeOle => write!(f, "Office Document (OLE)"),
            FileType::OfficeXml => write!(f, "Office Document (XML)"),
            FileType::Batch => write!(f, "Batch Script"),
            FileType::PowerShell => write!(f, "PowerShell Script"),
            FileType::VbScript => write!(f, "VBScript"),
            FileType::JavaScript => write!(f, "JavaScript"),
            FileType::Elf => write!(f, "ELF Binary"),
            FileType::MachO => write!(f, "Mach-O Binary"),
            FileType::Lnk => write!(f, "Windows Shortcut"),
            FileType::Html => write!(f, "HTML Document"),
            FileType::Xml => write!(f, "XML Document"),
            FileType::Text => write!(f, "Plain Text"),
            FileType::Binary => write!(f, "Binary Data"),
            FileType::Unknown => write!(f, "Unknown"),
        }
    }
}

/// File type detector using magic bytes.
pub struct FileTypeDetector;

impl FileTypeDetector {
    /// Detect file type from magic bytes.
    pub fn detect_from_bytes(bytes: &[u8]) -> FileType {
        if bytes.len() < 2 {
            return FileType::Unknown;
        }

        // PE executable (MZ header)
        if bytes.starts_with(b"MZ") || bytes.starts_with(b"ZM") {
            return FileType::Executable;
        }

        // ELF binary
        if bytes.starts_with(b"\x7fELF") {
            return FileType::Elf;
        }

        // Mach-O binary (various magic numbers)
        if bytes.len() >= 4 {
            let magic = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            if matches!(magic, 0xFEEDFACE | 0xFEEDFACF | 0xCAFEBABE | 0xBEBAFECA) {
                return FileType::MachO;
            }
        }

        // ZIP archive (and Office XML, JAR)
        if bytes.starts_with(b"PK\x03\x04") || bytes.starts_with(b"PK\x05\x06") {
            // Could be ZIP, DOCX, XLSX, JAR etc.
            return FileType::Zip;
        }

        // RAR archive
        if bytes.starts_with(b"Rar!\x1a\x07") {
            return FileType::Rar;
        }

        // 7-Zip archive
        if bytes.starts_with(b"7z\xbc\xaf\x27\x1c") {
            return FileType::SevenZip;
        }

        // GZIP
        if bytes.starts_with(b"\x1f\x8b") {
            return FileType::Gzip;
        }

        // PDF
        if bytes.starts_with(b"%PDF") {
            return FileType::Pdf;
        }

        // OLE Compound Document (legacy Office)
        if bytes.starts_with(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1") {
            return FileType::OfficeOle;
        }

        // Windows shortcut (LNK)
        if bytes.len() >= 4
            && bytes[0] == 0x4c
            && bytes[1] == 0x00
            && bytes[2] == 0x00
            && bytes[3] == 0x00
        {
            // LNK files have CLSID at offset 4
            if bytes.len() >= 20
                && bytes[4] == 0x01
                && bytes[5] == 0x14
                && bytes[6] == 0x02
                && bytes[7] == 0x00
            {
                return FileType::Lnk;
            }
        }

        // MSI (OLE with specific stream)
        // For now, detect as OLE and refine later

        // HTML detection
        if Self::looks_like_html(bytes) {
            return FileType::Html;
        }

        // XML detection
        if bytes.starts_with(b"<?xml") || bytes.starts_with(b"\xef\xbb\xbf<?xml") {
            return FileType::Xml;
        }

        // Script detection by content
        if Self::looks_like_script(bytes) {
            return Self::detect_script_type(bytes);
        }

        // Check if it's likely text
        if Self::is_likely_text(bytes) {
            return FileType::Text;
        }

        // Binary data
        FileType::Binary
    }

    /// Detect file type from a file path.
    pub fn detect_from_file(path: &Path) -> std::io::Result<FileType> {
        let file = File::open(path)?;
        let mut reader = BufReader::new(file);
        let mut buffer = [0u8; MAGIC_BYTES_SIZE];

        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 {
            return Ok(FileType::Unknown);
        }

        let file_type = Self::detect_from_bytes(&buffer[..bytes_read]);

        // Refine detection using extension for ambiguous cases
        if file_type == FileType::Zip {
            if let Some(ext) = path.extension() {
                match ext.to_string_lossy().to_lowercase().as_str() {
                    "jar" => return Ok(FileType::Jar),
                    "docx" | "xlsx" | "pptx" => return Ok(FileType::OfficeXml),
                    "apk" => return Ok(FileType::Zip), // Android package, still a ZIP
                    _ => {}
                }
            }
        }

        // Refine PE detection
        if file_type == FileType::Executable {
            if let Some(ext) = path.extension() {
                match ext.to_string_lossy().to_lowercase().as_str() {
                    "dll" => return Ok(FileType::Dll),
                    "sys" | "drv" => return Ok(FileType::Driver),
                    _ => {}
                }
            }
        }

        // Use extension for script files that might not have magic
        if file_type == FileType::Text || file_type == FileType::Unknown {
            if let Some(ext) = path.extension() {
                match ext.to_string_lossy().to_lowercase().as_str() {
                    "bat" | "cmd" => return Ok(FileType::Batch),
                    "ps1" | "psm1" | "psd1" => return Ok(FileType::PowerShell),
                    "vbs" | "vbe" => return Ok(FileType::VbScript),
                    "js" | "jse" => return Ok(FileType::JavaScript),
                    "html" | "htm" | "hta" => return Ok(FileType::Html),
                    "xml" => return Ok(FileType::Xml),
                    "msi" => return Ok(FileType::Msi),
                    _ => {}
                }
            }
        }

        Ok(file_type)
    }

    /// Check if bytes look like HTML.
    fn looks_like_html(bytes: &[u8]) -> bool {
        let lower = String::from_utf8_lossy(bytes).to_lowercase();
        lower.contains("<!doctype html")
            || lower.contains("<html")
            || lower.contains("<head")
            || lower.contains("<body")
    }

    /// Check if bytes look like a script.
    fn looks_like_script(bytes: &[u8]) -> bool {
        let text = String::from_utf8_lossy(bytes);

        // Shebang
        if text.starts_with("#!") {
            return true;
        }

        // PowerShell
        if text.contains("param(")
            || text.contains("function ")
            || text.contains("$PSScriptRoot")
            || text.contains("Write-Host")
        {
            return true;
        }

        // Batch file
        if text.contains("@echo off") || text.contains("@ECHO OFF") || text.starts_with("REM ") {
            return true;
        }

        // VBScript
        if text.contains("WScript.") || text.contains("CreateObject(") || text.contains("Dim ") {
            return true;
        }

        false
    }

    /// Detect specific script type from content.
    fn detect_script_type(bytes: &[u8]) -> FileType {
        let text = String::from_utf8_lossy(bytes).to_lowercase();

        if text.contains("@echo off")
            || text.contains("@echo on")
            || text.starts_with("rem ")
            || text.contains("\r\nrem ")
        {
            return FileType::Batch;
        }

        if text.contains("$psscriptroot")
            || text.contains("write-host")
            || text.contains("write-output")
            || text.contains("param(")
        {
            return FileType::PowerShell;
        }

        if text.contains("wscript.") || text.contains("createobject(") {
            return FileType::VbScript;
        }

        if text.contains("function ") && (text.contains("var ") || text.contains("let ")) {
            return FileType::JavaScript;
        }

        FileType::Text
    }

    /// Check if bytes are likely text (not binary).
    fn is_likely_text(bytes: &[u8]) -> bool {
        if bytes.is_empty() {
            return false;
        }

        // Count non-text characters
        let non_text_count = bytes
            .iter()
            .filter(|&&b| {
                // Allow common text characters
                !(b == 9 || b == 10 || b == 13 || (32..=126).contains(&b) || b >= 128)
            })
            .count();

        // If more than 10% non-text, it's probably binary
        (non_text_count as f64 / bytes.len() as f64) < 0.1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pe_detection() {
        let pe_header = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00";
        assert_eq!(
            FileTypeDetector::detect_from_bytes(pe_header),
            FileType::Executable
        );
    }

    #[test]
    fn test_zip_detection() {
        let zip_header = b"PK\x03\x04\x14\x00\x00\x00";
        assert_eq!(
            FileTypeDetector::detect_from_bytes(zip_header),
            FileType::Zip
        );
    }

    #[test]
    fn test_pdf_detection() {
        let pdf_header = b"%PDF-1.4\n%\xe2\xe3\xcf\xd3";
        assert_eq!(
            FileTypeDetector::detect_from_bytes(pdf_header),
            FileType::Pdf
        );
    }

    #[test]
    fn test_elf_detection() {
        let elf_header = b"\x7fELF\x02\x01\x01\x00";
        assert_eq!(
            FileTypeDetector::detect_from_bytes(elf_header),
            FileType::Elf
        );
    }

    #[test]
    fn test_rar_detection() {
        let rar_header = b"Rar!\x1a\x07\x00";
        assert_eq!(
            FileTypeDetector::detect_from_bytes(rar_header),
            FileType::Rar
        );
    }

    #[test]
    fn test_7z_detection() {
        let sevenz_header = b"7z\xbc\xaf\x27\x1c\x00\x04";
        assert_eq!(
            FileTypeDetector::detect_from_bytes(sevenz_header),
            FileType::SevenZip
        );
    }

    #[test]
    fn test_executable_check() {
        assert!(FileType::Executable.is_executable());
        assert!(FileType::Dll.is_executable());
        assert!(FileType::PowerShell.is_executable());
        assert!(!FileType::Zip.is_executable());
        assert!(!FileType::Pdf.is_executable());
    }

    #[test]
    fn test_archive_check() {
        assert!(FileType::Zip.is_archive());
        assert!(FileType::Rar.is_archive());
        assert!(FileType::SevenZip.is_archive());
        assert!(!FileType::Executable.is_archive());
        assert!(!FileType::Pdf.is_archive());
    }
}
