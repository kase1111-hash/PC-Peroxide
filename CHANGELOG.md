# Changelog

All notable changes to PC-Peroxide will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Project documentation (CONTRIBUTING.md, SECURITY.md, CHANGELOG.md)
- GitHub issue and PR templates

## [0.1.0] - 2026-01-23

### Added

#### Core Features
- Portable malware detection and removal for Windows systems
- No installation required - single executable deployment
- Offline-capable operation with optional cloud signature updates

#### Detection Engines
- **Signature-based detection**: SHA256 and MD5 hash matching against SQLite database
- **Heuristic analysis**: PE header anomalies, entropy detection, suspicious imports, certificate validation
- **Behavioral detection**: Process hollowing, DLL injection, memory anomalies
- **YARA integration**: Custom rule support for advanced pattern matching
- **LLM-powered analysis**: OpenAI and Ollama provider integration for intelligent threat analysis

#### Scanning Capabilities
- **File system scanner**: Quick, full, and custom scan modes
- **Registry scanner**: Persistence mechanisms, autoruns, shell extensions
- **Process scanner**: Running process analysis, memory inspection
- **Network scanner**: Connection analysis, suspicious port detection
- **Browser scanner**: Extension scanning, hijack detection

#### Remediation System
- **Quarantine vault**: AES-256 encrypted storage for isolated threats
- **Safe deletion**: Secure file removal with content overwrite
- **Restore capability**: Recover quarantined files when needed
- **Whitelist management**: Exclude trusted files from future scans

#### User Interfaces
- **CLI interface**: Full-featured command-line with multiple commands
  - `scan` - Run malware scans (quick, full, custom)
  - `quarantine` - Manage quarantined items
  - `update` - Update signature database
  - `config` - Configure settings
- **GUI application**: Modern egui-based interface (optional feature)
  - Dashboard with system status
  - Real-time scan progress visualization
  - Threat results with action buttons
  - Quarantine management view
  - Settings configuration panel

#### Reporting
- JSON export for machine-readable reports
- CSV export for spreadsheet analysis
- HTML reports for sharing
- PDF generation for formal documentation

#### Developer Experience
- Comprehensive error handling and reporting system
- Real-time progress indicator during scans
- Windows batch scripts for building and running
- Detailed logging with configurable levels

### Technical Details
- Built with Rust (Edition 2021) for safety and performance
- Async runtime using Tokio for concurrent scanning
- SQLite database for signature storage
- AES-GCM encryption for quarantine vault
- goblin library for PE/ELF parsing

### Known Limitations
- Windows-only support (cross-platform planned for future releases)
- Boot-time scanning not yet implemented
- Real-time file monitoring not yet implemented

## Development Phases Completed

1. **Phase 1**: Project foundation & infrastructure
2. **Phase 2**: Signature database & hash matching
3. **Phase 3**: File system scanner
4. **Phase 4**: Heuristic detection engine
5. **Phase 5**: Registry & persistence scanner
6. **Phase 6**: Process & memory scanner
7. **Phase 7**: Quarantine & remediation system
8. **Phase 8**: YARA integration & advanced detection
9. **Phase 9**: CLI interface & reporting
10. **Phase 10**: GUI application & signature updates

[Unreleased]: https://github.com/kase1111-hash/PC-Peroxide/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/kase1111-hash/PC-Peroxide/releases/tag/v0.1.0
