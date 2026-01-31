# CLAUDE.md

This file provides guidance for AI assistants working with the PC-Peroxide codebase.

## Project Overview

PC-Peroxide is a lightweight, portable malware detection and removal utility for Windows written in Rust. It's designed as a "second-opinion" scanner that complements existing antivirus solutions, offering on-demand scanning with no installation required.

**Key characteristics:**
- Portable executable (no installation)
- Offline-capable with optional signature updates
- Cross-platform compatible (Windows primary, Linux/macOS supported)
- ~10,500 lines of production Rust code

## Tech Stack

- **Language:** Rust (Edition 2021, requires Rust 1.70+)
- **Async Runtime:** Tokio
- **CLI:** Clap
- **GUI:** Tauri/egui (optional feature)
- **Database:** SQLite (rusqlite)
- **PE Analysis:** Goblin
- **Encryption:** AES-256-GCM

## Project Structure

```
src/
├── main.rs                 # CLI entry point
├── gui_main.rs             # GUI entry point (optional)
├── lib.rs                  # Library exports
├── analysis/               # LLM-powered analysis (Ollama, OpenAI)
├── core/                   # Core types & infrastructure
│   ├── config.rs           # JSON configuration system
│   ├── error.rs            # Error types
│   ├── types.rs            # Core data types (Detection, Threat, etc.)
│   └── reporting.rs        # Error reporting
├── detection/              # Detection engines
│   ├── database.rs         # SQLite signature database
│   ├── matcher.rs          # Hash matching logic
│   ├── signature.rs        # Signature types
│   ├── heuristic/          # Behavioral analysis (PE, entropy, imports)
│   └── yara/               # YARA rule integration
├── quarantine/             # Threat containment (vault, encryption, metadata)
├── scanner/                # Scanning engines
│   ├── file.rs             # File system scanner
│   ├── process/            # Process scanning
│   ├── persistence/        # Registry, startup, scheduled tasks
│   ├── browser/            # Browser extension scanning
│   └── network/            # Network analysis
├── ui/                     # User interfaces (CLI, GUI, reports)
└── utils/                  # Utilities (hash, logging, retry)
```

## Build Commands

```bash
# Debug build
cargo build

# Release build
cargo build --release

# Build with GUI
cargo build --features gui

# Run tests
cargo test

# Run with verbose logging
RUST_LOG=debug cargo run -- scan --quick
```

## Common CLI Usage

```bash
# Quick scan (temp, appdata, downloads, startup)
cargo run -- scan --quick

# Full system scan
cargo run -- scan --full

# Scan specific path
cargo run -- scan --path "/path/to/scan"

# Export results as JSON
cargo run -- scan --full --output report.json --json
```

## Windows Batch Scripts

- `setup-windows.bat` - Install dependencies
- `build.bat` - Release build
- `quick-scan.bat` - Execute quick scan
- `full-scan.bat` - Full system scan
- `run.bat` - Run UI

## Key Concepts

### Detection Pipeline
1. File enumeration with exclusions
2. File prioritization (critical: .exe/.dll/.sys)
3. SHA256 hash computation
4. Signature matching (SQLite database)
5. Heuristic analysis (PE parsing, entropy, imports)
6. YARA rule matching
7. Detection result aggregation

### Severity Levels
- **Low (0-20):** Potentially unwanted
- **Medium (21-50):** Flagged for review
- **High (51-80):** Likely malicious
- **Critical (81-100):** Confirmed malicious

### Threat Categories
Trojan, Ransomware, Virus, Worm, Spyware, Adware, Rootkit, Backdoor, Miner, PUP, Exploit

### Remediation Actions
- **Quarantine:** Move to AES-256-GCM encrypted vault
- **Delete:** Secure 3-pass overwrite deletion
- **Terminate:** Kill process before file action
- **Whitelist:** Exclude from future scans

## Coding Conventions

- Snake_case for functions, PascalCase for types
- Async-first design with Tokio
- Custom error types with `thiserror`
- Error propagation using `anyhow`
- Modular structure with clear separation of concerns

## Key Files to Understand

| Purpose | File |
|---------|------|
| CLI entry | `src/main.rs` |
| Library API | `src/lib.rs` |
| Core types | `src/core/types.rs` |
| Detection engine | `src/detection/mod.rs` |
| File scanner | `src/scanner/file.rs` |
| Configuration | `src/core/config.rs` |
| Dependencies | `Cargo.toml` |

## Configuration

Config file locations:
- Windows: `%LOCALAPPDATA%\PC-Peroxide\config.json`
- Linux: `~/.local/share/pc-peroxide/config.json`
- macOS: `~/Library/Application Support/PC-Peroxide/config.json`

## Testing

```bash
# Run all tests
cargo test

# Run with output
cargo test -- --nocapture

# Run specific module tests
cargo test detection::
cargo test scanner::
```

EICAR test file is supported for detection testing.

## Important Notes

- Windows-specific features use the `windows` crate for Win32 APIs
- Quarantine vault uses AES-256-GCM authenticated encryption
- Secure deletion uses 3-pass random overwrite
- SQLite is used for signatures, quarantine metadata, and scan history
- Optional LLM integration available (OpenAI, Ollama) for enhanced analysis
