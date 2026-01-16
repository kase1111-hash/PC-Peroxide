# PC-Peroxide: 10-Phase Development Plan

A structured implementation roadmap for the malware detection and removal tool.

---

## Phase 1: Project Foundation & Core Infrastructure

**Goal:** Establish the project structure, build system, and core abstractions.

### Tasks:
- [ ] Initialize Rust project with Cargo workspace structure
- [ ] Set up module hierarchy:
  ```
  src/
  ├── main.rs
  ├── lib.rs
  ├── core/
  │   ├── mod.rs
  │   ├── config.rs
  │   ├── error.rs
  │   └── types.rs
  ├── scanner/
  ├── detection/
  ├── quarantine/
  ├── ui/
  └── utils/
  ```
- [ ] Define core error types and result handling
- [ ] Implement configuration system (JSON-based settings)
- [ ] Create logging infrastructure with log levels
- [ ] Set up cross-compilation for Windows targets
- [ ] Add essential dependencies (serde, tokio, log, etc.)

### Deliverables:
- Compilable project skeleton
- Configuration loading/saving
- Logging system
- Error handling framework

---

## Phase 2: Signature Database & Hash Matching

**Goal:** Implement the signature database and basic hash-based detection.

### Tasks:
- [ ] Design SQLite schema for signature storage
- [ ] Implement signature database manager
- [ ] Create hash computation utilities (SHA256, MD5, ssdeep fuzzy)
- [ ] Build signature loader (JSON format from spec)
- [ ] Implement hash matching engine
- [ ] Create signature database CRUD operations
- [ ] Add signature versioning support

### Data Structures:
```rust
struct Signature {
    id: String,
    name: String,
    sig_type: SignatureType,
    hash_sha256: Option<String>,
    pattern: Option<Vec<u8>>,
    severity: Severity,
    category: Category,
    description: String,
    remediation: Action,
}
```

### Deliverables:
- SQLite database for signatures
- Hash computation (SHA256, MD5, ssdeep)
- Signature matching against file hashes

---

## Phase 3: File System Scanner

**Goal:** Build the file scanning engine with path traversal and file type prioritization.

### Tasks:
- [ ] Implement directory walker with exclusion support
- [ ] Create file type detector (by extension and magic bytes)
- [ ] Build priority queue for scan order (CRITICAL → LOW)
- [ ] Add Quick Scan paths (%TEMP%, %APPDATA%, etc.)
- [ ] Implement Full Scan with drive enumeration
- [ ] Add Custom Scan (user-selected paths)
- [ ] Create archive extraction support (ZIP, RAR, 7z)
- [ ] Implement file size limits and skip rules
- [ ] Add symlink handling with loop detection

### Scan Locations:
```rust
const QUICK_SCAN_PATHS: &[&str] = &[
    "%TEMP%",
    "%APPDATA%",
    "%LOCALAPPDATA%",
    "%PROGRAMDATA%",
    "C:\\Users\\*\\Downloads",
    "C:\\Windows\\Temp",
];
```

### Deliverables:
- Multi-threaded file scanner
- Archive content scanning
- Quick/Full/Custom scan modes

---

## Phase 4: Heuristic Detection Engine

**Goal:** Implement behavioral and structural analysis for unknown threats.

### Tasks:
- [ ] Build PE (Portable Executable) parser
- [ ] Implement PE header anomaly detection
- [ ] Create entropy calculator for packing detection
- [ ] Build import table analyzer (suspicious API detection)
- [ ] Implement certificate validation checker
- [ ] Create resource section analyzer
- [ ] Build scoring system (0-100 scale)
- [ ] Add packer detection (UPX, Themida signatures)

### Suspicious Imports to Detect:
```rust
const HIGH_RISK_IMPORTS: &[&str] = &[
    "VirtualAllocEx",
    "WriteProcessMemory",
    "CreateRemoteThread",
    "NtUnmapViewOfSection",
    "SetWindowsHookEx",
    "GetAsyncKeyState",
    "CryptEncrypt",
    "URLDownloadToFile",
];
```

### Scoring Thresholds:
- 0-20: Clean
- 21-50: Suspicious (flag for review)
- 51-80: Likely Malicious
- 81-100: Confirmed Malicious

### Deliverables:
- PE file parser
- Heuristic scoring engine
- Packer/obfuscation detection

---

## Phase 5: Registry & Persistence Scanner

**Goal:** Detect malware persistence mechanisms in the Windows registry.

### Tasks:
- [ ] Implement Windows registry access wrapper
- [ ] Build autorun location scanner (Run, RunOnce, Services)
- [ ] Create shell extension analyzer
- [ ] Implement Image File Execution Options checker
- [ ] Build AppInit_DLLs detector
- [ ] Add LSA and Winlogon persistence checks
- [ ] Create scheduled tasks scanner
- [ ] Implement startup folder scanner
- [ ] Build WMI subscription detector

### Registry Paths:
```rust
const PERSISTENCE_REGISTRY_KEYS: &[&str] = &[
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"HKLM\SYSTEM\CurrentControlSet\Services",
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs",
];
```

### Deliverables:
- Registry scanner for persistence
- Autorun entry enumeration
- Suspicious registry value detection

---

## Phase 6: Process & Memory Scanner

**Goal:** Analyze running processes for malicious behavior.

### Tasks:
- [ ] Implement process enumeration
- [ ] Build process-to-executable path validator
- [ ] Create parent-child relationship analyzer
- [ ] Implement masquerading detection (svchost, lsass, csrss)
- [ ] Build loaded DLL validator
- [ ] Add memory region analyzer (RWX permissions)
- [ ] Implement hidden window detector
- [ ] Create process termination functionality
- [ ] Build LOLBin abuse detection (powershell, certutil, mshta)

### Suspicious Patterns:
```rust
const SYSTEM_PROCESS_PATHS: &[(&str, &str)] = &[
    ("svchost.exe", r"C:\Windows\System32\svchost.exe"),
    ("lsass.exe", r"C:\Windows\System32\lsass.exe"),
    ("csrss.exe", r"C:\Windows\System32\csrss.exe"),
];
```

### Deliverables:
- Process scanner with validation
- Memory analysis for injections
- Masquerading detection

---

## Phase 7: Quarantine & Remediation System

**Goal:** Implement secure threat containment and removal.

### Tasks:
- [ ] Design quarantine vault structure
- [ ] Implement AES-256 encryption for quarantine
- [ ] Build quarantine metadata database (SQLite)
- [ ] Create secure file move operation
- [ ] Implement safe deletion (overwrite + rename + delete)
- [ ] Build process termination before file action
- [ ] Add file ownership acquisition
- [ ] Implement restore from quarantine
- [ ] Create whitelist management system
- [ ] Build locked file handler (schedule for boot-time)

### Quarantine Structure:
```
%PROGRAMDATA%\PC-Peroxide\Quarantine\
├── vault.db
├── items\
│   └── {guid}.qvault
└── metadata\
    └── {guid}.json
```

### Deliverables:
- Encrypted quarantine vault
- Safe deletion procedures
- Restore functionality
- Whitelist system

---

## Phase 8: YARA Integration & Advanced Detection

**Goal:** Add YARA rules support and network/browser scanning.

### Tasks:
- [ ] Integrate yara-rust library
- [ ] Build YARA rule loader and validator
- [ ] Implement YARA scanning on files
- [ ] Create custom YARA rule management
- [ ] Build network connection analyzer
- [ ] Implement suspicious port detection
- [ ] Add DNS query logging (optional)
- [ ] Create browser extension scanner (Chrome, Edge, Firefox)
- [ ] Build browser hijack detector (homepage, search)

### YARA Rule Example:
```yara
rule Ransomware_Generic {
    meta:
        description = "Generic ransomware detection"
        severity = "critical"
    strings:
        $ransom1 = "Your files have been encrypted" nocase
        $crypto1 = "CryptEncrypt"
    condition:
        uint16(0) == 0x5A4D and (any of ($ransom*)) and (any of ($crypto*))
}
```

### Deliverables:
- YARA engine integration
- Network connection analysis
- Browser security scanner

---

## Phase 9: CLI Interface & Reporting

**Goal:** Build the command-line interface and reporting system.

### Tasks:
- [ ] Design CLI argument parser (clap)
- [ ] Implement scan command with options
- [ ] Build quarantine management commands
- [ ] Create update command for signatures
- [ ] Add configuration command
- [ ] Implement progress output (verbose mode)
- [ ] Build JSON output mode
- [ ] Create silent mode (exit code only)
- [ ] Implement HTML report generator
- [ ] Add CSV export
- [ ] Build PDF report generation
- [ ] Create scan history logging

### CLI Structure:
```
malware-remover [OPTIONS] [COMMAND]

Commands:
  scan        Run a malware scan
  quarantine  Manage quarantined items
  update      Update signature database
  config      Configure settings

Options:
  -q, --quick           Quick scan
  -f, --full            Full system scan
  -p, --path <PATH>     Scan specific path
  -o, --output <FILE>   Export results
  --json                JSON output format
```

### Deliverables:
- Full CLI with all commands
- Multiple report formats (JSON, HTML, CSV, PDF)
- Scan history and logging

---

## Phase 10: GUI Application & Signature Updates

**Goal:** Build the graphical interface and automatic update system.

### Tasks:
- [ ] Set up Tauri/egui framework
- [ ] Design main dashboard view
- [ ] Implement scan progress view
- [ ] Create threat results view
- [ ] Build quarantine management UI
- [ ] Add settings/configuration UI
- [ ] Implement scan type selection (Quick/Full/Custom)
- [ ] Build drag-and-drop file scanning
- [ ] Create signature update checker
- [ ] Implement delta update downloads
- [ ] Add update signature verification (GPG)
- [ ] Build automatic update scheduler
- [ ] Create system tray integration
- [ ] Implement scan notifications

### UI Views:
1. Main Dashboard - scan buttons, status, recent activity
2. Scan Progress - live file count, threats found, progress bar
3. Threat Results - detection list with actions
4. Quarantine Manager - restore, delete, whitelist
5. Settings - scan options, detection sensitivity, updates

### Deliverables:
- Complete GUI application
- Automatic signature updates
- System tray integration

---

## Summary Timeline

| Phase | Component | Dependencies |
|-------|-----------|--------------|
| 1 | Project Foundation | None |
| 2 | Signature Database | Phase 1 |
| 3 | File Scanner | Phase 1, 2 |
| 4 | Heuristic Engine | Phase 1, 3 |
| 5 | Registry Scanner | Phase 1, 2 |
| 6 | Process Scanner | Phase 1, 2, 4 |
| 7 | Quarantine System | Phase 1, 3 |
| 8 | YARA & Advanced | Phase 1-4 |
| 9 | CLI & Reporting | Phase 1-8 |
| 10 | GUI & Updates | Phase 1-9 |

---

## Testing Requirements Per Phase

Each phase should include:
- Unit tests for core functions
- Integration tests for component interactions
- EICAR test file validation (detection testing)
- False positive testing against legitimate software
- Performance benchmarks

---

## Technology Stack (Recommended)

| Component | Choice | Rationale |
|-----------|--------|-----------|
| Language | Rust | Safety, performance, Windows support |
| GUI | Tauri/egui | Lightweight, native feel |
| Database | SQLite | Portable, reliable |
| Hashing | ring + ssdeep | Fast, secure |
| PE Parsing | goblin | Comprehensive PE support |
| YARA | yara-rust | Standard malware rules |
| CLI | clap | Feature-rich argument parsing |
| Async | tokio | Concurrent scanning |
