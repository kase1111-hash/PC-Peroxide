# Malware Remover Tool Specification

A lightweight, portable malware detection and removal utility for Windows systems.

---

## 1. Product Overview

### Name Ideas
- CleanSweep
- ThreatPurge
- MalwareAxe
- SystemSanitizer

### Core Philosophy
- No installation required (portable executable)
- No persistent services or background processes
- Transparent operation (user sees exactly what it's doing)
- Offline-capable with optional cloud signature updates
- Complement to (not replacement for) real-time AV

### Target Use Cases
- Second-opinion scanning alongside existing AV
- Cleaning infected systems where AV failed
- Post-compromise remediation
- Technician toolkit for client machines
- Paranoid manual scans on demand

---

## 2. Architecture

### Components

```
┌─────────────────────────────────────────────────────────┐
│                      GUI / CLI                          │
├─────────────────────────────────────────────────────────┤
│                   Scan Orchestrator                     │
├──────────┬──────────┬──────────┬──────────┬────────────┤
│  File    │ Registry │ Process  │ Network  │  Browser   │
│ Scanner  │ Scanner  │ Scanner  │ Scanner  │  Scanner   │
├──────────┴──────────┴──────────┴──────────┴────────────┤
│                  Detection Engine                       │
├─────────────┬─────────────┬─────────────┬──────────────┤
│  Signature  │  Heuristic  │  Behavior   │   YARA      │
│   Matcher   │   Analyzer  │   Flags     │   Rules     │
├─────────────┴─────────────┴─────────────┴──────────────┤
│                 Quarantine Manager                      │
├─────────────────────────────────────────────────────────┤
│              Signature Database (Local)                 │
└─────────────────────────────────────────────────────────┘
```

### Technology Stack Options

| Component | Options |
|-----------|---------|
| Language | Rust (safety + performance), C# (.NET), Go |
| GUI | WinForms, WPF, Tauri (Rust), Electron |
| CLI | Native console, PowerShell module |
| Database | SQLite (signatures), JSON (config) |
| Hashing | SHA256, MD5, ssdeep (fuzzy) |
| Pattern Matching | YARA, custom regex engine |

---

## 3. Detection Methods

### 3.1 Signature-Based Detection

**Hash Matching**
- SHA256 of known malware samples
- MD5 for legacy compatibility
- Fuzzy hashing (ssdeep) for variants

**Signature Database Structure**
```json
{
  "version": "2025.01.15",
  "signatures": [
    {
      "id": "MAL-00001",
      "name": "Trojan.GenericKD",
      "type": "hash",
      "hash_sha256": "a1b2c3...",
      "severity": "high",
      "category": "trojan",
      "description": "Generic trojan dropper",
      "remediation": "delete"
    }
  ]
}
```

**Byte Pattern Signatures**
```
{
  "id": "MAL-00002",
  "name": "Emotet.Variant",
  "type": "pattern",
  "pattern": "{ 8B 45 ?? 89 45 ?? E8 ?? ?? ?? ?? 85 C0 }",
  "offset": "entry_point",
  "severity": "critical"
}
```

### 3.2 Heuristic Detection

**File Heuristics**
- PE header anomalies (unusual section names, high entropy)
- Packed/obfuscated executables (UPX, Themida, custom packers)
- Certificate validation (unsigned, expired, revoked)
- Suspicious imports (injection APIs, keylogging, crypto)
- Resource section analysis (embedded executables)

**Suspicious API Import Patterns**
```
HIGH_RISK_IMPORTS = [
    "VirtualAllocEx",
    "WriteProcessMemory", 
    "CreateRemoteThread",
    "NtUnmapViewOfSection",
    "SetWindowsHookEx",
    "GetAsyncKeyState",
    "RegisterHotKey",
    "CryptEncrypt",
    "InternetOpenUrl",
    "URLDownloadToFile"
]
```

**Scoring System**
```
Score 0-20:   Clean
Score 21-50:  Suspicious (flag for review)
Score 51-80:  Likely Malicious
Score 81-100: Confirmed Malicious
```

### 3.3 Behavioral Indicators

**Runtime Behavior Flags** (for running processes)
- Process hollowing detection
- DLL injection signatures
- Unusual parent-child process relationships
- Hidden windows with keyboard hooks
- Cryptocurrency miner patterns (high CPU + specific network)
- Ransomware indicators (mass file enumeration + encryption APIs)

**Persistence Mechanism Detection**
```
PERSISTENCE_LOCATIONS = [
    # Registry Run Keys
    "HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    
    # Services
    "HKLM\System\CurrentControlSet\Services",
    
    # Scheduled Tasks
    "C:\Windows\System32\Tasks",
    
    # Startup Folders
    "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup",
    "%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup",
    
    # WMI Subscriptions
    "WMI EventConsumer bindings",
    
    # Browser Extensions
    "Chrome/Edge/Firefox extension directories",
    
    # DLL Hijacking Paths
    "Known DLL search order locations"
]
```

### 3.4 YARA Integration

**Custom YARA Rules Support**
```yara
rule Ransomware_Generic {
    meta:
        description = "Generic ransomware detection"
        severity = "critical"
    strings:
        $ransom1 = "Your files have been encrypted" nocase
        $ransom2 = "bitcoin" nocase
        $ransom3 = ".onion" nocase
        $crypto1 = "CryptEncrypt"
        $crypto2 = "CryptGenKey"
    condition:
        uint16(0) == 0x5A4D and
        (any of ($ransom*)) and
        (any of ($crypto*))
}
```

---

## 4. Scan Targets

### 4.1 File System Scan

**Quick Scan Locations**
```
%TEMP%
%APPDATA%
%LOCALAPPDATA%
%PROGRAMDATA%
C:\Users\*\Downloads
C:\Windows\Temp
C:\Windows\Prefetch
C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup
```

**Full Scan**
- All fixed drives
- Excludes: Windows\WinSxS (too slow), pagefile, hiberfil

**Custom Scan**
- User-selected paths
- Drag-and-drop file/folder support

**File Type Priorities**
```
CRITICAL:  .exe, .dll, .sys, .scr, .com, .bat, .cmd, .ps1, .vbs, .js
HIGH:      .msi, .jar, .hta, .wsf, .lnk, .pif
MEDIUM:    .doc, .docm, .xls, .xlsm, .pdf (macro/exploit check)
LOW:       Archives (.zip, .rar, .7z) - scan contents
```

### 4.2 Registry Scan

**Key Areas**
```
# Autoruns
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run

# Services
HKLM\SYSTEM\CurrentControlSet\Services

# Shell Extensions
HKCR\*\shellex\ContextMenuHandlers
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers

# Browser Hijacks
HKCU\SOFTWARE\Microsoft\Internet Explorer\Main\Start Page
HKLM\SOFTWARE\Microsoft\Internet Explorer\Main\Start Page

# Image File Execution Options (debugger hijacks)
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options

# AppInit DLLs
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs

# LSA
HKLM\SYSTEM\CurrentControlSet\Control\Lsa

# Winlogon
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
```

### 4.3 Process Scan

**Analysis Points**
- Process name vs executable path mismatch
- Unsigned processes in system directories
- Processes with hidden windows
- Unusual memory regions (RWX permissions)
- Network connections per process
- Loaded DLLs validation
- Parent process verification

**Suspicious Process Patterns**
```
# Masquerading
svchost.exe not running from C:\Windows\System32
csrss.exe not direct child of smss.exe
lsass.exe multiple instances

# Known malware names
svch0st.exe, scvhost.exe, csvhost.exe (typosquatting)

# Living-off-the-land binaries (LOLBins) abuse
powershell.exe with encoded commands
mshta.exe loading remote content
certutil.exe downloading files
bitsadmin.exe transferring suspicious URLs
```

### 4.4 Network Scan

**Connection Analysis**
- Active connections to known malicious IPs
- DNS queries to suspicious domains
- Unusual ports (crypto mining, C2 channels)
- Hidden/rootkit network connections

**Network Indicators**
```
SUSPICIOUS_PORTS = [4444, 5555, 6666, 1337, 31337, 8545]  # Common backdoor/miner ports
C2_PATTERNS = [
    "*.onion",
    "*.bit",
    "pastebin.com/raw/*",
    "discord.com/api/webhooks/*"
]
```

### 4.5 Browser Scan

**Targets**
- Malicious extensions
- Hijacked homepage/search
- Suspicious bookmarks
- Stored credential theft indicators
- Browser process injection

**Browser Paths**
```
Chrome:   %LOCALAPPDATA%\Google\Chrome\User Data\Default\Extensions
Edge:     %LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Extensions
Firefox:  %APPDATA%\Mozilla\Firefox\Profiles\*\extensions
```

---

## 5. Remediation Actions

### 5.1 Threat Response Options

| Action | Description | Risk Level |
|--------|-------------|------------|
| Quarantine | Move to encrypted vault, strip execute permissions | Safe |
| Delete | Permanent removal (recycle bin bypass) | Medium |
| Terminate | Kill process before file action | Safe |
| Restore | Return from quarantine | Safe |
| Whitelist | Exclude from future scans | User risk |

### 5.2 Quarantine System

**Quarantine Vault Structure**
```
%PROGRAMDATA%\MalwareRemover\Quarantine\
├── vault.db                    # SQLite index
├── items\
│   ├── {guid1}.qvault         # Encrypted original
│   ├── {guid2}.qvault
│   └── ...
└── metadata\
    ├── {guid1}.json           # Original path, hash, detection info
    └── ...
```

**Quarantine Metadata**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "original_path": "C:\\Users\\Admin\\AppData\\Local\\Temp\\malware.exe",
  "quarantine_date": "2025-01-15T14:30:00Z",
  "sha256": "a1b2c3d4...",
  "detection_name": "Trojan.GenericKD",
  "detection_method": "signature",
  "file_size": 245760,
  "can_restore": true
}
```

### 5.3 Safe Deletion

```
1. Terminate any processes using the file
2. Take ownership (if needed)
3. Remove read-only attribute
4. Overwrite file contents with zeros
5. Rename to random string
6. Delete file
7. Clear from MFT if possible
```

### 5.4 Boot-Time Scan

For locked files / rootkits:
- Register boot-time scan via registry
- Scan runs before Windows fully loads
- Uses Windows PE environment or custom bootloader
- Required for: MBR/VBR infections, locked system files, kernel rootkits

---

## 6. User Interface

### 6.1 Main Dashboard

```
┌─────────────────────────────────────────────────────────────┐
│  [Logo] MalwareRemover                    [Settings] [Help] │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │   QUICK     │  │    FULL     │  │   CUSTOM    │         │
│  │    SCAN     │  │    SCAN     │  │    SCAN     │         │
│  │   ~5 min    │  │  ~45 min    │  │  Select...  │         │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
│                                                             │
│  System Status: ✓ No active threats detected               │
│  Last Scan: January 14, 2025 at 3:45 PM (Quick)            │
│  Signatures: v2025.01.15 (Updated today)                   │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│  RECENT ACTIVITY                                            │
│  ├─ Quarantined: suspicious.exe (Trojan.Generic)           │
│  ├─ Cleaned: 3 registry entries                            │
│  └─ Blocked: 2 startup items                               │
│                                                             │
│  [View Quarantine]  [View Scan History]  [Update Sigs]     │
└─────────────────────────────────────────────────────────────┘
```

### 6.2 Scan Progress View

```
┌─────────────────────────────────────────────────────────────┐
│  SCANNING: Full System Scan                    [Cancel]     │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Progress: ████████████░░░░░░░░░░░░░░  48%                 │
│                                                             │
│  Currently scanning:                                        │
│  C:\Users\Admin\AppData\Local\Programs\...                 │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Files scanned:     124,532                          │   │
│  │ Threats found:     3                                │   │
│  │ Time elapsed:      12:34                            │   │
│  │ Time remaining:    ~14:00                           │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  THREATS FOUND (Click to expand)                           │
│  ├─ ⚠ HIGH: Trojan.Emotet - C:\Users\...\temp.exe         │
│  ├─ ⚠ MED:  PUP.Optional - C:\Program Files\...           │
│  └─ ⚠ LOW:  Adware.Generic - Chrome Extension             │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 6.3 Threat Results View

```
┌─────────────────────────────────────────────────────────────┐
│  SCAN COMPLETE - 3 Threats Found              [Export]      │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ☑ SELECT ALL                     [Quarantine] [Delete]    │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ ☑ Trojan.Emotet.AA                    CRITICAL      │   │
│  │   Path: C:\Users\Admin\AppData\Local\Temp\svc.exe   │   │
│  │   Size: 245 KB | SHA256: a1b2c3...                  │   │
│  │   Detection: Signature match + Heuristic (92/100)   │   │
│  │   [Details] [Whitelist] [VirusTotal]                │   │
│  ├─────────────────────────────────────────────────────┤   │
│  │ ☑ PUP.Optional.InstallCore             MEDIUM       │   │
│  │   Path: C:\Program Files\FreeApp\installer.exe      │   │
│  │   Detection: Heuristic (bundled installer)          │   │
│  │   [Details] [Whitelist] [VirusTotal]                │   │
│  ├─────────────────────────────────────────────────────┤   │
│  │ ☑ Adware.BrowserModifier                LOW         │   │
│  │   Path: Chrome Extension ID: abcdef123...           │   │
│  │   Detection: Known adware extension                 │   │
│  │   [Details] [Whitelist] [VirusTotal]                │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│                    [Quarantine Selected]                    │
└─────────────────────────────────────────────────────────────┘
```

### 6.4 CLI Interface

```
Usage: malware-remover [OPTIONS] [COMMAND]

Commands:
  scan        Run a malware scan
  quarantine  Manage quarantined items
  update      Update signature database
  config      Configure settings

Options:
  -q, --quick           Quick scan (common locations only)
  -f, --full            Full system scan
  -p, --path <PATH>     Scan specific path
  -o, --output <FILE>   Export results to file
  -s, --silent          No output (exit code only)
  -v, --verbose         Detailed output
  --json                Output in JSON format
  --no-action           Scan only, don't quarantine/delete
  --yara <RULES>        Use custom YARA rules file

Examples:
  malware-remover scan --quick
  malware-remover scan --path "C:\Users\Admin\Downloads"
  malware-remover scan --full --output report.json --json
  malware-remover quarantine --list
  malware-remover quarantine --restore <ID>
  malware-remover update --force
```

---

## 7. Signature Updates

### 7.1 Update Mechanism

**Sources**
- Primary: HTTPS endpoint (your server)
- Secondary: GitHub releases
- Offline: Manual signature file import

**Update Flow**
```
1. Check current version against remote manifest
2. Download delta update (or full if major version change)
3. Verify signature (GPG/code signing)
4. Apply atomically (old → new swap)
5. Verify integrity post-update
```

**Manifest Format**
```json
{
  "current_version": "2025.01.15",
  "release_date": "2025-01-15T00:00:00Z",
  "signatures_count": 1250000,
  "sha256": "abc123...",
  "download_url": "https://updates.example.com/sigs/2025.01.15.db",
  "delta_from": {
    "2025.01.14": "https://updates.example.com/sigs/delta-14-15.patch"
  },
  "min_app_version": "1.0.0"
}
```

### 7.2 Community/Custom Signatures

**User-Contributed Rules**
- YARA rules import
- Hash list import (one SHA256 per line)
- Custom heuristic rule definitions

```
# custom-hashes.txt
a1b2c3d4e5f6... # Known cryptominer
b2c3d4e5f6a1... # Ransomware variant
```

---

## 8. Logging and Reporting

### 8.1 Log Structure

**Scan Log**
```json
{
  "scan_id": "uuid",
  "scan_type": "full",
  "start_time": "2025-01-15T14:00:00Z",
  "end_time": "2025-01-15T14:45:00Z",
  "files_scanned": 245000,
  "threats_found": 3,
  "threats_quarantined": 2,
  "threats_deleted": 1,
  "errors": [],
  "detections": [
    {
      "path": "C:\\...",
      "threat_name": "Trojan.Generic",
      "detection_method": "signature",
      "action_taken": "quarantined",
      "sha256": "..."
    }
  ]
}
```

### 8.2 Report Export Formats

- JSON (machine readable)
- HTML (shareable report)
- CSV (spreadsheet analysis)
- PDF (formal documentation)

---

## 9. Configuration

### 9.1 Settings File

```json
{
  "scan": {
    "skip_large_files_mb": 100,
    "skip_archives_larger_than_mb": 50,
    "scan_archives": true,
    "max_archive_depth": 3,
    "follow_symlinks": false,
    "exclude_paths": [
      "C:\\Windows\\WinSxS",
      "C:\\$Recycle.Bin"
    ],
    "exclude_extensions": [".iso", ".vmdk"]
  },
  "detection": {
    "heuristic_sensitivity": "medium",
    "enable_yara": true,
    "enable_cloud_lookup": false,
    "pup_detection": true
  },
  "actions": {
    "default_action": "quarantine",
    "auto_quarantine_critical": true,
    "prompt_for_low_severity": true
  },
  "updates": {
    "auto_update_signatures": true,
    "update_check_interval_hours": 24,
    "update_url": "https://updates.example.com/manifest.json"
  },
  "logging": {
    "log_level": "info",
    "keep_logs_days": 30,
    "log_path": "%PROGRAMDATA%\\MalwareRemover\\logs"
  }
}
```

---

## 10. Security Considerations

### 10.1 Self-Protection

- Executable should be signed
- Integrity check on launch (detect tampering)
- Protected process if possible (PPL on Windows)
- Quarantine vault encryption (AES-256)
- No network requirements for core functionality

### 10.2 False Positive Handling

- Whitelist by hash (not path)
- Submit false positive reports
- Tiered detection (signature = confident, heuristic = flag)
- Clear user communication on confidence level

### 10.3 Privacy

- No file content uploads without explicit consent
- Hash-only cloud lookups (optional)
- Local-first operation
- Clear data retention policy

---

## 11. Development Phases

### Phase 1: Core Scanner (MVP)
- File hash matching against signature DB
- Basic registry autoruns check
- Quick/Full/Custom scan modes
- Quarantine and delete actions
- CLI interface
- Manual signature updates

### Phase 2: Enhanced Detection
- YARA rules integration
- Heuristic engine (PE analysis)
- Process scanner
- Browser extension scanning
- GUI application
- Automatic signature updates

### Phase 3: Advanced Features
- Boot-time scanning
- Real-time file monitor (optional)
- Network connection analysis
- Rootkit detection
- Cloud hash lookup
- API for integration

### Phase 4: Ecosystem
- Community signature sharing
- Plugin architecture
- Enterprise features (central management)
- Cross-platform (Linux/Mac)

---

## 12. Testing Strategy

### Test Cases

**Detection Testing**
- EICAR test file (standard AV test)
- Known malware samples (controlled environment)
- False positive corpus (legitimate software)
- Packed/obfuscated samples
- Living-off-the-land technique samples

**Remediation Testing**
- Locked file handling
- Permission-restricted files
- In-use DLLs
- Quarantine restore integrity

**Performance Testing**
- Scan speed benchmarks (files/second)
- Memory usage under load
- Large file handling
- Deep archive scanning

---

## Appendix A: Reference Signature Sources

**Free/Open Sources**
- VirusTotal (API for hash lookups)
- MalwareBazaar (abuse.ch)
- YARA rules repositories
- URLhaus (malicious URLs)
- PhishTank (phishing URLs)

**Hash Aggregators**
- abuse.ch
- malshare.com
- VirusShare (registration required)

---

## Appendix B: Useful Libraries

| Purpose | Library | Language |
|---------|---------|----------|
| PE Parsing | pefile, goblin | Python, Rust |
| YARA | yara-python, yara-rust | Python, Rust |
| Hashing | hashlib, ring | Python, Rust |
| Archive Handling | 7z SDK, zip | Various |
| GUI | egui, iced, Tauri | Rust |
| Process Info | psutil, sysinfo | Python, Rust |
| Registry | winreg | Python, Rust |
| Networking | reqwest | Rust |
| SQLite | rusqlite, sqlite3 | Rust, Python |
