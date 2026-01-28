# PC-Peroxide Software Audit Report

**Date:** 2026-01-28
**Auditor:** Claude Code Audit
**Version Audited:** v0.1.0 (commit 58948b8)

## Executive Summary

PC-Peroxide is a portable malware detection and removal utility for Windows systems. The codebase demonstrates **generally sound design and implementation** with proper use of Rust's safety features. However, several issues were identified that should be addressed to improve correctness, security, and fitness for purpose.

**Overall Assessment:** The software is **fit for its intended purpose** as a "second-opinion" scanner and technician toolkit, but with caveats noted below.

---

## 1. Correctness Issues

### 1.1 Critical Issues

**None identified.** The code uses Rust's type system and error handling effectively to prevent critical bugs.

### 1.2 Moderate Issues

#### Issue C1: Test Database Memory Leak
**Location:** `src/detection/matcher.rs:367-370`, `src/detection/database.rs:550-552`
**Description:** Test functions intentionally leak temporary directories using `std::mem::forget(dir)` to keep test databases alive.
```rust
std::mem::forget(dir);  // Memory leak in tests
```
**Impact:** Minor - only affects tests, not production code.
**Recommendation:** Use lazy_static or OnceCell for test fixtures, or restructure tests to properly manage lifetimes.

#### Issue C2: Potential Integer Overflow in Scan Rate Calculation
**Location:** `src/main.rs:209-211`
**Description:** Scan rate calculation uses integer division without checking for zero duration.
```rust
if summary.files_scanned > 0 && duration > 0 {
    let rate = summary.files_scanned as f64 / duration as f64;
```
**Impact:** Low - protected by the `> 0` check, but could cause issues with very short scans.
**Recommendation:** Already handled correctly; no change needed.

#### Issue C3: Unchecked Archive Scan Error
**Location:** `src/scanner/file.rs:482`
**Description:** Archive scan errors are silently ignored with `.ok()`.
```rust
}).ok();  // Errors silently ignored
```
**Impact:** Medium - malware inside corrupted archives could be missed.
**Recommendation:** Log archive scan failures for user awareness.

### 1.3 Minor Issues

#### Issue C4: EICAR Content Trimming Edge Case
**Location:** `src/detection/matcher.rs:44-51`
**Description:** The EICAR content check uses reverse iteration which may be less efficient for large files.
**Impact:** Low - EICAR files are typically small.

---

## 2. Security Assessment

### 2.1 Encryption Implementation (Quarantine)

**Assessment: SECURE**

The quarantine encryption implementation is **cryptographically sound**:
- Uses **AES-256-GCM** (authenticated encryption)
- 12-byte random nonces generated using `OsRng`
- Proper nonce prepending and extraction
- Key stored in separate file with no hardcoding

**Minor concern:** Key file (`vault.key`) permissions are not explicitly set. On shared systems, the key could potentially be read by other users.

**Recommendation:** Set restrictive file permissions (0600) when creating the key file.

### 2.2 Secure Deletion

**Assessment: ADEQUATE**

The secure delete implementation (`src/quarantine/operations.rs`):
- 3-pass random overwrite
- File rename before deletion
- Sync to ensure data written

**Limitation:** On SSDs and modern filesystems with wear leveling or copy-on-write, secure deletion is not fully guaranteed. This is a fundamental limitation, not a code issue.

### 2.3 Process Termination

**Assessment: SECURE**

Process termination uses proper system commands (`taskkill` on Windows, `kill -9` on Linux) rather than attempting unsafe memory manipulation.

### 2.4 Path Handling

**Assessment: SECURE**

- No command injection vulnerabilities found
- Path traversal protection via proper Path handling
- Environment variable expansion is controlled

---

## 3. Concurrency and Thread Safety

### 3.1 Database Locking

**Assessment: ADEQUATE WITH CAVEATS**

**Location:** `src/detection/database.rs`

The database uses `Arc<Mutex<Connection>>` for thread safety. This is correct but has performance implications:
- Every database operation acquires the mutex
- Long-running queries block other threads

**Recommendation for future:** Consider using connection pooling or WAL mode for better concurrent performance.

### 3.2 File Queue Handling

**Assessment: CORRECT**

**Location:** `src/scanner/file.rs:236-257`

The scan worker queue uses `Arc<Mutex<VecDeque>>` correctly:
- Lock is acquired briefly to pop items
- Lock poisoning is properly handled with clear error messages

### 3.3 Progress Tracking

**Assessment: CORRECT**

Uses `AtomicBool` for cancellation flag with proper `Ordering::SeqCst`.

---

## 4. Error Handling

### 4.1 Strengths

- Comprehensive error enum with contextual information
- Proper error propagation using `?` operator
- Category-specific exit codes
- User-friendly error suggestions via `suggestion()` method

### 4.2 Weaknesses

#### Issue E1: Silent Error Suppression
Several places suppress errors with `.ok()` or `let _ =`:
- `src/scanner/file.rs:482` - archive scanning
- `src/quarantine/vault.rs:172` - cleanup on failure
- Multiple handle close operations

**Recommendation:** Log warnings for suppressed errors that could indicate problems.

---

## 5. Heuristic Detection Quality

### 5.1 False Positive Mitigation

**Assessment: WELL DESIGNED**

Recent changes show good attention to false positive reduction:
- Trusted path detection with score reduction (0.5 multiplier)
- Legitimate packer recognition (UPX score reduced by 70%)
- Reduced scores for common legitimate APIs
- API combination detection (higher confidence)
- Diminishing returns formula for score inflation

### 5.2 Detection Thresholds

The default threshold of 70 appears reasonable:
- 0-20: Clean
- 21-50: Suspicious
- 51-80: Likely Malicious
- 81-100: Malicious

### 5.3 Potential False Negative Risk

**Concern:** Some suspicious APIs have very low or zero scores:
```rust
GetKeyState: 0      // Basic input
LoadLibrary: 0      // Used by malware loaders
GetProcAddress: 0   // Used by malware loaders
HttpSendRequest: 0  // C2 communication
```

While these are common in legitimate software, they're also essential for malware. The combination-based detection partially compensates.

---

## 6. Fitness for Purpose

### 6.1 Stated Purpose
Per documentation: "Lightweight, portable malware detection and removal utility" for:
- Post-compromise remediation
- Second-opinion scanning
- Technician toolkit

### 6.2 Assessment: FIT FOR PURPOSE

**Strengths:**
1. **Portability:** Single executable, no installation required
2. **Offline capability:** Signature database is local
3. **Multiple detection methods:** Signature, heuristic, YARA, LLM
4. **Comprehensive scanning:** Files, registry, processes, network, browser
5. **Safe remediation:** Quarantine with encryption before deletion
6. **Good CLI/GUI support:** Professional tooling

**Limitations:**
1. **Windows-only:** Linux/macOS support limited to development/testing
2. **No real-time protection:** On-demand only (by design)
3. **Signature database:** Requires manual updates, no bundled signatures
4. **Network scanning:** IP reputation checking not implemented (`TODO` comment)

### 6.3 Comparison to Purpose

| Capability | Required | Implemented | Notes |
|------------|----------|-------------|-------|
| Portable execution | Yes | Yes | Single binary |
| Offline operation | Yes | Yes | Local database |
| File scanning | Yes | Yes | Quick/Full/Custom modes |
| Signature detection | Yes | Yes | Hash-based |
| Heuristic detection | Yes | Yes | PE analysis, entropy |
| Process scanning | Yes | Yes | With memory patterns |
| Persistence detection | Yes | Yes | Registry, startup, tasks |
| Quarantine | Yes | Yes | Encrypted vault |
| Safe deletion | Yes | Yes | Multi-pass overwrite |
| Reporting | Yes | Yes | JSON/HTML/CSV/PDF |

---

## 7. Recommendations

### 7.1 High Priority

1. **Add warning logs for suppressed errors** - Archive scan failures and cleanup errors should be logged.

2. **Set key file permissions** - Explicitly set restrictive permissions on `vault.key`.

3. **Document signature database requirements** - Users need to know the tool requires importing signatures.

### 7.2 Medium Priority

4. **Implement IP reputation checking** - The `is_ip_suspicious` function has a TODO.

5. **Consider database connection pooling** - For performance in multi-threaded scenarios.

6. **Add API combination detection for common evasion** - Enhance detection of `LoadLibrary` + `GetProcAddress` patterns when combined with other indicators.

### 7.3 Low Priority

7. **Fix test memory leaks** - Use proper fixtures instead of `mem::forget`.

8. **Add telemetry/metrics** - Track scan performance and detection rates.

9. **Consider ASLR/DEP bypass detection** - ROP gadget scanning for advanced threats.

---

## 8. Code Quality

### 8.1 Positive Observations

- Well-organized module structure
- Comprehensive documentation comments
- Good test coverage for core functionality
- Proper use of Rust idioms (Result, Option, traits)
- Builder patterns for configuration
- No unsafe code in critical paths

### 8.2 Areas for Improvement

- Some functions are quite long (e.g., `run_scan` with 8 parameters)
- Test fixture management could be cleaner
- Some TODO comments remain in production code

---

## 9. Conclusion

PC-Peroxide is a **well-designed and implemented** malware detection tool that is **fit for its stated purpose** as a second-opinion scanner and technician utility. The codebase demonstrates mature Rust practices with proper error handling, thread safety, and security considerations.

The main areas for improvement are:
1. Better error visibility (logging suppressed errors)
2. Completing TODO items (IP reputation)
3. Minor security hardening (key file permissions)

**No critical issues were found that would prevent production use.** The software can be recommended for its intended use cases with the understanding that it is designed as a supplementary tool, not a replacement for real-time antivirus protection.

---

*End of Audit Report*
