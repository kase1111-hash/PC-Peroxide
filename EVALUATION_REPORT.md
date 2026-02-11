# PROJECT EVALUATION REPORT

**Primary Classification:** Underdeveloped
**Secondary Tags:** Good Concept, Partial Feature Creep

---

## CONCEPT ASSESSMENT

**Problem solved:** Provides a portable, no-install malware scanner for Windows that acts as a "second-opinion" alongside existing AV. Targets post-compromise cleanup, technician toolkits, and paranoid manual scans.

**User:** IT technicians, security-conscious power users, and incident responders who need a lightweight, self-contained scanner they can run from a USB stick without installation or persistent services.

**Is the pain real?** Yes. There is genuine demand for portable second-opinion scanners. Malwarebytes started here. The scenario of "AV failed, I need another tool to clean this up" is common in IT support.

**Is this solved better elsewhere?** Partially. Tools like Malwarebytes, HitmanPro, Emsisoft Emergency Kit, and ESET Online Scanner serve this niche. However, none are open-source Rust-based portable scanners. The open-source angle and Rust's safety guarantees are a legitimate differentiator — if the project ships.

**Value prop in one sentence:** A portable, open-source malware scanner written in Rust that provides signature, heuristic, and behavioral detection without requiring installation.

**Verdict:** Sound — the concept targets a real, validated niche. The Rust choice is appropriate for a security tool that needs to be fast, safe, and compile to a single binary. The portable/no-install constraint is a genuine differentiator versus bloated commercial alternatives.

---

## EXECUTION ASSESSMENT

### Architecture

The architecture is clean and well-structured. The module separation (`core/`, `detection/`, `scanner/`, `quarantine/`, `analysis/`, `ui/`, `utils/`) maps directly to the product's responsibilities. Each module has clear boundaries:

- `src/core/types.rs` — 510 lines of well-defined domain types with proper derives, Display impls, and serialization
- `src/core/error.rs` — 503 lines of comprehensive error types with `thiserror`, categorization, recoverability checks, and user-facing suggestions
- `src/detection/mod.rs` — Clean re-exports, engine composition
- `src/scanner/file.rs` — Parallel scanning with Tokio workers, cancellation support, progress tracking

Architecture complexity is *appropriate* for the stated goals. This is not over-engineered. The layered detection pipeline (hash → heuristic → YARA → behavioral) mirrors how real AV engines work.

### Code Quality

**Strengths:**
- All 298 tests pass, 0 failures
- Consistent Rust idioms: builder patterns (`with_description()`, `with_sha256()`), proper error propagation, `Arc<Mutex<>>` for shared state
- Tests cover real scenarios: quarantine+restore round-trip, duplicate detection, vault stats, EICAR, YARA rule matching
- Error handling is thorough — `Error` enum has 35+ variants covering every subsystem with categorization and recovery hints
- The quarantine vault (`src/quarantine/vault.rs`) is well-tested with 8 test cases covering quarantine, restore, delete, duplicates, stats
- YARA engine (`src/detection/yara/engine.rs`) has working default rules for ransomware, keyloggers, process injection, Cobalt Strike, credential stealers, crypto miners, and EICAR
- SQLite schema has proper migrations, indexes on hash columns, and foreign keys

**Weaknesses:**
- `src/main.rs:107` — `#[allow(clippy::too_many_arguments)]` on `run_scan()` with 10 parameters. Should be a struct.
- `format_bytes()` is duplicated in `src/main.rs:230`, `src/ui/report/pdf.rs:240`, and likely `src/ui/report/html.rs`. Should be in `utils/`.
- The `src/main.rs` at 1,255 lines is a monolithic CLI handler. Each `run_*` function could be extracted to a commands module.
- `run_scan()` has `_no_action` and `_yara` parameters (prefixed with underscore — unused). These are declared in the CLI but not wired up.
- The PDF reporter (`src/ui/report/pdf.rs`) generates raw PDF syntax manually instead of using a library. This produces technically valid but fragile PDFs. Acceptable for v0.1, questionable long-term.
- `full_scan()` at `src/scanner/file.rs:211` hardcodes drive letters `["C:\\", "D:\\", "E:\\"]` — should enumerate drives dynamically on Windows.
- The LLM analysis module (`src/analysis/`) exists and compiles but has no integration point in the scan pipeline — `run_scan()` never calls the analyzer. It's dead code in terms of the main workflow.
- Config `set` command at `src/main.rs:421` is unimplemented (`"Config modification not yet implemented"`)
- Signature updates (`run_update`) are unimplemented — both import (Phase 2) and online update (Phase 10)
- ~~Heuristic engine not wired~~ — **Correction:** `DetectionEngine.scan_file()` at `src/detection/matcher.rs:257-266` does call `HeuristicEngine.analyze_file()`. However, `FileScanner::new()` creates `DetectionEngine::new()` which hardcodes the heuristic threshold to 70, ignoring `config.detection.heuristic_threshold` and `config.detection.heuristic_sensitivity`. Config doesn't flow through.
- YARA engine is NOT wired into `DetectionEngine.scan_file()` — comment at `matcher.rs:269` says "Future: YARA rules". The 8 built-in rules (tested and working) never execute during a scan.

### Tech Stack

Appropriate choices throughout:
- **Rust** — correct for a security tool: memory safety, single binary, performance
- **Tokio** — async scanning with worker pool is well-implemented
- **rusqlite (bundled)** — SQLite for signatures and metadata is the standard choice; bundled avoids system dependency issues
- **goblin** — solid PE parser
- **aes-gcm** — proper authenticated encryption for quarantine
- **clap (derive)** — standard CLI framework
- **walkdir** — standard directory traversal

One concern: `reqwest` is pulled in for HTTP but update functionality is unimplemented. It adds OpenSSL/TLS dependencies to the binary for no current benefit.

### Build & Tests

- 298 tests, all passing
- Proper release profile (LTO, single codegen unit, strip symbols, opt-level 3)
- Cross-compilation config for both x86_64 and i686 Windows targets
- Test infrastructure uses `tempfile` for proper temporary file management
- No CI/CD pipeline (`.github/` has templates but no workflows)

**Verdict:** Execution partially matches ambition. The architecture and code quality are solid — this is well-written Rust by someone who knows the language. The detection pipeline runs hash matching and heuristic analysis, but YARA rules (8 working rules) are not connected, config settings don't flow to the detection engine, signature import is stubbed out, and config modification is unimplemented. The LLM module is completely disconnected. The codebase is a well-built chassis that's 80% wired — the remaining 20% is what separates it from a shippable multi-engine scanner.

---

## SCOPE ANALYSIS

**Core Feature:** File system scanning with signature-based malware detection and quarantine

**Supporting (directly enable core):**
- SQLite signature database with import/export (`src/detection/database.rs`)
- Hash matching engine (`src/detection/matcher.rs`)
- Quarantine vault with AES-256-GCM encryption (`src/quarantine/`)
- Whitelist management (`src/quarantine/whitelist.rs`)
- Scan result history and persistence (`src/scanner/results.rs`)
- Progress tracking and reporting (`src/scanner/progress.rs`)
- CLI interface (`src/ui/cli.rs`)

**Nice-to-Have (valuable, deferrable):**
- Heuristic analysis engine — PE parsing, entropy, import analysis (`src/detection/heuristic/`)
- YARA rule engine (`src/detection/yara/`)
- Scan result export — JSON, HTML, CSV (`src/ui/report/`)
- Configuration system (`src/core/config.rs`)
- Logging and retry utilities (`src/utils/`)

**Distractions (don't support core value yet):**
- Process scanning with memory analysis (`src/scanner/process/`) — this is runtime behavioral analysis, a fundamentally different capability than file scanning. It's built but serves a different use case.
- Network connection scanning (`src/scanner/network/`) — network monitoring is a different product category (NDR vs endpoint). The implementation is thin (port categorization) and doesn't add detection value.
- Browser extension scanning (`src/scanner/browser/`) — useful for a cleanup tool, but browser extension security is its own problem space. The implementation scans extension directories and checks for hijacks, which is tangentially related to malware removal.
- Persistence mechanism scanning (`src/scanner/persistence/`) — checking registry run keys and startup folders is legitimately useful for a cleanup tool, but it's a separate scanning vertical that doesn't integrate with the detection pipeline.

**Wrong Product (belong somewhere else):**
- LLM-powered analysis module (`src/analysis/`) — sending file contents to OpenAI/Ollama for malware classification is a fundamentally different approach. It requires network access (breaking the offline promise), depends on external services, and adds latency. More importantly, it's not wired into the scan pipeline. This is a research experiment, not a product feature.
- GUI application (`src/ui/gui/`) — 7 files for an egui-based GUI with dashboard, scan view, results view, quarantine view, settings view, and theme. This is premature when the core scanning pipeline is incomplete (heuristics not wired, updates not working). The GUI has a `// TODO: Spawn actual scan task` comment in `app.rs:488` — confirming it's non-functional.
- PDF report generation (`src/ui/report/pdf.rs`) — hand-rolled PDF generation from raw PDF primitives. This is a distraction. Users who need formal reports can use the HTML or JSON export and convert.

**Scope Verdict:** Feature Creep — mild but present. The project defines 10 development phases in `DEVELOPMENT_PHASES.md` and appears to have built scaffolding for Phases 1-3 simultaneously rather than completing Phase 1 fully. The core detection pipeline (hash + heuristic) works, but YARA rules aren't connected, config doesn't flow to the engine, and signature import is stubbed. Meanwhile, effort went to process scanning, network scanning, browser scanning, LLM integration, GUI, and PDF generation — widening the product instead of finishing the core pipeline.

---

## RECOMMENDATIONS

### CUT

- **`src/analysis/` (LLM module)** — Not integrated, breaks the offline promise, adds `reqwest` dependency weight. If LLM analysis is desired later, it belongs in a separate crate or behind a feature flag. Currently it's dead weight.
- **`src/ui/gui/` (GUI)** — Non-functional (TODO in app.rs:488). The CLI is the primary interface and it works. Ship the CLI, build GUI confidence later.
- **`src/ui/report/pdf.rs` (PDF generation)** — Hand-rolled PDF primitives are fragile and produce basic output. JSON and HTML exports cover reporting needs. If PDF is needed, use a library.

### DEFER

- **Process scanning** (`src/scanner/process/`) — Useful capability, but belongs in Phase 2 after the file scanning pipeline is complete with heuristics and YARA.
- **Network scanning** (`src/scanner/network/`) — Phase 3 feature. Thin implementation that doesn't add detection value currently.
- **Browser scanning** (`src/scanner/browser/`) — Phase 2 feature. Useful for cleanup scenarios but secondary to file detection.
- **Persistence scanning** (`src/scanner/persistence/`) — Keep accessible from CLI but defer integration with the detection pipeline.

### DOUBLE DOWN

- **Wire YARA into the detection pipeline** — `YaraEngine` has 8 working rules including ransomware, keylogger, injection, and EICAR detection. The engine works in tests but `DetectionEngine.scan_file()` never calls it (comment at `matcher.rs:269`: "Future: YARA rules"). This is the single highest-value change.
- **Flow config to DetectionEngine** — `FileScanner::new()` creates `DetectionEngine::new()` ignoring `config.detection.heuristic_threshold`, `enable_yara`, and `heuristic_sensitivity`. The heuristic engine IS connected but runs with hardcoded defaults instead of user settings.
- **Implement signature import** — The `run_update()` function is a stub, but `SignatureDatabase.import_file()` is fully implemented and tested. The stub just needs to call the existing method. Without this, the database ships with 4 example entries.
- **Implement config set** — `run_config set` prints "not yet implemented". Users can't change settings programmatically.
- **Wire `_no_action` and `_yara` CLI parameters** — These are declared in the CLI, accepted by clap, and silently ignored (underscore-prefixed unused parameters at `src/main.rs:115-116`).
- **Add CI** — 298 tests, zero CI. Add a GitHub Actions workflow for `cargo test` and `cargo clippy`.

### FINAL VERDICT: **Refocus**

The concept is sound, the code quality is high, and the architecture is clean. This is a well-built project that lost focus. The path forward is not to add more features — it's to finish connecting the engines that already exist.

The detection pipeline already runs hash matching and heuristic analysis. The immediate priority is wiring the YARA engine (8 tested rules) into `DetectionEngine.scan_file()`, connecting config settings to the engine, and implementing signature import (the backend method exists — the CLI stub just needs to call it).

**Next Step:** Wire `YaraEngine` into `DetectionEngine.scan_file()`, flow `DetectionConfig` settings from config to the engine, and connect the signature import CLI stub to the existing `SignatureDatabase.import_file()` method. These three changes (~70 LOC) complete the core detection pipeline. See `REFOCUS_PLAN.md` for the full implementation plan.
