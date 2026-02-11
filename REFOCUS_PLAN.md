# REFOCUS PLAN

Concrete implementation plan to ship PC-Peroxide as a credible multi-engine scanner. Ordered by impact. Each step is independently shippable.

---

## Correction from Evaluation Report

The evaluation report incorrectly stated that the heuristic engine is not wired into scanning. `DetectionEngine.scan_file()` at `src/detection/matcher.rs:247-266` **does** call `HeuristicEngine.analyze_file()`. The actual gaps are more targeted than initially stated.

---

## STEP 1: Wire YARA into the Detection Pipeline

**Impact:** High — activates 8 built-in rules (ransomware, keylogger, injection, Cobalt Strike, credential stealer, crypto miner, EICAR, shellcode) that are tested and working but never called during scans.

**Current state:**
- `YaraEngine` exists at `src/detection/yara/engine.rs` with `scan_file()` and `scan_data()` methods
- `DetectionEngine` at `src/detection/matcher.rs:202-307` has no reference to `YaraEngine`
- Comment at `matcher.rs:269`: `// 3. Future: YARA rules, behavioral analysis`

**Changes:**

1. **`src/detection/matcher.rs`** — Add `YaraEngine` to `DetectionEngine`:
   - Add field: `yara_engine: Option<crate::detection::yara::YaraEngine>`
   - In `new()`: initialize with `YaraEngine::with_default_rules().ok()`
   - In `with_settings()`: accept `yara_enabled: bool` parameter
   - In `scan_file()`: after heuristic check (line 266), add YARA scan step:
     ```
     // 3. YARA rules
     if let Some(ref yara) = self.yara_engine {
         let matches = yara.scan_file(path)?;
         if let Some(best) = pick_highest_severity_match(&matches) {
             return Ok(Some(yara_match_to_detection(path, best)));
         }
     }
     ```
   - Add helper `yara_match_to_detection()` converting `RuleMatch` → `Detection` using `meta.severity` and `meta.category`
   - In `ScanDetails`: add `yara_matches: Vec<RuleMatch>` field, populate in `scan_file_detailed()`

2. **`src/detection/mod.rs`** — Re-export `YaraEngine` (already done)

3. **Tests** — Add test in `matcher.rs`:
   - Create temp file with EICAR content → `engine.scan_file()` should return YARA match if hash isn't found first
   - Create temp file with ransomware strings + MZ header → should trigger `Ransomware_Generic` rule

**Files touched:** `src/detection/matcher.rs`
**Estimated scope:** ~40 lines of production code, ~30 lines of tests

---

## STEP 2: Flow Config into Detection Engine

**Impact:** Medium — currently `DetectionConfig.heuristic_threshold`, `enable_yara`, and `heuristic_sensitivity` exist in config but are ignored.

**Current state:**
- `FileScanner::new()` at `src/scanner/file.rs:57-66` creates `DetectionEngine::new(db)` — ignoring all config
- `Config.detection` has `heuristic_threshold: u8`, `enable_yara: bool`, `heuristic_sensitivity: Sensitivity`
- `DetectionEngine::with_settings()` exists but is never called

**Changes:**

1. **`src/scanner/file.rs`** — In `FileScanner::new()`, replace:
   ```rust
   DetectionEngine::new(Arc::new(db))
   ```
   with:
   ```rust
   DetectionEngine::with_settings(
       Arc::new(db),
       config.detection.heuristic_threshold,
       true, // heuristic always enabled
       config.detection.enable_yara,
   )
   ```

2. **`src/detection/matcher.rs`** — Update `with_settings()` to accept `yara_enabled`:
   ```rust
   pub fn with_settings(
       db: Arc<SignatureDatabase>,
       heuristic_threshold: u8,
       heuristic_enabled: bool,
       yara_enabled: bool,
   ) -> Self {
       Self {
           hash_matcher: HashMatcher::new(db),
           heuristic_engine: HeuristicEngine::new(),
           heuristic_threshold,
           heuristic_enabled,
           yara_engine: if yara_enabled {
               YaraEngine::with_default_rules().ok()
           } else {
               None
           },
       }
   }
   ```

**Files touched:** `src/scanner/file.rs`, `src/detection/matcher.rs`
**Estimated scope:** ~15 lines changed

---

## STEP 3: Wire Unused CLI Parameters

**Impact:** Medium — `--no-action` and `--yara` flags are accepted by clap but silently ignored, which is misleading to users.

**Current state:**
- `run_scan()` at `src/main.rs:108` has parameters `_no_action: bool` and `_yara: Option<PathBuf>` (underscore-prefixed, unused)

**Changes:**

1. **`--yara <PATH>` flag:**
   - Load custom YARA rules from the provided path into the engine
   - After creating `FileScanner`, if `yara` path is provided, call `engine.load_rules_file(path)` on the detection engine's YARA engine
   - This requires either exposing the engine or passing the rules path through to `FileScanner`
   - Simplest approach: add `FileScanner::load_yara_rules(&self, path: &Path)` method that delegates to the inner `DetectionEngine`'s `YaraEngine`

2. **`--no-action` flag:**
   - When `no_action` is true, skip auto-quarantine/delete after detection
   - Currently there is no auto-action in `run_scan()` anyway (scan is report-only), so this flag is effectively always on
   - For now: add a log message when `no_action` is true, and document that this flag suppresses future auto-remediation
   - Long-term: when auto-quarantine is implemented (per `ActionConfig.auto_quarantine_critical`), this flag should override it

**Files touched:** `src/main.rs`, `src/scanner/file.rs` (minor)
**Estimated scope:** ~25 lines

---

## STEP 4: Implement Signature File Import

**Impact:** High — without this, the scanner ships with 4 example signatures. The `import` command and `SignatureFile::load()` logic exist but are never called from the CLI.

**Current state:**
- `run_update()` at `src/main.rs:397-411`: both `import` and online update print "not yet implemented"
- `SignatureDatabase::import_file()` at `src/detection/database.rs:403-406` is fully implemented and tested
- `SignatureFile::load()` parses JSON signature files
- `data/signatures.json` has the expected format

**Changes:**

1. **`src/main.rs` — `run_update()`:**
   - Replace the import stub with:
     ```rust
     if let Some(path) = import {
         let db = SignatureDatabase::open_default()?;
         let result = db.import_file(&path)?;
         println!("{}", result);
         return Ok(());
     }
     ```
   - This fully connects the existing import pipeline

2. **Auto-import default signatures on first run:**
   - In `FileScanner::new()`, after opening the database, check if it's empty (`info().signature_count == 0`)
   - If empty and `data/signatures.json` exists (or is embedded), import it automatically
   - This ensures out-of-box detection without requiring manual import

**Files touched:** `src/main.rs`, optionally `src/scanner/file.rs`
**Estimated scope:** ~15 lines

---

## STEP 5: Implement Config Set

**Impact:** Low-medium — users currently cannot change settings from the CLI.

**Current state:**
- `run_config(ConfigAction::Set { key, value })` at `src/main.rs:419-423` prints "not yet implemented"
- `Config` supports load/save/validate

**Changes:**

1. **`src/main.rs` — `run_config()`:**
   - Parse `key` as a dotted path (e.g., `scan.skip_large_files_mb`)
   - Load config as `serde_json::Value`, traverse the path, set the value, validate, save
   - Implementation:
     ```rust
     ConfigAction::Set { key, value } => {
         let config_path = Config::default_config_path();
         let mut config = Config::load_or_default();
         let json_str = serde_json::to_string(&config)?;
         let mut json: serde_json::Value = serde_json::from_str(&json_str)?;

         // Navigate dotted path
         let parts: Vec<&str> = key.split('.').collect();
         let mut target = &mut json;
         for part in &parts[..parts.len()-1] {
             target = target.get_mut(part)
                 .ok_or_else(|| Error::ConfigInvalid {
                     field: key.clone(),
                     message: format!("Unknown config section: {}", part),
                 })?;
         }
         let field = parts.last().unwrap();

         // Parse value as JSON or string
         let parsed: serde_json::Value = serde_json::from_str(&value)
             .unwrap_or(serde_json::Value::String(value.clone()));
         target[field] = parsed;

         // Deserialize back, validate, save
         let updated: Config = serde_json::from_value(json)?;
         updated.validate()?;
         updated.save(&config_path)?;
         println!("Set {} = {}", key, value);
     }
     ```

**Files touched:** `src/main.rs`
**Estimated scope:** ~30 lines

---

## STEP 6: Aggregate Multi-Engine Results

**Impact:** Medium — currently `scan_file()` returns after the first detection (hash OR heuristic OR YARA). A file matching both a signature and YARA rules only reports the signature match. Aggregation provides richer results and higher confidence.

**Current state:**
- `scan_file()` returns `Option<Detection>` — first hit wins
- `scan_file_detailed()` exists and collects results from hash + heuristic, but is never called

**Changes:**

1. **`src/detection/matcher.rs`** — Update `scan_file_detailed()` to also run YARA
2. **`src/scanner/file.rs`** — In `scan_file_sync()`, optionally use `scan_file_detailed()` and `primary_detection()` instead of `scan_file()` — this requires no API change since `primary_detection()` already returns `Option<Detection>`
3. **Future enhancement:** Change `scan_file()` to return `Vec<Detection>` for full multi-engine results. Defer this since it's an API change that touches many callers.

**Files touched:** `src/detection/matcher.rs`, `src/scanner/file.rs`
**Estimated scope:** ~20 lines

---

## STEP 7: Add CI Pipeline

**Impact:** Medium — 298 tests, zero automation. Any contributor can break the build without knowing.

**Changes:**

1. **`.github/workflows/ci.yml`:**
   ```yaml
   name: CI
   on: [push, pull_request]
   jobs:
     test:
       runs-on: ubuntu-latest
       steps:
         - uses: actions/checkout@v4
         - uses: dtolnay/rust-toolchain@stable
         - run: cargo test
         - run: cargo clippy -- -D warnings
         - run: cargo fmt --check
   ```

2. **Optional:** Add Windows runner for platform-specific tests

**Files touched:** `.github/workflows/ci.yml` (new)
**Estimated scope:** ~20 lines

---

## DEFERRED (do not implement now)

These are explicitly out of scope for the refocus. They are tracked here so they don't creep back in.

| Item | Reason to Defer |
|------|----------------|
| Online signature updates | Requires server infrastructure, GPG signing. Import-from-file covers the need. |
| GUI scan integration | GUI has a TODO placeholder. CLI is the shipping interface. |
| LLM analysis integration | Breaks offline promise, requires external service. Keep as opt-in experiment. |
| PDF report generation | JSON and HTML cover reporting needs. |
| Process/network/browser scan integration with detection pipeline | These are separate scan verticals. They work independently via CLI subcommands. Integrating into file scan adds complexity without detection value. |
| Boot-time scanning | Phase 3+ feature requiring Windows PE environment. |
| Real-time file monitoring | Different product category (EDR vs scanner). |

---

## Implementation Order

```
Step 1: Wire YARA → DetectionEngine        (HIGH impact, ~40 LOC)
Step 4: Implement signature import          (HIGH impact, ~15 LOC)
Step 2: Flow config → DetectionEngine       (MED impact, ~15 LOC)
Step 3: Wire unused CLI params              (MED impact, ~25 LOC)
Step 5: Implement config set                (MED impact, ~30 LOC)
Step 6: Aggregate multi-engine results      (MED impact, ~20 LOC)
Step 7: Add CI                              (MED impact, ~20 LOC)
                                            ─────────────────────
                                    Total:  ~165 LOC production code
```

Steps 1 and 4 are the critical path. After those two, PC-Peroxide becomes a working three-engine scanner (hash + heuristic + YARA) with an importable signature database. The remaining steps are quality-of-life improvements.
