# Change Log — MITRE ATT&CK Local Lookup, LLM Diagnostic Logging & Ingester Hardening

**Date:** 2026-04-18
**Primary Files Modified:** `plugins/log_analysis/threat_intel_ingester/tool.py`, `framework/reference_data/mitre_attack.py` (new), `framework/cli/shell.py`, `framework/logging/structured.py`
**Supporting Files:** `scripts/build_mitre_lookup.py`, `scripts/verify_mitre_lookup.py`, `plugins/log_analysis/threat_intel_ingester/schemas/output.schema.json`, `plugins/log_analysis/threat_intel_ingester/README.md`, `framework/reference_data/__init__.py` (new), `framework/reference_data/README.md`

---

## Overview

Four areas of work across this session, driven by a production run where the
`threat_intel_ingester` silently fell back to regex-only IOC extraction and
produced output missing MITRE mappings and attack graph data, with no clear
indication in the CLI or GCP activity logs of what went wrong:

1. **Local MITRE ATT&CK technique database** — Built a compact lookup of all
   Enterprise + ICS ATT&CK techniques (v18.1, 774 entries) from official MITRE
   STIX bundles. Used to enrich, backfill, and validate LLM-generated technique
   data without relying on the LLM for reference accuracy.

2. **LLM-hallucinated technique ID marking** — Technique IDs not found in the
   official ATT&CK matrix are now marked with `"mitre_validated": false` and a
   visible `(non-ATT&CK ID)` suffix so frontline analysts can see at a glance
   which technique IDs were LLM-generated, without needing access to tool logs.

3. **LLM diagnostic logging fixes** — Fixed a pre-truncation bug where
   `response_text[:500]` was passed to `log_llm_interaction` before the function
   could measure the actual response length, making `response_length` always
   report ≤500 regardless of the real value. Added activity-level logging for
   JSON parse failures so they appear in GCP Cloud Logging alongside the
   original LLM call.

4. **ToolResult completeness & fallback visibility** — Added `attack_graph` to
   the `ToolResult.result` dict (previously only in the artifact file) and added
   `ingestion_mode` to the summary so the CLI clearly shows when the tool fell
   back to regex-only extraction.

5. **Shared MITRE module** — Extracted the MITRE lookup from the plugin into
   `framework/reference_data/mitre_attack.py` so all plugins can use it.
   Moved `mitre_techniques.json` to `framework/reference_data/`. Wired the
   database into `ReferenceDataView` for protocol-based access.

---

## Changes

### `scripts/build_mitre_lookup.py` — MITRE STIX Download & Extraction

**Purpose:** One-time setup script that downloads the Enterprise and ICS
ATT&CK STIX bundles from the official MITRE CTI GitHub repository and writes
a compact JSON lookup file.

**Changes:**
- Created the script with `_extract_techniques()` to parse STIX 2.x bundles
  and extract technique ID, name, tactics list, URL, matrix tag, and
  deprecation status.
- Initially pinned to ATT&CK v16.1; updated to **ATT&CK v18.1** after
  discovering the prior version was missing recent techniques.
- Output path updated from
  `plugins/log_analysis/threat_intel_ingester/data/mitre_techniques.json` to
  `framework/reference_data/mitre_techniques.json` when the lookup was
  promoted to a shared framework module.
- Produces 774 techniques (691 Enterprise + 83 ICS).

---

### `framework/reference_data/mitre_attack.py` — Shared MITRE Module (New)

**Purpose:** Central Python module providing MITRE ATT&CK technique data to
all Event Mill plugins and framework code.

**Public API:**
- `get_mitre_db() → dict[str, dict]` — Loads the compact technique lookup from
  `mitre_techniques.json`. Cached after first call (module-level singleton).
  Returns empty dict with a warning if the data file hasn't been built yet.
- `validate_technique_id(tid) → bool` — Returns True if the technique ID
  exists in the official ATT&CK matrix.
- `enrich_technique(tid) → dict` — Returns metadata (name, tactics, URL) for
  a technique ID, or empty dict if not found.
- `technique_count() → int` — Returns the number of loaded techniques.
- `_reset()` — Test-only function to clear the cached database.

**Design decisions:**
- Lazy-loaded singleton avoids startup cost when MITRE data isn't needed.
- Logger: `eventmill.reference_data.mitre` (distinct from plugin loggers).
- Graceful degradation: missing data file → empty dict + warning, not an error.

---

### `framework/reference_data/__init__.py` — Package Init (New)

- Exports `get_mitre_db`, `validate_technique_id`, `enrich_technique` for
  convenient imports: `from framework.reference_data import get_mitre_db`.

---

### `framework/reference_data/README.md` — Updated Documentation

- Replaced placeholder content listing files that didn't exist yet
  (`mitre_attack_enterprise.json`, `attack_chain_patterns.json`) with accurate
  descriptions of the current contents.
- Added two usage patterns: `context.reference_data.get("mitre_techniques")`
  for plugin protocol access, and direct import for any Python code.
- Added one-time setup instructions for `build_mitre_lookup.py`.

---

### `framework/cli/shell.py` — ReferenceDataView Wiring

**Problem:** `ReferenceDataView` was created empty (`ReferenceDataView()`) for
every tool execution, making `context.reference_data` useless.

**Fix:**
- Added import: `from ..reference_data.mitre_attack import get_mitre_db`.
- Changed `ReferenceDataView()` to
  `ReferenceDataView({"mitre_techniques": get_mitre_db()})` so all plugins
  can access the MITRE database via `context.reference_data.get("mitre_techniques")`.

---

### `plugins/log_analysis/threat_intel_ingester/tool.py` — Reconciliation, Validation & Diagnostics

This file received the most changes, organized into four functional areas:

#### A. MITRE Reconciliation (`_reconcile_mitre_mappings`)

**Purpose:** Post-process LLM-generated MITRE mappings using the local ATT&CK
database to fix gaps the LLM commonly leaves.

**Three-step process:**

1. **Backfill** (Step 1) — Technique IDs referenced in `attack_graph`
   paths/`leads_to` but missing from `mitre_mappings` are added with metadata
   from the local lookup. Each backfill is logged:
   ```
   [RECONCILE] Backfilled technique T1003.006 (DCSync, tactic=Credential Access)
   from attack_graph path 'ecrime-ransomware' | local_lookup=hit
   ```

2. **Enrich** (Step 2) — Entries with empty `technique_name` or `tactic` are
   filled from the local lookup. Common when the LLM returns IOC-derived entries
   with a technique ID but no metadata. Each enrichment is logged:
   ```
   [RECONCILE] Enriched T1190: name='Exploit Public-Facing Application',
   tactic='Initial Access' | from local MITRE lookup
   ```

3. **Validate** (Step 3) — Every technique ID is checked against the local
   ATT&CK database:
   - Found → `"mitre_validated": true`
   - Not found → `"mitre_validated": false`, technique name annotated with
     `(non-ATT&CK ID)`, warning logged:
     ```
     [RECONCILE] Unvalidated technique T1655 (Help-Desk Fraud (non-ATT&CK ID))
     — not found in ATT&CK v18.1 (DB has 774 techniques).
     Keeping entry but marking as non-ATT&CK.
     ```

**Reconciliation summary logged at end:**
```
[RECONCILE] Summary: 2 backfilled, 3 enriched, 1 unvalidated,
21 total mitre_mappings (local DB has 774 techniques)
```

**Design decision — why mark instead of remove:** LLM-hallucinated technique
IDs (e.g., T1655 "Help-Desk Fraud" from the CrowdStrike Scattered Spider
report) often describe real adversary behaviors that ATT&CK hasn't catalogued.
Removing them loses that intelligence. Marking them lets analysts see both the
inferred behavior and the fact that the ID is non-standard.

#### B. Local MITRE Loader Extraction

- Removed the 40-line `_get_mitre_db()` function, `_MITRE_DATA_FILE` constant,
  and `_MITRE_TECHNIQUE_DB` module-level variable.
- Replaced with a single import:
  `from framework.reference_data.mitre_attack import get_mitre_db as _get_mitre_db`
- All call sites (`_reconcile_mitre_mappings`, enrichment steps) unchanged.

#### C. LLM Activity Logging Fixes

**Problem 1 — Pre-truncation hid actual response length:**

Both `log_llm_interaction` calls (native PDF at line 884, chunked at line 1045)
were passing `response_text[:500]` instead of the full response. Since
`log_llm_interaction` computes `response_length = len(response_text)`, the GCP
activity log always showed `response_length: 500` (or less) regardless of
whether the LLM returned 500 chars or 50,000 chars. This made it impossible
to diagnose truncated responses from the activity log alone.

**Fix:** Removed `[:500]` from both calls. `log_llm_interaction` already
truncates the preview internally (line 326-328 of `structured.py`), so the
preview field is still bounded at 500 chars, but `response_length` now reports
the true response size.

**Problem 2 — JSON parse failures invisible in GCP activity log:**

When `_parse_llm_json` returned `None` (unparseable response), the diagnostic
warning went to logger `eventmill.plugin.threat_intel_ingester` — a different
log stream than the `eventmill.activity` log visible in GCP Cloud Logging.
Operators filtering on `logName: eventmill-activity` saw the LLM call succeed
but had no record of the subsequent parse failure.

**Fix:** Added a second `log_llm_interaction` call in the native PDF parse
failure path with:
- `prompt="[ti_ingester native_pdf] JSON_PARSE_FAILED"`
- `error=f"JSON parse failed on {len(response)}-char response. first_100=..."`
- Full response text passed for accurate `response_length`

This creates a second activity log entry that's clearly marked as a failure,
making the parse failure visible without checking the plugin log.

#### D. ToolResult Completeness

**Problem 1 — `attack_graph` missing from ToolResult:**

The `attack_graph` was written to the artifact file (line 1218) but was not
included in the `ToolResult.result` dict returned to the CLI. This meant:
- `summarize_for_llm` could never display attack graph info (line 1332-1339
  always got `{}` from `r.get("attack_graph", {})`)
- `_auto_persist_result` would lose the attack graph if it triggered
- Downstream consumers of the ToolResult had no access to attack graph data

**Fix:** Added `"attack_graph": attack_graph` to the ToolResult's `result`
dict alongside `iocs` and `mitre_mappings`.

**Problem 2 — No indication of regex-only fallback:**

When the LLM failed and the tool fell back to regex-only IOC extraction, the
CLI showed `✓ Completed successfully` with a generic summary. There was no
visible indication that the results were degraded.

**Fix:**
- Added `ingestion_mode` variable: set to `"llm"` by default, changed to
  `"regex_only"` when entering the fallback path.
- Added `"ingestion_mode"` to the `summary` dict in ToolResult.
- Added a check in `summarize_for_llm`: when `ingestion_mode == "regex_only"`,
  appends a warning:
  ```
  WARNING: LLM analysis failed — results are regex-only
  (low confidence, no MITRE mapping, no attack graph).
  Check logs for LLM failure details.
  ```

---

### `plugins/log_analysis/threat_intel_ingester/schemas/output.schema.json` — Schema Update

- Added `mitre_validated` boolean field to the `mitre_mappings` item schema
  with description explaining that `false` indicates an LLM-generated ID not
  found in the official ATT&CK matrix.

---

### `plugins/log_analysis/threat_intel_ingester/README.md` — Documentation Updates

- **Prerequisites section:** Added step 3 documenting the one-time
  `build_mitre_lookup.py` setup, what it downloads, where it writes, and what
  the plugin uses it for (enrich, backfill, validate).
- **Reference Data Overrides:** Updated to point to
  `framework/reference_data/mitre_techniques.json` and the shared module.
- **Chunked text extraction:** Corrected stale chunk size reference from
  ~3500 to ~6000 characters.

---

### `scripts/verify_mitre_lookup.py` — Verification Script (New)

- Quick-check script that validates a list of technique IDs from a CrowdStrike
  report against the local MITRE database.
- Used during development to confirm T1655 ("Help-Desk Fraud") was not in
  ATT&CK v18.1 (confirmed as LLM hallucination).
- Updated DB path from plugin `data/` to `framework/reference_data/`.

---

## Root Cause Analysis — Missing MITRE Mappings in v2 Output

The investigation that prompted these changes centered on why
`crowdstrikegeminiv2.json` contained only regex-extracted IOCs with no MITRE
mappings or attack graph, while `crowdstrikegemini.json` (same PDF) had full
LLM-enriched output.

**Finding:** The code changes (MITRE lookup + reconciliation) were **not** the
cause. All reconciliation logic runs downstream of the LLM calls and cannot
affect whether the LLM succeeds. The v2 run's LLM either timed out, hit a
rate limit, or returned an unparseable response, triggering the regex-only
fallback.

**Contributing factor — logging gap:** The pre-truncation bug
(`response_text[:500]`) made the GCP activity log report `response_length: 500`
for every run, masking whether the response was genuinely truncated or full-size.
After fixing this, the subsequent run showed `response_length: 18060` — a
healthy full response confirming the v2 failure was transient.

**Verified:** A third test run (`crowdstrikegeminiv3.json`) produced complete
output with 16 CVE IOCs, 21 MITRE mappings (all `mitre_validated: true`), and
4 attack graph paths with convergence at T1078 (Valid Accounts).

---

## File Movement

| From | To | Reason |
|------|----|--------|
| `plugins/log_analysis/threat_intel_ingester/data/mitre_techniques.json` | `framework/reference_data/mitre_techniques.json` | Shared across plugins |

---

## Test Results

285 tests passing, 0 failures, 0 modifications to existing tests.

---

## What's Next

- Other plugins (`attack_path_visualizer`, `risk_assessment_analyzer`,
  `threat_model_analyzer`) can now import `get_mitre_db()` or use
  `context.reference_data.get("mitre_techniques")` for technique validation.
- Consider adding `mitre_validated` filtering to the attack path visualizer
  to flag non-ATT&CK nodes in rendered graphs.
- Monitor GCP activity logs for future JSON parse failures now that they're
  visible in the activity log stream.
