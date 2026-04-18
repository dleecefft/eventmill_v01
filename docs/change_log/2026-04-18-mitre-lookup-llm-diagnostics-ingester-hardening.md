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

## Session 2 — Multi-Role Tactic Mapping Refactor

**Date:** 2026-04-18 (continued)
**Primary Files Modified:** `plugins/log_analysis/threat_intel_ingester/tool.py`, `plugins/threat_modeling/attack_path_visualizer/tool.py`
**Supporting Files:** `plugins/log_analysis/threat_intel_ingester/schemas/output.schema.json`, `plugins/log_analysis/threat_intel_ingester/README.md`, `plugins/log_analysis/threat_intel_ingester/examples/response.example.json`, both plugin `tests/test_contract.py` files

### Problem

The `mitre_mappings` array used `technique_id` as an implicit identity key —
each technique could appear at most once. When an LLM reported the same
technique serving different tactical roles in different attack paths (e.g.,
T1078 "Valid Accounts" as both "Initial Access" and "Persistence"), the
reconciler flattened to `tactics[0]` and discarded the per-path context.
The visualizer then rendered a single node, losing the multi-role insight.

### Changes

#### A. `_merge_llm_chunk_results()` — Dedup Key Change

- Changed dedup key from `technique_id` alone to `(technique_id, tactic)`.
- Two chunks can now each contribute a T1078 entry with different tactics and
  both survive the merge.

#### B. `_reconcile_mitre_mappings()` — Full Rewrite

Identity key changed to `(technique_id, tactic)`. Three-step process updated:

1. **Backfill** — Scans all `(tid, tactic)` pairs from attack graph steps.
   Existing exact matches get `context_paths` populated. Empty-tactic entries
   are promoted when a graph step provides the tactic. New `(tid, tactic)`
   pairs are created as backfill entries.
2. **Enrich** — Same as before, but logs a warning when a technique has
   multiple valid tactics and no graph context to disambiguate.
3. **Validate** — Now also checks the assigned tactic against the technique's
   allowed tactics list, logging warnings for mismatches that may indicate
   LLM hallucinations. Summary line includes tactic mismatch count.

New fields on mapping entries:
- `context_paths: list[str]` — attack graph path IDs where this `(tid, tactic)`
  pair appears.

#### C. LLM Prompt Update (Section 4)

- Added explicit instruction that the same technique ID can appear multiple
  times in `additional_mitre_techniques` with different tactics when it serves
  different roles — "This is expected, not a duplication error."
- Updated JSON response format example with T1078 appearing twice (Initial
  Access + Persistence) to demonstrate the expected pattern.

#### D. `execute()` Summary — `unique_technique_count`

- Added `unique_technique_count` (count of distinct `technique_id` values)
  alongside the existing `mitre_technique_count` (total role entries).

#### E. `summarize_for_llm()` — Multi-Role Display

- When `unique_technique_count != mitre_technique_count`, the summary reads:
  `"Mapped to 5 unique techniques across 7 tactical roles: T1078 (Initial Access, Persistence), ..."`
- When counts match, the standard format is preserved:
  `"Mapped to 5 MITRE techniques: T1078 (Valid Accounts), ..."`

#### F. `attack_path_visualizer/tool.py` — Composite Node Keys

- New helper `_node_key(tid, tactic) -> str` produces composite keys like
  `T1078|initial-access` so the same technique with different tactics becomes
  distinct DAG nodes.
- `_build_dag_from_attack_graph()` rewritten to:
  - Build metadata lookup keyed by `(technique_id, tactic)` with fallback by
    `technique_id` alone.
  - Build per-path step mapping for `leads_to` edge resolution.
  - Create nodes keyed by composite `tid|tactic-slug`.
  - Resolve `leads_to` targets within per-path context to connect to the
    correct tactic-specific node.
- `_render_mermaid_dag()` updated:
  - Node labels use `node.technique_id` instead of composite key.
  - Convergence/branch matching uses `node.technique_id` (plain IDs from LLM);
    entry/exit matching uses composite keys (computed by builder).
  - Convergence legend searches by `node.technique_id`.
- `_render_ascii_dag()` updated with same fixes.

#### G. Em-Dash Encoding Fix

- Replaced Unicode em-dash (`\u2014`) with ASCII ` - ` in Mermaid labels,
  ASCII header, and path legend lines. Prevents mojibake (`â€"`) when output
  is decoded as CP1252 on Windows terminals.

#### H. Schema & Documentation

- `output.schema.json`:
  - `mitre_mappings` description updated to document `(technique_id, tactic)` identity key.
  - Added `context_paths` property definition.
  - Added `unique_technique_count` to summary properties.
- `README.md`:
  - Added "Multi-Role Tactic Mappings" subsection under Prerequisites.
  - Added tactic validation bullet point.
  - Updated `summarize_for_llm()` example output.
- `response.example.json`:
  - Added `context_paths` to two entries.
  - Added `unique_technique_count` to summary.

#### I. New Contract Tests

**threat_intel_ingester** (9 new tests):
- `TestMergeMultiRole` — same tid with different tactics preserved; exact
  duplicates deduplicated.
- `TestReconcileMultiRole` — context_paths populated; new tactic backfilled;
  empty tactic promoted; leads_to orphan backfilled.
- `TestSummarizeMultiRole` — multi-role shows both counts; single-role shows
  standard format.

**attack_path_visualizer** (6 new tests):
- `TestMultiRoleDAG` — distinct nodes for same technique; total node count;
  both tactic labels in Mermaid output; both in ASCII; convergence styling
  by technique_id; `_node_key` helper correctness.

---

## Test Results

299 tests passing (232 plugin + 67 framework), 0 failures.

---

## What's Next

- Monitor production runs for tactic mismatch warnings to gauge LLM
  hallucination rate on tactic assignment.
- Consider adding `context_paths` filtering to `attack_path_visualizer`
  to render per-path subgraphs on demand.
- Monitor GCP activity logs for future JSON parse failures now that they're
  visible in the activity log stream.
