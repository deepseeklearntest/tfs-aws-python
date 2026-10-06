# Inventory Refresh — Design Spec
**Date:** 2026-06-04
**Status:** Approved

## Problem

`continuous/54_inventory_refresh.py` aggregates all findings CSVs into a flat
`inventory_*.csv`, but the output is low quality:

- Includes **all runs** of every script — if script 06 ran twice, both runs are merged
  and findings are double-counted.
- Missing `estimated_annual_savings_usd` and `wave` columns.
- Column order is non-deterministic (depends on which CSV is processed first).
- Account IDs are not normalized (scientific-notation IDs from Excel can sneak in).

`generate_report.py` produces the manager-facing Excel workbook but does its own
CSV discovery and ignores the inventory file entirely. The two scripts therefore
duplicate discovery logic independently.

## Goal

Make the inventory CSV the **clean single source of truth**: always deduplicated to
the latest run per script, enriched with the columns `generate_report.py` expects,
and Excel-ready with a stable column order.

Optionally wire `generate_report.py` to consume the inventory via `--from-inventory`
so the report can be generated from the pre-built snapshot without re-scanning.

## Design

### Role split

| Script | Role |
|---|---|
| `continuous/54_inventory_refresh.py` | Data layer — discover, dedupe, enrich, write flat CSV |
| `generate_report.py` | Presentation layer — read data, produce Excel workbook |

### Constraint: stdlib-only for script 54

`generate_report.py` imports `openpyxl` at module top. Script 54 is documented as
stdlib-only. Therefore script 54 **must not import from `generate_report.py`**. Small
shared helpers (`WAVE_MAP`, `wave_of`, `_normalize_account_id`) are duplicated locally
in script 54 — consistent with the existing pattern where both files already define
`_safe_float` independently.

---

## Part 1 — `continuous/54_inventory_refresh.py`

### 1. Deduplication (latest run per script)

Replace `_collect_csvs` "all files sorted by mtime" with filename-timestamp
deduplication matching `generate_report.py::discover_csvs`:

- Parse `^(.+?)_(\d{8})_(\d{6})$` from each CSV stem.
- Keep only the newest `YYYYMMDD+HHMMSS` per `script_name`.
- Skip path segments named `logs` and filenames starting with `inventory_`.
- `--since` filter applies first (restrict to mtime window, then pick latest within it).

### 2. Pinned column order

Pre-seed the field union with standard fields so they always lead, regardless of
file processing order:

```
scan_time, account_id, region, resource_id, resource_type,
finding, detail, estimated_monthly_savings_usd,
estimated_annual_savings_usd, wave, source_script, tags
```

Script-specific extras are appended after in first-seen order.

### 3. New / normalized per-row fields

All applied at row-read time (local helper copies, not imported):

| Field | Value |
|---|---|
| `estimated_annual_savings_usd` | `round(monthly * 12, 2)` |
| `wave` | Derived from `source_script` via local `WAVE_MAP` + `wave_of()` (mirrors `generate_report.py:30,143`) |
| `account_id` | Normalized via local `_normalize_account_id()` (mirrors `generate_report.py:160`) |

### 4. Unchanged

`--findings-dir`, `--output-dir`, `--since`, terminal summary printout,
`inventory_YYYYMMDD_HHMMSS.csv` output filename.

---

## Part 2 — `generate_report.py`

### 1. New flag: `--from-inventory`

`store_true`, opt-in. Without the flag, existing behavior is completely unchanged:
`discover_csvs` → `load_findings` → Excel. This is the built-in fallback.

### 2. New function: `load_from_inventory(findings_dir: str) -> list[dict]`

- Find the latest `inventory_*.csv` in the root of `findings_dir` (lexical sort on
  the `YYYYMMDD_HHMMSS` suffix).
- Read with `csv.DictReader`.
- Re-apply existing normalization from `load_findings` (`generate_report.py:174`):
  - `account_id` → `_normalize_account_id` (defensive; inventory already normalized)
  - `estimated_monthly_savings_usd` → float via `_safe_float`
  - `estimated_annual_savings_usd` → float via `_safe_float` (already in inventory; coerce, do not recompute)
- Reuses existing helpers; no new helpers needed.

### 3. Branch in `main()`

```python
if args.from_inventory:
    findings = load_from_inventory(args.findings_dir)
else:
    csv_paths = discover_csvs(args.findings_dir)
    findings = load_findings(csv_paths)
```

All downstream sheet writers are untouched — `findings: list[dict]` shape is identical
either way.

### 4. Error handling

If `--from-inventory` is passed but no `inventory_*.csv` exists in `--findings-dir`,
print a clear error to stderr and `sys.exit(1)` — same pattern as the existing
"no CSVs found" path at `generate_report.py:588`.

### 5. `wave` column

The `wave` column in the inventory CSV is ignored by the report pipeline (wave is
re-derived at render time via `wave_of(source_script)`). It exists for Excel users only.

---

## Workflows

```
# Just the inventory (Excel-ready flat CSV)
python continuous/54_inventory_refresh.py

# Report from inventory (fast — reads one file)
python continuous/54_inventory_refresh.py
python generate_report.py --from-inventory

# Report from individual CSVs (unchanged default path)
python generate_report.py
```

---

## Verification

1. **Dedupe check**
   ```
   python continuous/54_inventory_refresh.py --findings-dir findings
   ```
   Script `06_detect_nat_gateway_hotpaths` has two CSV runs. Confirm only the latest
   contributes — total row count must be less than the pre-change all-runs total.

2. **Enrichment check**
   Open `findings/inventory_*.csv`: header starts with the pinned order; `wave` and
   `estimated_annual_savings_usd` are populated; account IDs are plain 12-digit strings.

3. **Report from inventory**
   ```
   python generate_report.py --from-inventory
   ```
   Succeeds; writes `reports/aws_proactive_report_*.xlsx`. Totals match the default run.

4. **Fallback unchanged**
   ```
   python generate_report.py
   ```
   Behaves exactly as before.

5. **Missing inventory error**
   ```
   python generate_report.py --from-inventory --findings-dir nonexistent_dir
   ```
   Prints clear error, exits non-zero.
