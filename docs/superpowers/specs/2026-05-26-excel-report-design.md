# Excel Report Generator — Design Spec
**Date:** 2026-05-26
**Author:** Mohammed Afsal
**Status:** Approved for implementation

---

## Purpose

Generate a manager-ready Excel workbook from the findings CSVs produced by the AWS Proactive scanning scripts. The report surfaces savings opportunities, lifecycle risk, and security gaps across all scanned accounts — formatted for a technical manager audience with monthly and annual savings projections.

---

## Script

**File:** `generate_report.py` (project root, alongside `britive.py`)
**Run:** `python generate_report.py`
**No AWS credentials required** — reads only local CSV files.

---

## CLI Flags

| Flag | Default | Purpose |
|---|---|---|
| `--findings-dir` | `findings` | Root directory to scan for CSV files |
| `--output-dir` | `reports` | Directory to write the Excel file |

Output filename: `aws_proactive_report_YYYYMMDD_HHMMSS.xlsx`

---

## Input: Finding Files

### Discovery
- Recursively glob `{findings_dir}/**/*.csv`
- Exclude any path containing `\logs\` or `/logs/`
- Exclude filenames that match `inventory_*` (aggregator output from script 54)

### Latest-per-script selection
Filename pattern: `{script_name}_{YYYYMMDD}_{HHMMSS}.csv`

For each unique script name, parse the timestamp suffix and keep only the file with the latest timestamp. If a script was run three times, only the most recent CSV is included. This prevents double-counting without requiring manual file management.

### Script-to-wave mapping

| Wave | Label | Script prefixes |
|---|---|---|
| wave1_cost | Wave 1 – Cost | 06, 07, 10, 13 |
| wave2_lifecycle | Wave 2 – Lifecycle | 15, 16 |
| wave3_reliability | Wave 3 – Reliability | 26, 28 |
| wave4_security | Wave 4 – Security | 30, 33, 34, 35, 36, 37 |
| wave5_performance | Wave 5 – Performance | 38, 39, 40 |
| continuous | Continuous | 46, 48, 49, 54 |

Script number is extracted from the leading digits of the filename (e.g. `06_detect_...` → `06`).

---

## Output: Excel Workbook Structure

Sheets are generated **only if findings exist** for that wave. Empty sheets are never written.

### Sheet 1 — Executive Summary

Layout:
```
AWS Proactive Findings Report
Generated: 2026-05-26 14:30:00  |  Accounts scanned: 4  |  Scripts run: 6

KEY METRICS
┌──────────────────┬───────────────┬───────────────┐
│ Total Findings   │ Monthly Saves │ Annual Saves  │
│      87          │    $4,230     │   $50,760     │
└──────────────────┴───────────────┴───────────────┘

BREAKDOWN BY WAVE
Wave                  Findings    Monthly $    Annual $
Wave 1 – Cost            42        $2,100      $25,200
Wave 2 – Lifecycle       25        $1,680      $20,160
Wave 3 – Reliability      8            $0           $0
Wave 4 – Security        20            $0           $0

Note: Security and Reliability findings carry $0 estimated savings.
They are risk items requiring remediation, not direct cost savings.

TOP 10 ACTION ITEMS  (by monthly savings)
Rank  Account       Resource Type          Finding                    Monthly $   Annual $
1     860118397881  Classic Load Balancer  deletion candidate           $456       $5,472
...
```

- "Accounts scanned" = distinct `account_id` values across all loaded CSVs
- "Scripts run" = count of distinct script names with at least one CSV loaded
- Annual savings = monthly × 12
- Security/Reliability rows show finding counts but $0 savings with an explanatory note
- Top 10 is sorted by `estimated_monthly_savings_usd` descending, nulls last

### Sheet 2 — Top Savings

All findings where `estimated_monthly_savings_usd > 0`, sorted descending.

Columns: `account_id`, `region`, `resource_type`, `finding`, `detail`, `estimated_monthly_savings_usd`, `estimated_annual_savings_usd`, `source_script`

RAG applied to the entire row based on monthly savings:
- 🔴 Red (`FFC7CE` / `9C0006`): > $500/month
- 🟡 Amber (`FFEB9C` / `9C6500`): $50 – $500/month
- 🟢 Green (`C6EFCE` / `276221`): < $50/month

### Sheet 3 — By Account

One row per `account_id`. Columns:

`account_id`, `total_findings`, `est_monthly_savings_usd`, `est_annual_savings_usd`, `wave1_cost_findings`, `wave2_lifecycle_findings`, `wave3_reliability_findings`, `wave4_security_findings`, `wave5_performance_findings`

No RAG on this sheet — it is a summary reference table.

### Sheet 4 — Wave 1 – Cost

All findings from scripts 06, 07, 10, 13.

Columns: `account_id`, `region`, `resource_id`, `resource_type`, `finding`, `detail`, `estimated_monthly_savings_usd`, `estimated_annual_savings_usd`, `source_script`, `tags`

RAG by savings tier (same thresholds as Top Savings sheet).

### Sheet 5 — Wave 2 – Lifecycle

All findings from scripts 15, 16.

Columns: same standard set as Wave 1, plus `severity` where present.

RAG by finding content:
| Color | Finding contains |
|---|---|
| 🔴 Red | `deprecated-runtime`, `deletion candidate` |
| 🟡 Amber | `eol-soon`, `migrate to ALB or NLB` |
| 🟢 Green | anything else |

### Sheet 6 — Wave 3 – Reliability

All findings from scripts 26, 28.

Columns: same standard set.

RAG by finding content:
| Color | Finding contains |
|---|---|
| 🔴 Red | `quota-gap`, `never-tested`, `runbook-never-tested` |
| 🟡 Amber | `overdue`, `stale` |
| 🟢 Green | anything else |

### Sheet 7 — Wave 4 – Security

All findings from scripts 30, 33, 34, 35, 36, 37.

Columns: same standard set, plus `severity` where present.

RAG by finding content:
| Color | Finding content |
|---|---|
| 🔴 Red | open port (`0.0.0.0/0`), unencrypted, `no-trail`, `trail-not-logging`, `no-trail-in-region`, `guardduty-disabled`, `securityhub-disabled`, `config-disabled`, `wildcard`, root key |
| 🟡 Amber | `rotation-disabled`, `regional-trail-only`, `log-validation-disabled`, `unused-role`, `global-events-excluded` |
| 🟢 Green | anything else |

### Sheet 8 — Wave 5 – Performance

All findings from scripts 38, 39, 40.

Columns: same standard set.

RAG by savings tier (same thresholds as Wave 1 – Cost sheet) — performance findings carry estimated savings.

### Sheet 9 — Continuous

All findings from scripts 46, 48, 49, 54.

Columns: same standard set.

RAG by finding content:
| Color | Finding contains |
|---|---|
| 🔴 Red | `critical`, `quota-critical`, unmonitored production resource |
| 🟡 Amber | `warning`, `quota-warning` |
| 🟢 Green | anything else |

### Sheet 10 — All Findings

Every row from every loaded CSV. Standard columns only (no script-specific extra fields). Sorted by `estimated_monthly_savings_usd` descending, nulls last.

Columns: `account_id`, `region`, `resource_id`, `resource_type`, `finding`, `detail`, `estimated_monthly_savings_usd`, `estimated_annual_savings_usd`, `source_script`, `tags`

No RAG on this sheet — it is a raw reference.

---

## Formatting Rules (all sheets)

- **Header row**: bold, white text, dark blue fill (`1F4E79`), frozen
- **Column widths**: auto-fitted to content, minimum 12, maximum 60 characters
- **Number format**: savings columns formatted as `$#,##0.00`
- **Wrap text**: off (keeps rows compact)
- **Gridlines**: visible
- **Tab colors**:
  - Executive Summary: dark blue
  - Top Savings: dark green
  - By Account: dark grey
  - Wave sheets: colour-coded by wave (Cost=teal, Lifecycle=purple, Reliability=orange, Security=red)
  - All Findings: dark grey

---

## Dependencies

Add to `requirements.txt`:
```
openpyxl>=3.1.0
```

No pandas. All CSV reading via stdlib `csv.DictReader`. All Excel writing via `openpyxl`. No other new dependencies.

---

## Module structure

Single file `generate_report.py`. Internal functions:

| Function | Responsibility |
|---|---|
| `discover_csvs(findings_dir)` | Glob, exclude logs/inventory, return latest per script |
| `load_findings(csv_paths)` | Read all CSVs into list of dicts, add `source_script` and `estimated_annual_savings_usd` columns |
| `wave_of(script_name)` | Map script prefix → wave label |
| `rag_cost(monthly_usd)` | Return openpyxl fill+font for cost RAG |
| `rag_lifecycle(finding)` | Return openpyxl fill+font for lifecycle RAG |
| `rag_reliability(finding)` | Return openpyxl fill+font for reliability RAG |
| `rag_security(finding)` | Return openpyxl fill+font for security RAG |
| `write_summary_sheet(wb, findings)` | Build Executive Summary sheet |
| `write_top_savings_sheet(wb, findings)` | Build Top Savings sheet |
| `write_by_account_sheet(wb, findings)` | Build By Account sheet |
| `write_wave_sheet(wb, findings, wave, label, rag_fn)` | Generic wave sheet builder |
| `write_all_findings_sheet(wb, findings)` | Build All Findings sheet |
| `style_sheet(ws)` | Apply header styling, freeze pane, column widths |
| `main()` | Argparse, orchestrate, save workbook |

---

## Error handling

- Missing `findings_dir`: exit with clear message
- No CSVs found: exit with message listing what was searched
- Malformed CSV row (missing column): skip row, log warning, continue
- `estimated_monthly_savings_usd` non-numeric or blank: treat as 0 for sorting/totals
- `output_dir` does not exist: create it automatically

---

## Example run output

```
Scanning findings/ for CSVs...
  Loaded: 06_detect_nat_gateway_hotpaths  (47 rows)
  Loaded: 07_detect_cross_az_transfer     (0 rows — no findings above threshold)
  Loaded: 10_detect_athena_result_buckets (3 rows)
  Loaded: 13_detect_spot_opportunities    (12 rows)
  Loaded: 15_detect_lambda_deprecated_runtimes (28 rows)
  Loaded: 16_detect_classic_load_balancers     (25 rows)

Total: 115 findings across 4 accounts

Writing report...
  + Executive Summary
  + Top Savings (62 rows with savings > $0)
  + By Account (4 accounts)
  + Wave 1 – Cost (62 rows)
  + Wave 2 – Lifecycle (53 rows)
  + All Findings (115 rows)

Report saved: reports/aws_proactive_report_20260526_143022.xlsx
```
