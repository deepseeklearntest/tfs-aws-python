# Excel Report Generator Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `generate_report.py` at the project root — reads the latest findings CSVs from `findings/` and writes a manager-ready Excel workbook with 10 sheets, RAG row-colouring per wave, and currency-formatted savings columns.

**Architecture:** Single file, no external state. `discover_csvs()` globs and deduplicates; `load_findings()` reads via `csv.DictReader` into plain dicts; five `rag_*()` helpers return openpyxl fill/font pairs; five `write_*_sheet()` functions build individual sheets; `write_wave_sheet()` is a generic wave builder; `main()` wires discovery → load → write → save.

**Tech Stack:** Python 3.9+, `openpyxl>=3.1.0`, stdlib `csv` / `argparse` / `pathlib` / `re`. No pandas.

---

## File Map

| Path | Action | Responsibility |
|------|--------|---------------|
| `generate_report.py` | Create | Entire report generator — all functions in one file |
| `requirements.txt` | Verify | Confirm `openpyxl>=3.1.0` is present |

---

### Task 1: Scaffold — imports, constants, discover_csvs

**Files:**
- Create: `generate_report.py`

- [ ] **Step 1: Create the file with all imports and constants**

```python
#!/usr/bin/env python3
"""
AWS Proactive Excel Report Generator

Reads the latest findings CSVs from the findings directory and produces
a manager-ready Excel workbook with RAG-coloured sheets per wave.

Run: python generate_report.py
     python generate_report.py --findings-dir findings --output-dir reports
"""
from __future__ import annotations

import argparse
import csv
import logging
import re
import sys
from datetime import datetime
from pathlib import Path

from openpyxl import Workbook
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Wave mapping
# ---------------------------------------------------------------------------
WAVE_MAP: dict[str, str] = {
    '06': 'wave1_cost',        '07': 'wave1_cost',
    '10': 'wave1_cost',        '13': 'wave1_cost',
    '15': 'wave2_lifecycle',   '16': 'wave2_lifecycle',
    '26': 'wave3_reliability', '28': 'wave3_reliability',
    '30': 'wave4_security',    '33': 'wave4_security',
    '34': 'wave4_security',    '35': 'wave4_security',
    '36': 'wave4_security',    '37': 'wave4_security',
    '38': 'wave5_performance', '39': 'wave5_performance',
    '40': 'wave5_performance',
    '46': 'continuous',        '48': 'continuous',
    '49': 'continuous',        '54': 'continuous',
}

WAVE_LABELS: dict[str, str] = {
    'wave1_cost':         'Wave 1 – Cost',
    'wave2_lifecycle':    'Wave 2 – Lifecycle',
    'wave3_reliability':  'Wave 3 – Reliability',
    'wave4_security':     'Wave 4 – Security',
    'wave5_performance':  'Wave 5 – Performance',
    'continuous':         'Continuous',
}

TAB_COLORS: dict[str, str] = {
    'Executive Summary':            '1F4E79',   # dark blue
    'Top Savings':                  '375623',   # dark green
    'By Account':                   '595959',   # dark grey
    'Wave 1 – Cost':           '008080',   # teal
    'Wave 2 – Lifecycle':      '7030A0',   # purple
    'Wave 3 – Reliability':    'FF6600',   # orange
    'Wave 4 – Security':       'C00000',   # dark red
    'Wave 5 – Performance':    '4472C4',   # blue
    'Continuous':                   '2E75B6',   # steel blue
    'All Findings':                 '595959',   # dark grey
}

# Standard columns written to every data sheet (wave sheets, all-findings)
STANDARD_COLS = [
    'account_id', 'region', 'resource_id', 'resource_type',
    'finding', 'detail',
    'estimated_monthly_savings_usd', 'estimated_annual_savings_usd',
    'source_script', 'tags',
]

# Columns for Top Savings sheet (no resource_id per spec)
TOP_SAVINGS_COLS = [
    'account_id', 'region', 'resource_type', 'finding', 'detail',
    'estimated_monthly_savings_usd', 'estimated_annual_savings_usd', 'source_script',
]

# Columns for By Account sheet
BY_ACCOUNT_COLS = [
    'account_id', 'total_findings',
    'est_monthly_savings_usd', 'est_annual_savings_usd',
    'wave1_cost_findings', 'wave2_lifecycle_findings',
    'wave3_reliability_findings', 'wave4_security_findings',
    'wave5_performance_findings',
]

# ---------------------------------------------------------------------------
# RAG palette (module-level singletons — openpyxl reuses fill/font objects fine)
# ---------------------------------------------------------------------------
_RED_FILL   = PatternFill('solid', fgColor='FFC7CE')
_RED_FONT   = Font(color='9C0006')
_AMBER_FILL = PatternFill('solid', fgColor='FFEB9C')
_AMBER_FONT = Font(color='9C6500')
_GREEN_FILL = PatternFill('solid', fgColor='C6EFCE')
_GREEN_FONT = Font(color='276221')

_HEADER_FILL = PatternFill('solid', fgColor='1F4E79')
_HEADER_FONT = Font(bold=True, color='FFFFFF')
```

- [ ] **Step 2: Append discover_csvs() immediately below the constants block**

```python
# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------

def discover_csvs(findings_dir: str) -> list[Path]:
    """Return the latest CSV per script name, excluding logs/ paths and inventory_* files."""
    root = Path(findings_dir)
    if not root.exists():
        raise FileNotFoundError(f"findings directory not found: {root}")

    # script_name -> (timestamp_str, path)
    latest: dict[str, tuple[str, Path]] = {}

    for csv_path in root.rglob('*.csv'):
        # Exclude any path segment named 'logs'
        if '/logs/' in str(csv_path).replace('\\', '/'):
            continue
        # Exclude inventory_ aggregator output
        if csv_path.name.startswith('inventory_'):
            continue

        # Expect: {script_name}_{YYYYMMDD}_{HHMMSS}.csv
        m = re.match(r'^(.+?)_(\d{8})_(\d{6})$', csv_path.stem)
        if not m:
            continue

        script_name = m.group(1)
        timestamp = m.group(2) + m.group(3)   # 14-char string; lexical sort == chronological

        if script_name not in latest or timestamp > latest[script_name][0]:
            latest[script_name] = (timestamp, csv_path)

    return [v[1] for v in latest.values()]
```

- [ ] **Step 3: Smoke-test discover_csvs**

Run:
```
python -c "
from generate_report import discover_csvs
paths = discover_csvs('findings')
for p in paths:
    print(p.name)
print(len(paths), 'CSV(s) found')
"
```

Expected: one filename per unique script (latest run only), no log/ or inventory_ paths.
If `findings/` is empty, expected: `0 CSV(s) found` (no error).

- [ ] **Step 4: Commit**

```
git add generate_report.py
git commit -m "feat: scaffold generate_report.py with discover_csvs"
```

---

### Task 2: load_findings + wave_of

**Files:**
- Modify: `generate_report.py` (append after discover_csvs)

- [ ] **Step 1: Append wave_of, _safe_float, and load_findings**

```python
# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------

def wave_of(script_name: str) -> str | None:
    """Map script name (e.g. '06_detect_nat_gateway_hotpaths') to a wave key."""
    m = re.match(r'^(\d+)', script_name)
    if not m:
        return None
    prefix = m.group(1).zfill(2)
    return WAVE_MAP.get(prefix)


def _safe_float(value) -> float:
    """Convert any CSV cell to float; return 0.0 on blank or non-numeric."""
    try:
        return float(value) if value else 0.0
    except (ValueError, TypeError):
        return 0.0


def load_findings(csv_paths: list[Path]) -> list[dict]:
    """Read all CSVs into a list of dicts; add source_script and annual savings columns."""
    findings: list[dict] = []
    for csv_path in csv_paths:
        m = re.match(r'^(.+?)_(\d{8})_(\d{6})$', csv_path.stem)
        script_name = m.group(1) if m else csv_path.stem
        try:
            with open(csv_path, newline='', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                row_count = 0
                for row in reader:
                    try:
                        monthly = _safe_float(row.get('estimated_monthly_savings_usd'))
                        row['estimated_monthly_savings_usd'] = monthly
                        row['estimated_annual_savings_usd'] = round(monthly * 12, 2)
                        row['source_script'] = script_name
                        findings.append(row)
                        row_count += 1
                    except Exception as exc:
                        log.warning("Skipping malformed row in %s: %s", csv_path.name, exc)
            print(f"  Loaded: {script_name:<55} ({row_count} rows)")
        except Exception as exc:
            log.warning("Could not read %s: %s", csv_path, exc)
    return findings
```

- [ ] **Step 2: Smoke-test load_findings and wave_of**

```
python -c "
from generate_report import discover_csvs, load_findings, wave_of
paths = discover_csvs('findings')
rows = load_findings(paths)
print(f'{len(rows)} total rows loaded')
scripts = sorted(set(r.get('source_script','') for r in rows))
for s in scripts[:6]:
    print(f'  {s} -> {wave_of(s)}')
"
```

Expected: row count printed, each script maps to a non-None wave key.

- [ ] **Step 3: Commit**

```
git add generate_report.py
git commit -m "feat: add load_findings and wave_of"
```

---

### Task 3: RAG helper functions

**Files:**
- Modify: `generate_report.py` (append after load_findings)

All five RAG functions share a uniform signature `(finding: str, monthly_usd: float) -> tuple[PatternFill, Font]` so `write_wave_sheet` can call them identically regardless of whether the wave uses savings-tier or keyword-based colouring.

- [ ] **Step 1: Append all five RAG functions**

```python
# ---------------------------------------------------------------------------
# RAG helpers — uniform signature: (finding, monthly_usd) -> (fill, font)
# ---------------------------------------------------------------------------

RagResult = tuple[PatternFill, Font]


def rag_cost(finding: str, monthly_usd: float) -> RagResult:
    """Savings tier: red > $500, amber $50-$500, green < $50."""
    if monthly_usd > 500:
        return _RED_FILL, _RED_FONT
    if monthly_usd >= 50:
        return _AMBER_FILL, _AMBER_FONT
    return _GREEN_FILL, _GREEN_FONT


def rag_lifecycle(finding: str, monthly_usd: float) -> RagResult:
    f = finding.lower()
    if 'deprecated-runtime' in f or 'deletion candidate' in f:
        return _RED_FILL, _RED_FONT
    if 'eol-soon' in f or 'migrate to alb or nlb' in f:
        return _AMBER_FILL, _AMBER_FONT
    return _GREEN_FILL, _GREEN_FONT


def rag_reliability(finding: str, monthly_usd: float) -> RagResult:
    f = finding.lower()
    if any(kw in f for kw in ('quota-gap', 'never-tested', 'runbook-never-tested')):
        return _RED_FILL, _RED_FONT
    if 'overdue' in f or 'stale' in f:
        return _AMBER_FILL, _AMBER_FONT
    return _GREEN_FILL, _GREEN_FONT


def rag_security(finding: str, monthly_usd: float) -> RagResult:
    f = finding.lower()
    red_kw = (
        '0.0.0.0/0', 'unencrypted', 'no-trail', 'trail-not-logging',
        'no-trail-in-region', 'guardduty-disabled', 'securityhub-disabled',
        'config-disabled', 'wildcard', 'root key',
    )
    if any(kw in f for kw in red_kw):
        return _RED_FILL, _RED_FONT
    amber_kw = (
        'rotation-disabled', 'regional-trail-only', 'log-validation-disabled',
        'unused-role', 'global-events-excluded',
    )
    if any(kw in f for kw in amber_kw):
        return _AMBER_FILL, _AMBER_FONT
    return _GREEN_FILL, _GREEN_FONT


def rag_continuous(finding: str, monthly_usd: float) -> RagResult:
    f = finding.lower()
    if 'critical' in f or 'unmonitored' in f:
        return _RED_FILL, _RED_FONT
    if 'warning' in f:
        return _AMBER_FILL, _AMBER_FONT
    return _GREEN_FILL, _GREEN_FONT
```

- [ ] **Step 2: Smoke-test RAG functions**

```
python -c "
from generate_report import rag_cost, rag_lifecycle, rag_security, rag_continuous

fill, _ = rag_cost('', 600)
assert fill.fgColor.rgb == 'FFFFC7CE', f'Expected red, got {fill.fgColor.rgb}'
fill, _ = rag_cost('', 100)
assert fill.fgColor.rgb == 'FFFFEB9C', f'Expected amber, got {fill.fgColor.rgb}'
fill, _ = rag_cost('', 10)
assert fill.fgColor.rgb == 'FFC6EFCE', f'Expected green, got {fill.fgColor.rgb}'

fill, _ = rag_lifecycle('deprecated-runtime in python3.8', 0)
assert fill.fgColor.rgb == 'FFFFC7CE', 'deprecated-runtime should be red'
fill, _ = rag_lifecycle('migrate to ALB or NLB', 0)
assert fill.fgColor.rgb == 'FFFFEB9C', 'migrate to ALB should be amber'

fill, _ = rag_security('guardduty-disabled', 0)
assert fill.fgColor.rgb == 'FFFFC7CE', 'guardduty-disabled should be red'
fill, _ = rag_security('rotation-disabled', 0)
assert fill.fgColor.rgb == 'FFFFEB9C', 'rotation-disabled should be amber'

fill, _ = rag_continuous('quota-critical threshold', 0)
assert fill.fgColor.rgb == 'FFFFC7CE', 'critical should be red'
fill, _ = rag_continuous('quota-warning at 80pct', 0)
assert fill.fgColor.rgb == 'FFFFEB9C', 'warning should be amber'

print('All RAG assertions passed')
"
```

Expected: `All RAG assertions passed`

- [ ] **Step 3: Commit**

```
git add generate_report.py
git commit -m "feat: add RAG helper functions"
```

---

### Task 4: style_sheet helper

**Files:**
- Modify: `generate_report.py` (append after RAG functions)

- [ ] **Step 1: Append style_sheet**

```python
# ---------------------------------------------------------------------------
# Sheet formatting
# ---------------------------------------------------------------------------

def style_sheet(ws) -> None:
    """Dark-blue header row, freeze pane at A2, auto-fit columns (min 12, max 60)."""
    for cell in ws[1]:
        cell.fill = _HEADER_FILL
        cell.font = _HEADER_FONT
        cell.alignment = Alignment(wrap_text=False)

    ws.freeze_panes = 'A2'

    for col in ws.columns:
        col_letter = get_column_letter(col[0].column)
        max_len = max(
            (len(str(cell.value)) for cell in col if cell.value is not None),
            default=0,
        )
        ws.column_dimensions[col_letter].width = max(12, min(60, max_len + 2))
```

- [ ] **Step 2: Smoke-test style_sheet**

```
python -c "
from openpyxl import Workbook
from generate_report import style_sheet
wb = Workbook()
ws = wb.active
ws.append(['Account', 'Region', 'Finding'])
ws.append(['123456789012', 'us-east-1', 'idle NAT gateway - deletion candidate'])
style_sheet(ws)
assert ws.freeze_panes == 'A2', 'Freeze pane missing'
assert ws['A1'].font.bold, 'Header not bold'
assert ws['A1'].fill.fgColor.rgb == 'FF1F4E79', f'Wrong header fill: {ws[\"A1\"].fill.fgColor.rgb}'
print('style_sheet OK')
"
```

Expected: `style_sheet OK`

- [ ] **Step 3: Commit**

```
git add generate_report.py
git commit -m "feat: add style_sheet helper"
```

---

### Task 5: write_top_savings_sheet

**Files:**
- Modify: `generate_report.py` (append after style_sheet)

- [ ] **Step 1: Append write_top_savings_sheet**

```python
# ---------------------------------------------------------------------------
# Sheet writers
# ---------------------------------------------------------------------------

def write_top_savings_sheet(wb: Workbook, findings: list[dict]) -> None:
    """All findings with monthly savings > $0, sorted descending, RAG by savings tier."""
    savings_rows = [
        r for r in findings
        if _safe_float(r.get('estimated_monthly_savings_usd')) > 0
    ]
    if not savings_rows:
        return

    savings_rows.sort(
        key=lambda r: _safe_float(r.get('estimated_monthly_savings_usd')),
        reverse=True,
    )

    ws = wb.create_sheet('Top Savings')
    ws.append(TOP_SAVINGS_COLS)

    for row in savings_rows:
        monthly = _safe_float(row.get('estimated_monthly_savings_usd'))
        fill, font = rag_cost('', monthly)
        ws.append([row.get(c, '') for c in TOP_SAVINGS_COLS])
        for cell in ws[ws.max_row]:
            cell.fill = fill
            cell.font = font

    m_idx = TOP_SAVINGS_COLS.index('estimated_monthly_savings_usd') + 1
    a_idx = TOP_SAVINGS_COLS.index('estimated_annual_savings_usd') + 1
    for data_row in ws.iter_rows(min_row=2):
        data_row[m_idx - 1].number_format = '$#,##0.00'
        data_row[a_idx - 1].number_format = '$#,##0.00'

    style_sheet(ws)
```

- [ ] **Step 2: Smoke-test write_top_savings_sheet**

```
python -c "
from openpyxl import Workbook
from generate_report import write_top_savings_sheet
wb = Workbook()
findings = [
    {'account_id': '111', 'region': 'us-east-1', 'resource_type': 'NAT Gateway',
     'finding': 'idle', 'detail': '', 'estimated_monthly_savings_usd': 600,
     'estimated_annual_savings_usd': 7200, 'source_script': '06_detect_nat'},
    {'account_id': '222', 'region': 'us-east-1', 'resource_type': 'EC2',
     'finding': 'spot', 'detail': '', 'estimated_monthly_savings_usd': 0,
     'estimated_annual_savings_usd': 0, 'source_script': '13_detect_spot'},
]
write_top_savings_sheet(wb, findings)
ws = wb['Top Savings']
assert ws.max_row == 2, f'Expected header + 1 data row, got {ws.max_row}'
assert ws.cell(2, 1).value == '111', 'Row 2 should be account 111'
print('write_top_savings_sheet OK')
"
```

Expected: `write_top_savings_sheet OK`

- [ ] **Step 3: Commit**

```
git add generate_report.py
git commit -m "feat: add write_top_savings_sheet"
```

---

### Task 6: write_by_account_sheet

**Files:**
- Modify: `generate_report.py` (append after write_top_savings_sheet)

- [ ] **Step 1: Append write_by_account_sheet**

```python
def write_by_account_sheet(wb: Workbook, findings: list[dict]) -> None:
    """One summary row per account_id with per-wave finding counts and total savings."""
    accounts: dict[str, dict] = {}

    for row in findings:
        acct = row.get('account_id', 'unknown')
        if acct not in accounts:
            accounts[acct] = {
                'account_id': acct,
                'total_findings': 0,
                'est_monthly_savings_usd': 0.0,
                'est_annual_savings_usd': 0.0,
                'wave1_cost_findings': 0,
                'wave2_lifecycle_findings': 0,
                'wave3_reliability_findings': 0,
                'wave4_security_findings': 0,
                'wave5_performance_findings': 0,
            }
        a = accounts[acct]
        a['total_findings'] += 1
        monthly = _safe_float(row.get('estimated_monthly_savings_usd'))
        a['est_monthly_savings_usd'] += monthly
        a['est_annual_savings_usd'] += monthly * 12

        wave = wave_of(row.get('source_script', ''))
        wave_col = f'{wave}_findings' if wave else None
        if wave_col and wave_col in a:
            a[wave_col] += 1

    if not accounts:
        return

    ws = wb.create_sheet('By Account')
    ws.append(BY_ACCOUNT_COLS)

    for a in sorted(accounts.values(), key=lambda x: x['account_id']):
        a['est_monthly_savings_usd'] = round(a['est_monthly_savings_usd'], 2)
        a['est_annual_savings_usd'] = round(a['est_annual_savings_usd'], 2)
        ws.append([a.get(c, 0) for c in BY_ACCOUNT_COLS])

    m_idx = BY_ACCOUNT_COLS.index('est_monthly_savings_usd') + 1
    a_idx = BY_ACCOUNT_COLS.index('est_annual_savings_usd') + 1
    for data_row in ws.iter_rows(min_row=2):
        data_row[m_idx - 1].number_format = '$#,##0.00'
        data_row[a_idx - 1].number_format = '$#,##0.00'

    style_sheet(ws)
```

- [ ] **Step 2: Smoke-test write_by_account_sheet**

```
python -c "
from openpyxl import Workbook
from generate_report import write_by_account_sheet
wb = Workbook()
findings = [
    {'account_id': '111', 'estimated_monthly_savings_usd': 200, 'source_script': '06_detect_nat'},
    {'account_id': '111', 'estimated_monthly_savings_usd': 50,  'source_script': '15_detect_lambda'},
    {'account_id': '222', 'estimated_monthly_savings_usd': 0,   'source_script': '30_detect_sg'},
]
write_by_account_sheet(wb, findings)
ws = wb['By Account']
assert ws.max_row == 3, f'Expected header + 2 account rows, got {ws.max_row}'
assert ws.cell(2, 1).value == '111'
assert ws.cell(3, 1).value == '222'
print('write_by_account_sheet OK')
"
```

Expected: `write_by_account_sheet OK`

- [ ] **Step 3: Commit**

```
git add generate_report.py
git commit -m "feat: add write_by_account_sheet"
```

---

### Task 7: write_wave_sheet (generic)

**Files:**
- Modify: `generate_report.py` (append after write_by_account_sheet)

- [ ] **Step 1: Append write_wave_sheet**

```python
def write_wave_sheet(
    wb: Workbook,
    findings: list[dict],
    wave: str,
    label: str,
    rag_fn,
) -> None:
    """Generic wave sheet. Filters by wave, adds extra columns found in data, applies rag_fn."""
    wave_rows = [r for r in findings if wave_of(r.get('source_script', '')) == wave]
    if not wave_rows:
        return

    # Include script-specific extra columns that appear in this wave's data
    extra_cols: list[str] = []
    for row in wave_rows:
        for key in row:
            if key not in STANDARD_COLS and key not in extra_cols:
                extra_cols.append(key)

    cols = STANDARD_COLS + extra_cols

    ws = wb.create_sheet(label)
    ws.append(cols)

    for row in wave_rows:
        monthly = _safe_float(row.get('estimated_monthly_savings_usd'))
        finding = row.get('finding', '')
        fill, font = rag_fn(finding, monthly)
        ws.append([row.get(c, '') for c in cols])
        for cell in ws[ws.max_row]:
            cell.fill = fill
            cell.font = font

    m_idx = cols.index('estimated_monthly_savings_usd') + 1
    a_idx = cols.index('estimated_annual_savings_usd') + 1
    for data_row in ws.iter_rows(min_row=2):
        data_row[m_idx - 1].number_format = '$#,##0.00'
        data_row[a_idx - 1].number_format = '$#,##0.00'

    style_sheet(ws)
```

- [ ] **Step 2: Smoke-test write_wave_sheet with extra columns**

```
python -c "
from openpyxl import Workbook
from generate_report import write_wave_sheet, rag_cost, rag_lifecycle
wb = Workbook()
findings = [
    {'account_id': '111', 'region': 'us-east-1', 'resource_id': 'nat-1',
     'resource_type': 'NAT Gateway', 'finding': 'idle NAT GW - deletion candidate',
     'detail': '', 'estimated_monthly_savings_usd': 32.85,
     'estimated_annual_savings_usd': 394.2, 'source_script': '06_detect_nat_gateway_hotpaths',
     'tags': ''},
    {'account_id': '222', 'region': 'us-east-1', 'resource_id': 'arn:aws:lambda:fn',
     'resource_type': 'Lambda Function', 'finding': 'deprecated-runtime',
     'detail': '', 'estimated_monthly_savings_usd': 0,
     'estimated_annual_savings_usd': 0, 'source_script': '15_detect_lambda_deprecated_runtimes',
     'tags': '', 'severity': 'deprecated', 'eol_date': '2023-11-27'},
]
write_wave_sheet(wb, findings, 'wave1_cost', 'Wave 1 – Cost', rag_cost)
write_wave_sheet(wb, findings, 'wave2_lifecycle', 'Wave 2 – Lifecycle', rag_lifecycle)
cost_ws = wb['Wave 1 – Cost']
life_ws = wb['Wave 2 – Lifecycle']
assert cost_ws.max_row == 2
assert life_ws.max_row == 2
# Extra columns (severity, eol_date) should appear in lifecycle sheet
assert 'severity' in [cell.value for cell in life_ws[1]]
print('write_wave_sheet OK')
"
```

Expected: `write_wave_sheet OK`

- [ ] **Step 3: Commit**

```
git add generate_report.py
git commit -m "feat: add write_wave_sheet generic builder"
```

---

### Task 8: write_summary_sheet

**Files:**
- Modify: `generate_report.py` (append after write_wave_sheet)

- [ ] **Step 1: Append write_summary_sheet**

```python
def write_summary_sheet(wb: Workbook, findings: list[dict]) -> None:
    """Executive Summary: title, key metrics box, wave breakdown, top 10 action items."""
    ws = wb.create_sheet('Executive Summary')

    # --- Title ---
    ws['A1'] = 'AWS Proactive Findings Report'
    ws['A1'].font = Font(bold=True, size=16, color='1F4E79')

    accounts = sorted({f.get('account_id', '') for f in findings if f.get('account_id')})
    scripts  = sorted({f.get('source_script', '') for f in findings if f.get('source_script')})
    now_str  = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    ws['A2'] = (
        f"Generated: {now_str}  |  Accounts scanned: {len(accounts)}"
        f"  |  Scripts run: {len(scripts)}"
    )

    # --- Key Metrics ---
    ws['A4'] = 'KEY METRICS'
    ws['A4'].font = Font(bold=True)

    for col, header in enumerate(['Total Findings', 'Monthly Saves', 'Annual Saves'], 1):
        cell = ws.cell(row=5, column=col, value=header)
        cell.fill = _HEADER_FILL
        cell.font = _HEADER_FONT

    total_monthly = sum(_safe_float(f.get('estimated_monthly_savings_usd')) for f in findings)
    ws.cell(row=6, column=1, value=len(findings))
    m_cell = ws.cell(row=6, column=2, value=round(total_monthly, 2))
    a_cell = ws.cell(row=6, column=3, value=round(total_monthly * 12, 2))
    m_cell.number_format = '$#,##0.00'
    a_cell.number_format = '$#,##0.00'

    # --- Wave Breakdown ---
    ws['A8'] = 'BREAKDOWN BY WAVE'
    ws['A8'].font = Font(bold=True)

    for col, header in enumerate(['Wave', 'Findings', 'Monthly $', 'Annual $'], 1):
        cell = ws.cell(row=9, column=col, value=header)
        cell.fill = _HEADER_FILL
        cell.font = _HEADER_FONT

    ZERO_SAVINGS_WAVES = {'wave3_reliability', 'wave4_security'}
    wave_order = [
        'wave1_cost', 'wave2_lifecycle', 'wave3_reliability',
        'wave4_security', 'wave5_performance', 'continuous',
    ]
    data_row = 10
    for wave_key in wave_order:
        wave_rows = [f for f in findings if wave_of(f.get('source_script', '')) == wave_key]
        if not wave_rows:
            continue
        monthly = (
            0.0 if wave_key in ZERO_SAVINGS_WAVES
            else sum(_safe_float(r.get('estimated_monthly_savings_usd')) for r in wave_rows)
        )
        ws.cell(row=data_row, column=1, value=WAVE_LABELS[wave_key])
        ws.cell(row=data_row, column=2, value=len(wave_rows))
        m = ws.cell(row=data_row, column=3, value=round(monthly, 2))
        a = ws.cell(row=data_row, column=4, value=round(monthly * 12, 2))
        m.number_format = '$#,##0.00'
        a.number_format = '$#,##0.00'
        data_row += 1

    data_row += 1
    note = ws.cell(
        row=data_row, column=1,
        value=(
            'Note: Security and Reliability findings carry $0 estimated savings. '
            'They are risk items requiring remediation, not direct cost savings.'
        ),
    )
    note.font = Font(italic=True, color='595959')

    # --- Top 10 Action Items ---
    data_row += 2
    ws.cell(row=data_row, column=1, value='TOP 10 ACTION ITEMS  (by monthly savings)').font = Font(bold=True)
    data_row += 1

    for col, header in enumerate(['Rank', 'Account', 'Resource Type', 'Finding', 'Monthly $', 'Annual $'], 1):
        cell = ws.cell(row=data_row, column=col, value=header)
        cell.fill = _HEADER_FILL
        cell.font = _HEADER_FONT
    data_row += 1

    top10 = sorted(
        findings,
        key=lambda r: _safe_float(r.get('estimated_monthly_savings_usd')),
        reverse=True,
    )[:10]

    for rank, row in enumerate(top10, 1):
        monthly = _safe_float(row.get('estimated_monthly_savings_usd'))
        ws.cell(row=data_row, column=1, value=rank)
        ws.cell(row=data_row, column=2, value=row.get('account_id', ''))
        ws.cell(row=data_row, column=3, value=row.get('resource_type', ''))
        ws.cell(row=data_row, column=4, value=row.get('finding', ''))
        m = ws.cell(row=data_row, column=5, value=round(monthly, 2))
        a = ws.cell(row=data_row, column=6, value=round(monthly * 12, 2))
        m.number_format = '$#,##0.00'
        a.number_format = '$#,##0.00'
        data_row += 1

    # Fixed column widths — non-standard layout so style_sheet is not used
    ws.column_dimensions['A'].width = 55
    ws.column_dimensions['B'].width = 18
    ws.column_dimensions['C'].width = 22
    ws.column_dimensions['D'].width = 50
    ws.column_dimensions['E'].width = 15
    ws.column_dimensions['F'].width = 15
```

- [ ] **Step 2: Smoke-test write_summary_sheet**

```
python -c "
from openpyxl import Workbook
from generate_report import write_summary_sheet
wb = Workbook()
findings = [
    {'account_id': '111', 'source_script': '06_detect_nat', 'resource_type': 'NAT',
     'finding': 'idle', 'estimated_monthly_savings_usd': 600.0},
    {'account_id': '222', 'source_script': '30_detect_sg', 'resource_type': 'SG',
     'finding': 'open port 0.0.0.0/0', 'estimated_monthly_savings_usd': 0.0},
]
write_summary_sheet(wb, findings)
ws = wb['Executive Summary']
assert ws['A1'].value == 'AWS Proactive Findings Report', 'Title wrong'
assert 'Accounts scanned: 2' in ws['A2'].value, 'Account count wrong'
assert ws.cell(6, 1).value == 2, 'Total findings should be 2'
print('write_summary_sheet OK')
"
```

Expected: `write_summary_sheet OK`

- [ ] **Step 3: Commit**

```
git add generate_report.py
git commit -m "feat: add write_summary_sheet"
```

---

### Task 9: write_all_findings_sheet

**Files:**
- Modify: `generate_report.py` (append after write_summary_sheet)

- [ ] **Step 1: Append write_all_findings_sheet**

```python
def write_all_findings_sheet(wb: Workbook, findings: list[dict]) -> None:
    """All findings, standard columns only, sorted by monthly savings descending. No RAG."""
    sorted_rows = sorted(
        findings,
        key=lambda r: _safe_float(r.get('estimated_monthly_savings_usd')),
        reverse=True,
    )

    ws = wb.create_sheet('All Findings')
    ws.append(STANDARD_COLS)

    for row in sorted_rows:
        ws.append([row.get(c, '') for c in STANDARD_COLS])

    m_idx = STANDARD_COLS.index('estimated_monthly_savings_usd') + 1
    a_idx = STANDARD_COLS.index('estimated_annual_savings_usd') + 1
    for data_row in ws.iter_rows(min_row=2):
        data_row[m_idx - 1].number_format = '$#,##0.00'
        data_row[a_idx - 1].number_format = '$#,##0.00'

    style_sheet(ws)
```

- [ ] **Step 2: Smoke-test write_all_findings_sheet**

```
python -c "
from openpyxl import Workbook
from generate_report import write_all_findings_sheet
wb = Workbook()
findings = [
    {'account_id': '111', 'region': 'us-east-1', 'resource_id': 'r1',
     'resource_type': 'NAT', 'finding': 'idle', 'detail': '',
     'estimated_monthly_savings_usd': 100.0, 'estimated_annual_savings_usd': 1200.0,
     'source_script': '06_detect', 'tags': ''},
    {'account_id': '222', 'region': 'us-east-1', 'resource_id': 'r2',
     'resource_type': 'SG', 'finding': 'open port', 'detail': '',
     'estimated_monthly_savings_usd': 0.0, 'estimated_annual_savings_usd': 0.0,
     'source_script': '30_detect', 'tags': ''},
]
write_all_findings_sheet(wb, findings)
ws = wb['All Findings']
assert ws.max_row == 3, f'Expected header + 2 rows, got {ws.max_row}'
assert ws.cell(2, 1).value == '111', 'Higher-savings row should sort first'
print('write_all_findings_sheet OK')
"
```

Expected: `write_all_findings_sheet OK`

- [ ] **Step 3: Commit**

```
git add generate_report.py
git commit -m "feat: add write_all_findings_sheet"
```

---

### Task 10: main() + tab colors + end-to-end verification

**Files:**
- Modify: `generate_report.py` (append main and WAVE_CONFIG constant)
- Verify: `requirements.txt`

- [ ] **Step 1: Verify openpyxl is in requirements.txt**

Open `requirements.txt`. If `openpyxl>=3.1.0` is not present, add it.

Run to confirm the package is importable:
```
python -c "import openpyxl; print('openpyxl', openpyxl.__version__)"
```

Expected: `openpyxl 3.x.x`

- [ ] **Step 2: Append WAVE_CONFIG and main()**

```python
# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

WAVE_CONFIG = [
    ('wave1_cost',        WAVE_LABELS['wave1_cost'],        rag_cost),
    ('wave2_lifecycle',   WAVE_LABELS['wave2_lifecycle'],   rag_lifecycle),
    ('wave3_reliability', WAVE_LABELS['wave3_reliability'], rag_reliability),
    ('wave4_security',    WAVE_LABELS['wave4_security'],    rag_security),
    ('wave5_performance', WAVE_LABELS['wave5_performance'], rag_cost),     # savings-tier RAG
    ('continuous',        WAVE_LABELS['continuous'],        rag_continuous),
]


def main() -> None:
    logging.basicConfig(level=logging.WARNING, format='%(levelname)s %(message)s')

    parser = argparse.ArgumentParser(
        description='Generate Excel report from AWS Proactive findings CSVs.'
    )
    parser.add_argument(
        '--findings-dir', default='findings',
        help='Root directory to scan for CSV files (default: findings)',
    )
    parser.add_argument(
        '--output-dir', default='reports',
        help='Directory to write the Excel file (default: reports)',
    )
    args = parser.parse_args()

    print(f"Scanning {args.findings_dir}/ for CSVs...")
    try:
        csv_paths = discover_csvs(args.findings_dir)
    except FileNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    if not csv_paths:
        print(
            f"No CSVs found in {args.findings_dir}/ "
            "(searched recursively, excluding logs/ and inventory_*)",
            file=sys.stderr,
        )
        sys.exit(1)

    findings = load_findings(csv_paths)
    accounts = {f.get('account_id', '') for f in findings}
    print(f"\nTotal: {len(findings)} findings across {len(accounts)} accounts")

    print("\nWriting report...")
    wb = Workbook()
    wb.remove(wb.active)   # discard the default blank sheet

    write_summary_sheet(wb, findings)
    print("  + Executive Summary")

    existing = {ws.title for ws in wb.worksheets}
    write_top_savings_sheet(wb, findings)
    if 'Top Savings' not in existing and 'Top Savings' in {ws.title for ws in wb.worksheets}:
        savings_count = sum(1 for f in findings if _safe_float(f.get('estimated_monthly_savings_usd')) > 0)
        print(f"  + Top Savings ({savings_count} rows with savings > $0)")

    write_by_account_sheet(wb, findings)
    if 'By Account' in {ws.title for ws in wb.worksheets}:
        print(f"  + By Account ({len(accounts)} accounts)")

    for wave_key, label, rag_fn in WAVE_CONFIG:
        before = {ws.title for ws in wb.worksheets}
        write_wave_sheet(wb, findings, wave_key, label, rag_fn)
        if label not in before and label in {ws.title for ws in wb.worksheets}:
            wave_count = sum(1 for f in findings if wave_of(f.get('source_script', '')) == wave_key)
            print(f"  + {label} ({wave_count} rows)")

    write_all_findings_sheet(wb, findings)
    print(f"  + All Findings ({len(findings)} rows)")

    # Apply tab colours
    for ws in wb.worksheets:
        color = TAB_COLORS.get(ws.title)
        if color:
            ws.sheet_properties.tabColor = color

    # Save
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_path = output_dir / f"aws_proactive_report_{timestamp}.xlsx"
    wb.save(str(output_path))
    print(f"\nReport saved: {output_path}")


if __name__ == '__main__':
    main()
```

- [ ] **Step 3: End-to-end run against real findings**

```
python generate_report.py --findings-dir findings --output-dir reports
```

Expected output shape:
```
Scanning findings/ for CSVs...
  Loaded: 06_detect_nat_gateway_hotpaths             (N rows)
  Loaded: 15_detect_lambda_deprecated_runtimes       (N rows)
  ...

Total: NNN findings across N accounts

Writing report...
  + Executive Summary
  + Top Savings (NN rows with savings > $0)
  + By Account (N accounts)
  + Wave 1 – Cost (NN rows)
  + Wave 2 – Lifecycle (NN rows)
  ...
  + All Findings (NNN rows)

Report saved: reports/aws_proactive_report_YYYYMMDD_HHMMSS.xlsx
```

Then open the file in Excel and visually verify:
- Sheet tabs are coloured (dark blue, green, grey, teal, purple, orange, red, blue, steel blue)
- Executive Summary has correct totals
- Header row on each data sheet is dark blue with white bold text, frozen at row 2
- Savings columns display as `$x,xxx.xx`
- Wave 2 – Lifecycle rows show red for deprecated-runtime rows, amber for eol-soon rows
- Wave 4 – Security rows show red for open-port / unencrypted / no-trail findings

- [ ] **Step 4: Commit**

```
git add generate_report.py requirements.txt
git commit -m "feat: complete generate_report.py with main() and tab colors"
```

---

## Self-Review

**Spec coverage check:**

| Spec requirement | Task |
|---|---|
| `discover_csvs` — glob, exclude logs/, exclude inventory_*, latest-per-script | 1 |
| `load_findings` — DictReader, add source_script + annual savings | 2 |
| `wave_of` — script prefix → wave key | 2 |
| `rag_cost`, `rag_lifecycle`, `rag_reliability`, `rag_security` | 3 |
| `rag_continuous` (Sheet 9 has distinct keyword RAG) | 3 |
| `style_sheet` — dark blue header, frozen row 2, auto-fit 12–60 | 4 |
| Top Savings sheet — savings > $0, descending, savings-tier RAG | 5 |
| By Account sheet — one row per account, wave counts, no RAG | 6 |
| Generic `write_wave_sheet` with extra-column discovery | 7 |
| Executive Summary — title, key metrics, wave breakdown, top 10 | 8 |
| All Findings — standard cols only, no RAG, savings-sorted | 9 |
| `main()` — argparse, orchestrate, save, tab colors | 10 |
| CLI flags `--findings-dir` / `--output-dir` | 10 |
| Output filename `aws_proactive_report_YYYYMMDD_HHMMSS.xlsx` | 10 |
| Empty sheets never written (early-return guards) | 5, 6, 7, 9 |
| `output_dir` auto-created | 10 |
| Missing `findings_dir` → exit with message | 10 |
| No CSVs found → exit with message | 10 |
| Malformed row → skip + warning | 2 |
| Non-numeric savings treated as 0 | 2, 3 |
| `$#,##0.00` number format on savings columns | 5, 6, 7, 8, 9 |
| Security/Reliability show $0 savings in summary breakdown | 8 |
| `openpyxl>=3.1.0` dependency | 10 |
| Wave 5 Performance uses savings-tier RAG (same as Wave 1) | 10 (WAVE_CONFIG) |

**No placeholders found.**

**Type consistency:** `_safe_float()` used uniformly in tasks 2, 3, 5, 6, 7, 8, 9. All `rag_fn(finding, monthly)` calls match the two-arg signature defined in Task 3. `STANDARD_COLS`, `TOP_SAVINGS_COLS`, `BY_ACCOUNT_COLS` defined in Task 1 and referenced consistently in Tasks 5–9. `WAVE_LABELS` keys match `WAVE_MAP` values throughout.
