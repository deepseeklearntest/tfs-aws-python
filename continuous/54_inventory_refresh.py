#!/usr/bin/env python3
"""Task 54 — Inventory Dashboard Refresh

Standalone aggregator: reads all findings CSVs from the findings/ directory,
merges them into a single consolidated inventory snapshot, and prints a summary
of findings by resource type, finding code, and top savings opportunities.

Does NOT use Britive auth, cli.py, or session.py — stdlib only.

Run: python continuous/54_inventory_refresh.py --findings-dir findings
"""
from __future__ import annotations

import argparse
import csv
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from common.findings_io import WAVE_MAP, is_complete_csv


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_TIMESTAMP_RE = re.compile(r'_(\d{8}_\d{6})$')


def _wave_of(script_name: str) -> str:
    m = re.match(r'^(\d+)', script_name)
    if not m:
        return ''
    return WAVE_MAP.get(m.group(1).zfill(2), '')


def _normalize_account_id(value: str) -> str:
    if not value or 'E' not in value.upper():
        return value
    try:
        return str(int(float(value)))
    except (ValueError, TypeError):
        return value


def _script_name_from_filename(filename: str) -> str:
    """
    Strip the trailing timestamp suffix and .csv extension to get the script name.

    e.g. '06_detect_nat_gateway_hotpaths_20240101_120000.csv'
         -> '06_detect_nat_gateway_hotpaths'
    """
    stem = Path(filename).stem            # strip .csv
    stripped = _TIMESTAMP_RE.sub('', stem)
    return stripped


def _collect_csvs(findings_dir: Path, since_days: int | None) -> list[Path]:
    """Return one CSV per script (latest by filename timestamp), excluding inventory_ snapshots."""
    cutoff = None
    if since_days is not None:
        cutoff = datetime.now(timezone.utc) - timedelta(days=since_days)

    latest: dict[str, tuple[str, Path]] = {}

    for path in findings_dir.rglob('*.csv'):
        if 'logs' in path.parts:
            continue
        if path.name.startswith('inventory_') or not is_complete_csv(path):
            continue
        if cutoff is not None:
            mtime = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
            if mtime < cutoff:
                continue

        stem = path.stem
        script_name = _TIMESTAMP_RE.sub('', stem)
        m = _TIMESTAMP_RE.search(stem)
        if not m:
            continue
        timestamp = m.group(1)

        if script_name not in latest or timestamp > latest[script_name][0]:
            latest[script_name] = (timestamp, path)

    return sorted(v[1] for v in latest.values())


def _read_csv(path: Path, script_name: str) -> tuple[list[str], list[dict]]:
    """
    Read a CSV file.  Returns (fieldnames, rows) where each row already has
    'source_script' populated.  Returns empty lists on read error.
    """
    try:
        with open(path, newline='', encoding='utf-8') as fh:
            reader = csv.DictReader(fh)
            if reader.fieldnames is None:
                return [], []
            fieldnames = list(reader.fieldnames)
            rows = []
            for row in reader:
                row['source_script'] = script_name
                rows.append(row)
            return fieldnames, rows
    except Exception as exc:
        print(f"  WARNING: could not read {path.name}: {exc}", file=sys.stderr)
        return [], []


def _write_consolidated(output_path: Path, all_fields: list[str], all_rows: list[dict]) -> None:
    with open(output_path, 'w', newline='', encoding='utf-8') as fh:
        writer = csv.DictWriter(fh, fieldnames=all_fields, extrasaction='ignore')
        writer.writeheader()
        for row in all_rows:
            writer.writerow(row)


def _safe_float(value: str) -> float:
    """Parse a savings value, returning 0.0 on failure."""
    try:
        return float(value) if value else 0.0
    except (ValueError, TypeError):
        return 0.0


# ---------------------------------------------------------------------------
# Summary printer
# ---------------------------------------------------------------------------

def _print_summary(all_rows: list[dict], output_path: Path) -> None:
    total = len(all_rows)

    # Breakdown by resource_type
    by_resource_type: Counter = Counter()
    by_finding: Counter = Counter()
    by_script: Counter = Counter()
    savings_by_row: list[tuple[float, str, str, str]] = []

    for row in all_rows:
        by_resource_type[row.get('resource_type', '(unknown)')] += 1
        by_finding[row.get('finding', '(unknown)')] += 1
        by_script[row.get('source_script', '(unknown)')] += 1
        savings = _safe_float(row.get('estimated_monthly_savings_usd', ''))
        savings_by_row.append((
            savings,
            row.get('resource_id', ''),
            row.get('resource_type', ''),
            row.get('finding', ''),
        ))

    total_savings = sum(s for s, *_ in savings_by_row)
    top_savings = sorted(savings_by_row, key=lambda x: x[0], reverse=True)[:10]

    sep = '-' * 64
    print(sep)
    print(f"  Inventory Refresh — {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    print(f"  Output: {output_path}")
    print(sep)
    print(f"\nTotal findings : {total:,}")
    print(f"Total est. savings: ${total_savings:,.2f}/month\n")

    print('Findings by resource type:')
    for rtype, count in by_resource_type.most_common():
        print(f"  {count:>6,}  {rtype}")

    print('\nFindings by finding code:')
    for finding, count in by_finding.most_common(20):
        print(f"  {count:>6,}  {finding}")

    print('\nFindings by source script:')
    for script, count in by_script.most_common():
        print(f"  {count:>6,}  {script}")

    print('\nTop 10 by estimated monthly savings (USD):')
    for rank, (savings, resource_id, rtype, finding) in enumerate(top_savings, 1):
        print(f"  {rank:>2}. ${savings:>10,.2f}  {rtype:<30}  {resource_id[:40]}  {finding}")

    print(sep)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        '--findings-dir', default='findings',
        help='Directory containing findings CSVs (default: findings)',
    )
    parser.add_argument(
        '--output-dir', default='findings',
        help='Directory to write the consolidated inventory CSV (default: findings)',
    )
    parser.add_argument(
        '--since', type=int, default=None, metavar='DAYS',
        help='Only include CSVs modified within the last N days',
    )
    args = parser.parse_args()

    findings_dir = Path(args.findings_dir)
    output_dir = Path(args.output_dir)

    if not findings_dir.exists():
        print(f"ERROR: findings directory '{findings_dir}' does not exist.", file=sys.stderr)
        sys.exit(1)

    output_dir.mkdir(parents=True, exist_ok=True)

    csv_files = _collect_csvs(findings_dir, args.since)
    if not csv_files:
        print('No findings CSVs found — nothing to consolidate.', file=sys.stderr)
        sys.exit(0)

    print(f'Reading {len(csv_files)} CSV file(s) from {findings_dir.resolve()} ...')

    # Standard fields lead in fixed order; script-specific extras follow.
    _STANDARD_FIELDS = [
        'scan_time', 'account_id', 'region', 'resource_id', 'resource_type',
        'finding', 'detail', 'estimated_monthly_savings_usd',
        'estimated_annual_savings_usd', 'wave', 'source_script', 'tags',
    ]
    all_fields_set: dict[str, None] = dict.fromkeys(_STANDARD_FIELDS)
    all_rows: list[dict] = []

    for path in csv_files:
        script_name = _script_name_from_filename(path.name)
        wave = _wave_of(script_name)
        fieldnames, rows = _read_csv(path, script_name)
        if not fieldnames:
            continue
        for field in fieldnames:
            all_fields_set[field] = None
        for row in rows:
            row['account_id'] = _normalize_account_id(row.get('account_id', ''))
            monthly = _safe_float(row.get('estimated_monthly_savings_usd', ''))
            row['estimated_monthly_savings_usd'] = monthly
            row['estimated_annual_savings_usd'] = round(monthly * 12, 2)
            row['wave'] = wave
        all_rows.extend(rows)
        print(f'  {len(rows):>6,} rows  <- {path.name}')

    all_fields = list(all_fields_set.keys())

    ts = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
    output_path = output_dir / f"inventory_{ts}.csv"

    print(f'\nWriting consolidated inventory -> {output_path}')
    _write_consolidated(output_path, all_fields, all_rows)

    _print_summary(all_rows, output_path)


if __name__ == '__main__':
    main()
