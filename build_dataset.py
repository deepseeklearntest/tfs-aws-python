#!/usr/bin/env python3
"""Build a flat, append-idempotent findings dataset for the HTML dashboard and Power BI.

Run: python build_dataset.py
     python build_dataset.py --findings-dir findings --dataset-file dataset/findings_dataset.csv
"""
from __future__ import annotations

import argparse
import csv
import re
import sys
from datetime import date
from pathlib import Path

from common.findings_io import (
    discover_latest_csvs,
    normalize_account_id,
    parse_tags,
    safe_float,
    severity_of,
    wave_of,
)

DATASET_COLUMNS = [
    'snapshot_date',
    'wave',
    'source_script',
    'account_id',
    'region',
    'resource_type',
    'resource_id',
    'finding',
    'detail',
    'severity',
    'estimated_monthly_savings_usd',
    'estimated_annual_savings_usd',
    'tag_CostCenter',
    'tag_Environment',
    'tag_Owner',
    'tag_Application',
    'owner',
]


def load_existing_dataset(dataset_path: Path) -> list[dict]:
    """Read existing dataset CSV; return [] if file does not exist."""
    if not dataset_path.exists():
        return []
    rows: list[dict] = []
    with open(dataset_path, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(dict(row))
    return rows


def normalize_row(row: dict, script_name: str, snapshot_date: str) -> dict:
    """Map one raw findings CSV row to the output schema."""
    monthly = round(safe_float(row.get('estimated_monthly_savings_usd', '')), 2)
    wave = wave_of(script_name) or ''
    finding = row.get('finding', '')
    tags = parse_tags(row.get('tags', ''))
    return {
        'snapshot_date':                   snapshot_date,
        'wave':                            wave,
        'source_script':                   script_name,
        'account_id':                      normalize_account_id(row.get('account_id', '')),
        'region':                          row.get('region', ''),
        'resource_type':                   row.get('resource_type', ''),
        'resource_id':                     row.get('resource_id', ''),
        'finding':                         finding,
        'detail':                          row.get('detail', ''),
        'severity':                        severity_of(wave or None, finding, monthly),
        'estimated_monthly_savings_usd':   monthly,
        'estimated_annual_savings_usd':    round(monthly * 12, 2),
        'tag_CostCenter':                  tags.get('CostCenter', ''),
        'tag_Environment':                 tags.get('Environment', ''),
        'tag_Owner':                       tags.get('Owner', ''),
        'tag_Application':                 tags.get('Application', ''),
        # Prefer the finding's own explicit owner (e.g. script 40's
        # instance-first resolution); fall back to the tag-derived owner.
        'owner':                           row.get('owner', '') or tags.get('Owner', ''),
    }


def write_dataset(dataset_path: Path, rows: list[dict]) -> None:
    """Write all rows to dataset CSV; creates parent directory if needed."""
    dataset_path.parent.mkdir(parents=True, exist_ok=True)
    with open(dataset_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=DATASET_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)


def print_summary(new_rows: list[dict], all_rows: list[dict], snapshot_date: str) -> None:
    """Print a human-readable summary of the latest snapshot and full dataset."""
    snapshots = sorted({r['snapshot_date'] for r in all_rows})
    total = len(all_rows)
    new_count = len(new_rows)

    print(f"\nToday's snapshot: {new_count} rows added for {snapshot_date}")
    print(f"Total in dataset: {total} rows across {len(snapshots)} snapshot(s)")

    if not new_rows:
        return

    monthly_total = sum(safe_float(r['estimated_monthly_savings_usd']) for r in new_rows)
    annual_total = sum(safe_float(r['estimated_annual_savings_usd']) for r in new_rows)
    high = sum(1 for r in new_rows if r['severity'] == 'High')
    medium = sum(1 for r in new_rows if r['severity'] == 'Medium')
    low = sum(1 for r in new_rows if r['severity'] == 'Low')

    print(f"\nSUMMARY - latest snapshot ({snapshot_date})")
    print(f"  Monthly savings:  ${monthly_total:,.2f}")
    print(f"  Annual savings:   ${annual_total:,.2f}")
    print(f"  Total findings:   {new_count}")
    print(f"  High severity:    {high}")
    print(f"  Medium severity:  {medium}")
    print(f"  Low severity:     {low}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    parser.add_argument('--findings-dir', default='findings',
                        help='Directory to scan for findings CSVs (default: findings)')
    parser.add_argument('--dataset-file', default='dataset/findings_dataset.csv',
                        help='Output dataset CSV path (default: dataset/findings_dataset.csv)')
    args = parser.parse_args()

    findings_dir = Path(args.findings_dir)
    dataset_path = Path(args.dataset_file)

    if not findings_dir.exists():
        print(f"Error: findings directory not found: {findings_dir}", file=sys.stderr)
        sys.exit(1)

    print(f"Scanning {findings_dir}/ for CSVs...")

    try:
        csv_paths = discover_latest_csvs(findings_dir)
    except FileNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    if not csv_paths:
        print(f"No CSVs found in {findings_dir}/ (searched recursively, excluding logs/ and inventory_*)")
        sys.exit(0)

    snapshot_date = date.today().isoformat()
    new_rows: list[dict] = []

    for csv_path in csv_paths:
        m = re.match(r'^(.+?)_(\d{8})_(\d{6})$', csv_path.stem)
        script_name = m.group(1) if m else csv_path.stem
        row_count = 0
        try:
            with open(csv_path, newline='', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for raw_row in reader:
                    try:
                        new_rows.append(normalize_row(raw_row, script_name, snapshot_date))
                        row_count += 1
                    except Exception as exc:
                        print(f"Warning: skipping malformed row in {csv_path.name}: {exc}",
                              file=sys.stderr)
            print(f"  Loaded: {script_name:<55} ({row_count} rows)")
        except Exception as exc:
            print(f"Warning: could not read {csv_path}: {exc}", file=sys.stderr)

    # Detect account IDs that look like precision-lost Excel scientific-notation conversions.
    # 12-digit IDs with 5+ trailing zeros almost certainly had their last digits rounded away.
    corrupted: dict[str, list[str]] = {}
    for row in new_rows:
        aid = row.get('account_id', '')
        if len(aid) == 12 and aid.isdigit() and aid.endswith('00000'):
            corrupted.setdefault(aid, [])
            script = row.get('source_script', '')
            if script and script not in corrupted[aid]:
                corrupted[aid].append(script)

    if corrupted:
        print("\nWARNING: Likely Excel-corrupted account IDs detected (precision lost):", file=sys.stderr)
        for aid, scripts in sorted(corrupted.items()):
            print(f"  {aid}  (from: {', '.join(scripts)})", file=sys.stderr)
        print("  Fix: re-run those scripts to regenerate the CSVs with correct account IDs.", file=sys.stderr)
        print("  Do NOT open findings CSVs in Excel and save — use generate_report.py instead.", file=sys.stderr)

    existing_rows = load_existing_dataset(dataset_path)
    retained_rows = [r for r in existing_rows if r.get('snapshot_date') != snapshot_date]
    all_rows = retained_rows + new_rows

    write_dataset(dataset_path, all_rows)
    print_summary(new_rows, all_rows, snapshot_date)


if __name__ == '__main__':
    main()
