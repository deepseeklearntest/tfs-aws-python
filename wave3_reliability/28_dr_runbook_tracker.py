#!/usr/bin/env python3
"""Task 28 — Untested DR Runbooks

Reads a local registry CSV (28_dr_runbook_registry.csv) and flags workloads
whose last DR runbook test is older than --threshold-days (default: 180) or
has never been tested.

No AWS authentication is required — this is a process-level compliance check
against a manually maintained registry.

Run: python 28_dr_runbook_tracker.py
     python 28_dr_runbook_tracker.py --registry /path/to/registry.csv --threshold-days 90
"""
from __future__ import annotations

import argparse
import csv
import logging
import sys
from datetime import date, datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Output schema — matches COMMON_FIELDS from common/output.py so findings CSVs
# can be concatenated with other scanner outputs.
# ---------------------------------------------------------------------------
COMMON_FIELDS = [
    'scan_time',
    'account_id',
    'region',
    'resource_id',
    'resource_type',
    'finding',
    'detail',
    'estimated_monthly_savings_usd',
    'tags',
]

SCRIPT_NAME = '28_dr_runbook_tracker'
DEFAULT_THRESHOLD_DAYS = 180
DEFAULT_REGISTRY = Path(__file__).resolve().parent / '28_dr_runbook_registry.csv'

log = logging.getLogger(SCRIPT_NAME)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_date(date_str: str) -> date | None:
    """Parse a YYYY-MM-DD string; return None if blank or unparseable."""
    if not date_str or not date_str.strip():
        return None
    try:
        return datetime.strptime(date_str.strip(), '%Y-%m-%d').date()
    except ValueError:
        log.warning("Could not parse date '%s' — treating as never tested", date_str)
        return None


def _days_since(last_test: date | None) -> int | None:
    """Return number of days since last_test, or None if never tested."""
    if last_test is None:
        return None
    return (date.today() - last_test)


def _build_detail(row: dict, last_test: date | None, days_since: int | None) -> str:
    if last_test is None:
        return f"No test date recorded. tested_by={row.get('tested_by', '').strip() or 'unknown'}"
    return (
        f"last_test_date={last_test.isoformat()}  "
        f"days_since_test={days_since}  "
        f"last_outcome={row.get('last_test_outcome', '').strip() or 'unknown'}  "
        f"tested_by={row.get('tested_by', '').strip() or 'unknown'}"
    )


# ---------------------------------------------------------------------------
# Core checker
# ---------------------------------------------------------------------------

def check_registry(registry_path: Path, threshold_days: int) -> list[dict]:
    """Read the registry CSV and return a list of finding rows."""
    if not registry_path.exists():
        log.error("Registry file not found: %s", registry_path)
        sys.exit(1)

    findings: list[dict] = []
    scan_time = datetime.now(timezone.utc).isoformat()

    with registry_path.open(newline='', encoding='utf-8') as fh:
        reader = csv.DictReader(fh)
        for lineno, row in enumerate(reader, start=2):  # 2 = first data row
            workload = row.get('workload_name', '').strip()
            if not workload:
                log.debug("Line %d: empty workload_name, skipping", lineno)
                continue

            last_test = _parse_date(row.get('last_test_date', ''))
            days = _days_since(last_test)

            # Determine whether this row is stale
            if last_test is None:
                finding_code = 'runbook-never-tested'
                stale = True
            elif days >= threshold_days:
                finding_code = 'untested-runbook'
                stale = True
            else:
                stale = False

            if not stale:
                log.debug(
                    "Workload '%s': last tested %s (%d days ago) — OK",
                    workload, last_test, days,
                )
                continue

            log.info(
                "FLAGGED workload='%s' account=%s finding=%s",
                workload,
                row.get('account_id', '').strip(),
                finding_code,
            )

            findings.append({
                'scan_time': scan_time,
                'account_id': row.get('account_id', '').strip(),
                'region': row.get('primary_region', '').strip(),
                'resource_id': workload,
                'resource_type': 'DR Runbook',
                'finding': finding_code,
                'detail': _build_detail(row, last_test, days),
                'estimated_monthly_savings_usd': '0.00',
                'tags': '',
            })

    return findings


# ---------------------------------------------------------------------------
# Output writer
# ---------------------------------------------------------------------------

def write_findings(findings: list[dict], output_dir: Path) -> Path:
    """Write findings to a timestamped CSV; return the output path."""
    output_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
    out_path = output_dir / f"{SCRIPT_NAME}_{ts}.csv"

    with out_path.open('w', newline='', encoding='utf-8') as fh:
        writer = csv.DictWriter(fh, fieldnames=COMMON_FIELDS, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(findings)

    log.info("Wrote %d finding(s) → %s", len(findings), out_path)
    return out_path


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def make_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        '--registry',
        default=str(DEFAULT_REGISTRY),
        help=f'Path to the runbook registry CSV (default: {DEFAULT_REGISTRY})',
    )
    p.add_argument(
        '--threshold-days',
        type=int,
        default=DEFAULT_THRESHOLD_DAYS,
        help=f'Flag runbooks not tested within this many days (default: {DEFAULT_THRESHOLD_DAYS})',
    )
    p.add_argument(
        '--output-dir',
        default='findings',
        help='Directory for CSV output (default: findings)',
    )
    p.add_argument(
        '--log-level',
        default='INFO',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        help='Log verbosity (default: INFO)',
    )
    return p


def main() -> None:
    parser = make_parser()
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format='%(asctime)s  %(levelname)-8s  %(name)s  %(message)s',
        datefmt='%Y-%m-%dT%H:%M:%SZ',
    )

    registry_path = Path(args.registry).resolve()
    output_dir = Path(args.output_dir).resolve()

    log.info("Reading registry: %s", registry_path)
    log.info("Threshold: %d days", args.threshold_days)

    findings = check_registry(registry_path, args.threshold_days)

    if not findings:
        log.info("No stale runbooks found — all workloads tested within %d days.", args.threshold_days)
        sys.exit(0)

    out_path = write_findings(findings, output_dir)
    print(f"Found {len(findings)} stale runbook(s). Output: {out_path}")


if __name__ == '__main__':
    main()
