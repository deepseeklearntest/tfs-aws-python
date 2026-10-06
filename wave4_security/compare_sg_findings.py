#!/usr/bin/env python3
"""Reconcile our open-SG findings (script 30) against the security team's Wiz export

Standalone, auth-free comparison tool. The security team tracks security
groups open to the internet on SSH (TCP:22) and RDP (TCP:3389) in a Wiz
export. Our detector (30_detect_open_security_groups.py) covers those two
ports plus 9 more sensitive ports and all-traffic rules. This script joins
the two datasets per exposure — (account_id, security_group, port) — so we
only act on what the security team is NOT already covering, and surface any
of their findings our scan never caught (coverage gaps).

Does NOT use Britive auth, cli.py, or session.py — stdlib only.

Run: python wave4_security/compare_sg_findings.py
"""
from __future__ import annotations

import argparse
import csv
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

# Kept in sync with wave4_security/30_detect_open_security_groups.py's
# SENSITIVE_PORTS — that script is the source of truth for which ports we
# scan for; duplicated here rather than imported so this tool stays
# stdlib-only (script 30 pulls in common.session, which imports boto3).
SENSITIVE_PORTS = {22, 3389, 3306, 5432, 1433, 6379, 27017, 9200, 9300, 2181, 27018}

# Ports the security team's Wiz export covers.
THEIR_PORTS = {22, 3389}

_OUR_SCRIPT_NAME = '30_detect_open_security_groups'
_TIMESTAMP_RE = re.compile(r'_(\d{8}_\d{6})$')
_RESOURCE_NAME_RE = re.compile(r'^(.*)\s\(sg-[0-9a-f]+\)$')


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _normalize_account_id(value: str) -> str:
    """Undo Excel's scientific-notation mangling of large account-ID numbers."""
    if not value or 'E' not in value.upper():
        return value
    try:
        return str(int(float(value)))
    except (ValueError, TypeError):
        return value


def _find_latest_our_csv(findings_dir: Path) -> Path | None:
    """Return the newest 30_detect_open_security_groups_*.csv under findings_dir."""
    candidates = []
    for path in findings_dir.rglob(f"{_OUR_SCRIPT_NAME}_*.csv"):
        m = _TIMESTAMP_RE.search(path.stem)
        if m:
            candidates.append((m.group(1), path))
    if not candidates:
        return None
    return max(candidates, key=lambda t: t[0])[1]


def _parse_our_ports(port_range: str) -> set[int]:
    """Expand a script-30 port_range string into the sensitive ports it covers.

    Mirrors script 30's _format_port_range / _overlaps_sensitive: from_port is
    never -1 here (that case is formatted as 'all' upstream), but to_port can
    be -1 for ICMP rules (e.g. "8--1" = type 8, all codes) — script 30 treats
    that as matching every sensitive port, via its 65535 fallback.
    """
    port_range = (port_range or '').strip()
    if not port_range or port_range == 'all':
        return set(SENSITIVE_PORTS)
    if '-' in port_range:
        lo_str, hi_str = port_range.split('-', 1)
        try:
            lo, hi = int(lo_str), int(hi_str)
        except ValueError:
            return set()
        if hi == -1:
            hi = 65535
        return {p for p in SENSITIVE_PORTS if lo <= p <= hi}
    try:
        port = int(port_range)
    except ValueError:
        return set()
    return {port} if port in SENSITIVE_PORTS else set()


def _derive_their_port(finding_text: str) -> int | None:
    """Map a Wiz 'Finding' string to the port it's about."""
    text = (finding_text or '').upper()
    if 'SSH' in text or 'TCP:22' in text:
        return 22
    if 'RDP' in text or 'TCP:3389' in text:
        return 3389
    return None


def _extract_sg_name(resource_field: str) -> str:
    m = _RESOURCE_NAME_RE.match((resource_field or '').strip())
    return m.group(1) if m else ''


def _read_their_csv(path: Path) -> list[dict]:
    # utf-8-sig strips the leading BOM the Wiz export ships with.
    with open(path, newline='', encoding='utf-8-sig') as fh:
        return list(csv.DictReader(fh))


def _read_our_csv(path: Path) -> list[dict]:
    with open(path, newline='', encoding='utf-8') as fh:
        return list(csv.DictReader(fh))


# ---------------------------------------------------------------------------
# Reconciliation
# ---------------------------------------------------------------------------

OUTPUT_FIELDS = [
    'category', 'account_id', 'account_name', 'region', 'sg_id', 'sg_name',
    'port', 'covered_ports', 'uncovered_ports', 'our_detail',
    'their_finding', 'their_owner', 'their_severity', 'their_wiz_status',
]


def _index_their_rows(their_rows: list[dict]) -> tuple[
    dict[tuple[str, str, int], dict], dict[tuple[str, str], dict]
]:
    """Build (account, sg, port) -> row and (account, sg) -> latest metadata lookups."""
    by_exposure: dict[tuple[str, str, int], dict] = {}
    by_sg: dict[tuple[str, str], dict] = {}

    for row in their_rows:
        account_id = _normalize_account_id(row.get('Account ID', ''))
        sg_id = (row.get('Security Group', '') or '').strip()
        port = _derive_their_port(row.get('Finding', ''))
        if not account_id or not sg_id:
            continue
        by_sg[(account_id, sg_id)] = row
        if port is not None:
            by_exposure[(account_id, sg_id, port)] = row

    return by_exposure, by_sg


def _reconcile(
    our_rows: list[dict], their_rows: list[dict]
) -> tuple[list[dict], Counter]:
    their_by_exposure, their_by_sg = _index_their_rows(their_rows)

    output_rows: list[dict] = []
    stats: Counter = Counter()

    # (account, sg, port) pairs our scan detected, restricted to the ports the
    # security team tracks — used below to find their coverage gaps.
    our_detected_their_ports: set[tuple[str, str, int]] = set()

    for row in our_rows:
        account_id = _normalize_account_id(row.get('account_id', ''))
        sg_id = row.get('resource_id', '')
        ports = _parse_our_ports(row.get('port_range', ''))
        if not ports:
            continue

        their_relevant = ports & THEIR_PORTS
        for p in their_relevant:
            our_detected_their_ports.add((account_id, sg_id, p))

        covered = {p for p in their_relevant if (account_id, sg_id, p) in their_by_exposure}
        uncovered = ports - covered

        category = 'OVERLAP' if not uncovered else 'OURS-ONLY'
        stats[category] += 1

        their_meta = their_by_sg.get((account_id, sg_id), {})

        output_rows.append({
            'category': category,
            'account_id': account_id,
            'account_name': their_meta.get('Account Name', ''),
            'region': row.get('region', ''),
            'sg_id': sg_id,
            'sg_name': row.get('sg_name', ''),
            'port': '',
            'covered_ports': ','.join(str(p) for p in sorted(covered)),
            'uncovered_ports': ','.join(str(p) for p in sorted(uncovered)),
            'our_detail': row.get('detail', ''),
            'their_finding': '',
            'their_owner': their_meta.get('Owner', ''),
            'their_severity': their_meta.get('Severity', ''),
            'their_wiz_status': their_meta.get('Wiz Status', ''),
        })

    for (account_id, sg_id, port), row in their_by_exposure.items():
        if (account_id, sg_id, port) in our_detected_their_ports:
            continue
        stats['THEIRS-ONLY'] += 1
        output_rows.append({
            'category': 'THEIRS-ONLY',
            'account_id': account_id,
            'account_name': row.get('Account Name', ''),
            'region': row.get('Region', ''),
            'sg_id': sg_id,
            'sg_name': _extract_sg_name(row.get('Resource', '')),
            'port': port,
            'covered_ports': '',
            'uncovered_ports': '',
            'our_detail': '',
            'their_finding': row.get('Finding', ''),
            'their_owner': row.get('Owner', ''),
            'their_severity': row.get('Severity', ''),
            'their_wiz_status': row.get('Wiz Status', ''),
        })

    return output_rows, stats


def _write_output(output_path: Path, rows: list[dict]) -> None:
    # utf-8-sig (BOM) so Excel auto-detects UTF-8 instead of mangling the
    # Wiz Status emoji under the system codepage (cp1252 mojibake).
    with open(output_path, 'w', newline='', encoding='utf-8-sig') as fh:
        writer = csv.DictWriter(fh, fieldnames=OUTPUT_FIELDS, extrasaction='ignore')
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def _print_summary(stats: Counter, output_path: Path) -> None:
    sep = '-' * 64
    print(sep)
    print(f"  SG Findings Reconciliation — {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    print(f"  Output: {output_path}")
    print(sep)
    print(f"\nOVERLAP     (security team owns):   {stats['OVERLAP']:>6,} of our findings")
    print(f"OURS-ONLY   (we action):            {stats['OURS-ONLY']:>6,} of our findings")
    print(f"THEIRS-ONLY (our scan missed):      {stats['THEIRS-ONLY']:>6,} exposures")
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
        '--our-findings', default=None,
        help='Path to a 30_detect_open_security_groups CSV '
             '(default: newest one under --findings-dir)',
    )
    parser.add_argument(
        '--security-csv', default='ec2_filtered_findings.csv',
        help='Path to the security team\'s Wiz export (default: ec2_filtered_findings.csv)',
    )
    parser.add_argument(
        '--findings-dir', default='findings',
        help='Directory to search for our findings CSV when --our-findings is omitted',
    )
    parser.add_argument(
        '--output-dir', default='findings',
        help='Directory to write the reconciliation CSV (default: findings)',
    )
    args = parser.parse_args()

    findings_dir = Path(args.findings_dir)
    security_csv = Path(args.security_csv)
    output_dir = Path(args.output_dir)

    our_path = Path(args.our_findings) if args.our_findings else _find_latest_our_csv(findings_dir)
    if our_path is None or not our_path.exists():
        print(f"ERROR: no {_OUR_SCRIPT_NAME} CSV found under '{findings_dir}'.", file=sys.stderr)
        sys.exit(1)
    if not security_csv.exists():
        print(f"ERROR: security team CSV '{security_csv}' does not exist.", file=sys.stderr)
        sys.exit(1)

    print(f'Reading our findings  <- {our_path}')
    our_rows = _read_our_csv(our_path)
    print(f'Reading security team findings <- {security_csv}')
    their_rows = _read_their_csv(security_csv)
    print(f'  {len(our_rows):>6,} rows (ours)')
    print(f'  {len(their_rows):>6,} rows (theirs)')

    output_rows, stats = _reconcile(our_rows, their_rows)

    output_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
    output_path = output_dir / f"compare_sg_findings_{ts}.csv"
    _write_output(output_path, output_rows)

    _print_summary(stats, output_path)


if __name__ == '__main__':
    main()
