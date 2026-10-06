"""Shared stdlib-only data-engineering utilities for findings CSVs.

No boto3, no truststore, no openpyxl. Safe to import from any context.
"""
from __future__ import annotations

import re
import json
import logging
from pathlib import Path

from common import tags as tagutil

# ---------------------------------------------------------------------------
# Wave mapping
# ---------------------------------------------------------------------------

WAVE_MAP: dict[str, str] = {
    '06': 'wave1_cost',        '07': 'wave1_cost',
    '10': 'wave1_cost',        '13': 'wave1_cost',
    '15': 'wave2_lifecycle',   '16': 'wave2_lifecycle',
    '26': 'wave3_reliability', '28': 'wave3_reliability',
    '30': 'wave4_security',    '31': 'wave4_security',
    '33': 'wave4_security',    '34': 'wave4_security',
    '35': 'wave4_security',    '36': 'wave4_security',
    '37': 'wave4_security',
    '38': 'wave5_performance', '39': 'wave5_performance',
    '40': 'wave5_performance', '41': 'wave5_performance',
    '43': 'continuous',        '46': 'continuous',
    '48': 'continuous',        '49': 'continuous',
    '52': 'continuous',        '54': 'continuous',
}

WAVE_LABELS: dict[str, str] = {
    'wave1_cost':         'Wave 1 - Cost',
    'wave2_lifecycle':    'Wave 2 - Lifecycle',
    'wave3_reliability':  'Wave 3 - Reliability',
    'wave4_security':     'Wave 4 - Security',
    'wave5_performance':  'Wave 5 - Performance',
    'continuous':         'Continuous',
}

# ---------------------------------------------------------------------------
# Scalar helpers
# ---------------------------------------------------------------------------

def safe_float(value) -> float:
    """Return 0.0 on blank or non-numeric input."""
    try:
        return float(value) if value else 0.0
    except (ValueError, TypeError):
        return 0.0


def normalize_account_id(value: str) -> str:
    """Convert scientific-notation account IDs (Excel artefact) to plain decimal strings."""
    if not value or ('E' not in value.upper()):
        return value
    try:
        result = str(int(float(value)))
        # 5+ trailing zeros on a 12-digit ID means Excel rounded away real digits.
        # We can't recover the original — caller should re-run the scan for that account.
        if len(result) == 12 and result.endswith('00000'):
            import warnings
            warnings.warn(
                f"Account ID '{value}' converted to '{result}' but likely lost precision "
                f"(Excel scientific-notation truncation). Re-run the scan to get the real ID.",
                stacklevel=2,
            )
        return result
    except (ValueError, TypeError):
        return value

# ---------------------------------------------------------------------------
# CSV discovery
# ---------------------------------------------------------------------------

def is_complete_csv(path: Path) -> bool:
    """Legacy timestamped CSVs are accepted; new manifests must be complete."""
    if not re.match(r'^.+_\d{8}_\d{6}\.csv$', path.name):
        if path.name.endswith('.incomplete.csv'):
            logging.getLogger(__name__).warning('Excluded incomplete scan (older results may remain): %s', path)
        return False
    manifest = path.with_suffix('.json')
    if not manifest.exists():
        return True
    try:
        return json.loads(manifest.read_text(encoding='utf-8')).get('status') == 'complete'
    except (OSError, ValueError, AttributeError):
        logging.getLogger(__name__).warning('Invalid run manifest: %s', manifest)
        return False


def discover_latest_csvs(findings_dir: str | Path) -> list[Path]:
    """Return the latest CSV per script name, excluding logs/ and inventory_* files."""
    root = Path(findings_dir)
    if not root.exists():
        raise FileNotFoundError(f"findings directory not found: {root}")

    latest: dict[str, tuple[str, Path]] = {}

    for csv_path in root.rglob('*.csv'):
        if 'logs' in csv_path.parts:
            continue
        if csv_path.name.startswith('inventory_') or not is_complete_csv(csv_path):
            continue

        m = re.match(r'^(.+?)_(\d{8})_(\d{6})$', csv_path.stem)
        if not m:
            continue

        script_name = m.group(1)
        timestamp = m.group(2) + m.group(3)

        if script_name not in latest or timestamp > latest[script_name][0]:
            latest[script_name] = (timestamp, csv_path)

    return sorted(v[1] for v in latest.values())


def wave_of(script_name: str) -> str | None:
    """Map a script filename stem to its wave key via the numeric prefix."""
    m = re.match(r'^(\d+)', script_name)
    if not m:
        return None
    prefix = m.group(1).zfill(2)
    return WAVE_MAP.get(prefix)

# ---------------------------------------------------------------------------
# Severity classification
# ---------------------------------------------------------------------------

FINDING_SEVERITIES = {
    'guardduty-not-enabled': 'High', 'securityhub-not-enabled': 'High',
    'config-not-enabled': 'High', 'config-recorder-stopped': 'High',
    'console-no-mfa': 'High', 'dr-quota-lower-than-primary': 'High',
    'untested-runbook': 'Medium', 'role-no-recorded-use': 'Medium',
    'role-never-used': 'Medium', 'stale-key-90d': 'Medium',
    'key-never-used': 'Medium', 'dormant-user': 'Medium',
    'wrong-instance-family-memory-starved': 'Medium',
    'low-cache-hit-rate': 'Medium', 'icmp-echo-open-to-internet': 'Low',
}


def severity_of(wave: str | None, finding: str, monthly_usd: float) -> str:
    """Map wave + finding text + monthly savings to High / Medium / Low."""
    f = finding.lower()
    if f in FINDING_SEVERITIES:
        return FINDING_SEVERITIES[f]

    if wave in ('wave1_cost', 'wave5_performance'):
        if monthly_usd > 500:
            return 'High'
        if monthly_usd >= 50:
            return 'Medium'
        return 'Low'

    if wave == 'wave2_lifecycle':
        if 'deprecated-runtime' in f or 'deletion candidate' in f:
            return 'High'
        if 'eol-soon' in f or 'migrate to alb or nlb' in f:
            return 'Medium'
        return 'Low'

    if wave == 'wave3_reliability':
        if any(kw in f for kw in ('quota-gap', 'never-tested', 'runbook-never-tested')):
            return 'High'
        if 'overdue' in f or 'stale' in f:
            return 'Medium'
        return 'Medium'

    if wave == 'wave4_security':
        # Exact match, not substring: 'open-to-internet' is also a suffix of
        # 'icmp-open-to-internet' / 'icmp-echo-open-to-internet', which must
        # stay Medium/Low respectively rather than escalate to High here.
        if f == 'open-to-internet':
            return 'High'
        red_kw = (
            '0.0.0.0/0', 'unencrypted', 'no-trail', 'trail-not-logging',
            'no-trail-in-region', 'guardduty-disabled', 'securityhub-disabled',
            'config-disabled', 'wildcard', 'root key',
        )
        if any(kw in f for kw in red_kw):
            return 'High'
        amber_kw = (
            'rotation-disabled', 'regional-trail-only', 'log-validation-disabled',
            'unused-role', 'global-events-excluded', 'icmp-open-to-internet',
        )
        if any(kw in f for kw in amber_kw):
            return 'Medium'
        return 'Medium'

    if wave == 'continuous':
        _HIGH = {
            'quota-at-80pct',       # 48: quota at critical threshold
            'service-issue',        # 52: active AWS service disruption
            'retirement-notice',    # 52: resource retirement / EOL notice
            'no-cloudwatch-agent',  # 46: EC2 with no OS-level metrics
        }
        _MEDIUM = {
            'quota-at-70pct',                   # 48: quota at warning threshold
            'custom-quota-threshold-reached',   # 49: custom-tracked limit
            'scheduled-change',                 # 52: scheduled maintenance
            'missing-required-tags',            # 43: mandatory tags absent
            'inconsistent-tag-key',             # 43: non-canonical tag key casing
            'enhanced-monitoring-disabled',     # 46: RDS without enhanced monitoring
            'access-logs-disabled',             # 46: ELB without access logs
            'account-notification',             # 52: general account notification
        }
        if f in _HIGH:
            return 'High'
        if f in _MEDIUM:
            return 'Medium'
        return 'Medium'

    return 'Medium'

# ---------------------------------------------------------------------------
# Tag parsing
# ---------------------------------------------------------------------------

_ORG_TAGS = ('CostCenter', 'Environment', 'Owner', 'Application')
# Every OWNER_TAG_KEYS alias also resolves to the canonical 'Owner' slot, so
# this parser and common.tags.owner_from_tags() (used by detector scripts and
# FindingsWriter) recognize the same owner-tag vocabulary and never disagree
# about which resources have an owner tag.
# Keyed by tagutil.normalize_key so 'cost center', 'cost-center', 'CostCenter',
# and 'costcenter' all resolve identically (real tagging in this org mixes
# separators for the same concept).
_TAG_KEY_MAP = {tagutil.normalize_key(t): t for t in _ORG_TAGS}
_TAG_KEY_MAP.update({tagutil.normalize_key(alias): 'Owner' for alias in tagutil.OWNER_TAG_KEYS})


def parse_tags(tag_blob: str) -> dict[str, str]:
    """Extract org tag values from a semicolon-separated key=value tag string."""
    result: dict[str, str] = {t: '' for t in _ORG_TAGS}
    if not tag_blob:
        return result
    for pair in tag_blob.split(';'):
        if '=' not in pair:
            continue
        key, _, val = pair.partition('=')
        canonical = _TAG_KEY_MAP.get(tagutil.normalize_key(key))
        if canonical:
            result[canonical] = val.strip()
    return result
