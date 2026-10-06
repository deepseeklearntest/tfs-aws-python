#!/usr/bin/env python3
"""
Task 7 - Cross-AZ Data Transfer Top Sources

Queries Cost Explorer for cross-AZ (intra-region) data transfer cost per linked
account over the last full month. Cross-AZ traffic surfaces in CUR/CE under
USAGE_TYPE values matching '*-DataTransfer-Regional-Bytes'.

NOTE: Resource-level attribution requires CUR 2.0 + Athena. This script
quantifies the per-account magnitude so you know where to prioritise the
deeper Athena dive. Cost Explorer data lags 24-48 hours.

PERMISSIONS: ce:GetCostAndUsage on each role.

Run: python 07_detect_cross_az_transfer.py --accounts 123456789012
"""
from __future__ import annotations

import logging
import sys
from datetime import date, timedelta
from pathlib import Path

from botocore.exceptions import ClientError

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from common import cli, session

SCRIPT_NAME = '07_detect_cross_az_transfer'
CE_REGION = 'us-east-1'
THRESHOLD_USD_DEFAULT = 50.0

log = logging.getLogger(SCRIPT_NAME)
EXTRA_FIELDS = ['usage_type', 'period_start', 'period_end', 'total_cost_usd']


def _last_month_window() -> tuple[str, str]:
    today = date.today()
    first_this = today.replace(day=1)
    last_prev = first_this - timedelta(days=1)
    first_prev = last_prev.replace(day=1)
    return first_prev.isoformat(), first_this.isoformat()


def make_scan(threshold_usd: float, start: str, end: str):
    def scan(sess, account_id: str, writer) -> None:
        ce = sess.client('ce', region_name=CE_REGION)
        log.info("Account %s - CE period %s to %s", account_id, start, end)

        try:
            # CE dimension filters only support EQUALS/CASE_SENSITIVE/ABSENT,
            # not CONTAINS. Fetch all USAGE_TYPE groups and filter in Python.
            resp = ce.get_cost_and_usage(
                TimePeriod={'Start': start, 'End': end},
                Granularity='MONTHLY',
                Filter={
                    'Dimensions': {
                        'Key': 'RECORD_TYPE',
                        'Values': ['Usage'],
                        'MatchOptions': ['EQUALS'],
                    }
                },
                GroupBy=[{'Type': 'DIMENSION', 'Key': 'USAGE_TYPE'}],
                Metrics=['UnblendedCost'],
            )
        except ClientError as exc:
            if session.is_skippable(exc):
                log.warning("%s: CE skipped - %s", account_id, exc.response['Error']['Code'])
                return
            log.error("%s: CE query failed - %s", account_id, exc)
            return

        for result in resp.get('ResultsByTime', []):
            for group in result.get('Groups', []):
                usage_type = group['Keys'][0] if group.get('Keys') else 'unknown'
                # Keep only cross-AZ / intra-region transfer lines
                if 'Regional' not in usage_type and 'DataTransfer-Regional' not in usage_type:
                    continue
                cost = float(group['Metrics']['UnblendedCost']['Amount'])
                if cost < threshold_usd:
                    continue
                writer.write(
                    account_id=account_id,
                    region=CE_REGION,
                    resource_id=f"{account_id}/{usage_type}",
                    resource_type='Data Transfer',
                    finding='high cross-AZ data transfer - investigate with CUR+Athena',
                    detail=f"UsageType={usage_type} Cost=${cost:.2f} Period={start} to {end}",
                    estimated_monthly_savings_usd=round(cost * 0.50, 2),
                    usage_type=usage_type,
                    period_start=start,
                    period_end=end,
                    total_cost_usd=f"{cost:.2f}",
                )
    return scan


def main() -> None:
    default_start, default_end = _last_month_window()
    parser = cli.make_parser(__doc__, account_level=True)
    parser.add_argument(
        '--threshold-usd', type=float, default=THRESHOLD_USD_DEFAULT,
        help=f'Minimum monthly cost to flag (default: ${THRESHOLD_USD_DEFAULT})',
    )
    parser.add_argument(
        '--start', default=default_start,
        help=f'Period start date YYYY-MM-DD (default: {default_start})',
    )
    parser.add_argument(
        '--end', default=default_end,
        help=f'Period end date YYYY-MM-DD, exclusive (default: {default_end})',
    )
    args = parser.parse_args()
    cli.run(
        args, SCRIPT_NAME, make_scan(args.threshold_usd, args.start, args.end),
        extra_fields=EXTRA_FIELDS, account_level=True,
    )


if __name__ == '__main__':
    main()
