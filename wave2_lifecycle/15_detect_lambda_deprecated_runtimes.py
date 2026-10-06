#!/usr/bin/env python3
"""Task 15 - Lambda Deprecated Runtimes

Flags Lambda functions running on runtimes that are deprecated (security risk,
no patches) or approaching end-of-life (action required soon).

Columns:
  eol_date         - the date AWS ended/ends support for the runtime
  days_past_eol    - days since EOL (deprecated runtimes); blank for warn-soon
  days_until_eol   - days remaining until EOL (warn-soon runtimes); blank for deprecated

Run: python 15_detect_lambda_deprecated_runtimes.py --accounts 123456789012,234567890123
"""
from __future__ import annotations

import logging
import sys
from datetime import date
from pathlib import Path

from botocore.exceptions import ClientError

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from common import cli, session

SCRIPT_NAME = '15_detect_lambda_deprecated_runtimes'
EXTRA_FIELDS = [
    'function_name', 'runtime', 'last_modified', 'memory_mb',
    'severity', 'eol_date', 'days_past_eol', 'days_until_eol',
]

# AWS Lambda runtime EOL dates (date support ended or will end).
# Source: https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html
RUNTIME_EOL: dict[str, date] = {
    'dotnetcore2.1': date(2022, 7, 14),
    'dotnetcore3.1': date(2023, 12, 3),
    'nodejs14.x':    date(2023, 11, 27),
    'python3.7':     date(2023, 11, 27),
    'ruby2.7':       date(2023, 12, 7),
    'go1.x':         date(2023, 12, 31),
    'java8':         date(2023, 12, 31),
    'nodejs16.x':    date(2024, 3, 11),
    'python3.8':     date(2025, 2, 28),
    'nodejs18.x':    date(2025, 9, 1),
    # warn-soon
    'python3.9':     date(2025, 11, 14),
    'nodejs20.x':    date(2026, 4, 30),
}

# Runtimes flagged as eol-soon when within this many days of their EOL date.
WARN_SOON_DAYS = 180

log = logging.getLogger(SCRIPT_NAME)


def _classify(runtime: str, today: date) -> tuple[str, str, str, str, str] | None:
    """
    Return (severity, finding, eol_date_str, days_past_str, days_until_str)
    or None if the runtime is not flagged.

    Classification is fully date-driven so it stays accurate without manual
    updates to hardcoded sets as runtimes cross their EOL dates.
    """
    eol = RUNTIME_EOL.get(runtime)
    if eol is None:
        return None

    eol_str = eol.isoformat()
    delta = (eol - today).days  # negative means past EOL

    if delta <= 0:
        # EOL date has passed — deprecated
        return 'deprecated', 'deprecated-runtime', eol_str, str(-delta), ''
    elif delta <= WARN_SOON_DAYS:
        # EOL is approaching
        return 'eol-soon', 'runtime-eol-soon', eol_str, '', str(delta)
    return None


def scan(sess, account_id: str, region: str, writer) -> None:
    lambda_client = sess.client('lambda', region_name=region)
    today = date.today()

    try:
        paginator = lambda_client.get_paginator('list_functions')
        for page in paginator.paginate():
            for fn in page['Functions']:
                runtime = fn.get('Runtime', '')
                classified = _classify(runtime, today)
                if classified is None:
                    continue

                severity, finding, eol_date_str, days_past_str, days_until_str = classified

                name = fn['FunctionName']
                last_modified = fn.get('LastModified', '')

                writer.write(
                    account_id=account_id,
                    region=region,
                    resource_id=fn['FunctionArn'],
                    resource_type='Lambda Function',
                    finding=finding,
                    detail=(
                        f"function={name} runtime={runtime} "
                        f"eol={eol_date_str} days_past={days_past_str} "
                        f"days_until={days_until_str} last_modified={last_modified}"
                    ),
                    estimated_monthly_savings_usd=0,
                    tags=fn.get('Tags'),
                    function_name=name,
                    runtime=runtime,
                    last_modified=last_modified,
                    memory_mb=fn.get('MemorySize', ''),
                    severity=severity,
                    eol_date=eol_date_str,
                    days_past_eol=days_past_str,
                    days_until_eol=days_until_str,
                )
    except ClientError as exc:
        if session.is_skippable(exc):
            log.warning("%s/%s: skipped - %s", account_id, region, exc.response['Error']['Code'])
            return
        raise


def main() -> None:
    parser = cli.make_parser(__doc__)
    args = parser.parse_args()
    cli.run(args, SCRIPT_NAME, scan, extra_fields=EXTRA_FIELDS)


if __name__ == '__main__':
    main()
