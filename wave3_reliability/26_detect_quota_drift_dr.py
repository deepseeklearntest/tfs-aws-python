#!/usr/bin/env python3
"""Task 26 — Quota Drift Between Active and DR Regions

Compares service quota limits between a primary region and a DR region. Flags
any quota that is lower in the DR region than in the primary — asymmetric quotas
mean failover will fail under load.

Run: python 26_detect_quota_drift_dr.py --accounts 123456789012,234567890123
"""
from __future__ import annotations

import logging
import sys
from pathlib import Path

from botocore.exceptions import ClientError

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from common import cli, session

SCRIPT_NAME = '26_detect_quota_drift_dr'

DEFAULT_PRIMARY_REGION = 'us-east-1'
DEFAULT_DR_REGION = 'us-west-2'
DEFAULT_SERVICES = [
    'ec2',
    'lambda',
    'rds',
    'elasticloadbalancing',
    'ecs',
    'eks',
    'sqs',
    'sns',
    'dynamodb',
]

EXTRA_FIELDS = [
    'service_code',
    'quota_name',
    'quota_code',
    'primary_region',
    'primary_value',
    'dr_region',
    'dr_value',
    'gap',
]

log = logging.getLogger(SCRIPT_NAME)


def _collect_quotas(sq_client, service_code: str) -> dict[str, dict]:
    """Return {quota_name: {value, code}} for all applied/service quotas."""
    quotas: dict[str, dict] = {}
    try:
        paginator = sq_client.get_paginator('list_service_quotas')
        for page in paginator.paginate(ServiceCode=service_code):
            for q in page.get('Quotas', []):
                quotas[q['QuotaName']] = {
                    'value': q['Value'],
                    'code': q['QuotaCode'],
                }
    except ClientError as exc:
        code = exc.response['Error']['Code']
        if code in ('NoSuchResourceException', 'ServiceException'):
            log.debug("Service %s not available in this region: %s", service_code, exc)
        elif session.is_skippable(exc):
            log.debug("Skipping service %s: %s", service_code, code)
        else:
            log.warning("list_service_quotas failed for %s: %s", service_code, exc)
    return quotas


def make_scan(primary_region: str, dr_region: str, service_codes: list[str]):
    """Factory — returns a scan(sess, account_id, writer) closure."""

    def scan(sess, account_id: str, writer) -> None:
        sq_primary = sess.client('service-quotas', region_name=primary_region)
        sq_dr = sess.client('service-quotas', region_name=dr_region)

        for service_code in service_codes:
            log.debug("%s: collecting quotas for service=%s", account_id, service_code)

            primary_quotas = _collect_quotas(sq_primary, service_code)
            dr_quotas = _collect_quotas(sq_dr, service_code)

            if not primary_quotas:
                log.debug("%s/%s: no quotas returned, skipping", account_id, service_code)
                continue

            for quota_name, primary_info in primary_quotas.items():
                if quota_name not in dr_quotas:
                    # Quota not present in DR region at all — treat as 0 / unavailable
                    log.debug(
                        "%s: quota '%s/%s' absent in DR region %s",
                        account_id, service_code, quota_name, dr_region,
                    )
                    continue

                primary_value = primary_info['value']
                dr_value = dr_quotas[quota_name]['value']

                if dr_value < primary_value:
                    gap = primary_value - dr_value
                    writer.write(
                        account_id=account_id,
                        region=primary_region,  # anchor finding to the primary region
                        resource_id=f"{service_code}/{quota_name}",
                        resource_type='Service Quota',
                        finding='dr-quota-lower-than-primary',
                        detail=(
                            f"Primary ({primary_region})={primary_value:.0f}  "
                            f"DR ({dr_region})={dr_value:.0f}  "
                            f"gap={gap:.0f}"
                        ),
                        estimated_monthly_savings_usd=0,
                        tags='',
                        service_code=service_code,
                        quota_name=quota_name,
                        quota_code=primary_info['code'],
                        primary_region=primary_region,
                        primary_value=primary_value,
                        dr_region=dr_region,
                        dr_value=dr_value,
                        gap=gap,
                    )

    return scan


def main() -> None:
    parser = cli.make_parser(__doc__, account_level=True)
    parser.add_argument(
        '--primary-region',
        default=DEFAULT_PRIMARY_REGION,
        help=f'Primary AWS region to compare from (default: {DEFAULT_PRIMARY_REGION})',
    )
    parser.add_argument(
        '--dr-region',
        default=DEFAULT_DR_REGION,
        help=f'DR AWS region to compare against (default: {DEFAULT_DR_REGION})',
    )
    parser.add_argument(
        '--services',
        default=','.join(DEFAULT_SERVICES),
        help=(
            'Comma-separated service codes to check '
            f'(default: {",".join(DEFAULT_SERVICES)})'
        ),
    )
    args = parser.parse_args()

    service_codes = [s.strip() for s in args.services.split(',') if s.strip()]

    cli.run(
        args,
        SCRIPT_NAME,
        make_scan(args.primary_region, args.dr_region, service_codes),
        extra_fields=EXTRA_FIELDS,
        account_level=True,
    )


if __name__ == '__main__':
    main()
