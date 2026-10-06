#!/usr/bin/env python3
"""Task 49 — Quotas Not Exposed by Service Quotas API

Checks hard limits that are not surfaced through the AWS Service Quotas API
by querying the relevant service APIs directly.  Quota definitions are loaded
from QuotaList.json in the same directory.

Account-scoped checks (IAM, S3 bucket count) run only when region == 'us-east-1'
to avoid duplicate findings.

Run: python 49_detect_custom_quotas.py --accounts 123456789012,234567890123
"""
from __future__ import annotations


import json
import logging
import sys
from pathlib import Path

from botocore.exceptions import ClientError

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from common import cli, session

SCRIPT_NAME = '49_detect_custom_quotas'
EXTRA_FIELDS = ['quota_id', 'service', 'current_count', 'limit', 'utilization_pct', 'warn_pct']

QUOTA_LIST_PATH = Path(__file__).resolve().parent / 'QuotaList.json'

log = logging.getLogger(SCRIPT_NAME)


def _load_quota_list() -> list[dict]:
    with open(QUOTA_LIST_PATH, encoding='utf-8') as fh:
        return json.load(fh)


# ---------------------------------------------------------------------------
# Individual check implementations
# ---------------------------------------------------------------------------

def _check_list_buckets_count(sess, region: str) -> int | None:
    s3 = sess.client('s3', region_name='us-east-1')
    try:
        resp = s3.list_buckets()
        return len(resp.get('Buckets', []))
    except ClientError as exc:
        if session.is_skippable(exc):
            return None
        log.warning('s3.list_buckets failed: %s', exc)
        return None


def _check_lambda_vpc_eni_count(sess, region: str) -> int | None:
    """Count Lambda functions that have a VpcConfig attached (proxy for ENI usage)."""
    lam = sess.client('lambda', region_name='us-east-1')
    count = 0
    try:
        paginator = lam.get_paginator('list_functions')
        for page in paginator.paginate():
            for fn in page.get('Functions', []):
                vpc_config = fn.get('VpcConfig', {})
                if vpc_config.get('VpcId'):
                    count += 1
    except ClientError as exc:
        if session.is_skippable(exc):
            return None
        log.warning('lambda.list_functions failed: %s', exc)
        return None
    return count


def _check_iam_role_count(sess, region: str) -> int | None:
    iam = sess.client('iam', region_name='us-east-1')
    try:
        resp = iam.get_account_summary()
        return resp['SummaryMap'].get('Roles', 0)
    except ClientError as exc:
        if session.is_skippable(exc):
            return None
        log.warning('iam.get_account_summary failed: %s', exc)
        return None


def _check_iam_policy_count(sess, region: str) -> int | None:
    iam = sess.client('iam', region_name='us-east-1')
    try:
        resp = iam.get_account_summary()
        return resp['SummaryMap'].get('Policies', 0)
    except ClientError as exc:
        if session.is_skippable(exc):
            return None
        log.warning('iam.get_account_summary (policies) failed: %s', exc)
        return None


def _check_vpc_count(sess, region: str) -> int | None:
    ec2 = sess.client('ec2', region_name=region)
    try:
        resp = ec2.describe_vpcs()
        return len(resp.get('Vpcs', []))
    except ClientError as exc:
        if session.is_skippable(exc):
            return None
        log.warning('%s ec2.describe_vpcs failed: %s', region, exc)
        return None


def _check_eip_count(sess, region: str) -> int | None:
    ec2 = sess.client('ec2', region_name=region)
    try:
        resp = ec2.describe_addresses()
        return len(resp.get('Addresses', []))
    except ClientError as exc:
        if session.is_skippable(exc):
            return None
        log.warning('%s ec2.describe_addresses failed: %s', region, exc)
        return None


def _check_acm_cert_count(sess, region: str) -> int | None:
    acm = sess.client('acm', region_name=region)
    count = 0
    try:
        paginator = acm.get_paginator('list_certificates')
        for page in paginator.paginate():
            count += len(page.get('CertificateSummaryList', []))
    except ClientError as exc:
        if session.is_skippable(exc):
            return None
        log.warning('%s acm.list_certificates failed: %s', region, exc)
        return None
    return count


_CHECK_DISPATCH = {
    'list_buckets_count':    _check_list_buckets_count,
    'lambda_vpc_eni_count':  _check_lambda_vpc_eni_count,
    'iam_role_count':        _check_iam_role_count,
    'iam_policy_count':      _check_iam_policy_count,
    'vpc_count':             _check_vpc_count,
    'eip_count':             _check_eip_count,
    'acm_cert_count':        _check_acm_cert_count,
}


# ---------------------------------------------------------------------------
# Main scan function
# ---------------------------------------------------------------------------

def scan(sess, account_id: str, region: str, writer) -> None:
    try:
        quota_list = _load_quota_list()
    except Exception as exc:
        log.error('Failed to load QuotaList.json: %s', exc)
        return

    for quota in quota_list:
        quota_id = quota['id']
        scope = quota.get('scope', 'region')
        check_name = quota['check']
        limit = quota['limit']
        warn_pct = quota.get('warn_pct', 70)
        description = quota.get('description', quota_id)
        service = quota.get('service', '')

        # Account-scoped checks run exactly once: only in us-east-1.
        if scope == 'account' and region != 'us-east-1':
            continue

        check_fn = _CHECK_DISPATCH.get(check_name)
        if check_fn is None:
            log.warning('Unknown check function "%s" for quota %s — skipping.', check_name, quota_id)
            continue

        current_count = check_fn(sess, region)
        if current_count is None:
            continue

        threshold = limit * (warn_pct / 100)
        if current_count < threshold:
            continue

        utilization_pct = (current_count / limit) * 100 if limit else 0.0

        writer.write(
            account_id=account_id,
            region=region,
            resource_id=quota_id,
            resource_type='Custom Quota',
            finding='custom-quota-threshold-reached',
            detail=(
                f"{description}: current={current_count} limit={limit} "
                f"utilization={utilization_pct:.1f}% (warn at {warn_pct}%)"
            ),
            estimated_monthly_savings_usd=0,
            tags=None,
            quota_id=quota_id,
            service=service,
            current_count=str(current_count),
            limit=str(limit),
            utilization_pct=f"{utilization_pct:.1f}",
            warn_pct=str(warn_pct),
        )


def main() -> None:
    parser = cli.make_parser(__doc__)
    args = parser.parse_args()
    cli.run(args, SCRIPT_NAME, scan, extra_fields=EXTRA_FIELDS)


if __name__ == '__main__':
    main()
