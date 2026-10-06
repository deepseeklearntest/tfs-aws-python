#!/usr/bin/env python3
"""
Task 10 - Athena Query Result Buckets Without Lifecycle Rules

Finds buckets matching aws-athena-query-results-* and flags any missing:
  - 7-day expiration rule for completed query results
  - 7-day abort rule for incomplete multipart uploads (MPUs)

Also reports oldest/newest object age and object count so you can see
how long results have been accumulating and whether the bucket is still active.

Run: python 10_detect_athena_result_buckets.py --accounts 123456789012
"""
from __future__ import annotations

import logging
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

from botocore.exceptions import ClientError

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from common import cli, pricing, session

SCRIPT_NAME = '10_detect_athena_result_buckets'
ATHENA_PREFIX = 'aws-athena-query-results-'
EXPIRY_DAYS_EXPECTED = 7
MPU_ABORT_DAYS_EXPECTED = 7
OBJECT_SCAN_LIMIT = 10_000  # cap to avoid runaway scans on very large buckets

log = logging.getLogger(SCRIPT_NAME)
EXTRA_FIELDS = [
    'bucket_name', 'bucket_region', 'missing_expiry', 'missing_mpu_abort',
    'size_gb', 'object_count', 'oldest_object_days', 'newest_object_days',
]


def _get_lifecycle_gaps(s3, bucket_name: str) -> tuple[bool, bool]:
    try:
        rules = s3.get_bucket_lifecycle_configuration(Bucket=bucket_name).get('Rules', [])
    except ClientError as exc:
        if exc.response['Error']['Code'] == 'NoSuchLifecycleConfiguration':
            return True, True
        raise

    has_expiry = False
    has_mpu_abort = False
    for rule in rules:
        if rule.get('Status') != 'Enabled':
            continue
        # A rule limited by prefix, tags, or size cannot prove bucket-wide
        # coverage. Only an empty legacy Prefix or empty Filter covers all.
        if rule.get('Prefix', '') or any(rule.get('Filter', {}).values()):
            continue
        if rule.get('Expiration', {}).get('Days', 9999) <= EXPIRY_DAYS_EXPECTED:
            has_expiry = True
        if rule.get('AbortIncompleteMultipartUpload', {}).get('DaysAfterInitiation', 9999) <= MPU_ABORT_DAYS_EXPECTED:
            has_mpu_abort = True
    return not has_expiry, not has_mpu_abort


def _get_bucket_region(s3, bucket_name: str) -> str:
    try:
        loc = s3.get_bucket_location(Bucket=bucket_name)['LocationConstraint']
        return 'eu-west-1' if loc == 'EU' else (loc or 'us-east-1')
    except Exception:
        return 'unknown'


def _get_bucket_size_gb(cw, bucket_name: str) -> float:
    try:
        end = datetime.now(timezone.utc)
        resp = cw.get_metric_statistics(
            Namespace='AWS/S3',
            MetricName='BucketSizeBytes',
            Dimensions=[
                {'Name': 'BucketName', 'Value': bucket_name},
                {'Name': 'StorageType', 'Value': 'StandardStorage'},
            ],
            StartTime=end - timedelta(days=3),
            EndTime=end,
            Period=86400,
            Statistics=['Average'],
        )
        points = resp.get('Datapoints', [])
        return max((d['Average'] for d in points), default=0.0) / (1024 ** 3)
    except Exception as exc:
        session.mark_incomplete(f'Could not retrieve bucket size: {exc}')
        return 0.0


def _get_object_ages(s3, bucket_name: str) -> tuple[int | None, int | None, int]:
    """
    Scan objects in the bucket (up to OBJECT_SCAN_LIMIT) and return:
      (oldest_age_days, newest_age_days, object_count)

    oldest_age_days: days since the oldest object was last modified
    newest_age_days: days since the most recently modified object
    object_count:    total objects scanned (capped at OBJECT_SCAN_LIMIT)
    """
    now = datetime.now(timezone.utc)
    oldest: datetime | None = None
    newest: datetime | None = None
    count = 0

    try:
        paginator = s3.get_paginator('list_objects_v2')
        for page in paginator.paginate(Bucket=bucket_name):
            for obj in page.get('Contents', []):
                lm = obj['LastModified']
                if oldest is None or lm < oldest:
                    oldest = lm
                if newest is None or lm > newest:
                    newest = lm
                count += 1
                if count >= OBJECT_SCAN_LIMIT:
                    log.debug("%s: object scan capped at %d", bucket_name, OBJECT_SCAN_LIMIT)
                    return (now - oldest).days, (now - newest).days, count
    except ClientError as exc:
        log.debug("list_objects_v2 failed for %s: %s", bucket_name, exc)
        return None, None, 0

    if oldest is None:
        return None, None, 0

    return (now - oldest).days, (now - newest).days, count


def scan(sess, account_id: str, writer) -> None:
    s3 = sess.client('s3', region_name='us-east-1')

    try:
        buckets = [
            b for b in s3.list_buckets().get('Buckets', [])
            if b['Name'].startswith(ATHENA_PREFIX)
        ]
    except ClientError as exc:
        if session.is_skippable(exc):
            log.warning("%s: skipped - %s", account_id, exc.response['Error']['Code'])
            return
        log.error("%s: list_buckets failed - %s", account_id, exc)
        return

    log.info("Account %s - %d Athena result bucket(s)", account_id, len(buckets))

    for bucket in buckets:
        name = bucket['Name']
        try:
            missing_expiry, missing_mpu = _get_lifecycle_gaps(s3, name)
        except ClientError as exc:
            log.debug("Lifecycle check failed for %s: %s", name, exc)
            continue

        if not missing_expiry and not missing_mpu:
            continue

        bucket_region = _get_bucket_region(s3, name)
        if bucket_region == 'unknown':
            session.mark_incomplete(f'Could not determine region for {name}')
            continue
        cw = sess.client('cloudwatch', region_name=bucket_region)
        size_gb = _get_bucket_size_gb(cw, name)
        monthly_cost = size_gb * pricing.s3_standard_per_gb(bucket_region)
        oldest_days, newest_days, obj_count = _get_object_ages(s3, name)

        gaps = []
        if missing_expiry:
            gaps.append(f'no {EXPIRY_DAYS_EXPECTED}d expiry rule')
        if missing_mpu:
            gaps.append(f'no {MPU_ABORT_DAYS_EXPECTED}d MPU abort rule')

        oldest_str = str(oldest_days) if oldest_days is not None else 'unknown'
        newest_str = str(newest_days) if newest_days is not None else 'unknown'

        writer.write(
            account_id=account_id,
            region=bucket_region,
            resource_id=f"arn:aws:s3:::{name}",
            resource_type='S3 Bucket (Athena Results)',
            finding=f"Athena result bucket missing lifecycle: {', '.join(gaps)}",
            detail=(
                f"SizeGB={size_gb:.3f} MonthlyCost=${monthly_cost:.2f} "
                f"Objects={obj_count} OldestDays={oldest_str} NewestDays={newest_str}"
            ),
            estimated_monthly_savings_usd=monthly_cost if size_gb > 0 else None,
            bucket_name=name,
            bucket_region=bucket_region,
            missing_expiry=str(missing_expiry),
            missing_mpu_abort=str(missing_mpu),
            size_gb=f"{size_gb:.4f}",
            object_count=str(obj_count),
            oldest_object_days=oldest_str,
            newest_object_days=newest_str,
        )


def main() -> None:
    parser = cli.make_parser(__doc__, account_level=True)
    args = parser.parse_args()
    cli.run(args, SCRIPT_NAME, scan, extra_fields=EXTRA_FIELDS, account_level=True)


if __name__ == '__main__':
    main()
