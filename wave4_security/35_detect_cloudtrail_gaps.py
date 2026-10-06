#!/usr/bin/env python3
"""Task 35 — CloudTrail Not Fully Configured

Audits CloudTrail configuration in every region. Flags four distinct gap types
per trail, plus a 'no-trail-in-region' finding when a region has no trails at
all. Each gap is written as a separate finding row so the output can be
filtered by finding type.

Gaps detected:
  trail-not-logging        — IsLogging is False
  regional-trail-only      — IsMultiRegionTrail is False
  log-validation-disabled  — LogFileValidationEnabled is False
  global-events-excluded   — IncludeGlobalServiceEvents is False
  no-trail-in-region       — No trails exist for this region

Run: python 35_detect_cloudtrail_gaps.py --accounts 123456789012,234567890123
"""
from __future__ import annotations


import logging
import sys
from pathlib import Path

from botocore.exceptions import ClientError

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from common import cli, session

SCRIPT_NAME = '35_detect_cloudtrail_gaps'
EXTRA_FIELDS = [
    'trail_name', 'home_region', 'is_multi_region',
    'log_validation', 'global_events', 'is_logging', 's3_bucket',
    'is_organization_trail', 'kms_key_id', 'latest_delivery_error',
]

log = logging.getLogger(SCRIPT_NAME)


def scan(sess, account_id: str, region: str, writer) -> None:
    ct = sess.client('cloudtrail', region_name=region)

    try:
        resp = ct.describe_trails(includeShadowTrails=True)
    except ClientError as exc:
        if session.is_skippable(exc):
            log.warning("%s/%s: skipped — %s", account_id, region, exc.response['Error']['Code'])
            return
        raise

    trails = resp.get('trailList', [])

    if not trails:
        writer.write(
            account_id=account_id,
            region=region,
            resource_id=f"{account_id}/{region}",
            resource_type='CloudTrail Trail',
            finding='no-trail-in-region',
            detail=f"No CloudTrail trails found in region {region}",
            estimated_monthly_savings_usd=0,
            tags=None,
            trail_name='',
            home_region='',
            is_multi_region='',
            log_validation='',
            global_events='',
            is_logging='',
            s3_bucket='',
            is_organization_trail='',
            kms_key_id='',
            latest_delivery_error='',
        )
        return

    for trail in trails:
        trail_arn = trail.get('TrailARN', '')
        trail_name = trail.get('Name', '')
        home_region = trail.get('HomeRegion', '')
        s3_bucket = trail.get('S3BucketName', '')
        is_multi_region = trail.get('IsMultiRegionTrail', False)
        log_validation = trail.get('LogFileValidationEnabled', False)
        global_events = trail.get('IncludeGlobalServiceEvents', False)
        is_org_trail = trail.get('IsOrganizationTrail', False)
        kms_key_id = trail.get('KMSKeyId', '')

        # Fetch live logging status and delivery health
        is_logging = False
        latest_delivery_error = ''
        try:
            status_resp = ct.get_trail_status(Name=trail_arn)
            is_logging = status_resp.get('IsLogging', False)
            latest_delivery_error = status_resp.get('LatestDeliveryError', '')
        except ClientError as exc:
            if session.is_skippable(exc):
                log.debug("get_trail_status skipped for %s: %s", trail_arn, exc.response['Error']['Code'])
            else:
                log.warning("get_trail_status failed for %s: %s", trail_arn, exc)

        # Shared detail string and extra-field values for all findings on this trail
        base_detail = (
            f"Trail={trail_name} HomeRegion={home_region} S3={s3_bucket}"
        )
        common_extra = dict(
            trail_name=trail_name,
            home_region=home_region,
            is_multi_region=str(is_multi_region),
            log_validation=str(log_validation),
            global_events=str(global_events),
            is_logging=str(is_logging),
            s3_bucket=s3_bucket,
            is_organization_trail=str(is_org_trail),
            kms_key_id=kms_key_id,
            latest_delivery_error=latest_delivery_error,
        )

        # Gap 1: trail not currently logging
        if not is_logging:
            writer.write(
                account_id=account_id,
                region=region,
                resource_id=trail_arn,
                resource_type='CloudTrail Trail',
                finding='trail-not-logging',
                detail=base_detail + ' IsLogging=False',
                estimated_monthly_savings_usd=0,
                tags=None,
                **common_extra,
            )

        # Gap 2: regional trail only (no multi-region coverage)
        if not is_multi_region:
            writer.write(
                account_id=account_id,
                region=region,
                resource_id=trail_arn,
                resource_type='CloudTrail Trail',
                finding='regional-trail-only',
                detail=base_detail + ' IsMultiRegionTrail=False',
                estimated_monthly_savings_usd=0,
                tags=None,
                **common_extra,
            )

        # Gap 3: log file validation disabled
        if not log_validation:
            writer.write(
                account_id=account_id,
                region=region,
                resource_id=trail_arn,
                resource_type='CloudTrail Trail',
                finding='log-validation-disabled',
                detail=base_detail + ' LogFileValidationEnabled=False',
                estimated_monthly_savings_usd=0,
                tags=None,
                **common_extra,
            )

        # Gap 4: global service events excluded
        if not global_events:
            writer.write(
                account_id=account_id,
                region=region,
                resource_id=trail_arn,
                resource_type='CloudTrail Trail',
                finding='global-events-excluded',
                detail=base_detail + ' IncludeGlobalServiceEvents=False',
                estimated_monthly_savings_usd=0,
                tags=None,
                **common_extra,
            )


def main() -> None:
    parser = cli.make_parser(__doc__)
    args = parser.parse_args()
    cli.run(args, SCRIPT_NAME, scan, extra_fields=EXTRA_FIELDS)


if __name__ == '__main__':
    main()
