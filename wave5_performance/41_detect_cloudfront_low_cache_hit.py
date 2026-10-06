#!/usr/bin/env python3
"""Task 41 — CloudFront Distributions with Low Cache-Hit Ratio

Finds CloudFront distributions where the 30-day average CacheHitRate falls
below a configurable threshold (default: 70%). A low cache-hit rate means
most requests are forwarded to the origin, incurring data-transfer costs that
better caching configuration would eliminate.

CloudFront metrics are global and always published to us-east-1. This is an
account-level script (no region loop).

Run: python 41_detect_cloudfront_low_cache_hit.py --accounts 123456789012,234567890123
"""
from __future__ import annotations

import logging
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from botocore.exceptions import ClientError

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from common import cli, session

SCRIPT_NAME = '41_detect_cloudfront_low_cache_hit'
EXTRA_FIELDS = [
    'distribution_domain', 'aliases', 'origins',
    'price_class', 'cache_hit_rate_avg', 'http_version',
]

THRESHOLD_PCT_DEFAULT = 70.0
LOOKBACK_DAYS = 30
CW_REGION = 'us-east-1'  # CloudFront metrics are always published here
CW_BATCH_SIZE = 500

log = logging.getLogger(SCRIPT_NAME)


def _fetch_cache_hit_rates(cw, dist_ids: list[str]) -> dict[str, float | None]:
    """Return {dist_id: avg_cache_hit_rate_pct} using batched CloudWatch queries."""
    if not dist_ids:
        return {}

    end = datetime.now(timezone.utc)
    start = end - timedelta(days=LOOKBACK_DAYS)

    queries = [
        {
            'Id': f'q{i}',
            'MetricStat': {
                'Metric': {
                    'Namespace': 'AWS/CloudFront',
                    'MetricName': 'CacheHitRate',
                    'Dimensions': [
                        {'Name': 'DistributionId', 'Value': dist_id},
                        {'Name': 'Region', 'Value': 'Global'},
                    ],
                },
                'Period': 86400,
                'Stat': 'Average',
            },
            'ReturnData': True,
        }
        for i, dist_id in enumerate(dist_ids)
    ]

    results: dict[str, float | None] = {d: None for d in dist_ids}
    for chunk in session.chunked(queries, CW_BATCH_SIZE):
        try:
            paginator = cw.get_paginator('get_metric_data')
            for resp in paginator.paginate(
                MetricDataQueries=chunk, StartTime=start, EndTime=end
            ):
                for r in resp.get('MetricDataResults', []):
                    idx = int(r['Id'][1:])
                    values = r.get('Values', [])
                    if values:
                        results[dist_ids[idx]] = sum(values) / len(values)
        except ClientError as exc:
            log.warning("CloudWatch get_metric_data failed (%d queries): %s", len(chunk), exc)
    return results


def make_scan(threshold_pct: float):
    def scan(sess, account_id: str, writer) -> None:
        cf = sess.client('cloudfront')
        cw = sess.client('cloudwatch', region_name=CW_REGION)

        try:
            paginator = cf.get_paginator('list_distributions')
            distributions = []
            for page in paginator.paginate():
                distributions.extend(
                    page.get('DistributionList', {}).get('Items', [])
                )
        except ClientError as exc:
            if session.is_skippable(exc):
                log.warning("%s: CloudFront skipped — %s", account_id, exc.response['Error']['Code'])
                return
            raise

        # Only check enabled distributions — disabled ones produce no CloudWatch data
        enabled = [d for d in distributions if d.get('Enabled', False)]
        if not enabled:
            return

        dist_ids = [d['Id'] for d in enabled]
        cache_hit_rates = _fetch_cache_hit_rates(cw, dist_ids)

        for dist in enabled:
            dist_id = dist['Id']
            avg_rate = cache_hit_rates.get(dist_id)

            if avg_rate is None:
                # No data points — distribution has received no traffic in the window
                continue
            if avg_rate >= threshold_pct:
                continue

            domain = dist.get('DomainName', '')
            aliases = ','.join(dist.get('Aliases', {}).get('Items', []))
            origins = ','.join(
                o.get('DomainName', '')
                for o in dist.get('Origins', {}).get('Items', [])
            )
            price_class = dist.get('PriceClass', '')
            http_version = dist.get('HttpVersion', '')
            dist_arn = dist.get('ARN', dist_id)

            writer.write(
                account_id=account_id,
                region='global',
                resource_id=dist_arn,
                resource_type='CloudFront Distribution',
                finding='low-cache-hit-rate',
                detail=(
                    f"Domain={domain} CacheHitRate={avg_rate:.1f}% "
                    f"Threshold={threshold_pct:.0f}% Origins={origins}"
                ),
                estimated_monthly_savings_usd=None,
                tags=None,
                distribution_domain=domain,
                aliases=aliases,
                origins=origins,
                price_class=price_class,
                cache_hit_rate_avg=f"{avg_rate:.2f}",
                http_version=http_version,
            )

    return scan


def main() -> None:
    parser = cli.make_parser(__doc__, account_level=True)
    parser.add_argument(
        '--threshold-pct',
        type=float,
        default=THRESHOLD_PCT_DEFAULT,
        help=f'Cache-hit rate %% below which to flag (default: {THRESHOLD_PCT_DEFAULT})',
    )
    args = parser.parse_args()
    cli.run(
        args, SCRIPT_NAME, make_scan(args.threshold_pct),
        extra_fields=EXTRA_FIELDS, account_level=True,
    )


if __name__ == '__main__':
    main()
