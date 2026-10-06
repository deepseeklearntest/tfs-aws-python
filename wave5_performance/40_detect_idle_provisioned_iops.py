#!/usr/bin/env python3
"""Task 40 — Provisioned IOPS Volumes with Low Utilization

Find io1/io2 EBS volumes where actual IOPS consumed are significantly below
the provisioned level. The unused provisioned IOPS still cost $0.065/IOPS/month
for io1 and approximately $0.065/IOPS/month for io2 (simplified).

Use --utilization-threshold to control the flag threshold (default 20%):
a volume is flagged when actual_avg_iops < provisioned_iops * threshold.

Run: python 40_detect_idle_provisioned_iops.py --accounts 123456789012,234567890123
"""
from __future__ import annotations

import logging
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path
from botocore.exceptions import ClientError

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from common import cli, pricing, session
from common import ec2 as ec2util
from common import tags as tagutil

SCRIPT_NAME = '40_detect_idle_provisioned_iops'
EXTRA_FIELDS = [
    'volume_type',
    'provisioned_iops',
    'actual_avg_iops',
    'utilization_pct',
    'size_gib',
    'attached_instance',
    'instance_name',
    'state',
]

LOOKBACK_DAYS = 14
UTILIZATION_THRESHOLD_DEFAULT = 0.20   # flag if actual < 20% of provisioned
IOPS_PRICE_PER_MONTH = 0.065           # $/provisioned-IOPS/month (io1 & io2, simplified)
CW_BATCH_SIZE = 500

log = logging.getLogger(SCRIPT_NAME)


def _batch_iops(cw, volume_ids: list[str]) -> dict[str, float | None]:
    """
    Return {volume_id: actual_avg_iops} over the full LOOKBACK_DAYS window.

    Strategy: fetch VolumeReadOps + VolumeWriteOps (Sum) with a single
    period equal to the full window.  Divide by window seconds to get
    average IOPS.
    """
    if not volume_ids:
        return {}

    end = datetime.now(timezone.utc)
    start = end - timedelta(days=LOOKBACK_DAYS)
    window_seconds = LOOKBACK_DAYS * 86400

    # Two queries per volume: read ops and write ops
    queries: list[dict] = []
    for i, vid in enumerate(volume_ids):
        for j, metric in enumerate(('VolumeReadOps', 'VolumeWriteOps')):
            queries.append({
                'Id': f"v{i}m{j}",
                'MetricStat': {
                    'Metric': {
                        'Namespace': 'AWS/EBS',
                        'MetricName': metric,
                        'Dimensions': [{'Name': 'VolumeId', 'Value': vid}],
                    },
                    'Period': window_seconds,
                    'Stat': 'Sum',
                },
                'ReturnData': True,
            })

    # Accumulate totals per volume index
    totals: dict[int, float] = {}
    observed: set[str] = set()
    invalid: set[int] = set()

    for chunk in session.chunked(queries, CW_BATCH_SIZE):
        try:
            paginator = cw.get_paginator('get_metric_data')
            for resp in paginator.paginate(
                MetricDataQueries=chunk,
                StartTime=start,
                EndTime=end,
            ):
                for r in resp.get('MetricDataResults', []):
                    qid = r['Id']           # e.g. "v3m1"
                    vals = r.get('Values', [])
                    m_sep = qid.index('m')
                    idx = int(qid[1:m_sep])
                    if r.get('StatusCode', 'Complete') != 'Complete':
                        invalid.add(idx)
                    if not vals:
                        continue
                    observed.add(qid)
                    totals[idx] = totals.get(idx, 0.0) + sum(vals)
        except ClientError as exc:
            log.warning("CloudWatch batch failed (%d queries): %s", len(chunk), exc)

    result: dict[str, float | None] = {}
    for i, vid in enumerate(volume_ids):
        if i in invalid or not {f'v{i}m0', f'v{i}m1'} <= observed:
            result[vid] = None
            session.mark_incomplete(f'Missing or incomplete IOPS metrics for {vid}')
        else:
            result[vid] = totals[i] / window_seconds

    return result


def make_scan(threshold: float):
    """
    Factory that returns a scan() closure capturing the utilization threshold.
    Mirrors the make_scan() pattern used in the reference scripts.
    """
    def scan(sess, account_id: str, region: str, writer) -> None:
        ec2 = sess.client('ec2', region_name=region)
        cw = sess.client('cloudwatch', region_name=region)

        # -------------------------------------------------------------- #
        # 1. Enumerate io1/io2 volumes                                    #
        # -------------------------------------------------------------- #
        volumes: list[dict] = []
        try:
            paginator = ec2.get_paginator('describe_volumes')
            for page in paginator.paginate(
                Filters=[{'Name': 'volume-type', 'Values': ['io1', 'io2']}]
            ):
                volumes.extend(page['Volumes'])
        except ClientError as exc:
            if session.is_skippable(exc):
                log.warning(
                    "%s/%s: skipped — %s", account_id, region,
                    exc.response['Error']['Code'],
                )
                return
            log.error("%s/%s describe_volumes: %s", account_id, region, exc)
            return

        if not volumes:
            return

        volume_ids = [v['VolumeId'] for v in volumes]
        log.info(
            "%s/%s: querying CloudWatch IOPS for %d io1/io2 volume(s)",
            account_id, region, len(volume_ids),
        )

        # -------------------------------------------------------------- #
        # 2. Batch-query CloudWatch IOPS                                  #
        # -------------------------------------------------------------- #
        actual_iops_map = _batch_iops(cw, volume_ids)

        # -------------------------------------------------------------- #
        # 3. Filter to underutilized volumes                              #
        # -------------------------------------------------------------- #
        region_mult = pricing.region_multiplier(region)
        candidates: list[dict] = []

        for vol in volumes:
            vid = vol['VolumeId']
            provisioned = vol.get('Iops', 0) or 0

            if provisioned == 0:
                continue

            actual = actual_iops_map.get(vid)
            if actual is None:
                continue
            utilization = actual / provisioned  # fraction 0–1

            if utilization >= threshold:
                continue  # adequately utilised — skip

            # Determine attached instance (first attachment if any). Use .get()
            # throughout rather than indexing — a malformed/incomplete
            # attachment record should degrade to 'unattached', not crash the
            # whole region's scan.
            attachments = vol.get('Attachments', [])
            attached_instance = (
                attachments[0].get('InstanceId', '') if attachments else ''
            )

            candidates.append({
                'vol': vol,
                'vid': vid,
                'provisioned': provisioned,
                'actual': actual,
                'utilization': utilization,
                'attached_instance': attached_instance,
            })

        if not candidates:
            log.info(
                "%s/%s: 0/%d io1/io2 volume(s) flagged as underutilized",
                account_id, region, len(volumes),
            )
            return

        # -------------------------------------------------------------- #
        # 4. Resolve attached instance Name/owner tags — only for the     #
        #    volumes that actually got flagged, not every volume seen.    #
        # -------------------------------------------------------------- #
        attached_instance_ids = sorted({
            c['attached_instance'] for c in candidates if c['attached_instance']
        })
        inst_map = ec2util.describe_instances_by_id(ec2, attached_instance_ids)

        # -------------------------------------------------------------- #
        # 5. Write a finding per flagged volume                           #
        # -------------------------------------------------------------- #
        flagged = 0

        for c in candidates:
            vol = c['vol']
            vid = c['vid']
            provisioned = c['provisioned']
            actual = c['actual']
            utilization = c['utilization']
            attached_instance = c['attached_instance']
            vol_type = vol.get('VolumeType', '')
            size_gib = vol.get('Size', 0)
            state = vol.get('State', '')
            tags = vol.get('Tags', [])

            inst = inst_map.get(attached_instance, {})
            inst_tags = inst.get('Tags', [])
            instance_name = tagutil.tag_value(inst_tags, 'Name')
            # Owner: prefer the attached instance's tag, fall back to the volume's own
            # (the volume-only fallback is also what FindingsWriter derives automatically
            # from `tags`, but we resolve it here so the instance-first preference wins).
            owner = tagutil.owner_from_tags(inst_tags) or tagutil.owner_from_tags(tags)

            wasted_iops = provisioned - actual
            monthly_savings = wasted_iops * IOPS_PRICE_PER_MONTH * region_mult

            detail = (
                f"VolumeType={vol_type} "
                f"ProvisionedIOPS={provisioned} "
                f"ActualAvgIOPS={actual:.1f} "
                f"Utilization={utilization * 100:.1f}% "
                f"AttachedInstance={attached_instance or 'unattached'}"
                + (f" ({instance_name})" if instance_name else '')
            )

            writer.write(
                account_id=account_id,
                region=region,
                resource_id=vid,
                resource_type='EBS Volume',
                finding='underutilized-provisioned-iops',
                detail=detail,
                estimated_monthly_savings_usd=round(monthly_savings, 2),
                tags=tags,
                owner=owner,
                volume_type=vol_type,
                provisioned_iops=provisioned,
                actual_avg_iops=f"{actual:.2f}",
                utilization_pct=f"{utilization * 100:.1f}",
                size_gib=size_gib,
                attached_instance=attached_instance,
                instance_name=instance_name,
                state=state,
            )
            flagged += 1

        log.info(
            "%s/%s: %d/%d io1/io2 volume(s) flagged as underutilized",
            account_id, region, flagged, len(volumes),
        )

    return scan


def main() -> None:
    parser = cli.make_parser(__doc__)
    parser.add_argument(
        '--utilization-threshold',
        type=float,
        default=UTILIZATION_THRESHOLD_DEFAULT,
        help=(
            'Flag volumes where actual IOPS < provisioned_iops * threshold '
            f'(default: {UTILIZATION_THRESHOLD_DEFAULT}, i.e. 20%%)'
        ),
    )
    args = parser.parse_args()
    cli.run(
        args,
        SCRIPT_NAME,
        make_scan(args.utilization_threshold),
        extra_fields=EXTRA_FIELDS,
    )


if __name__ == '__main__':
    main()
