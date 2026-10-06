#!/usr/bin/env python3
"""Task 39 — EC2 Instances with Low CPU but High Memory Utilization

Find instances with <10% peak CPU over 14 days AND >70% memory utilization.
These are in the wrong instance FAMILY (need memory-optimized r-series),
not just the wrong size. Compute Optimizer will quantify the exact savings;
this script surfaces the pattern for review.

Requires the CloudWatch Agent to be installed on the instance for memory
metrics (Namespace: CWAgent, MetricName: mem_used_percent). Instances
without CWAgent data are silently skipped.

Run: python 39_detect_cpu_memory_mismatch.py --accounts 123456789012,234567890123
"""
from __future__ import annotations

import logging
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path
from botocore.exceptions import ClientError

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from common import cli, pricing, session
from common import tags as tagutil

SCRIPT_NAME = '39_detect_cpu_memory_mismatch'
EXTRA_FIELDS = [
    'instance_type',
    'peak_cpu_pct',
    'peak_mem_pct',
    'name_tag',
    'environment_tag',
]

CPU_THRESHOLD = 10.0    # flag if peak CPU  < this %
MEM_THRESHOLD = 70.0    # flag if peak MEM  > this %
LOOKBACK_DAYS = 14
CW_BATCH_SIZE = 500     # CloudWatch get_metric_data limit per request

log = logging.getLogger(SCRIPT_NAME)


def _batch_metrics(
    cw,
    instance_ids: list[str],
) -> dict[str, dict[str, float | None]]:
    """
    Query CloudWatch for CPUUtilization (AWS/EC2) and mem_used_percent (CWAgent)
    for each instance in `instance_ids`.

    Returns:
        {instance_id: {'cpu': max_value_or_None, 'mem': max_value_or_None}}
    """
    if not instance_ids:
        return {}

    end = datetime.now(timezone.utc)
    start = end - timedelta(days=LOOKBACK_DAYS)

    # Build paired queries: two queries per instance (cpu_<i>, mem_<i>)
    # We track index → instance_id mapping for both query types.
    queries: list[dict] = []
    for i, iid in enumerate(instance_ids):
        queries.append({
            'Id': f"cpu{i}",
            'MetricStat': {
                'Metric': {
                    'Namespace': 'AWS/EC2',
                    'MetricName': 'CPUUtilization',
                    'Dimensions': [{'Name': 'InstanceId', 'Value': iid}],
                },
                'Period': 86400,
                'Stat': 'Maximum',
            },
            'ReturnData': True,
        })
        queries.append({
            'Id': f"mem{i}",
            'MetricStat': {
                'Metric': {
                    'Namespace': 'CWAgent',
                    'MetricName': 'mem_used_percent',
                    'Dimensions': [{'Name': 'InstanceId', 'Value': iid}],
                },
                'Period': 86400,
                'Stat': 'Maximum',
            },
            'ReturnData': True,
        })

    # Accumulate raw values before taking the max
    cpu_values: dict[int, list[float]] = {}
    mem_values: dict[int, list[float]] = {}

    for chunk in session.chunked(queries, CW_BATCH_SIZE):
        try:
            paginator = cw.get_paginator('get_metric_data')
            for resp in paginator.paginate(
                MetricDataQueries=chunk,
                StartTime=start,
                EndTime=end,
            ):
                for r in resp.get('MetricDataResults', []):
                    qid = r['Id']
                    vals = r.get('Values', [])
                    if not vals:
                        continue
                    if qid.startswith('cpu'):
                        idx = int(qid[3:])
                        cpu_values.setdefault(idx, []).extend(vals)
                    elif qid.startswith('mem'):
                        idx = int(qid[3:])
                        mem_values.setdefault(idx, []).extend(vals)
        except ClientError as exc:
            log.warning("CloudWatch batch failed (%d queries): %s", len(chunk), exc)

    result: dict[str, dict[str, float | None]] = {}
    for i, iid in enumerate(instance_ids):
        result[iid] = {
            'cpu': max(cpu_values[i]) if i in cpu_values else None,
            'mem': max(mem_values[i]) if i in mem_values else None,
        }
    return result


def scan(sess, account_id: str, region: str, writer) -> None:
    ec2 = sess.client('ec2', region_name=region)
    cw = sess.client('cloudwatch', region_name=region)

    # ------------------------------------------------------------------ #
    # 1. Collect all running instances                                     #
    # ------------------------------------------------------------------ #
    instances: list[dict] = []
    try:
        paginator = ec2.get_paginator('describe_instances')
        for page in paginator.paginate(
            Filters=[{'Name': 'instance-state-name', 'Values': ['running']}]
        ):
            for reservation in page['Reservations']:
                instances.extend(reservation['Instances'])
    except ClientError as exc:
        if session.is_skippable(exc):
            log.warning("%s/%s: skipped — %s", account_id, region, exc.response['Error']['Code'])
            return
        log.error("%s/%s describe_instances: %s", account_id, region, exc)
        return

    if not instances:
        return

    instance_ids = [i['InstanceId'] for i in instances]
    instance_map = {i['InstanceId']: i for i in instances}

    log.info(
        "%s/%s: querying CloudWatch metrics for %d instance(s)",
        account_id, region, len(instance_ids),
    )

    # ------------------------------------------------------------------ #
    # 2. Batch-query CloudWatch (CPU + memory) in groups of 500 queries   #
    # ------------------------------------------------------------------ #
    metrics = _batch_metrics(cw, instance_ids)

    # ------------------------------------------------------------------ #
    # 3. Evaluate each instance                                            #
    # ------------------------------------------------------------------ #
    flagged = 0
    for iid, vals in metrics.items():
        peak_cpu = vals['cpu']
        peak_mem = vals['mem']

        # Skip if CWAgent data is missing (agent not installed)
        if peak_cpu is None or peak_mem is None:
            continue

        if not (peak_cpu < CPU_THRESHOLD and peak_mem > MEM_THRESHOLD):
            continue

        inst = instance_map[iid]
        instance_type = inst.get('InstanceType', '')
        tags = inst.get('Tags', [])
        name_tag = tagutil.tag_value(tags, 'Name')
        env_tag = tagutil.tag_value(tags, 'Environment')

        detail = (
            f"InstanceType={instance_type} "
            f"PeakCPU={peak_cpu:.1f}% "
            f"PeakMem={peak_mem:.1f}% "
            f"Recommendation=migrate-to-r-series-memory-optimized"
        )

        writer.write(
            account_id=account_id,
            region=region,
            resource_id=iid,
            resource_type='EC2 Instance',
            finding='wrong-instance-family-memory-starved',
            detail=detail,
            estimated_monthly_savings_usd=0,
            tags=tags,
            instance_type=instance_type,
            peak_cpu_pct=f"{peak_cpu:.2f}",
            peak_mem_pct=f"{peak_mem:.2f}",
            name_tag=name_tag,
            environment_tag=env_tag,
        )
        flagged += 1

    log.info(
        "%s/%s: %d/%d instance(s) flagged as wrong-family (low-CPU/high-mem)",
        account_id, region, flagged, len(instances),
    )


def main() -> None:
    parser = cli.make_parser(__doc__)
    args = parser.parse_args()
    cli.run(args, SCRIPT_NAME, scan, extra_fields=EXTRA_FIELDS)


if __name__ == '__main__':
    main()
