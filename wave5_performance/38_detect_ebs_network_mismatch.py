#!/usr/bin/env python3
"""Task 38 — Network Bandwidth vs EBS IOPS Mismatch

Find EC2 instances where total provisioned EBS IOPS exceeds the instance's
EBS-optimized IOPS ceiling — making that provisioned capacity unreachable.

The over-provisioned IOPS still incur the full io1/io2 cost ($0.065/IOPS/month)
even though they can never be reached through the network path.

Run: python 38_detect_ebs_network_mismatch.py --accounts 123456789012,234567890123
"""
from __future__ import annotations

import logging
import sys
from pathlib import Path
from botocore.exceptions import ClientError

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from common import cli, pricing, session

SCRIPT_NAME = '38_detect_ebs_network_mismatch'
EXTRA_FIELDS = [
    'instance_type',
    'network_gbps',
    'instance_max_iops',
    'provisioned_iops',
    'excess_iops',
    'volume_ids',
]

# io1/io2 provisioned-IOPS cost per IOPS per month (us-east-1 list price)
IOPS_PRICE_PER_MONTH = 0.065

# Network performance string → Gbps mappings
_NET_GBPS: dict[str, float] = {
    'high': 10.0,
    'moderate': 1.0,
    'low': 1.0,
    'very low': 0.5,
}

log = logging.getLogger(SCRIPT_NAME)


def _parse_network_gbps(perf: str) -> float:
    """
    Convert an AWS NetworkPerformance string to a float Gbps value.

    Examples handled:
      "Up to 25 Gigabit"  → 25.0
      "10 Gigabit"        → 10.0
      "High"              → 10.0  (conservative estimate)
      "Moderate"          → 1.0
      "Low"               → 1.0
      "25 Gigabit"        → 25.0
    """
    lower = perf.lower().strip()
    # Check simple word mappings first
    for key, gbps in _NET_GBPS.items():
        if lower == key:
            return gbps

    # Try to extract a number (handles "Up to X Gigabit" and "X Gigabit")
    import re
    m = re.search(r'([\d.]+)\s*gigabit', lower)
    if m:
        return float(m.group(1))

    # Fallback: anything else treated as 1 Gbps (conservative)
    log.debug("Unrecognised NetworkPerformance string %r — defaulting to 1 Gbps", perf)
    return 1.0


def _batch_instance_type_info(ec2, instance_types: list[str]) -> dict[str, dict]:
    """
    Return {instance_type: {'network_gbps': float, 'max_iops': int, 'max_throughput_mbps': float}}
    by calling describe_instance_types in batches of 100.
    """
    result: dict[str, dict] = {}
    for chunk in session.chunked(instance_types, 100):
        try:
            resp = ec2.describe_instance_types(InstanceTypes=chunk)
        except ClientError as exc:
            if session.is_skippable(exc):
                log.warning("describe_instance_types skipped: %s", exc.response['Error']['Code'])
                continue
            log.error("describe_instance_types failed: %s", exc)
            continue
        for it in resp.get('InstanceTypes', []):
            itype = it['InstanceType']
            net_perf = it.get('NetworkInfo', {}).get('NetworkPerformance', 'Low')
            network_gbps = _parse_network_gbps(net_perf)

            ebs_info = it.get('EbsInfo', {}).get('EbsOptimizedInfo', {})
            max_iops = ebs_info.get('MaximumIops', 0) or 0
            max_throughput = ebs_info.get('MaximumThroughputInMBps', 0.0) or 0.0

            result[itype] = {
                'network_gbps': network_gbps,
                'max_iops': int(max_iops),
                'max_throughput_mbps': float(max_throughput),
            }
    return result


def scan(sess, account_id: str, region: str, writer) -> None:
    ec2 = sess.client('ec2', region_name=region)

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

    # ------------------------------------------------------------------ #
    # 2. Look up instance-type capabilities in bulk                        #
    # ------------------------------------------------------------------ #
    unique_types = list({i['InstanceType'] for i in instances})
    type_info = _batch_instance_type_info(ec2, unique_types)

    # ------------------------------------------------------------------ #
    # 3. For each instance, sum provisioned IOPS across io1/io2 volumes   #
    # ------------------------------------------------------------------ #
    for inst in instances:
        instance_id = inst['InstanceId']
        instance_type = inst['InstanceType']
        tags = inst.get('Tags', [])

        # Skip instance types we couldn't retrieve limits for
        info = type_info.get(instance_type)
        if info is None:
            log.debug("%s: no info for instance type %s — skipping", instance_id, instance_type)
            continue

        instance_max_iops = info['max_iops']
        network_gbps = info['network_gbps']

        # No meaningful ceiling to compare against if max_iops is unknown
        if instance_max_iops == 0:
            log.debug(
                "%s (%s): EbsOptimizedInfo.MaximumIops=0 — skipping mismatch check",
                instance_id, instance_type,
            )
            continue

        # Enumerate attached volumes
        block_devices = inst.get('BlockDeviceMappings', [])
        volume_ids = [
            bd['Ebs']['VolumeId']
            for bd in block_devices
            if bd.get('Ebs', {}).get('VolumeId')
        ]
        if not volume_ids:
            continue

        # Fetch volume details for io1/io2 volumes only
        provisioned_iops_total = 0
        io_volume_ids: list[str] = []
        try:
            for chunk in session.chunked(volume_ids, 100):
                vol_resp = ec2.describe_volumes(
                    VolumeIds=chunk,
                    Filters=[{'Name': 'volume-type', 'Values': ['io1', 'io2']}],
                )
                for vol in vol_resp.get('Volumes', []):
                    iops = vol.get('Iops', 0) or 0
                    provisioned_iops_total += iops
                    io_volume_ids.append(vol['VolumeId'])
        except ClientError as exc:
            if session.is_skippable(exc):
                continue
            log.error("%s/%s describe_volumes(%s): %s", account_id, region, instance_id, exc)
            continue

        if provisioned_iops_total == 0:
            # No io1/io2 volumes attached — nothing to compare
            continue

        if provisioned_iops_total <= instance_max_iops:
            continue  # Within the ceiling — no issue

        # ---------------------------------------------------------------- #
        # 4. Flag the mismatch                                              #
        # ---------------------------------------------------------------- #
        excess_iops = provisioned_iops_total - instance_max_iops
        region_mult = pricing.region_multiplier(region)
        monthly_savings = excess_iops * IOPS_PRICE_PER_MONTH * region_mult

        detail = (
            f"InstanceType={instance_type} "
            f"NetworkPerf={network_gbps:.0f}Gbps "
            f"InstanceMaxIOPS={instance_max_iops} "
            f"ProvisionedIOPS={provisioned_iops_total} "
            f"ExcessIOPS={excess_iops}"
        )

        writer.write(
            account_id=account_id,
            region=region,
            resource_id=instance_id,
            resource_type='EC2 Instance',
            finding='ebs-iops-exceeds-network-ceiling',
            detail=detail,
            estimated_monthly_savings_usd=round(monthly_savings, 2),
            tags=tags,
            instance_type=instance_type,
            network_gbps=f"{network_gbps:.1f}",
            instance_max_iops=instance_max_iops,
            provisioned_iops=provisioned_iops_total,
            excess_iops=excess_iops,
            volume_ids=','.join(io_volume_ids),
        )

    log.info("%s/%s: scanned %d running instance(s)", account_id, region, len(instances))


def main() -> None:
    parser = cli.make_parser(__doc__)
    args = parser.parse_args()
    cli.run(args, SCRIPT_NAME, scan, extra_fields=EXTRA_FIELDS)


if __name__ == '__main__':
    main()
