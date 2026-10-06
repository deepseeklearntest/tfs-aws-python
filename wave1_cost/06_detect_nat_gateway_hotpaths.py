#!/usr/bin/env python3
"""
Task 6 â€” NAT Gateway Egress Hot Paths

Identifies NAT Gateways processing >150 GB/month outbound. Those are VPC endpoint
candidates â€” moving the traffic to S3/DynamoDB/STS Gateway endpoints typically
cuts processing cost 60-80%.

NAT Gateway data processing: $0.045/GB (us-east-1, region-adjusted).

Run: python 06_detect_nat_gateway_hotpaths.py --vault-group CloudOps
"""
from __future__ import annotations

import logging
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

from botocore.exceptions import ClientError

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from common import cli, pricing, session

SCRIPT_NAME = '06_detect_nat_gateway_hotpaths'
LOOKBACK_DAYS = 30
THRESHOLD_GB_DEFAULT = 150
VPC_ENDPOINT_SAVING_PCT = 0.70
CW_BATCH_SIZE = 500
IDLE_GB = 1.0  # less than 1 GB/30d = no meaningful traffic

log = logging.getLogger(SCRIPT_NAME)
EXTRA_FIELDS = ['nat_gw_id', 'vpc_id', 'subnet_id', 'state', 'total_gb_30d', 'data_cost_usd']


def _batch_bytes(cw, nat_gw_ids: list[str]) -> dict[str, float]:
    """Return {nat_gw_id: total_bytes_30d}."""
    if not nat_gw_ids:
        return {}

    end = datetime.now(timezone.utc)
    start = end - timedelta(days=LOOKBACK_DAYS)
    queries = [
        {
            'Id': f"q{i}",
            'MetricStat': {
                'Metric': {
                    'Namespace': 'AWS/NATGateway',
                    'MetricName': 'BytesOutToDestination',
                    'Dimensions': [{'Name': 'NatGatewayId', 'Value': gw_id}],
                },
                'Period': 86400,
                'Stat': 'Sum',
            },
            'ReturnData': True,
        }
        for i, gw_id in enumerate(nat_gw_ids)
    ]

    totals: dict[str, float] = {}
    for chunk in session.chunked(queries, CW_BATCH_SIZE):
        try:
            paginator = cw.get_paginator('get_metric_data')
            for resp in paginator.paginate(
                MetricDataQueries=chunk, StartTime=start, EndTime=end
            ):
                for r in resp.get('MetricDataResults', []):
                    idx = int(r['Id'][1:])
                    gw_id = nat_gw_ids[idx]
                    totals[gw_id] = totals.get(gw_id, 0.0) + sum(r.get('Values', []))
        except ClientError as exc:
            log.warning("CloudWatch batch failed (%d queries): %s", len(chunk), exc)
    return totals


def make_scan(threshold_gb: float):
    def scan(sess, account_id: str, region: str, writer) -> None:
        ec2 = sess.client('ec2', region_name=region)
        cw = sess.client('cloudwatch', region_name=region)
        data_price = pricing.nat_gateway_data_price_per_gb(region)

        try:
            gateways: list[dict] = []
            for page in ec2.get_paginator('describe_nat_gateways').paginate(
                Filters=[{'Name': 'state', 'Values': ['available']}]
            ):
                gateways.extend(page['NatGateways'])
        except ClientError as exc:
            if session.is_skippable(exc):
                log.warning("%s/%s: skipped â€” %s", account_id, region, exc.response['Error']['Code'])
                return
            log.error("%s/%s: %s", account_id, region, exc)
            return

        if not gateways:
            return

        gw_ids = [g['NatGatewayId'] for g in gateways]
        totals = _batch_bytes(cw, gw_ids)
        hourly_price = pricing.nat_gateway_hourly_price(region)

        for gw in gateways:
            gw_id = gw['NatGatewayId']
            total_bytes = totals.get(gw_id, 0.0)
            total_gb = total_bytes / (1024 ** 3)

            if total_gb < IDLE_GB:
                # Idle: savings = the $0.045/hr existence charge (~$32.85/mo)
                writer.write(
                    account_id=account_id,
                    region=region,
                    resource_id=gw_id,
                    resource_type='NAT Gateway',
                    finding=f'idle NAT GW ({total_gb:.2f} GB/30d) - deletion candidate',
                    detail=(
                        f"VPC={gw.get('VpcId', '')} Subnet={gw.get('SubnetId', '')} "
                        f"no meaningful traffic in 30d"
                    ),
                    estimated_monthly_savings_usd=round(hourly_price * 730, 2),
                    tags=gw.get('Tags'),
                    nat_gw_id=gw_id,
                    vpc_id=gw.get('VpcId', ''),
                    subnet_id=gw.get('SubnetId', ''),
                    state=gw.get('State', ''),
                    total_gb_30d=f"{total_gb:.2f}",
                    data_cost_usd='0.00',
                )
            elif total_gb >= threshold_gb:
                # High-egress: savings = estimated data processing avoided via VPC endpoint
                data_cost = total_gb * data_price
                monthly_savings = (total_gb / LOOKBACK_DAYS * 30) * data_price * VPC_ENDPOINT_SAVING_PCT
                writer.write(
                    account_id=account_id,
                    region=region,
                    resource_id=gw_id,
                    resource_type='NAT Gateway',
                    finding=f'high-egress NAT GW ({total_gb:.0f} GB/30d) - VPC endpoint candidate',
                    detail=(
                        f"VPC={gw.get('VpcId', '')} Subnet={gw.get('SubnetId', '')} "
                        f"DataCost30d=${data_cost:.2f}"
                    ),
                    estimated_monthly_savings_usd=round(monthly_savings, 2),
                    tags=gw.get('Tags'),
                    nat_gw_id=gw_id,
                    vpc_id=gw.get('VpcId', ''),
                    subnet_id=gw.get('SubnetId', ''),
                    state=gw.get('State', ''),
                    total_gb_30d=f"{total_gb:.2f}",
                    data_cost_usd=f"{data_cost:.2f}",
                )
    return scan


def main() -> None:
    parser = cli.make_parser(__doc__)
    parser.add_argument(
        '--threshold-gb', type=float, default=THRESHOLD_GB_DEFAULT,
        help=f'Minimum GB/30d to flag (default: {THRESHOLD_GB_DEFAULT})',
    )
    args = parser.parse_args()
    cli.run(args, SCRIPT_NAME, make_scan(args.threshold_gb), extra_fields=EXTRA_FIELDS)


if __name__ == '__main__':
    main()
