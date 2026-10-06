#!/usr/bin/env python3
"""
Task 13 â€” Spot Adoption Opportunities

Identifies ASGs and EKS managed node groups running 100% On-Demand capacity in
non-production environments. Spot adoption typically delivers 70-90% savings.

Criteria:
  - ASG: no MixedInstancesPolicy, or OnDemandPercentageAboveBaseCapacity = 100
  - EKS node group: capacityType = ON_DEMAND
  - Environment tag value matches --nonprod-values (default: dev,test,qa,...)

Run: python 13_detect_spot_opportunities.py --vault-group CloudOps
     python 13_detect_spot_opportunities.py --nonprod-values dev,sandbox,uat
"""
from __future__ import annotations

import logging
import sys
from pathlib import Path

from botocore.exceptions import ClientError

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from common import cli, session

SCRIPT_NAME = '13_detect_spot_opportunities'

DEFAULT_NONPROD_VALUES = (
    'dev,development,test,testing,qa,staging,stage,'
    'nonprod,non-prod,sandbox,sbx,uat,integration'
)

log = logging.getLogger(SCRIPT_NAME)
EXTRA_FIELDS = [
    'resource_name', 'resource_kind', 'environment_tag',
    'current_spot_pct', 'desired_capacity', 'on_demand_base',
]


def _env_tag(tags: list) -> str:
    for t in tags:
        if t.get('Key', '').lower() in ('environment', 'env'):
            return t.get('Value', '').lower()
    return ''


def _is_nonprod(tags: list, nonprod_set: set[str]) -> bool:
    return _env_tag(tags) in nonprod_set


def _scan_asgs(asg, account_id: str, region: str, writer, nonprod_set: set[str]) -> None:
    for page in asg.get_paginator('describe_auto_scaling_groups').paginate():
        for group in page['AutoScalingGroups']:
            tag_list = [{'Key': t['Key'], 'Value': t['Value']} for t in group.get('Tags', [])]
            if not _is_nonprod(tag_list, nonprod_set):
                continue

            name = group['AutoScalingGroupName']
            desired = group.get('DesiredCapacity', 0)
            mix = group.get('MixedInstancesPolicy')

            if mix:
                dist = mix.get('InstancesDistribution', {})
                od_pct = dist.get('OnDemandPercentageAboveBaseCapacity', 100)
                od_base = dist.get('OnDemandBaseCapacity', 0)
                if od_pct < 100:
                    continue
            else:
                od_pct = 100
                od_base = desired

            writer.write(
                account_id=account_id,
                region=region,
                resource_id=group['AutoScalingGroupARN'],
                resource_type='Auto Scaling Group',
                finding='100% On-Demand ASG in non-prod â€” Spot adoption opportunity',
                detail=f"Name={name} Desired={desired} Env={_env_tag(tag_list)}",
                estimated_monthly_savings_usd=None,
                tags=tag_list,
                resource_name=name,
                resource_kind='ASG',
                environment_tag=_env_tag(tag_list),
                current_spot_pct='0',
                desired_capacity=str(desired),
                on_demand_base=str(od_base),
            )


def _scan_eks_nodegroups(eks, account_id: str, region: str, writer, nonprod_set: set[str]) -> None:
    try:
        clusters = eks.list_clusters().get('clusters', [])
    except ClientError as exc:
        if session.is_skippable(exc):
            log.warning("%s/%s: EKS skipped â€” %s", account_id, region, exc.response['Error']['Code'])
            return
        raise

    for cluster_name in clusters:
        try:
            ng_names = eks.list_nodegroups(clusterName=cluster_name).get('nodegroups', [])
        except ClientError as exc:
            log.debug("list_nodegroups failed for %s: %s", cluster_name, exc)
            continue

        for ng_name in ng_names:
            try:
                ng = eks.describe_nodegroup(
                    clusterName=cluster_name, nodegroupName=ng_name
                )['nodegroup']
            except ClientError as exc:
                log.debug("describe_nodegroup failed for %s/%s: %s", cluster_name, ng_name, exc)
                continue

            if ng.get('capacityType') != 'ON_DEMAND':
                continue

            tag_list = [{'Key': k, 'Value': v} for k, v in ng.get('tags', {}).items()]
            if not _is_nonprod(tag_list, nonprod_set):
                continue

            desired = ng.get('scalingConfig', {}).get('desiredSize', 0)
            writer.write(
                account_id=account_id,
                region=region,
                resource_id=ng.get('nodegroupArn', ng_name),
                resource_type='EKS Node Group',
                finding='ON_DEMAND EKS node group in non-prod â€” Spot adoption opportunity',
                detail=(
                    f"Cluster={cluster_name} NG={ng_name} "
                    f"InstanceTypes={ng.get('instanceTypes', [])} Desired={desired}"
                ),
                estimated_monthly_savings_usd=None,
                tags=tag_list,
                resource_name=ng_name,
                resource_kind='EKSNodeGroup',
                environment_tag=_env_tag(tag_list),
                current_spot_pct='0',
                desired_capacity=str(desired),
                on_demand_base=str(desired),
            )


def make_scan(nonprod_set: set[str]):
    def scan(sess, account_id: str, region: str, writer) -> None:
        asg = sess.client('autoscaling', region_name=region)
        eks = sess.client('eks', region_name=region)

        for fn, client in ((_scan_asgs, asg), (_scan_eks_nodegroups, eks)):
            try:
                fn(client, account_id, region, writer, nonprod_set)
            except ClientError as exc:
                if session.is_skippable(exc):
                    log.warning(
                        "%s/%s: skipped (%s) â€” %s",
                        account_id, region, fn.__name__, exc.response['Error']['Code']
                    )
                else:
                    log.error("%s/%s (%s): %s", account_id, region, fn.__name__, exc)
    return scan


def main() -> None:
    parser = cli.make_parser(__doc__)
    parser.add_argument(
        '--nonprod-values', default=DEFAULT_NONPROD_VALUES,
        help='Comma-separated Environment tag values that count as non-prod',
    )
    args = parser.parse_args()
    nonprod_set = {v.strip().lower() for v in args.nonprod_values.split(',') if v.strip()}
    log.info("Treating these env tag values as non-prod: %s", sorted(nonprod_set))

    cli.run(args, SCRIPT_NAME, make_scan(nonprod_set), extra_fields=EXTRA_FIELDS)


if __name__ == '__main__':
    main()
