#!/usr/bin/env python3
"""Task 16 - Classic Load Balancers

Finds all Classic Load Balancers (CLBv1) in use. CLBs are a modernisation risk:
they lack features of ALB/NLB and AWS has signalled long-term deprecation intent.
Every CLB found is flagged as a migration candidate.

Extra columns:
  age_days              - days since the CLB was created
  listener_protocols    - protocols/ports the CLB listens on (e.g. HTTPS:443,HTTP:80)
  migration_target      - ALB or NLB recommendation based on listener protocols
  request_count_30d     - requests over the last 30 days
  request_count_60d     - requests over the last 60 days
  request_count_90d     - requests over the last 90 days
  deletion_confidence   - HIGH, MEDIUM, or LOW confidence in deletion being safe
  deployment_source     - CloudFormation when its stack tags exist, otherwise Manual/Other
  instance_owner_source - how the COMMON_FIELDS 'owner' column was resolved: clb-tag
                          (the CLB's own tags), instance-consensus (registered instances
                          agree on an owner), instance-mixed (they disagree - see detail
                          for candidates), or none

Run: python 16_detect_classic_load_balancers.py --accounts 123456789012,234567890123
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

SCRIPT_NAME = '16_detect_classic_load_balancers'
EXTRA_FIELDS = [
    'dns_name', 'scheme', 'instance_count', 'created_time', 'availability_zones',
    'age_days', 'listener_protocols', 'migration_target', 'request_count_30d',
    'request_count_60d', 'request_count_90d', 'deletion_confidence',
    'deployment_source',
    'instance_owner_source',
]

# Protocols that route to ALB; anything else (TCP, SSL, UDP) routes to NLB
ALB_PROTOCOLS = {'HTTP', 'HTTPS'}
REQUEST_WINDOWS_DAYS = (30, 60, 90)
REQUEST_METRIC_PERIOD_SECONDS = 2 * 60 * 60

log = logging.getLogger(SCRIPT_NAME)


def _get_tags(elb, name: str) -> tuple[list[dict], bool]:
    try:
        resp = elb.describe_tags(LoadBalancerNames=[name])
        raw = resp['TagDescriptions'][0].get('Tags', []) if resp.get('TagDescriptions') else []
        return [{'Key': t['Key'], 'Value': t['Value']} for t in raw], True
    except Exception:
        log.exception("Unable to retrieve tags for Classic Load Balancer %s", name)
        return [], False


def _deployment_source(tags: list[dict], tags_available: bool = True) -> str:
    if not tags_available:
        return 'Unknown'
    if any(
        tag.get('Key', '').casefold().startswith('aws:cloudformation:')
        for tag in tags
    ):
        return 'CloudFormation'
    return 'Manual/Other'


def _resolve_instance_owner(ec2, instance_ids: list[str]) -> tuple[str, str, list[str]]:
    """Return (owner_value, source, distinct_owners) from registered instances' tags.

    Uses common.tags.owner_from_tags (the shared owner-alias resolver also used by
    common/output.py's default 'owner' column) against each instance's own tags.
    owner_value is empty when no instance resolves an owner, the single shared
    value when all tagged instances agree, or "mixed" when they don't.
    distinct_owners lists the candidate values found (0, 1, or more entries) so
    callers can surface them in the finding detail when the result is mixed.
    """
    owners: set[str] = set()
    try:
        for batch in session.chunked(instance_ids, 100):
            resp = ec2.describe_instances(InstanceIds=batch)
            for reservation in resp.get('Reservations', []):
                for inst in reservation.get('Instances', []):
                    owner = tagutil.owner_from_tags(inst.get('Tags', []))
                    if owner:
                        owners.add(owner)
    except ClientError as exc:
        if session.is_skippable(exc):
            return '', 'none', []
        raise
    distinct = sorted(owners)
    if not owners:
        return '', 'none', distinct
    if len(owners) == 1:
        return distinct[0], 'instance-consensus', distinct
    return 'mixed', 'instance-mixed', distinct


def _get_request_counts(cw, name: str) -> tuple[int, int, int]:
    try:
        end = datetime.now(timezone.utc)
        counts = []
        for window_days in REQUEST_WINDOWS_DAYS:
            resp = cw.get_metric_statistics(
                Namespace='AWS/ELB',
                MetricName='RequestCount',
                Dimensions=[{'Name': 'LoadBalancerName', 'Value': name}],
                StartTime=end - timedelta(days=window_days),
                EndTime=end,
                Period=REQUEST_METRIC_PERIOD_SECONDS,
                Statistics=['Sum'],
            )
            counts.append(int(sum(p['Sum'] for p in resp.get('Datapoints', []))))
        return tuple(counts)
    except Exception:
        log.exception("Unable to retrieve RequestCount metrics for Classic Load Balancer %s", name)
        return (-1, -1, -1)  # -1 = metric could not be retrieved


def _deletion_confidence(
    request_count_30d: int, request_count_60d: int, request_count_90d: int,
    instance_count: int,
) -> str:
    if (
        request_count_30d < 0 or request_count_60d < 0 or request_count_90d < 0
        or request_count_30d > 0 or request_count_60d > 0
    ):
        return 'LOW'
    if request_count_90d == 0 and instance_count == 0:
        return 'HIGH'
    return 'MEDIUM'


def _migration_target(protocols: set[str]) -> str:
    if protocols <= ALB_PROTOCOLS:
        return 'ALB'
    if protocols.isdisjoint(ALB_PROTOCOLS):
        return 'NLB'
    return 'ALB+NLB'  # mixed listeners — may need split


def scan(sess, account_id: str, region: str, writer) -> None:
    elb = sess.client('elb', region_name=region)
    cw = sess.client('cloudwatch', region_name=region)
    ec2 = sess.client('ec2', region_name=region)
    now = datetime.now(timezone.utc)

    try:
        paginator = elb.get_paginator('describe_load_balancers')
        for page in paginator.paginate():
            for lb in page['LoadBalancerDescriptions']:
                name = lb['LoadBalancerName']
                scheme = lb.get('Scheme', '')
                dns_name = lb.get('DNSName', '')
                instance_count = len(lb.get('Instances', []))
                created_time = lb.get('CreatedTime')
                azs = ','.join(lb.get('AvailabilityZones', []))

                age_days = (now - created_time).days if created_time else ''
                created_str = created_time.isoformat() if created_time else ''

                listeners = lb.get('ListenerDescriptions', [])
                protocols = {
                    l['Listener']['Protocol'].upper()
                    for l in listeners
                    if l.get('Listener', {}).get('Protocol')
                }
                listener_str = ','.join(
                    f"{l['Listener']['Protocol']}:{l['Listener']['LoadBalancerPort']}"
                    for l in listeners if l.get('Listener')
                )
                migration_target = _migration_target(protocols) if protocols else 'unknown'

                request_count_30d, request_count_60d, request_count_90d = (
                    _get_request_counts(cw, name)
                )
                request_counts = (
                    request_count_30d, request_count_60d, request_count_90d,
                )
                request_strings = tuple(
                    str(count) if count >= 0 else 'unknown' for count in request_counts
                )
                deletion_confidence = _deletion_confidence(
                    request_count_30d, request_count_60d, request_count_90d,
                    instance_count,
                )

                tags, tags_available = _get_tags(elb, name)
                deployment_source = _deployment_source(tags, tags_available)
                monthly_cost = pricing.lb_monthly_floor(region, 'classic')

                clb_owner = tagutil.owner_from_tags(tags)
                mixed_owners: list[str] = []
                if clb_owner:
                    instance_owner, instance_owner_source = clb_owner, 'clb-tag'
                elif instance_count > 0:
                    instance_ids = [
                        i['InstanceId'] for i in lb.get('Instances', []) if i.get('InstanceId')
                    ]
                    instance_owner, instance_owner_source, mixed_owners = _resolve_instance_owner(
                        ec2, instance_ids
                    )
                else:
                    instance_owner, instance_owner_source = '', 'none'

                if deletion_confidence in {'HIGH', 'MEDIUM'}:
                    finding = 'classic-load-balancer - low recent traffic, deletion candidate'
                elif request_count_30d < 0 or request_count_60d < 0 or request_count_90d < 0:
                    finding = 'classic-load-balancer - traffic unknown, review before deletion'
                else:
                    finding = 'classic-load-balancer - recent traffic, migrate to ALB or NLB'

                detail_owner = (
                    f" owner_candidates={','.join(mixed_owners)}"
                    if instance_owner_source == 'instance-mixed'
                    else ''
                )

                writer.write(
                    account_id=account_id,
                    region=region,
                    resource_id=name,
                    resource_type='Classic Load Balancer',
                    finding=finding,
                    detail=(
                        f"scheme={scheme} instances={instance_count} "
                        f"age_days={age_days} listeners={listener_str} "
                        f"requests_30d={request_strings[0]} "
                        f"requests_60d={request_strings[1]} "
                        f"requests_90d={request_strings[2]} "
                        f"deletion_confidence={deletion_confidence} "
                        f"deployment_source={deployment_source} "
                        f"dns={dns_name}{detail_owner}"
                    ),
                    estimated_monthly_savings_usd=round(monthly_cost, 2),
                    tags=tags,
                    owner=instance_owner,
                    dns_name=dns_name,
                    scheme=scheme,
                    instance_count=instance_count,
                    created_time=created_str,
                    availability_zones=azs,
                    age_days=age_days,
                    listener_protocols=listener_str,
                    migration_target=migration_target,
                    request_count_30d=request_strings[0],
                    request_count_60d=request_strings[1],
                    request_count_90d=request_strings[2],
                    deletion_confidence=deletion_confidence,
                    deployment_source=deployment_source,
                    instance_owner_source=instance_owner_source,
                )
    except ClientError as exc:
        if session.is_skippable(exc):
            log.warning("%s/%s: skipped - %s", account_id, region, exc.response['Error']['Code'])
            return
        raise


def main() -> None:
    parser = cli.make_parser(__doc__)
    args = parser.parse_args()
    cli.run(args, SCRIPT_NAME, scan, extra_fields=EXTRA_FIELDS)


if __name__ == '__main__':
    main()
