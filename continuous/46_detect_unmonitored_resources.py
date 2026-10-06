#!/usr/bin/env python3
"""Task 46 — Resources Without Monitoring

Identifies EC2 instances without the CloudWatch agent, RDS instances with enhanced
monitoring disabled, and ALB/NLB load balancers without access logs enabled.

Covers all environments (prod and non-prod). The output CSV includes an
'environment' column extracted from the Environment tag so findings can be
filtered by environment without parsing the raw tags blob.

Run: python 46_detect_unmonitored_resources.py --accounts 123456789012,234567890123
"""
from __future__ import annotations


import logging
import sys
from pathlib import Path

from botocore.exceptions import ClientError

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
try:
    from common import cli, session
    from common import tags as tagutil
except Exception:
    # Support running as a module/package where a relative import is needed
    from .common import cli, session  # type: ignore
    from .common import tags as tagutil  # type: ignore

SCRIPT_NAME = '46_detect_unmonitored_resources'
EXTRA_FIELDS = ['resource_subtype', 'name', 'detail2', 'environment']

log = logging.getLogger(SCRIPT_NAME)


def _env_tag(tags) -> str:
    """Extract the Environment tag value from a tag list (EC2/RDS/ELB format).

    Case- and separator-insensitive (common.tags.tag_value) since this org
    tags 'environment' lowercase as often as 'Environment'.
    """
    return tagutil.tag_value(tags, 'Environment')


def _scan_ec2(sess, account_id: str, region: str, writer) -> None:
    """Flag running EC2 instances that have no CWAgent metrics."""
    ec2 = sess.client('ec2', region_name=region)
    cw = sess.client('cloudwatch', region_name=region)

    try:
        paginator = ec2.get_paginator('describe_instances')
        pages = paginator.paginate(
            Filters=[{'Name': 'instance-state-name', 'Values': ['running']}]
        )
        instances = [
            instance
            for page in pages
            for reservation in page.get('Reservations', [])
            for instance in reservation.get('Instances', [])
        ]
    except ClientError as exc:
        if session.is_skippable(exc):
            log.warning('%s/%s EC2: skipped — %s', account_id, region, exc.response['Error']['Code'])
            return
        log.error('%s/%s EC2 describe_instances failed: %s', account_id, region, exc)
        return

    for instance in instances:
        instance_id = instance['InstanceId']
        name = tagutil.tag_value(instance.get('Tags', []), 'Name')

        try:
            result = cw.list_metrics(
                Namespace='CWAgent',
                Dimensions=[{'Name': 'InstanceId', 'Value': instance_id}],
            )
            has_agent = bool(result.get('Metrics'))
        except ClientError as exc:
            if session.is_skippable(exc):
                log.warning(
                    '%s/%s CWAgent list_metrics skipped for %s — %s',
                    account_id, region, instance_id, exc.response['Error']['Code'],
                )
                continue
            log.error('%s/%s CWAgent list_metrics failed for %s: %s', account_id, region, instance_id, exc)
            continue

        if not has_agent:
            instance_type = instance.get('InstanceType', '')
            instance_tags = instance.get('Tags', [])
            writer.write(
                account_id=account_id,
                region=region,
                resource_id=instance_id,
                resource_type='EC2 Instance',
                finding='no-cloudwatch-agent',
                detail=(
                    f"Instance {instance_id} ({instance_type}) is running "
                    f"without the CloudWatch agent — no OS-level metrics."
                ),
                estimated_monthly_savings_usd=0,
                tags=instance_tags,
                resource_subtype='ec2',
                name=name,
                detail2=instance_type,
                environment=_env_tag(instance_tags),
            )


def _scan_rds(sess, account_id: str, region: str, writer) -> None:
    """Flag RDS instances with MonitoringInterval == 0 (enhanced monitoring off)."""
    rds = sess.client('rds', region_name=region)

    try:
        paginator = rds.get_paginator('describe_db_instances')
        db_instances = [
            db
            for page in paginator.paginate()
            for db in page.get('DBInstances', [])
        ]
    except ClientError as exc:
        if session.is_skippable(exc):
            log.warning('%s/%s RDS: skipped — %s', account_id, region, exc.response['Error']['Code'])
            return
        log.error('%s/%s RDS describe_db_instances failed: %s', account_id, region, exc)
        return

    for db in db_instances:
        if db.get('MonitoringInterval', 0) != 0:
            continue

        db_id = db['DBInstanceIdentifier']
        engine = db.get('Engine', '')
        instance_class = db.get('DBInstanceClass', '')
        db_tags = db.get('TagList', [])

        writer.write(
            account_id=account_id,
            region=region,
            resource_id=db_id,
            resource_type='RDS Instance',
            finding='enhanced-monitoring-disabled',
            detail=(
                f"Engine={engine} Class={instance_class}. "
                f"Enhanced monitoring is disabled (MonitoringInterval=0)."
            ),
            estimated_monthly_savings_usd=0,
            tags=db_tags,
            resource_subtype='rds',
            name=db_id,
            detail2=f"engine={engine} class={instance_class}",
            environment=_env_tag(db_tags),
        )


def _scan_elb(sess, account_id: str, region: str, writer) -> None:
    """Flag ALB/NLB load balancers that have S3 access logging disabled."""
    elbv2 = sess.client('elbv2', region_name=region)

    try:
        paginator = elbv2.get_paginator('describe_load_balancers')
        load_balancers = [
            lb
            for page in paginator.paginate()
            for lb in page.get('LoadBalancers', [])
        ]
    except ClientError as exc:
        if session.is_skippable(exc):
            log.warning('%s/%s ELBv2: skipped — %s', account_id, region, exc.response['Error']['Code'])
            return
        log.error('%s/%s ELBv2 describe_load_balancers failed: %s', account_id, region, exc)
        return

    # describe_load_balancers() doesn't include tags; batch-fetch them (up to 20 ARNs per call)
    lb_tags: dict[str, list] = {}
    all_arns = [lb['LoadBalancerArn'] for lb in load_balancers]
    for i in range(0, len(all_arns), 20):
        batch = all_arns[i:i + 20]
        try:
            tag_resp = elbv2.describe_tags(ResourceArns=batch)
            for td in tag_resp.get('TagDescriptions', []):
                lb_tags[td['ResourceArn']] = td.get('Tags', [])
        except ClientError as exc:
            if session.is_skippable(exc):
                log.warning('%s/%s ELBv2 describe_tags skipped — %s',
                            account_id, region, exc.response['Error']['Code'])
            else:
                log.error('%s/%s ELBv2 describe_tags failed: %s', account_id, region, exc)

    for lb in load_balancers:
        lb_arn = lb['LoadBalancerArn']
        lb_name = lb.get('LoadBalancerName', '')
        lb_type = lb.get('Type', '')
        lb_scheme = lb.get('Scheme', '')
        tags = lb_tags.get(lb_arn, [])

        try:
            attrs_resp = elbv2.describe_load_balancer_attributes(LoadBalancerArn=lb_arn)
            attrs = {a['Key']: a['Value'] for a in attrs_resp.get('Attributes', [])}
        except ClientError as exc:
            if session.is_skippable(exc):
                log.warning(
                    '%s/%s ELBv2 attributes skipped for %s — %s',
                    account_id, region, lb_name, exc.response['Error']['Code'],
                )
                continue
            log.error('%s/%s ELBv2 describe_load_balancer_attributes failed for %s: %s',
                      account_id, region, lb_name, exc)
            continue

        if attrs.get('access_logs.s3.enabled', 'false') != 'false':
            continue

        writer.write(
            account_id=account_id,
            region=region,
            resource_id=lb_arn,
            resource_type='Load Balancer',
            finding='access-logs-disabled',
            detail=(
                f"Name={lb_name} Type={lb_type} Scheme={lb_scheme}. "
                f"S3 access logging is disabled."
            ),
            estimated_monthly_savings_usd=0,
            tags=tags,
            resource_subtype='elb',
            name=lb_name,
            detail2=f"type={lb_type} scheme={lb_scheme}",
            environment=_env_tag(tags),
        )


def scan(sess, account_id: str, region: str, writer) -> None:
    _scan_ec2(sess, account_id, region, writer)
    _scan_rds(sess, account_id, region, writer)
    _scan_elb(sess, account_id, region, writer)


def main() -> None:
    parser = cli.make_parser(__doc__)
    args = parser.parse_args()
    cli.run(args, SCRIPT_NAME, scan, extra_fields=EXTRA_FIELDS)


if __name__ == '__main__':
    main()
