#!/usr/bin/env python3
"""Task 48 — All Quotas at >70% Utilization

Checks AWS Service Quotas against current CloudWatch usage metrics
(AWS/Usage namespace) and flags any quota at or above the warn/critical
thresholds so teams can request increases before hitting hard limits.

Run: python 48_detect_quota_utilization.py --accounts 123456789012,234567890123
"""
from __future__ import annotations


import logging
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

from botocore.exceptions import ClientError, EndpointConnectionError

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from common import cli, session

SCRIPT_NAME = '48_detect_quota_utilization'
EXTRA_FIELDS = [
    'service_code', 'quota_name', 'quota_code',
    'current_value', 'quota_limit', 'utilization_pct', 'severity',
    'production_impact',
]

WARN_THRESHOLD_DEFAULT = 70
CRITICAL_THRESHOLD_DEFAULT = 80

DEFAULT_SERVICES = [
    'ec2', 'lambda', 'rds', 'elasticloadbalancing', 'vpc',
    'iam', 'sqs', 'sns', 'dynamodb', 'kinesis',
    'ecs', 'eks', 'firehose', 's3',
]

log = logging.getLogger(SCRIPT_NAME)

# Keyword-based impact map: (service_code, lowercase substring of quota name) -> what breaks
# Last verified: 2026-06-15
_IMPACT_HINTS: dict[tuple[str, str], str] = {
    # EC2
    ('ec2', 'running on-demand'):           'EC2 launch failures - ASG scale-out and EKS node provisioning blocked',
    ('ec2', 'vcpu'):                        'EC2 launch failures - instance starts blocked for this CPU family',
    ('ec2', 'elastic ip'):                  'EIP allocation fails - new NAT gateways and EIPs cannot be assigned',
    ('ec2', 'spot'):                        'Spot requests rejected - batch and CI workloads throttled',
    # VPC
    ('vpc', 'vpcs per region'):             'New VPCs cannot be created - environment provisioning blocked',
    ('vpc', 'nat gateway'):                 'NAT Gateway creation fails - new subnets lose outbound internet access',
    ('vpc', 'internet gateway'):            'IGW creation fails - new VPCs cannot reach the internet',
    ('vpc', 'security group'):              'Security group creation fails - new service deployments blocked',
    ('vpc', 'subnets per vpc'):             'Subnet creation fails - VPC expansion blocked',
    # Lambda
    ('lambda', 'concurrent execution'):     'Lambda throttling - API responses fail and event processing stalls',
    ('lambda', 'function'):                 'No new Lambda functions can be deployed',
    # RDS
    ('rds', 'db instance'):                 'RDS creation fails - new databases and failover replicas cannot be provisioned',
    ('rds', 'db cluster'):                  'Aurora cluster creation fails - multi-AZ and read replica provisioning blocked',
    # ELB
    ('elasticloadbalancing', 'application load balancer'): 'ALB creation fails - new service endpoints cannot be deployed',
    ('elasticloadbalancing', 'network load balancer'):     'NLB creation fails - new service endpoints cannot be deployed',
    ('elasticloadbalancing', 'target group'):              'Target group exhausted - ALB routing capacity full',
    # ECS
    ('ecs', 'task'):                        'ECS task scaling fails - container capacity capped',
    ('ecs', 'service'):                     'No new ECS services can be created in this cluster',
    # EKS
    ('eks', 'cluster'):                     'No new EKS clusters can be created - new environment provisioning blocked',
    # IAM
    ('iam', 'role'):                        'IAM role creation fails - new service accounts and application deployments blocked',
    ('iam', 'polic'):                       'IAM policy creation fails - permission management blocked',
    # SQS
    ('sqs', 'queue'):                       'SQS queue creation fails - new messaging pipelines blocked',
    # SNS
    ('sns', 'topic'):                       'SNS topic creation fails - notification pipelines blocked',
    # DynamoDB
    ('dynamodb', 'table'):                  'DynamoDB table creation fails - new data stores cannot be provisioned',
    # Kinesis
    ('kinesis', 'shard'):                   'Kinesis shard limit reached - stream scaling and data ingestion blocked',
    # Firehose
    ('firehose', 'delivery stream'):        'Firehose delivery stream creation fails - data delivery pipelines blocked',
    # S3
    ('s3', 'bucket'):                       'S3 bucket creation fails - new storage locations blocked',
}

_SERVICE_FALLBACK: dict[str, str] = {
    'ec2':                  'EC2 capacity or feature limit - instance operations may fail',
    'vpc':                  'VPC resource limit - network provisioning may fail',
    'lambda':               'Lambda limit - function invocations or deployments may be affected',
    'rds':                  'RDS limit - database provisioning or scaling may fail',
    'elasticloadbalancing': 'ELB limit - load balancer or target group operations may fail',
    'ecs':                  'ECS limit - container task or service operations may fail',
    'eks':                  'EKS limit - cluster operations may fail',
    'iam':                  'IAM limit - role or policy creation may fail',
    'sqs':                  'SQS limit - queue operations may fail',
    'sns':                  'SNS limit - topic or subscription operations may fail',
    'dynamodb':             'DynamoDB limit - table operations may fail',
    'kinesis':              'Kinesis limit - stream operations may fail',
    'firehose':             'Firehose limit - delivery stream operations may fail',
    's3':                   'S3 limit - bucket operations may fail',
}


def _impact(service_code: str, quota_name: str) -> str:
    """Return a production-impact description for a quota approaching its limit."""
    name_lower = quota_name.lower()
    for (svc, keyword), msg in _IMPACT_HINTS.items():
        if svc == service_code and keyword in name_lower:
            return msg
    return _SERVICE_FALLBACK.get(service_code, 'Service limit reached - operations may be affected')


def _get_usage_value(cw, usage_metric: dict, now: datetime) -> float | None:
    """Fetch current utilization from the exact CloudWatch metric the quota declares.

    The Service Quotas API embeds the authoritative metric coordinates in the
    UsageMetric field of each quota object — namespace, metric name, dimensions,
    and recommended statistic.  Using these directly avoids the speculative
    list_metrics calls that the previous approach required per quota.

    EndpointConnectionError is intentionally NOT caught here so the caller can
    skip the entire region when CloudWatch is unreachable.
    """
    dims = [
        {'Name': k, 'Value': v}
        for k, v in usage_metric.get('MetricDimensions', {}).items()
    ]
    stat = usage_metric.get('MetricStatisticRecommendation', 'Maximum')
    try:
        resp = cw.get_metric_statistics(
            Namespace=usage_metric['MetricNamespace'],
            MetricName=usage_metric['MetricName'],
            Dimensions=dims,
            StartTime=now - timedelta(hours=1),
            EndTime=now,
            Period=3600,
            Statistics=[stat],
        )
    except ClientError:
        return None
    datapoints = resp.get('Datapoints', [])
    if not datapoints:
        return None
    return max(dp[stat] for dp in datapoints)


def make_scan(warn_threshold: float, critical_threshold: float):
    def scan(sess, account_id: str, region: str, writer) -> None:
        sq = sess.client('service-quotas', region_name=region)
        cw = sess.client('cloudwatch', region_name=region)
        now = datetime.now(timezone.utc)

        for service_code in DEFAULT_SERVICES:
            try:
                paginator = sq.get_paginator('list_service_quotas')
                quotas = [
                    q
                    for page in paginator.paginate(ServiceCode=service_code)
                    for q in page.get('Quotas', [])
                ]
            except ClientError as exc:
                code = exc.response['Error']['Code']
                if session.is_skippable(exc) or code == 'NoSuchResourceException':
                    # NoSuchResourceException is expected for global services (e.g. iam)
                    # queried against a regional endpoint — not a real error.
                    log.debug('%s/%s service-quotas skipped for %s — %s',
                              account_id, region, service_code, code)
                    continue
                if code == 'InvalidPaginationTokenException':
                    log.warning('%s/%s list_service_quotas pagination token expired for %s '
                                '— results may be incomplete', account_id, region, service_code)
                    continue
                log.warning('%s/%s list_service_quotas failed for %s: %s',
                            account_id, region, service_code, exc)
                continue

            for quota in quotas:
                quota_value = quota.get('Value')
                if not quota_value:
                    continue

                # Service Quotas embeds the authoritative CW metric in UsageMetric
                # when one exists. Quotas without it have no live utilization data
                # (task 49 covers static-limit quotas separately).
                usage_metric = quota.get('UsageMetric')
                if not usage_metric:
                    continue

                quota_name = quota.get('QuotaName', '')
                quota_code = quota.get('QuotaCode', '')

                try:
                    current_value = _get_usage_value(cw, usage_metric, now)
                except EndpointConnectionError:
                    log.warning('%s/%s CloudWatch endpoint unreachable — skipping region',
                                account_id, region)
                    return
                if current_value is None:
                    continue

                utilization_pct = (current_value / quota_value) * 100

                if utilization_pct < warn_threshold:
                    continue

                if utilization_pct >= critical_threshold:
                    severity = 'critical'
                    finding = 'quota-at-80pct'
                else:
                    severity = 'warning'
                    finding = 'quota-at-70pct'

                writer.write(
                    account_id=account_id,
                    region=region,
                    resource_id=f"{service_code}/{quota_name}",
                    resource_type='Service Quota',
                    finding=finding,
                    detail=(
                        f"Service={service_code} Quota='{quota_name}' "
                        f"Current={current_value:.0f} Limit={quota_value:.0f} "
                        f"Utilization={utilization_pct:.1f}%"
                    ),
                    estimated_monthly_savings_usd=0,
                    tags=None,
                    service_code=service_code,
                    quota_name=quota_name,
                    quota_code=quota_code,
                    current_value=f"{current_value:.0f}",
                    quota_limit=f"{quota_value:.0f}",
                    utilization_pct=f"{utilization_pct:.1f}",
                    severity=severity,
                    production_impact=_impact(service_code, quota_name),
                )

    return scan


def main() -> None:
    parser = cli.make_parser(__doc__)
    parser.add_argument(
        '--warn-threshold', type=float, default=WARN_THRESHOLD_DEFAULT,
        help=f'Utilization %% to flag as warning (default: {WARN_THRESHOLD_DEFAULT})',
    )
    parser.add_argument(
        '--critical-threshold', type=float, default=CRITICAL_THRESHOLD_DEFAULT,
        help=f'Utilization %% to flag as critical (default: {CRITICAL_THRESHOLD_DEFAULT})',
    )
    args = parser.parse_args()
    cli.run(
        args, SCRIPT_NAME,
        make_scan(args.warn_threshold, args.critical_threshold),
        extra_fields=EXTRA_FIELDS,
    )


if __name__ == '__main__':
    main()
