#!/usr/bin/env python3
"""Task 43 — Tagging Compliance

Identifies AWS resources missing mandatory organisational tags using the
Resource Groups Tagging API. Produces two finding types per resource:

  missing-required-tags  — one or more required tags absent entirely
  inconsistent-tag-key   — required tag present but under a non-canonical key
                           (case variant or defined alias)

Mandatory tags: costcenter, environment, application_owner, application

Parallelism strategy
--------------------
The Tagging API's pagination token has a ~15-minute TTL. In large regions
(e.g. us-east-1) a full-region scan can outlast that window, giving silently
incomplete results. To avoid this, the region is split into disjoint
*resource-type shards*. Each shard is a separate paginator with its own
independent token TTL, and all shards run as flat work units in the shared
thread pool (bounded by --workers). No nested pools, no thread explosion.

Recommendation: use --workers >= 8 for full multi-account runs so shards
within a region can run concurrently with shards in other accounts/regions.

Run: python 43_detect_tagging_compliance.py --accounts 123456789012,234567890123
"""
from __future__ import annotations

import logging
import sys
from pathlib import Path

from botocore.exceptions import ClientError

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from common import cli, session  # truststore.inject_into_ssl() runs here
from common import tags as tagutil  # stdlib-only, safe at any import position

import botocore.config  # must come AFTER truststore injection — botocore.config
                        # transitively loads botocore.httpsession + urllib3 + ssl;
                        # importing it before injection causes ssl.SSLContext's
                        # options setter to recurse infinitely (Python 3.11 + truststore)

SCRIPT_NAME = '43_detect_tagging_compliance'
REQUIRED_TAGS = ['costcenter', 'environment', 'application_owner', 'application']
EXTRA_FIELDS = ['missing_tags', 'present_tags', 'missing_count', 'total_tag_count', 'inconsistent_keys']

# Aliases for required tags — PascalCase/legacy variants that satisfy the requirement
# but should be flagged as inconsistent-tag-key for remediation.
# Expand this dict as new naming patterns are discovered across accounts.
TAG_ALIASES: dict[str, set[str]] = {
    'costcenter':       {'CostCenter', 'cost_center', 'cost-center'},
    'application_owner': {'Owner', 'owner', 'resource_owner', 'team_owner'},
    'application':      {'Application', 'app_name', 'application_name'},
    'environment':      {'Environment', 'env'},
}

# Infrastructure primitives — not customer-owned, never tagged.
# Kept as a Python-side post-filter because ResourceTypeFilters narrows the API
# request but some primitives can still appear in results for certain filter
# combinations (e.g. querying ec2 broadly).
EXCLUDED_RESOURCE_TYPES = {
    'ec2:network-interface',
    'ec2:security-group',
    'ec2:subnet',
    'ec2:vpc',
    'ec2:route-table',
    'ec2:internet-gateway',
    'ec2:egress-only-internet-gateway',
    'ec2:dhcp-options',
    'ec2:network-acl',
    'ec2:key-pair',
    'ec2:snapshot',
    'ec2:prefix-list',
    'ec2:spot-instances-request',
}

# Tag-key prefixes that mark resources managed by a controller and org-tagged at
# the parent level (ASG / EKS nodegroup / Beanstalk env / CloudFormation stack).
# Flagging these as missing tags is noise — the obligation sits on the parent.
# Verified against current AWS/k8s tagging conventions: 2026-06-02.
# Expand this tuple as new managed-fleet patterns are discovered.
MANAGED_TAG_KEY_PREFIXES = (
    'aws:',               # AWS-managed: ASG (aws:autoscaling:groupName), CFN, aws:eks:*, EB
    'eks:',               # EKS cluster/nodegroup instance markers
    'kubernetes.io/',     # k8s controller-managed: worker nodes, EBS volumes, ELBs
    'k8s.io/',            # older k8s controller convention
    'alpha.eksctl.io/',   # eksctl-provisioned resources
    'elasticbeanstalk:',  # Beanstalk-managed EC2 instances and related resources
)

# ---------------------------------------------------------------------------
# Resource-type shards
# ---------------------------------------------------------------------------
# Each inner list is a disjoint set of ResourceTypeFilter values passed to the
# Tagging API paginator. Shards are disjoint by construction: no resource type
# appears in more than one shard, so no ARN can produce duplicate findings.
#
# Grouping rationale:
#   - EC2 customer resources that carry org-tagging obligations are listed
#     explicitly, omitting infrastructure primitives (those still handled by
#     EXCLUDED_RESOURCE_TYPES above as a belt-and-suspenders check).
#   - S3 has its own shard; large accounts can have thousands of buckets.
#   - Data / analytics services grouped by rough volume similarity.
#   - Management / security / integration services in the final shard.
#
# Last verified against AWS Resource Groups Tagging API supported types: 2026-06-03.
# Review when new services are onboarded or this list is revisited.
RESOURCE_TYPE_SHARDS: list[list[str]] = [
    # Shard 0 — EC2 customer resources (excludes infrastructure primitives)
    [
        'ec2:instance',
        'ec2:volume',
        'ec2:elastic-ip',
        'ec2:natgateway',
        'ec2:capacity-reservation',
        'ec2:dedicated-host',
        'ec2:fleet',
        'ec2:fpga-image',
        'ec2:image',
        'ec2:launch-template',
        'ec2:placement-group',
        'ec2:reserved-instances',
        'ec2:spot-fleet-request',
        'ec2:transit-gateway',
        'ec2:transit-gateway-attachment',
        'ec2:transit-gateway-route-table',
        'ec2:vpn-connection',
        'ec2:vpn-gateway',
        'ec2:vpc-endpoint',
        'ec2:vpc-endpoint-service',
        'ec2:vpc-peering-connection',
        'ec2:verified-access-endpoint',
        'ec2:verified-access-group',
        'ec2:verified-access-instance',
    ],
    # Shard 1 — S3 (standalone; large accounts may have thousands of buckets)
    [
        's3',
    ],
    # Shard 2 — Compute / containers
    [
        'lambda:function',
        'ecs:cluster',
        'ecs:service',
        'ecs:task-definition',
        'eks:cluster',
        'eks:nodegroup',
        'eks:addon',
        'eks:fargateprofile',
        'ecr:repository',
        'batch:compute-environment',
        'batch:job-definition',
        'batch:job-queue',
        'lightsail:instance',
        'apprunner:service',
    ],
    # Shard 3 — Databases
    [
        'rds:db',
        'rds:cluster',
        'rds:snapshot',
        'rds:cluster-snapshot',
        'rds:subgrp',
        'rds:pg',
        'rds:cluster-pg',
        'rds:og',
        'rds:proxy',
        'elasticache:cluster',
        'elasticache:replicationgroup',
        'elasticache:subnetgroup',
        'elasticache:snapshot',
        'redshift:cluster',
        'redshift:snapshot',
        'redshift:subnetgroup',
        'redshift:parametergroup',
        'dynamodb:table',
        'dax:cluster',

        'timestream:database',
        'timestream:table',
        'cassandra:keyspace',
        'cassandra:table',
        'qldb:ledger',
    ],
    # Shard 4 — Storage / file systems
    [
        'elasticfilesystem:file-system',
        'elasticfilesystem:access-point',
        'fsx:file-system',
        'fsx:volume',
        'backup:backup-vault',
        'backup:backup-plan',
        'storagegateway:gateway',
        'ds:directory',
        'transfer:server',
        'datasync:task',
        'datasync:location',
        'snow-device-management:managed-device',
    ],
    # Shard 5 — Networking / content delivery
    [
        'elasticloadbalancing:loadbalancer',
        'elasticloadbalancing:targetgroup',
        'cloudfront:distribution',
        'cloudfront:streaming-distribution',
        'route53:hostedzone',
        'route53resolver:resolver-rule',
        'route53resolver:resolver-endpoint',
        'globalaccelerator:accelerator',
        'wafv2:webacl',
        'wafv2:ipset',
        'wafv2:regexpatternset',
        'wafv2:rulegroup',
        'shield:protection',
        'directconnect:dxcon',
        'directconnect:dxlag',
        'directconnect:dxvif',
        'networkmanager:global-network',
        'networkmanager:device',
        'networkmanager:site',
    ],
    # Shard 6 — Integration / messaging / events
    [
        'sns:topic',
        'sqs:queue',
        'events:rule',
        'events:event-bus',
        'schemas:registry',
        'pipes:pipe',
        'kinesis:stream',
        'firehose:deliverystream',
        'kafka:cluster',
        'mq:broker',
        'apigateway:restapis',
        'apigateway:stages',
        'states:stateMachine',
        'states:activity',
        'scheduler:schedule',
        'scheduler:schedule-group',
    ],
    # Shard 7 — Security / identity / secrets
    [
        'kms:key',
        'secretsmanager:secret',
        'acm:certificate',
        'acm-pca:certificate-authority',
        'iam:role',
        'iam:policy',
        'iam:instance-profile',
        'cognito-idp:userpool',
        'cognito-identity:identitypool',
        'sso:permissionSet',
        'ssm:parameter',
        'ssm:document',
        'ssm:patchbaseline',
        'ssm:maintenancewindow',
        'ssm:opsmetadata',
        'config:config-rule',
        'config:conformance-pack',
        'guardduty:detector',
        'inspector2:filter',
        'securityhub:hub',
        'detective:graph',
        'macie2:custom-data-identifier',
        'access-analyzer:analyzer',
    ],
    # Shard 8 — Analytics / ML / developer tools
    [
        'glue:database',
        'glue:table',
        'glue:trigger',
        'glue:workflow',
        'glue:crawler',
        'glue:job',
        'athena:workgroup',
        'athena:data-catalog',
        'elasticmapreduce:cluster',
        'es:domain',
        'quicksight:dashboard',
        'quicksight:dataset',
        'databrew:dataset',
        'databrew:project',
        'databrew:recipe',
        'sagemaker:notebook-instance',
        'sagemaker:training-job',
        'sagemaker:model',
        'sagemaker:endpoint',
        'sagemaker:endpoint-config',
        'sagemaker:domain',
        'sagemaker:pipeline',
        'sagemaker:experiment',
    ],
    # Shard 9 — Management / logging / developer experience
    [
        'logs:log-group',
        'cloudwatch:alarm',
        'cloudwatch:composite-alarm',
        'applicationinsights:application',
        'synthetics:canary',
        'xray:group',
        'cloudformation:stack',
        'servicecatalog:portfolio',
        'servicecatalog:product',
        'codecommit:repository',
        'codebuild:project',
        'codepipeline:pipeline',
        'codedeploy:application',
        'codedeploy:deploymentgroup',
        'codeartifact:domain',
        'codeartifact:repository',
        'amplify:apps',
        'amplify:branches',
        'elastic-inference:accelerator',
        'iot:thing',
        'iot:thinggroup',
        'iot:topicrule',
        'greengrass:group',
        'iot1click:placement',
        'iot1click:project',
    ],
]

# Retry config for the Tagging API client — adaptive mode backs off gracefully
# when many shards run concurrently against the same account endpoint.
_RETRY_CFG = botocore.config.Config(retries={'max_attempts': 8, 'mode': 'adaptive'})

log = logging.getLogger(SCRIPT_NAME)

# Pre-compute reverse alias lookup: normalized_alias -> canonical name.
# Normalized (not just lowercased) via tagutil.normalize_key so separator
# variants (e.g. 'cost center', 'cost-center') also resolve to the same
# canonical name as their listed alias.
_ALIAS_LOOKUP: dict[str, str] = {}
for _canonical, _aliases in TAG_ALIASES.items():
    for _alias in _aliases:
        _ALIAS_LOOKUP[tagutil.normalize_key(_alias)] = _canonical


def _name_from_arn(arn: str) -> str:
    # arn:aws:lambda:us-east-1:123:function:my-function  -> my-function
    # arn:aws:ec2:us-east-1:123:instance/i-abc123        -> i-abc123
    last = arn.rsplit(':', 1)[-1]
    return last.rsplit('/', 1)[-1]


def _resolve_tags(tags: list) -> tuple[list[str], list[tuple[str, str]]]:
    """Classify required tags against a resource's actual tag set.

    Returns:
        missing      — canonical names with no match (exact, case variant, or alias)
        inconsistent — (canonical, actual_key) pairs where the tag was found under
                       a non-canonical key (case variant or alias)
    """
    # Build map: normalized_actual_key -> actual_key (only tags with non-empty
    # values). Normalized via tagutil.normalize_key (case + separator
    # insensitive) since real tag keys mix spaces/dashes/underscores for the
    # same concept (e.g. 'cost center', 'CostCenter', 'costcenter').
    norm_to_actual: dict[str, str] = {
        tagutil.normalize_key(t['Key']): t['Key']
        for t in tags
        if t['Key'] and t['Value'].strip()
    }
    exact_keys = {t['Key'] for t in tags if t['Key'] and t['Value'].strip()}

    missing: list[str] = []
    inconsistent: list[tuple[str, str]] = []

    for canonical in REQUIRED_TAGS:
        if canonical in exact_keys:
            # Exact canonical match — fully compliant, nothing to report.
            continue

        canonical_norm = tagutil.normalize_key(canonical)

        if canonical_norm in norm_to_actual:
            # Case/separator variant (e.g. 'cost center' found for 'costcenter').
            inconsistent.append((canonical, norm_to_actual[canonical_norm]))
            continue

        # Check explicit aliases.
        found_alias: str | None = None
        for alias_norm, alias_canonical in _ALIAS_LOOKUP.items():
            if alias_canonical == canonical and alias_norm in norm_to_actual:
                found_alias = norm_to_actual[alias_norm]
                break

        if found_alias is not None:
            inconsistent.append((canonical, found_alias))
        else:
            missing.append(canonical)

    return missing, inconsistent


def scan(sess, account_id: str, region: str, shard: list[str], writer) -> None:
    """Scan one resource-type shard in one account/region for tagging compliance.

    Each call paginates only the resource types listed in `shard`, giving it
    its own independent Tagging API pagination token (own 15-min TTL). All
    shards for a region are submitted as flat work units to the shared thread
    pool — no nested pools, concurrency stays bounded by --workers.
    """
    tagging = sess.client('resourcegroupstaggingapi', region_name=region, config=_RETRY_CFG)
    shard_label = ','.join(shard[:3]) + (',...' if len(shard) > 3 else '')
    try:
        paginator = tagging.get_paginator('get_resources')
        for page in paginator.paginate(ResourceTypeFilters=shard):
            for resource in page.get('ResourceTagMappingList', []):
                resource_type = resource.get('ResourceType', '')

                # Layer 1: drop infrastructure primitives (belt-and-suspenders —
                # ResourceTypeFilters already narrows what the API returns, but
                # some primitives can still appear in broad filter responses).
                if resource_type in EXCLUDED_RESOURCE_TYPES:
                    continue

                tags = resource.get('Tags', [])

                # Layer 2: drop resources managed by a controller (ASG, EKS
                # nodegroup, eksctl, Beanstalk, CloudFormation, etc.). These
                # are org-tagged at the parent level, not individually.
                if any(t['Key'].startswith(MANAGED_TAG_KEY_PREFIXES) for t in tags):
                    continue

                missing, inconsistent = _resolve_tags(tags)

                if not missing and not inconsistent:
                    continue

                arn = resource['ResourceARN']
                name = _name_from_arn(arn)
                total_tag_count = str(len(tags))

                # Canonical names satisfied exactly, via case variant, or via alias.
                present = [t for t in REQUIRED_TAGS if t not in missing]

                def _base_write(finding, detail, **extra):
                    kwargs = dict(
                        account_id=account_id,
                        region=region,
                        resource_id=arn,
                        resource_type=resource_type,
                        finding=finding,
                        detail=detail,
                        estimated_monthly_savings_usd=0,
                        tags=tags,
                        missing_tags='',
                        present_tags=', '.join(present),
                        missing_count='',
                        total_tag_count=total_tag_count,
                        inconsistent_keys='',
                    )
                    kwargs.update(extra)
                    writer.write(**kwargs)

                if missing:
                    _base_write(
                        'missing-required-tags',
                        f"Missing: {', '.join(missing)} "
                        f"({len(missing)}/{len(REQUIRED_TAGS)} required tags absent) — {name}",
                        missing_tags=', '.join(missing),
                        missing_count=str(len(missing)),
                    )

                if inconsistent:
                    parts = [f"{actual}->{canonical}" for canonical, actual in inconsistent]
                    _base_write(
                        'inconsistent-tag-key',
                        f"Non-canonical keys: {', '.join(parts)} — {name}",
                        inconsistent_keys=', '.join(parts),
                    )

    except ClientError as exc:
        code = exc.response['Error']['Code']
        if code == 'PaginationTokenExpiredException':
            # Safety-net: with per-shard tokens this should be rare, but very
            # large shards on huge accounts could still hit the limit. Findings
            # collected before expiry are already written.
            log.warning(
                "%s/%s shard [%s]: pagination token expired — "
                "results for this shard may be incomplete",
                account_id, region, shard_label,
            )
            return
        if session.is_skippable(exc):
            log.warning("%s/%s shard [%s]: skipped — %s",
                        account_id, region, shard_label, code)
            return
        raise


def _shard_expander(task: tuple) -> list[tuple]:
    """Expand one (sess, account_id, region) base task into per-shard tuples.

    Shards are disjoint by construction (each resource type appears in exactly
    one shard), so no ARN can appear in two shards and produce duplicate findings.
    """
    sess, account_id, region = task
    return [(sess, account_id, region, shard) for shard in RESOURCE_TYPE_SHARDS]


def main() -> None:
    parser = cli.make_parser(__doc__)
    args = parser.parse_args()
    cli.run(
        args, SCRIPT_NAME, scan,
        extra_fields=EXTRA_FIELDS,
        task_expander=_shard_expander,
    )


if __name__ == '__main__':
    main()
