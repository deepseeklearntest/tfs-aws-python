#!/usr/bin/env python3
"""Task 34 — KMS Key Rotation Disabled

Finds customer-managed KMS symmetric keys that do not have automatic annual
key rotation enabled. Asymmetric keys and AWS-managed keys are skipped as
they are ineligible for automatic rotation. Keys that are not in the Enabled
state are also skipped.

Run: python 34_detect_kms_rotation_disabled.py --accounts 123456789012,234567890123
"""
from __future__ import annotations

import logging
import sys
from datetime import date, timezone
from pathlib import Path

from botocore.exceptions import ClientError

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from common import cli, session

SCRIPT_NAME = '34_detect_kms_rotation_disabled'
EXTRA_FIELDS = [
    'key_alias', 'key_manager', 'key_state', 'key_spec',
    'created_date', 'days_since_creation', 'description',
    'protects', 'priority',
]

log = logging.getLogger(SCRIPT_NAME)

# (label, keyword_set) pairs checked in order; first match wins.
# Ordered high-value -> low-value so priority reflects what breaks most if key is compromised.
_PROTECTS_MAP: list[tuple[str, set[str]]] = [
    ('RDS database',      {'rds', 'database', 'db', 'postgres', 'mysql', 'aurora', 'mariadb'}),
    ('Secrets Manager',   {'secret', 'secrets', 'secretsmanager'}),
    ('S3 bucket',         {'s3', 'bucket'}),
    ('EKS / Kubernetes',  {'eks', 'kubernetes', 'k8s'}),
    ('SSM parameters',    {'ssm', 'parameter', 'parameterstore'}),
    ('ECR images',        {'ecr', 'container', 'registry'}),
    ('DynamoDB table',    {'dynamo', 'dynamodb'}),
    ('Lambda',            {'lambda'}),
    ('SQS / SNS',         {'sqs', 'sns', 'queue', 'topic'}),
    ('EBS volume',        {'ebs', 'volume', 'snapshot'}),
    ('Backup',            {'backup', 'restore'}),
]

_HIGH_ENV_KEYWORDS = {'prod', 'production', 'prd', 'live'}
_LOW_ENV_KEYWORDS  = {'dev', 'development', 'test', 'staging', 'stage', 'qa', 'uat', 'sandbox', 'nonprod', 'non-prod'}


def _classify_key(alias: str, description: str) -> tuple[str, str]:
    """Return (protects_label, priority) by inspecting alias and description text."""
    combined = (alias + ' ' + description).lower()
    tokens = set(combined.replace('-', ' ').replace('_', ' ').replace('/', ' ').split())

    protects = 'unknown'
    for label, keywords in _PROTECTS_MAP:
        if tokens & keywords:
            protects = label
            break

    # Priority: high if prod environment OR protects a critical resource
    # Low if clearly non-prod. Medium otherwise.
    if tokens & _HIGH_ENV_KEYWORDS or protects in {'RDS database', 'Secrets Manager', 'S3 bucket', 'EKS / Kubernetes'}:
        priority = 'high'
    elif tokens & _LOW_ENV_KEYWORDS:
        priority = 'low'
    else:
        priority = 'medium'

    return protects, priority


def _build_alias_map(kms) -> dict[str, str]:
    """Return {TargetKeyId: AliasName} for all aliases in the region."""
    alias_map: dict[str, str] = {}
    try:
        paginator = kms.get_paginator('list_aliases')
        for page in paginator.paginate():
            for alias in page.get('Aliases', []):
                target = alias.get('TargetKeyId')
                name = alias.get('AliasName', '')
                if target:
                    # Prefer the first non-aws/ alias if multiple exist
                    if target not in alias_map or alias_map[target].startswith('alias/aws/'):
                        alias_map[target] = name
    except ClientError as exc:
        log.warning("list_aliases failed: %s", exc)
    return alias_map


def scan(sess, account_id: str, region: str, writer) -> None:
    kms = sess.client('kms', region_name=region)

    try:
        alias_map = _build_alias_map(kms)

        paginator = kms.get_paginator('list_keys')
        keys: list[dict] = []
        for page in paginator.paginate():
            keys.extend(page.get('Keys', []))
    except ClientError as exc:
        if session.is_skippable(exc):
            log.warning("%s/%s: skipped — %s", account_id, region, exc.response['Error']['Code'])
            return
        raise

    for key_entry in keys:
        key_id = key_entry['KeyId']
        key_arn = key_entry['KeyArn']

        # Fetch key metadata
        try:
            meta_resp = kms.describe_key(KeyId=key_id)
        except ClientError as exc:
            if session.is_skippable(exc):
                log.debug("describe_key skipped for %s: %s", key_id, exc.response['Error']['Code'])
                continue
            raise
        meta = meta_resp['KeyMetadata']

        # Only check customer-managed keys
        if meta.get('KeyManager') != 'CUSTOMER':
            continue

        key_state = meta.get('KeyState', '')
        key_spec = meta.get('KeySpec', '')

        # Only check enabled symmetric keys
        if key_state != 'Enabled':
            continue
        if key_spec != 'SYMMETRIC_DEFAULT':
            continue

        # Check rotation status
        try:
            rotation_resp = kms.get_key_rotation_status(KeyId=key_id)
            rotation_enabled = rotation_resp.get('KeyRotationEnabled', False)
        except ClientError as exc:
            if session.is_skippable(exc):
                log.debug("get_key_rotation_status skipped for %s: %s", key_id, exc.response['Error']['Code'])
                continue
            raise

        if rotation_enabled:
            continue

        key_alias = alias_map.get(key_id, '')
        key_description = meta.get('Description', '')
        created_date = meta.get('CreationDate')
        created_str = created_date.isoformat() if created_date else ''
        days_since_creation = (
            (date.today() - created_date.astimezone(timezone.utc).date()).days
            if created_date else ''
        )
        protects, priority = _classify_key(key_alias, key_description)

        writer.write(
            account_id=account_id,
            region=region,
            resource_id=key_arn,
            resource_type='KMS Key',
            finding='key-rotation-disabled',
            detail=(
                f"Alias={key_alias or '(none)'} "
                f"Protects={protects} "
                f"Priority={priority} "
                f"Created={created_str} "
                f"AgeDays={days_since_creation}"
            ),
            estimated_monthly_savings_usd=0,
            tags=meta.get('Tags'),
            key_alias=key_alias,
            key_manager=meta.get('KeyManager', ''),
            key_state=key_state,
            key_spec=key_spec,
            created_date=created_str,
            days_since_creation=days_since_creation,
            description=key_description,
            protects=protects,
            priority=priority,
        )


def main() -> None:
    parser = cli.make_parser(__doc__)
    args = parser.parse_args()
    cli.run(args, SCRIPT_NAME, scan, extra_fields=EXTRA_FIELDS)


if __name__ == '__main__':
    main()
