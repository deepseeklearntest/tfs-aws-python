#!/usr/bin/env python3
"""Task 37 — IAM Roles with Wildcard Policies or Unused >90 Days

Account-level scan (IAM is global).  Detects two classes of risk:

1. Wildcard policies — any attached or inline policy whose statements grant
   Action:* AND Resource:* (over-privileged roles).

2. Unused roles — roles whose RoleLastUsed.LastUsedDate is absent (never used)
   or older than 90 days (stale credentials surface area).

Run: python 37_detect_iam_risky_roles.py --accounts 123456789012,234567890123
"""
from __future__ import annotations

import logging
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

from botocore.exceptions import ClientError

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from common import cli, session

SCRIPT_NAME = '37_detect_iam_risky_roles'
EXTRA_FIELDS = [
    'role_name',
    'role_path',
    'finding_type',
    'policy_name',
    'policy_type',
    'policy_arn',
    'last_used_date',
    'days_unused',
    'role_created_date',
    'permission_boundary_arn',
    'trust_principal',
]
UNUSED_THRESHOLD_DAYS = 90

log = logging.getLogger(SCRIPT_NAME)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_trust_principals(assume_role_policy_doc: dict) -> str:
    principals = []
    for stmt in assume_role_policy_doc.get('Statement', []):
        principal = stmt.get('Principal', '')
        if isinstance(principal, str):
            principals.append(principal)
        elif isinstance(principal, dict):
            for vals in principal.values():
                if isinstance(vals, list):
                    principals.extend(vals)
                else:
                    principals.append(str(vals))
    return ', '.join(sorted(set(principals)))


def _has_wildcard_statement(policy_doc: dict) -> tuple[bool, str]:
    """
    Return (True, statement_summary) if any statement in the policy document
    grants Action:* (or contains '*') and Resource:* (or contains '*').
    Returns (False, '') otherwise.
    """
    statements = policy_doc.get('Statement', [])
    if isinstance(statements, dict):
        statements = [statements]

    for stmt in statements:
        if stmt.get('Effect', '').upper() != 'ALLOW':
            continue

        actions = stmt.get('Action', [])
        if isinstance(actions, str):
            actions = [actions]
        resources = stmt.get('Resource', [])
        if isinstance(resources, str):
            resources = [resources]

        action_wildcard = actions == ['*'] or '*' in actions
        resource_wildcard = resources == ['*'] or '*' in resources

        if action_wildcard and resource_wildcard:
            summary = f"Action={actions} Resource={resources}"
            return True, summary

    return False, ''


# ---------------------------------------------------------------------------
# Wildcard-policy helpers
# ---------------------------------------------------------------------------

def _check_attached_policies(iam, role_name: str, role_arn: str,
                              account_id: str, writer, role_path: str,
                              role_created_date: str, permission_boundary_arn: str,
                              trust_principal: str) -> None:
    """Inspect all managed policies attached to a role for wildcard statements."""
    try:
        paginator = iam.get_paginator('list_attached_role_policies')
        for page in paginator.paginate(RoleName=role_name):
            for policy in page.get('AttachedPolicies', []):
                policy_arn = policy['PolicyArn']
                policy_name = policy['PolicyName']
                try:
                    version_id = iam.get_policy(PolicyArn=policy_arn)['Policy']['DefaultVersionId']
                    doc = iam.get_policy_version(
                        PolicyArn=policy_arn, VersionId=version_id
                    )['PolicyVersion']['Document']
                    found, stmt_summary = _has_wildcard_statement(doc)
                    if found:
                        writer.write(
                            account_id=account_id,
                            region='global',
                            resource_id=role_arn,
                            resource_type='IAM Role',
                            finding='wildcard-policy',
                            detail=(
                                f"Managed policy '{policy_name}' grants Action:* Resource:*  "
                                f"Statement: {stmt_summary}"
                            ),
                            estimated_monthly_savings_usd=0,
                            tags=None,
                            role_name=role_name,
                            role_path=role_path,
                            finding_type='wildcard-policy',
                            policy_name=policy_name,
                            policy_type='managed',
                            policy_arn=policy_arn,
                            last_used_date='',
                            days_unused='',
                            role_created_date=role_created_date,
                            permission_boundary_arn=permission_boundary_arn,
                            trust_principal=trust_principal,
                        )
                except ClientError as exc:
                    code = exc.response['Error']['Code']
                    if session.is_skippable(exc):
                        log.debug("Role %s policy %s: skipped — %s", role_name, policy_name, code)
                    else:
                        log.warning("Role %s policy %s: error — %s", role_name, policy_name, exc)
    except ClientError as exc:
        code = exc.response['Error']['Code']
        if session.is_skippable(exc):
            log.debug("Role %s list_attached_role_policies: skipped — %s", role_name, code)
        else:
            log.warning("Role %s list_attached_role_policies: error — %s", role_name, exc)


def _check_inline_policies(iam, role_name: str, role_arn: str,
                            account_id: str, writer, role_path: str,
                            role_created_date: str, permission_boundary_arn: str,
                            trust_principal: str) -> None:
    """Inspect all inline policies embedded directly on a role for wildcard statements."""
    try:
        paginator = iam.get_paginator('list_role_policies')
        for page in paginator.paginate(RoleName=role_name):
            for policy_name in page.get('PolicyNames', []):
                try:
                    doc = iam.get_role_policy(
                        RoleName=role_name, PolicyName=policy_name
                    )['PolicyDocument']
                    found, stmt_summary = _has_wildcard_statement(doc)
                    if found:
                        writer.write(
                            account_id=account_id,
                            region='global',
                            resource_id=role_arn,
                            resource_type='IAM Role',
                            finding='wildcard-policy',
                            detail=(
                                f"Inline policy '{policy_name}' grants Action:* Resource:*  "
                                f"Statement: {stmt_summary}"
                            ),
                            estimated_monthly_savings_usd=0,
                            tags=None,
                            role_name=role_name,
                            role_path=role_path,
                            finding_type='wildcard-policy',
                            policy_name=policy_name,
                            policy_type='inline',
                            policy_arn='',
                            last_used_date='',
                            days_unused='',
                            role_created_date=role_created_date,
                            permission_boundary_arn=permission_boundary_arn,
                            trust_principal=trust_principal,
                        )
                except ClientError as exc:
                    code = exc.response['Error']['Code']
                    if session.is_skippable(exc):
                        log.debug("Role %s inline policy %s: skipped — %s", role_name, policy_name, code)
                    else:
                        log.warning("Role %s inline policy %s: error — %s", role_name, policy_name, exc)
    except ClientError as exc:
        code = exc.response['Error']['Code']
        if session.is_skippable(exc):
            log.debug("Role %s list_role_policies: skipped — %s", role_name, code)
        else:
            log.warning("Role %s list_role_policies: error — %s", role_name, exc)


# ---------------------------------------------------------------------------
# Main scan
# ---------------------------------------------------------------------------

def scan(sess, account_id: str, writer) -> None:
    iam = sess.client('iam', region_name='us-east-1')
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=UNUSED_THRESHOLD_DAYS)

    try:
        paginator = iam.get_paginator('list_roles')
        for page in paginator.paginate():
            for role in page.get('Roles', []):
                role_name = role['RoleName']
                role_arn = role['Arn']
                role_path = role.get('Path', '/')
                role_created_date = str(role['CreateDate'].date())
                permission_boundary_arn = role.get('PermissionsBoundary', {}).get('PermissionsBoundaryArn', '')
                trust_principal = _extract_trust_principals(role.get('AssumeRolePolicyDocument', {}))

                # ---- 1. Wildcard policy check ----
                _check_attached_policies(iam, role_name, role_arn, account_id, writer, role_path,
                                         role_created_date, permission_boundary_arn, trust_principal)
                _check_inline_policies(iam, role_name, role_arn, account_id, writer, role_path,
                                       role_created_date, permission_boundary_arn, trust_principal)

                # ---- 2. Unused-role check ----
                role_last_used = role.get('RoleLastUsed', {})
                last_used_date = role_last_used.get('LastUsedDate')

                if last_used_date is None:
                    # Role has never been used
                    writer.write(
                        account_id=account_id,
                        region='global',
                        resource_id=role_arn,
                        resource_type='IAM Role',
                        finding='role-never-used',
                        detail=f"Role '{role_name}' has never been used",
                        estimated_monthly_savings_usd=0,
                        tags=None,
                        role_name=role_name,
                        role_path=role_path,
                        finding_type='unused-role',
                        policy_name='',
                        policy_type='',
                        policy_arn='',
                        last_used_date='never',
                        days_unused='',
                        role_created_date=role_created_date,
                        permission_boundary_arn=permission_boundary_arn,
                        trust_principal=trust_principal,
                    )
                elif last_used_date < cutoff:
                    days_unused = (now - last_used_date).days
                    writer.write(
                        account_id=account_id,
                        region='global',
                        resource_id=role_arn,
                        resource_type='IAM Role',
                        finding='unused-role-90d',
                        detail=(
                            f"Role '{role_name}' last used {last_used_date.date()} "
                            f"({days_unused} days ago)"
                        ),
                        estimated_monthly_savings_usd=0,
                        tags=None,
                        role_name=role_name,
                        role_path=role_path,
                        finding_type='unused-role',
                        policy_name='',
                        policy_type='',
                        policy_arn='',
                        last_used_date=str(last_used_date.date()),
                        days_unused=str(days_unused),
                        role_created_date=role_created_date,
                        permission_boundary_arn=permission_boundary_arn,
                        trust_principal=trust_principal,
                    )

    except ClientError as exc:
        if session.is_skippable(exc):
            log.warning("%s IAM list_roles: skipped — %s",
                        account_id, exc.response['Error']['Code'])
            return
        raise


def main() -> None:
    parser = cli.make_parser(__doc__, account_level=True)
    args = parser.parse_args()
    cli.run(args, SCRIPT_NAME, scan, extra_fields=EXTRA_FIELDS, account_level=True)


if __name__ == '__main__':
    main()
