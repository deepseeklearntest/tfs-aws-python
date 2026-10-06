#!/usr/bin/env python3
"""PPD-Era IAM Users Audit

Flags IAM users with native console access or long-lived access keys that
survived the Britive SSO migration (cutover: 2026-03-31).

Run: python ppd_era_iam_users.py --accounts 123456789012,234567890123
"""
from __future__ import annotations

import logging
import sys
from datetime import date, datetime, timezone
from pathlib import Path

from botocore.exceptions import ClientError

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from common import cli, session

SCRIPT_NAME = 'ppd_era_iam_users'
SSO_CUTOVER_DATE = date(2026, 3, 31)   # Britive SSO cutover -- end of March 2026
STALE_KEY_DAYS   = 90

EXTRA_FIELDS = [
    'username',
    'created_date',
    'era',
    'last_console_login',
    'days_since_console_login',
    'mfa_enabled',
    'key_id',
    'key_created',
    'key_last_used',
    'key_age_days',
    'account_alias',
]

log = logging.getLogger(SCRIPT_NAME)


def _fetch_account_alias(sess) -> str:
    try:
        iam = sess.client('iam', region_name='us-east-1')
        aliases = iam.list_account_aliases().get('AccountAliases', [])
        return aliases[0] if aliases else ''
    except ClientError:
        return ''


def _check_user(iam, user: dict, account_id: str, today: date, writer, account_alias: str = '') -> None:
    username        = user['UserName']
    user_arn        = user['Arn']
    created         = user['CreateDate'].date()
    era             = 'pre-sso' if created < SSO_CUTOVER_DATE else 'post-sso'
    pw_last_used    = user.get('PasswordLastUsed')
    last_console_login = str(pw_last_used.date()) if pw_last_used else 'never'
    days_since_console_login = str((today - pw_last_used.date()).days) if pw_last_used else ''

    # --- MFA status (fetched once, used for all findings on this user) ---
    try:
        mfa_devices = iam.list_mfa_devices(UserName=username)['MFADevices']
        mfa_enabled = 'true' if mfa_devices else 'false'
    except ClientError as exc:
        if session.is_skippable(exc):
            log.debug('%s list_mfa_devices %s: skipped -- %s',
                      account_id, username, exc.response['Error']['Code'])
        else:
            log.warning('%s list_mfa_devices %s: error -- %s', account_id, username, exc)
        mfa_enabled = 'unknown'

    # --- Console login profile ---
    try:
        iam.get_login_profile(UserName=username)
        finding = 'ppd-era-console' if era == 'pre-sso' else 'post-sso-console'
        writer.write(
            account_id=account_id,
            region='global',
            resource_id=user_arn,
            resource_type='IAM User',
            finding=finding,
            detail=f"User '{username}' has a native console login profile (created {created}, era={era})",
            estimated_monthly_savings_usd=0,
            tags=None,
            username=username,
            created_date=str(created),
            era=era,
            last_console_login=last_console_login,
            days_since_console_login=days_since_console_login,
            mfa_enabled=mfa_enabled,
            key_id='',
            key_created='',
            key_last_used='',
            key_age_days='',
            account_alias=account_alias,
        )
    except iam.exceptions.NoSuchEntityException:
        pass
    except ClientError as exc:
        if session.is_skippable(exc):
            log.debug('%s get_login_profile %s: skipped -- %s',
                      account_id, username, exc.response['Error']['Code'])
        else:
            log.warning('%s get_login_profile %s: error -- %s', account_id, username, exc)

    # --- Access keys ---
    try:
        keys = iam.list_access_keys(UserName=username)['AccessKeyMetadata']
    except ClientError as exc:
        if session.is_skippable(exc):
            log.warning('%s list_access_keys %s: skipped -- %s (key findings incomplete)',
                        account_id, username, exc.response['Error']['Code'])
            return
        raise

    for key in keys:
        if key['Status'] != 'Active':
            continue

        key_id        = key['AccessKeyId']
        key_created   = key['CreateDate'].date()
        key_age_days  = (today - key_created).days

        try:
            last_used_resp = iam.get_access_key_last_used(AccessKeyId=key_id)
            last_used_date = last_used_resp['AccessKeyLastUsed'].get('LastUsedDate')
            key_last_used  = str(last_used_date.date()) if last_used_date else 'never'
        except ClientError as exc:
            if session.is_skippable(exc):
                log.warning('%s get_access_key_last_used %s: skipped -- %s (last_used unknown)',
                            account_id, key_id, exc.response['Error']['Code'])
                key_last_used = 'unknown'
            else:
                raise

        key_finding = 'stale-key-90d' if key_age_days >= STALE_KEY_DAYS else 'active-key'
        writer.write(
            account_id=account_id,
            region='global',
            resource_id=user_arn,
            resource_type='IAM User',
            finding=key_finding,
            detail=(
                f"Key {key_id} for '{username}' is {key_age_days}d old, "
                f"last used: {key_last_used}"
            ),
            estimated_monthly_savings_usd=0,
            tags=None,
            username=username,
            created_date=str(created),
            era=era,
            last_console_login=last_console_login,
            days_since_console_login=days_since_console_login,
            mfa_enabled=mfa_enabled,
            key_id=key_id,
            key_created=str(key_created),
            key_last_used=key_last_used,
            key_age_days=str(key_age_days),
            account_alias=account_alias,
        )


def scan(sess, account_id: str, writer) -> None:
    iam          = sess.client('iam', region_name='us-east-1')
    today        = datetime.now(timezone.utc).date()
    account_alias = _fetch_account_alias(sess)

    try:
        paginator = iam.get_paginator('list_users')
        for page in paginator.paginate():
            for user in page['Users']:
                _check_user(iam, user, account_id, today, writer, account_alias)
    except ClientError as exc:
        if session.is_skippable(exc):
            log.warning('%s IAM list_users: skipped -- %s',
                        account_id, exc.response['Error']['Code'])
            return
        raise


def main() -> None:
    parser = cli.make_parser(__doc__, account_level=True)
    args = parser.parse_args()
    cli.run(args, SCRIPT_NAME, scan, extra_fields=EXTRA_FIELDS, account_level=True)


if __name__ == '__main__':
    main()
