#!/usr/bin/env python3
"""Task 31 — IAM User Hygiene (Recurring)

Recurring account-level scan for IAM user hygiene issues. Detects:

1. console-no-mfa  — user has a native login profile but no MFA device
2. stale-key-90d   — active access key older than 90 days
3. key-never-used  — active access key that has never been used
4. dormant-user    — no console or key activity for >180 days

Complements ppd_era_iam_users.py (one-time SSO migration audit).

Run: python 31_detect_iam_user_hygiene.py --accounts 123456789012,234567890123
"""
from __future__ import annotations

import logging
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

from botocore.exceptions import ClientError

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from common import cli, session

SCRIPT_NAME = '31_detect_iam_user_hygiene'
STALE_KEY_DAYS = 90
DORMANT_DAYS = 180

# IAM path fragments that identify service/automation accounts
_SERVICE_ACCOUNT_PATHS = (
    '/service-accounts/', '/service-account/', '/automation/',
    '/system/', '/svc/', '/bots/', '/ci/', '/service/',
)

EXTRA_FIELDS = [
    'username',
    'user_type',
    'mfa_enabled',
    'last_console_login',
    'days_since_console_login',
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


def _user_type(path: str) -> str:
    for fragment in _SERVICE_ACCOUNT_PATHS:
        if fragment in path:
            return 'service-account'
    return 'human'


def _check_user(iam, user: dict, account_id: str, now: datetime, writer, account_alias: str = '') -> None:
    username   = user['UserName']
    user_arn   = user['Arn']
    utype      = _user_type(user.get('Path', '/'))
    pw_last_used = user.get('PasswordLastUsed')
    last_console_login = str(pw_last_used.date()) if pw_last_used else 'never'
    days_since_console_login = str((now.date() - pw_last_used.date()).days) if pw_last_used else ''
    cutoff = now - timedelta(days=DORMANT_DAYS)

    # --- MFA (fetched once, shared across all findings for this user) ---
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

    def _base(finding, detail, **kw):
        payload = dict(
            account_id=account_id,
            region='global',
            resource_id=user_arn,
            resource_type='IAM User',
            finding=finding,
            detail=detail,
            estimated_monthly_savings_usd=0,
            tags=None,
            username=username,
            user_type=utype,
            mfa_enabled=mfa_enabled,
            last_console_login=last_console_login,
            days_since_console_login=days_since_console_login,
            key_id='',
            key_created='',
            key_last_used='',
            key_age_days='',
            account_alias=account_alias,
        )
        payload.update(kw)
        writer.write(**payload)

    # --- Console profile + MFA check ---
    has_console = False
    try:
        iam.get_login_profile(UserName=username)
        has_console = True
        if mfa_enabled == 'false':
            _base('console-no-mfa',
                  f"User '{username}' has a console login profile with no MFA device")
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
            log.warning('%s list_access_keys %s: skipped -- %s',
                        account_id, username, exc.response['Error']['Code'])
            return
        raise

    active_keys = [k for k in keys if k['Status'] == 'Active']
    latest_key_activity: datetime | None = None

    for key in active_keys:
        key_id       = key['AccessKeyId']
        key_created  = key['CreateDate'].date()
        key_age_days = (now.date() - key_created).days

        try:
            resp = iam.get_access_key_last_used(AccessKeyId=key_id)
            last_used_dt = resp['AccessKeyLastUsed'].get('LastUsedDate')
            key_last_used = str(last_used_dt.date()) if last_used_dt else 'never'
            if last_used_dt and (latest_key_activity is None or last_used_dt > latest_key_activity):
                latest_key_activity = last_used_dt
        except ClientError as exc:
            if session.is_skippable(exc):
                log.warning('%s get_access_key_last_used %s: skipped -- %s',
                            account_id, key_id, exc.response['Error']['Code'])
                key_last_used = 'unknown'
            else:
                raise

        key_kwargs = dict(key_id=key_id, key_created=str(key_created),
                          key_last_used=key_last_used, key_age_days=str(key_age_days))

        if key_last_used == 'never':
            _base('key-never-used',
                  f"Key {key_id} for '{username}' ({key_age_days}d old) has never been used",
                  **key_kwargs)
        elif key_age_days >= STALE_KEY_DAYS:
            _base('stale-key-90d',
                  f"Key {key_id} for '{username}' is {key_age_days}d old, last used: {key_last_used}",
                  **key_kwargs)

    # --- Dormancy check ---
    # Only relevant for users with some active attack surface.
    if not has_console and not active_keys:
        return

    console_active = has_console and pw_last_used is not None and pw_last_used >= cutoff
    keys_active = bool(active_keys) and latest_key_activity is not None and latest_key_activity >= cutoff

    if not console_active and not keys_active:
        _base('dormant-user',
              f"User '{username}' has had no console or key activity in >{DORMANT_DAYS} days")


def scan(sess, account_id: str, writer) -> None:
    iam          = sess.client('iam', region_name='us-east-1')
    now          = datetime.now(timezone.utc)
    account_alias = _fetch_account_alias(sess)

    try:
        paginator = iam.get_paginator('list_users')
        for page in paginator.paginate():
            for user in page['Users']:
                _check_user(iam, user, account_id, now, writer, account_alias)
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
