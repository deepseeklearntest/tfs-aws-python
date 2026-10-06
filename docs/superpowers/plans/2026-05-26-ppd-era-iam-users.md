# PPD-Era IAM Users Audit — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rewrite `ppderauser.py` as `wave4_security/ppd_era_iam_users.py` using the project's standard script anatomy to sweep all AWS accounts for IAM users with native console access or long-lived access keys that survived the Britive SSO migration.

**Architecture:** Account-level scan (IAM is global) using `common/cli.py` + `common/session.py`. One CSV row per finding: `ppd-era-console`, `post-sso-console`, `active-key`, or `stale-key-90d`. Each IAM user can produce multiple rows. A `_check_user()` helper handles both the console and key checks for a single user.

**Tech Stack:** Python 3, boto3, `common/cli.py`, `common/session.py`, `common/output.py`

---

## File Map

| Action | Path | Responsibility |
|---|---|---|
| Create | `wave4_security/ppd_era_iam_users.py` | Full scan script |
| Delete (after verification) | `ppderauser.py` | Superseded by above |

---

### Task 1: Scaffold — imports, constants, EXTRA_FIELDS, stub scan, main

**Files:**
- Create: `wave4_security/ppd_era_iam_users.py`

- [ ] **Step 1: Create the file with scaffold**

```python
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
SSO_CUTOVER_DATE = date(2026, 3, 31)   # Britive SSO cutover — end of March 2026
STALE_KEY_DAYS   = 90

EXTRA_FIELDS = [
    'username',
    'created_date',
    'era',
    'last_console_login',
    'key_id',
    'key_created',
    'key_last_used',
    'key_age_days',
]

log = logging.getLogger(SCRIPT_NAME)


def scan(sess, account_id: str, writer) -> None:
    pass


def main() -> None:
    parser = cli.make_parser(__doc__, account_level=True)
    args = parser.parse_args()
    cli.run(args, SCRIPT_NAME, scan, extra_fields=EXTRA_FIELDS, account_level=True)


if __name__ == '__main__':
    main()
```

- [ ] **Step 2: Verify syntax and help text**

Run from `wave4_security/`:
```
python -m py_compile ppd_era_iam_users.py && echo OK
python ppd_era_iam_users.py --help
```

Expected: `OK` then the standard argparse help block listing `--accounts`, `--creds-file`, `--output-dir`, `--max-accounts`, `--workers`.

- [ ] **Step 3: Commit scaffold**

```bash
git add wave4_security/ppd_era_iam_users.py
git commit -m "feat: scaffold ppd_era_iam_users.py with stub scan"
```

---

### Task 2: Implement `_check_user` — console finding

**Files:**
- Modify: `wave4_security/ppd_era_iam_users.py`

- [ ] **Step 1: Replace the stub `scan` and add `_check_user` with console logic**

Replace the entire file body from the `log = ...` line onward with:

```python
log = logging.getLogger(SCRIPT_NAME)


def _check_user(iam, user: dict, account_id: str, today: date, writer) -> None:
    username        = user['UserName']
    user_arn        = user['Arn']
    created         = user['CreateDate'].date()
    era             = 'pre-sso' if created < SSO_CUTOVER_DATE else 'post-sso'
    pw_last_used    = user.get('PasswordLastUsed')
    last_console_login = str(pw_last_used.date()) if pw_last_used else 'never'

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
            key_id='',
            key_created='',
            key_last_used='',
            key_age_days='',
        )
    except iam.exceptions.NoSuchEntityException:
        pass
    except ClientError as exc:
        if session.is_skippable(exc):
            log.debug('%s get_login_profile %s: skipped — %s',
                      account_id, username, exc.response['Error']['Code'])
        else:
            log.warning('%s get_login_profile %s: error — %s', account_id, username, exc)


def scan(sess, account_id: str, writer) -> None:
    iam   = sess.client('iam', region_name='us-east-1')
    today = datetime.now(timezone.utc).date()

    try:
        paginator = iam.get_paginator('list_users')
        for page in paginator.paginate():
            for user in page['Users']:
                _check_user(iam, user, account_id, today, writer)
    except ClientError as exc:
        if session.is_skippable(exc):
            log.warning('%s IAM list_users: skipped — %s',
                        account_id, exc.response['Error']['Code'])
            return
        raise


def main() -> None:
    parser = cli.make_parser(__doc__, account_level=True)
    args = parser.parse_args()
    cli.run(args, SCRIPT_NAME, scan, extra_fields=EXTRA_FIELDS, account_level=True)


if __name__ == '__main__':
    main()
```

- [ ] **Step 2: Verify syntax**

```
python -m py_compile wave4_security/ppd_era_iam_users.py && echo OK
```

Expected: `OK`

- [ ] **Step 3: Commit**

```bash
git add wave4_security/ppd_era_iam_users.py
git commit -m "feat: add console login profile finding (ppd-era-console / post-sso-console)"
```

---

### Task 3: Add access-key findings to `_check_user`

**Files:**
- Modify: `wave4_security/ppd_era_iam_users.py`

- [ ] **Step 1: Insert access-key block at the end of `_check_user`, before the closing of the function**

Add after the `except ClientError` block that closes the console section (i.e., after `log.warning('%s get_login_profile %s: error...`)):

```python
    # --- Access keys ---
    try:
        keys = iam.list_access_keys(UserName=username)['AccessKeyMetadata']
    except ClientError as exc:
        if session.is_skippable(exc):
            log.debug('%s list_access_keys %s: skipped — %s',
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
                log.debug('%s get_access_key_last_used %s: skipped — %s',
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
            key_id=key_id,
            key_created=str(key_created),
            key_last_used=key_last_used,
            key_age_days=str(key_age_days),
        )
```

- [ ] **Step 2: Verify syntax**

```
python -m py_compile wave4_security/ppd_era_iam_users.py && echo OK
```

Expected: `OK`

- [ ] **Step 3: Commit**

```bash
git add wave4_security/ppd_era_iam_users.py
git commit -m "feat: add access key findings (active-key / stale-key-90d)"
```

---

### Task 4: Smoke test and retire the old script

**Files:**
- Read: `findings/wave4_security/ppd_era_iam_users/` (output dir after run)
- Delete: `ppderauser.py`

- [ ] **Step 1: Run against one account**

```bash
python wave4_security/ppd_era_iam_users.py --accounts <YOUR_ACCOUNT_ID> --max-accounts 1 --workers 1
```

Expected console output: `Audited account <ID> — N findings written to findings/...`

- [ ] **Step 2: Inspect the CSV**

Open the CSV in `findings/wave4_security/ppd_era_iam_users/ppd_era_iam_users_<timestamp>.csv`.

Check:
- Columns present: `account_id`, `region`, `resource_id`, `resource_type`, `finding`, `detail`, `estimated_monthly_savings_usd`, `tags`, `username`, `created_date`, `era`, `last_console_login`, `key_id`, `key_created`, `key_last_used`, `key_age_days`
- `region` column shows `global` for all rows
- `finding` values are only: `ppd-era-console`, `post-sso-console`, `active-key`, `stale-key-90d`
- `era` is `pre-sso` for users created before 2026-03-31, `post-sso` otherwise
- Key rows have `key_id` populated; console rows have `key_id` blank

- [ ] **Step 3: Delete the old script**

```bash
git rm ppderauser.py
git commit -m "chore: retire ppderauser.py — replaced by wave4_security/ppd_era_iam_users.py"
```
