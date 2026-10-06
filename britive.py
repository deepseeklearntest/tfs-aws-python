#!/usr/bin/env python3
"""
Britive credential collector for AWS proactive scanning.

For each account the operator is prompted to check out credentials in the
Britive portal (Britive → account → Check Out → CLI tab) and paste the
three AWS credential values here.  No Britive SDK required.
"""
from __future__ import annotations

import getpass
import json
import logging
from pathlib import Path

import boto3
from botocore.exceptions import ClientError

log = logging.getLogger(__name__)


def _prompt_creds(account_id: str) -> tuple[str, str, str] | None:
    width = 65
    print(f"\n{'=' * width}")
    print(f"  Account : {account_id}")
    print(f"{'─' * width}")
    print(f"  In Britive: find this account → Check Out → CLI tab")
    print(f"  Copy the three credential values and paste them below.")
    print(f"  (Type 'skip' for Access Key ID to skip this account)")
    print(f"{'=' * width}")

    access_key = input("  AWS_ACCESS_KEY_ID     : ").strip()
    if not access_key or access_key.lower() == "skip":
        print("  [SKIPPED]")
        return None

    try:
        secret_key    = getpass.getpass("  AWS_SECRET_ACCESS_KEY : ")
        session_token = getpass.getpass("  AWS_SESSION_TOKEN     : ")
    except Exception:
        secret_key    = input("  AWS_SECRET_ACCESS_KEY : ").strip()
        session_token = input("  AWS_SESSION_TOKEN     : ").strip()

    if not secret_key or not session_token:
        print("  [SKIPPED] Incomplete credentials.")
        return None

    return access_key, secret_key, session_token


def _verify_identity(
    access_key: str, secret_key: str, session_token: str, account_id: str
) -> bool:
    try:
        sts = boto3.client(
            "sts",
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            aws_session_token=session_token,
            region_name="us-east-1",
        )
        identity = sts.get_caller_identity()
        actual_id = identity["Account"]
        if actual_id != account_id:
            print(
                f"  [WARN] Credential account ({actual_id}) does not match "
                f"expected ({account_id})."
            )
            return input("  Continue anyway? [y/N]: ").strip().lower() == "y"
        print(f"  Identity OK : {identity.get('Arn', actual_id)}")
        return True
    except ClientError as exc:
        print(f"  [ERROR] STS identity check failed: {exc}")
        return False


def _load_from_file(path: str, account_ids: list[str]) -> dict[str, dict]:
    """
    Read saved credentials from a JSON file.

    Expected format:
        {
          "123456789012": {
            "aws_access_key_id": "ASIA...",
            "aws_secret_access_key": "...",
            "aws_session_token": "..."
          }
        }

    Returns only the accounts that are both requested and present in the file.
    """
    try:
        with open(path) as f:
            data = json.load(f)
    except FileNotFoundError:
        return {}
    except Exception as exc:
        print(f"  [WARN] Could not read credentials file '{path}': {exc}")
        return {}

    loaded: dict[str, dict] = {}
    for account_id in account_ids:
        entry = data.get(account_id)
        if not entry:
            continue
        key = entry.get("aws_access_key_id", "")
        secret = entry.get("aws_secret_access_key", "")
        token = entry.get("aws_session_token", "")
        if key and secret and token:
            loaded[account_id] = {
                "access_key":     key,
                "secret_key":     secret,
                "security_token": token,
            }
        else:
            print(f"  [WARN] Incomplete entry for {account_id} in '{path}' — will prompt.")
    return loaded


class BritiveKeychain:
    """
    Collects temporary AWS credentials from Britive via manual copy-paste,
    with optional pre-loading from a JSON credentials file.

    account_keys maps account_id → credential dict compatible with
    session._make_session():
        {'access_key': ..., 'secret_key': ..., 'security_token': ...}

    revoke_all_leases() is a no-op — Britive credentials expire naturally.
    """

    def __init__(self) -> None:
        self.account_keys: dict[str, dict] = {}

    def collect_creds(self, account_ids: list[str], creds_file: str | None = None) -> None:
        # --- load from file first ---
        if creds_file and Path(creds_file).exists():
            file_creds = _load_from_file(creds_file, account_ids)
            if file_creds:
                print(f"\nLoading credentials from '{creds_file}' for "
                      f"{len(file_creds)} account(s).")
            for account_id, creds in file_creds.items():
                if _verify_identity(
                    creds["access_key"], creds["secret_key"],
                    creds["security_token"], account_id,
                ):
                    self.account_keys[account_id] = creds
                else:
                    print(f"  Credentials for {account_id} in file are invalid or expired"
                          f" — will prompt.")

        # --- prompt for any accounts not loaded from file ---
        remaining = [a for a in account_ids if a not in self.account_keys]
        if remaining:
            print(f"\nCollecting Britive credentials interactively for {len(remaining)} account(s).")
            for account_id in remaining:
                for attempt in range(1, 4):
                    raw = _prompt_creds(account_id)
                    if raw is None:
                        break
                    access_key, secret_key, session_token = raw
                    if _verify_identity(access_key, secret_key, session_token, account_id):
                        self.account_keys[account_id] = {
                            "access_key":     access_key,
                            "secret_key":     secret_key,
                            "security_token": session_token,
                        }
                        break
                    remaining_attempts = 3 - attempt
                    if remaining_attempts:
                        print(f"  Credentials rejected — {remaining_attempts} attempt(s) remaining.")
                else:
                    print(f"  [WARN] Skipping account {account_id} after 3 failed attempts.")

        collected = len(self.account_keys)
        skipped   = len(account_ids) - collected
        print(
            f"\nCredentials collected: {collected}/{len(account_ids)} account(s)"
            + (f"  ({skipped} skipped)" if skipped else "")
        )

    def revoke_all_leases(self) -> None:
        pass
