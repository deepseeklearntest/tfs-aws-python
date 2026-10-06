# PPD-Era IAM Users Audit — Design Spec

**Date:** 2026-05-26
**Status:** Approved
**Triggered by:** CRG Cloud9 incident — a PPD-era IAM user's old assumed role was still referenced by a Cloud9 environment after the org migrated to Britive SSO, blocking the user's access under their new TFS role.

---

## Background

ThermoFisher Scientific acquired PPD (now the CRG division). CRG employees originally accessed AWS via native IAM users with email/password. The org migrated first to Azure SSO, then to Britive SSO, with the Britive cutover completing at end of March 2026 (2026-03-31).

After the cutover, human access should be exclusively via Britive-federated roles. Native IAM users with console login profiles or long-lived access keys are a security lapse — they bypass SSO, MFA enforcement, and centralised session control.

---

## Goal

Sweep all AWS accounts and surface:
1. IAM users with native console access (login profile) that survived the SSO migration.
2. IAM users with active access keys — including stale keys not rotated within 90 days.

---

## File Location

`wave4_security/ppd_era_iam_users.py`

Not numbered — this is outside the 54-task proactive.md list, a targeted audit script. Lives alongside Wave 4 security scripts for discoverability.

Account-level scan (IAM is global; no region loop). Uses `account_level=True` in both `cli.make_parser()` and `cli.run()`.

---

## Finding Types

Each IAM user can produce multiple finding rows (one per finding).

| `finding` | Condition | Severity |
|---|---|---|
| `ppd-era-console` | Login profile exists AND `CreateDate` < 2026-03-31 | High |
| `post-sso-console` | Login profile exists AND `CreateDate` >= 2026-03-31 | Medium |
| `stale-key-90d` | Active key AND `CreateDate` >= 90 days ago | High |
| `active-key` | Active key AND `CreateDate` < 90 days ago | Informational |

- Each active key gets exactly one row: `stale-key-90d` or `active-key` (never both).
- Staleness is determined by key `CreateDate` age alone; `LastUsedDate` is recorded in `detail` as context but does not affect classification.
- Inactive (disabled) keys are ignored entirely.
- `estimated_monthly_savings_usd = 0` for all rows (security finding).

---

## CSV Schema

**COMMON_FIELDS** (from `common/output.py`):

| Field | Value |
|---|---|
| `account_id` | AWS account ID |
| `region` | `'global'` (IAM is not regional) |
| `resource_id` | IAM user ARN |
| `resource_type` | `'IAM User'` |
| `finding` | Finding code (see table above) |
| `detail` | Human-readable description |
| `estimated_monthly_savings_usd` | `0` |
| `tags` | `None` (IAM users have tags but not fetched to keep scan fast) |

**EXTRA_FIELDS:**

| Field | Description |
|---|---|
| `username` | IAM username |
| `created_date` | User creation date (`YYYY-MM-DD`) |
| `era` | `'pre-sso'` if created before 2026-03-31, else `'post-sso'` |
| `last_console_login` | Date of last password-based console login, or `'never'` |
| `key_id` | Access key ID (blank for console findings) |
| `key_created` | Key creation date (`YYYY-MM-DD`, blank for console findings) |
| `key_last_used` | Last used date or `'never'` (blank for console findings) |
| `key_age_days` | Days since key was created (blank for console findings) |

---

## Scan Logic

```
list_users (paginated)
└── for each user:
    │
    ├── get_login_profile
    │   ├── NoSuchEntityException → no console access, skip
    │   └── success → emit ppd-era-console or post-sso-console
    │       (based on user CreateDate vs 2026-03-31)
    │
    └── list_access_keys → filter Status == 'Active'
        └── for each active key:
            ├── get_access_key_last_used → LastUsedDate
            └── key_age = today - key.CreateDate
                ├── age >= 90 days → emit stale-key-90d
                └── age < 90 days  → emit active-key
```

---

## Error Handling

- All `ClientError` exceptions passed through `session.is_skippable()`.
- Skippable codes (access-denied, unsupported-region, etc.) → `log.debug` and continue.
- Non-skippable codes → re-raise (lets the framework log and move on to next account).
- `IndexError` on empty results is not possible — `FindingsWriter` handles zero rows cleanly.

---

## Constants

```python
SSO_CUTOVER_DATE = date(2026, 3, 31)   # Britive SSO cutover — end of March 2026
STALE_KEY_DAYS   = 90                   # Keys older than this are flagged stale
```

---

## AWS APIs Used

| API | Purpose |
|---|---|
| `iam.list_users` (paginated) | Enumerate all IAM users |
| `iam.get_login_profile` | Check for console password |
| `iam.list_access_keys` | List keys and their status/creation date |
| `iam.get_access_key_last_used` | Fetch last-used date per key |

---

## Out of Scope

- Fetching IAM user tags (adds N API calls per user; not needed for this finding).
- Checking group memberships or attached policies (covered by script 37).
- Automated remediation (report only).
