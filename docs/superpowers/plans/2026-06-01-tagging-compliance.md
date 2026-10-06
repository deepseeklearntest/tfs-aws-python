# Tagging Compliance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rewrite `continuous/43_detect_tagging_compliance.py` to use the Resource Groups Tagging API for broad cross-service coverage, replacing the existing per-service implementation.

**Architecture:** Single regional scan function using `resourcegroupstaggingapi.get_resources()` paginator. Two-layer noise filter (excluded resource type set + `aws:` tag key check). One finding row per non-compliant resource with `missing_tags`, `present_tags`, `missing_count`, and `total_tag_count` columns.

**Tech Stack:** Python 3, boto3 `resourcegroupstaggingapi`, project `common/` package (cli, session, output).

---

## File Map

| Action | Path | Purpose |
|---|---|---|
| Rewrite | `continuous/43_detect_tagging_compliance.py` | Full replacement — Tagging API approach |
| Reference | `docs/superpowers/specs/2026-06-01-tagging-compliance-design.md` | Approved design spec |
| Reference | `common/cli.py` | `make_parser()`, `run()` — standard script wiring |
| Reference | `common/session.py` | `is_skippable()` — error handling pattern |
| Reference | `common/output.py` | `FindingsWriter.write()` — column contract |

---

## Task 1: Rewrite the Script

**Files:**
- Rewrite: `continuous/43_detect_tagging_compliance.py`

- [ ] **Step 1: Replace the file contents with the new implementation**

Write the following to `continuous/43_detect_tagging_compliance.py`:

```python
#!/usr/bin/env python3
"""Task 43 — Tagging Compliance

Identifies AWS resources missing mandatory organisational tags using the
Resource Groups Tagging API. One finding per non-compliant resource listing
all absent required tags.

Mandatory tags: CostCenter, Environment, Owner, Application

Run: python 43_detect_tagging_compliance.py --accounts 123456789012,234567890123
"""
from __future__ import annotations

import logging
import sys
from pathlib import Path

from botocore.exceptions import ClientError

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from common import cli, session

SCRIPT_NAME = '43_detect_tagging_compliance'
REQUIRED_TAGS = ['CostCenter', 'Environment', 'Owner', 'Application']
EXTRA_FIELDS = ['missing_tags', 'present_tags', 'missing_count', 'total_tag_count']

# Infrastructure primitives — not customer-owned, never tagged.
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

log = logging.getLogger(SCRIPT_NAME)


def _name_from_arn(arn: str) -> str:
    # arn:aws:lambda:us-east-1:123:function:my-function  -> my-function
    # arn:aws:ec2:us-east-1:123:instance/i-abc123        -> i-abc123
    last = arn.rsplit(':', 1)[-1]
    return last.rsplit('/', 1)[-1]


def scan(sess, account_id: str, region: str, writer) -> None:
    tagging = sess.client('resourcegroupstaggingapi', region_name=region)
    try:
        paginator = tagging.get_paginator('get_resources')
        for page in paginator.paginate():
            for resource in page.get('ResourceTagMappingList', []):
                resource_type = resource.get('ResourceType', '')

                # Layer 1: drop infrastructure primitives
                if resource_type in EXCLUDED_RESOURCE_TYPES:
                    continue

                tags = resource.get('Tags', [])

                # Layer 2: drop AWS-managed resources
                if any(t['Key'].startswith('aws:') for t in tags):
                    continue

                # A tag only counts as present if key exists AND value is non-empty
                tag_keys = {t['Key'] for t in tags if t.get('Key') and t.get('Value', '').strip()}
                missing = [t for t in REQUIRED_TAGS if t not in tag_keys]

                if not missing:
                    continue

                present = [t for t in REQUIRED_TAGS if t in tag_keys]
                arn = resource['ResourceARN']

                writer.write(
                    account_id=account_id,
                    region=region,
                    resource_id=arn,
                    resource_type=resource_type,
                    finding='missing-required-tags',
                    detail=(
                        f"Missing: {', '.join(missing)} "
                        f"({len(missing)}/4 required tags absent) — {_name_from_arn(arn)}"
                    ),
                    estimated_monthly_savings_usd=0,
                    tags=tags,
                    missing_tags=', '.join(missing),
                    present_tags=', '.join(present),
                    missing_count=str(len(missing)),
                    total_tag_count=str(len(tags)),
                )
    except ClientError as exc:
        if session.is_skippable(exc):
            log.warning("%s/%s tagging scan: skipped — %s",
                        account_id, region, exc.response['Error']['Code'])
            return
        raise


def main() -> None:
    parser = cli.make_parser(__doc__)
    args = parser.parse_args()
    cli.run(args, SCRIPT_NAME, scan, extra_fields=EXTRA_FIELDS)


if __name__ == '__main__':
    main()
```

- [ ] **Step 2: Verify no curly quotes were introduced**

Run:
```powershell
Select-String -Path "continuous\43_detect_tagging_compliance.py" -Pattern "[‘’“”]"
```
Expected: no output (zero matches). If any matches appear, replace the curly quotes with straight ASCII quotes before proceeding.

- [ ] **Step 3: Commit**

```powershell
git add continuous/43_detect_tagging_compliance.py
git commit -m "refactor(43): rewrite tagging compliance to use Resource Groups Tagging API"
```

---

## Task 2: Dry-Run Validation

**Goal:** Confirm the script runs end-to-end, produces output, and the columns are correct.

- [ ] **Step 1: Run against one account, one region**

```powershell
python continuous/43_detect_tagging_compliance.py --accounts <any_account_id> --max-regions 1 --workers 1
```

Expected: script completes without traceback. A CSV is written to `findings/43_detect_tagging_compliance_<timestamp>.csv`.

- [ ] **Step 2: Inspect the CSV header**

Open the CSV and verify the header row contains all expected columns:

```
account_id, region, resource_id, resource_type, finding, detail,
estimated_monthly_savings_usd, tags, missing_tags, present_tags,
missing_count, total_tag_count
```

- [ ] **Step 3: Spot-check a sample finding**

Pick any row and verify:
- `finding` = `missing-required-tags`
- `resource_type` contains a colon (e.g., `ec2:instance`, `lambda:function`) — confirms the Tagging API format
- `missing_tags` lists only tag names from `{CostCenter, Environment, Owner, Application}`
- `present_tags` + `missing_tags` together equal exactly the required tags that were checked
- `missing_count` = number of comma-separated entries in `missing_tags`
- `total_tag_count` is a non-negative integer string
- No rows with `resource_type` matching any entry in `EXCLUDED_RESOURCE_TYPES` (e.g., no `ec2:security-group` rows)

- [ ] **Step 4: Verify AWS-managed resources are filtered**

In the CSV, confirm there are no rows where `tags` contains a key beginning with `aws:`. A quick check:

```powershell
Select-String -Path "findings\43_detect_tagging_compliance_*.csv" -Pattern "aws:cloudformation|aws:eks"
```

Expected: no matches (or only in the `tags` column of rows that were NOT written — if any appear, the filter has a bug).

- [ ] **Step 5: Run across all regions for one account to confirm scale**

```powershell
python continuous/43_detect_tagging_compliance.py --accounts <any_account_id> --workers 10
```

Expected: completes without error. Review the log file at `findings/logs/43_detect_tagging_compliance_<timestamp>.log` for any `WARNING` lines — these indicate skipped regions (expected for regions where the Tagging API is not available or access is denied).
