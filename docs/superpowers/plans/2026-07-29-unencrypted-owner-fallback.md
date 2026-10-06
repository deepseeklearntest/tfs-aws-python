# Unencrypted Resources — Owner Fallback & Instance Name Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an `attached_instance_name` column and an EC2-instance owner-tag
fallback to `wave4_security/33_detect_unencrypted_resources.py`'s EBS scan, per
`docs/superpowers/specs/2026-07-29-unencrypted-owner-fallback-design.md`.

**Architecture:** A single per-region lookup cache (`instance_cache: dict[str, dict]`),
populated lazily via `ec2.describe_instances`, feeds both the new
`attached_instance_name` column and an owner fallback used only when the EBS
volume's own tags have no owner. Mirrors the existing `_get_associated_resources`
/ `eni_cache` pattern already in this file (script 30 uses the identical shape
for a different lookup).

**Tech Stack:** Python 3.11, boto3/botocore, stdlib `unittest.mock` for
verification (no pytest/test framework exists in this repo).

## Global Constraints

- This project directory is **not a git repository** — skip all `git add`/`git commit`
  steps from the standard task template. End each task by confirming the
  verification output, not by committing.
- All strings must use straight ASCII quotes (`'`/`"`) — curly quotes cause
  `SyntaxError`.
- `botocore.config`-importing modules must load after `from common import cli, session`
  (not relevant here — no new such import is added).
- Only `wave4_security/33_detect_unencrypted_resources.py` is modified. No other
  file in the repo reads this script's `EXTRA_FIELDS` columns (confirmed via
  repo-wide grep during design) — no downstream changes needed.

---

### Task 1: `_get_instance_info` lookup helper

**Files:**
- Modify: `wave4_security/33_detect_unencrypted_resources.py`
  - Imports section (currently `from common import cli, session`)
  - After `_get_associated_resources`... actually this file has no such
    function; add the new helper directly after the module-level
    `log = logging.getLogger(SCRIPT_NAME)` line and before `_scan_ebs`.
- Verification script (scratchpad, not part of the repo):
  `C:\Users\MOHAMM~1.MA\AppData\Local\Temp\claude\...\scratchpad\verify_task1.py`
  (use whatever scratchpad path this session's tool description gives you —
  do not write this file into the repo).

**Interfaces:**
- Produces: `_get_instance_info(ec2, instance_id: str, cache: dict) -> dict`
  returning `{'name': str, 'owner': str}`. Task 2 calls this directly.

- [ ] **Step 1: Write the failing verification script**

Create the verification script with this content:

```python
import sys
import importlib.util
from unittest.mock import MagicMock
from botocore.exceptions import ClientError

spec = importlib.util.spec_from_file_location(
    'sg33', r'wave4_security/33_detect_unencrypted_resources.py'
)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

# --- cache hit: second call must not hit the API again ---
ec2 = MagicMock()
ec2.describe_instances.return_value = {
    'Reservations': [{'Instances': [{
        'InstanceId': 'i-abc123',
        'Tags': [
            {'Key': 'Name', 'Value': 'web-server-01'},
            {'Key': 'Owner', 'Value': 'alice@example.com'},
        ],
    }]}]
}
cache = {}
info1 = mod._get_instance_info(ec2, 'i-abc123', cache)
info2 = mod._get_instance_info(ec2, 'i-abc123', cache)
assert info1 == {'name': 'web-server-01', 'owner': 'alice@example.com'}, info1
assert info2 == info1
assert ec2.describe_instances.call_count == 1, ec2.describe_instances.call_count

# --- no owner tag on instance ---
ec2_no_owner = MagicMock()
ec2_no_owner.describe_instances.return_value = {
    'Reservations': [{'Instances': [{
        'InstanceId': 'i-noowner',
        'Tags': [{'Key': 'Name', 'Value': 'batch-worker'}],
    }]}]
}
info3 = mod._get_instance_info(ec2_no_owner, 'i-noowner', {})
assert info3 == {'name': 'batch-worker', 'owner': ''}, info3

# --- API error must not raise, must cache a blank result ---
ec2_error = MagicMock()
ec2_error.describe_instances.side_effect = ClientError(
    {'Error': {'Code': 'InvalidInstanceID.NotFound', 'Message': 'gone'}},
    'DescribeInstances',
)
cache_err = {}
info4 = mod._get_instance_info(ec2_error, 'i-terminated', cache_err)
assert info4 == {'name': '', 'owner': ''}, info4
assert cache_err['i-terminated'] == {'name': '', 'owner': ''}

print('TASK1_OK')
```

- [ ] **Step 2: Run it to verify it fails**

Run: `python <path-to-verify_task1.py>`
Expected: `AttributeError: module 'sg33' has no attribute '_get_instance_info'`
(the function does not exist yet).

- [ ] **Step 3: Add the import and the helper function**

In `wave4_security/33_detect_unencrypted_resources.py`, change:

```python
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from common import cli, session
```

to:

```python
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from common import cli, session
from common import tags as tagutil
```

Then add, immediately after `log = logging.getLogger(SCRIPT_NAME)`:

```python
def _get_instance_info(ec2, instance_id: str, cache: dict) -> dict:
    """Return {'name': ..., 'owner': ...} for instance_id, from cache or API.

    Never raises — a missing/terminated instance must not abort the scan.
    """
    if instance_id in cache:
        return cache[instance_id]

    info = {'name': '', 'owner': ''}
    try:
        resp = ec2.describe_instances(InstanceIds=[instance_id])
        for reservation in resp.get('Reservations', []):
            for inst in reservation.get('Instances', []):
                info = {
                    'name': tagutil.tag_value(inst.get('Tags'), 'Name'),
                    'owner': tagutil.owner_from_tags(inst.get('Tags')),
                }
    except ClientError as exc:
        log.warning("describe_instances failed for %s: %s", instance_id, exc)

    cache[instance_id] = info
    return info
```

- [ ] **Step 4: Run the verification script again to confirm it passes**

Run: `python <path-to-verify_task1.py>`
Expected: prints `TASK1_OK` with no assertion errors.

- [ ] **Step 5: Syntax-check the whole file**

Run: `python -m py_compile wave4_security/33_detect_unencrypted_resources.py`
Expected: exits with no output (success).

---

### Task 2: Wire the cache and owner fallback into `_scan_ebs` / `_scan_rds`

**Files:**
- Modify: `wave4_security/33_detect_unencrypted_resources.py`
  - `EXTRA_FIELDS` list
  - `_scan_ebs` function signature and body
  - `_scan_rds` function body (one field added to its `writer.write()` call)
  - `scan()` function body (create and thread the cache)
- Verification script (scratchpad, not part of the repo).

**Interfaces:**
- Consumes: `_get_instance_info(ec2, instance_id: str, cache: dict) -> dict`
  from Task 1.
- Produces: `_scan_ebs(ec2, account_id: str, region: str, writer, instance_cache: dict) -> None`
  (signature changes — one new required parameter). `scan()` is the only
  caller and is updated in this same task, so no other file is affected.

- [ ] **Step 1: Write the failing verification script**

```python
import importlib.util
from unittest.mock import MagicMock

spec = importlib.util.spec_from_file_location(
    'sg33', r'wave4_security/33_detect_unencrypted_resources.py'
)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

written_rows = []

class FakeWriter:
    def write(self, **kwargs):
        written_rows.append(kwargs)

ec2 = MagicMock()
ec2.get_paginator.return_value.paginate.return_value = [{
    'Volumes': [
        {
            'VolumeId': 'vol-taggedowner',
            'Size': 100,
            'VolumeType': 'gp3',
            'State': 'in-use',
            'Attachments': [{'InstanceId': 'i-1'}],
            'Tags': [{'Key': 'Owner', 'Value': 'volume-owner@example.com'}],
        },
        {
            'VolumeId': 'vol-fallback',
            'Size': 50,
            'VolumeType': 'gp2',
            'State': 'in-use',
            'Attachments': [{'InstanceId': 'i-2'}],
            'Tags': [],
        },
        {
            'VolumeId': 'vol-unattached',
            'Size': 20,
            'VolumeType': 'gp2',
            'State': 'available',
            'Attachments': [],
            'Tags': [],
        },
    ]
}]

def fake_describe_instances(InstanceIds):
    instance_id = InstanceIds[0]
    tag_map = {
        'i-2': [
            {'Key': 'Name', 'Value': 'fallback-instance'},
            {'Key': 'Owner', 'Value': 'instance-owner@example.com'},
        ],
    }
    return {'Reservations': [{'Instances': [{
        'InstanceId': instance_id,
        'Tags': tag_map.get(instance_id, []),
    }]}]}

ec2.describe_instances.side_effect = fake_describe_instances

instance_cache = {}
mod._scan_ebs(ec2, '111111111111', 'us-east-1', FakeWriter(), instance_cache)

by_id = {r['resource_id']: r for r in written_rows}

# Volume's own Owner tag wins — no fallback triggered.
assert by_id['vol-taggedowner']['owner'] == 'volume-owner@example.com'
assert by_id['vol-taggedowner']['attached_instance_name'] == ''

# No owner tag on volume, but instance has one -> fallback used, name resolved.
assert by_id['vol-fallback']['owner'] == 'instance-owner@example.com'
assert by_id['vol-fallback']['attached_instance_name'] == 'fallback-instance'

# Unattached volume -> both blank, no crash.
assert by_id['vol-unattached']['owner'] == ''
assert by_id['vol-unattached']['attached_instance_name'] == ''
assert by_id['vol-unattached']['attached_instance'] == ''

print('TASK2_OK')
```

- [ ] **Step 2: Run it to verify it fails**

Run: `python <path-to-verify_task2.py>`
Expected: `KeyError: 'attached_instance_name'` (column does not exist yet in the
written rows), since `_scan_ebs` does not currently pass it.

- [ ] **Step 3: Update `EXTRA_FIELDS`**

```python
EXTRA_FIELDS = [
    'resource_subtype',
    'volume_type',
    'size_gib',
    'state',
    'attached_instance',
    'attached_instance_name',
    'engine',
    'engine_version',
    'instance_class',
    'multi_az',
]
```

- [ ] **Step 4: Update `_scan_ebs`**

Change the signature:

```python
def _scan_ebs(ec2, account_id: str, region: str, writer, instance_cache: dict) -> None:
```

Inside the `for vol in page.get('Volumes', []):` loop, replace:

```python
                vol_id = vol['VolumeId']
                attachments = vol.get('Attachments', [])
                attached_instance = attachments[0]['InstanceId'] if attachments else ''
                detail = (
```

with:

```python
                vol_id = vol['VolumeId']
                attachments = vol.get('Attachments', [])
                attached_instance = attachments[0]['InstanceId'] if attachments else ''

                instance_name = ''
                instance_owner = ''
                if attached_instance:
                    info = _get_instance_info(ec2, attached_instance, instance_cache)
                    instance_name = info['name']
                    instance_owner = info['owner']

                vol_owner = tagutil.owner_from_tags(vol.get('Tags')) or instance_owner

                detail = (
```

Then in the same loop's `writer.write(...)` call, add `owner=vol_owner,`
right after `tags=vol.get('Tags'),`, and add
`attached_instance_name=instance_name,` right after `attached_instance=attached_instance,`:

```python
                writer.write(
                    account_id=account_id,
                    region=region,
                    resource_id=vol_id,
                    resource_type='EBS Volume',
                    finding='unencrypted-ebs-volume',
                    detail=detail,
                    estimated_monthly_savings_usd=0,
                    tags=vol.get('Tags'),
                    owner=vol_owner,
                    resource_subtype='ebs',
                    volume_type=vol.get('VolumeType', ''),
                    size_gib=str(vol.get('Size', '')),
                    state=vol.get('State', ''),
                    attached_instance=attached_instance,
                    attached_instance_name=instance_name,
                    engine='',
                    engine_version='',
                    instance_class='',
                    multi_az='',
                )
```

- [ ] **Step 5: Update `_scan_rds`**

In its `writer.write(...)` call, add `attached_instance_name='',` right after
`attached_instance='',`:

```python
                writer.write(
                    account_id=account_id,
                    region=region,
                    resource_id=db_id,
                    resource_type='RDS Instance',
                    finding='unencrypted-rds-instance',
                    detail=detail,
                    estimated_monthly_savings_usd=0,
                    tags=db.get('TagList'),
                    resource_subtype='rds',
                    volume_type='',
                    size_gib='',
                    state='',
                    attached_instance='',
                    attached_instance_name='',
                    engine=db.get('Engine', ''),
                    engine_version=db.get('EngineVersion', ''),
                    instance_class=db.get('DBInstanceClass', ''),
                    multi_az=multi_az,
                )
```

- [ ] **Step 6: Update `scan()` to create and thread the cache**

```python
def scan(sess, account_id: str, region: str, writer) -> None:
    ec2 = sess.client('ec2', region_name=region)
    rds = sess.client('rds', region_name=region)

    instance_cache: dict[str, dict] = {}
    _scan_ebs(ec2, account_id, region, writer, instance_cache)
    _scan_rds(rds, account_id, region, writer)
```

- [ ] **Step 7: Run the verification script again to confirm it passes**

Run: `python <path-to-verify_task2.py>`
Expected: prints `TASK2_OK` with no assertion errors.

- [ ] **Step 8: Syntax-check the whole file**

Run: `python -m py_compile wave4_security/33_detect_unencrypted_resources.py`
Expected: exits with no output (success).

- [ ] **Step 9: Optional live smoke test (requires Britive creds in `britive_creds.json`)**

```
python wave4_security/33_detect_unencrypted_resources.py --accounts <one-account-id> --max-regions 2
```

Open the resulting CSV under `findings/wave4_security/` and confirm:
- `attached_instance_name` column exists and is populated for at least one
  attached, tagged instance.
- At least one row shows a non-blank `owner` that does not appear in that
  row's own `tags` column (i.e. came from the instance fallback) — check
  by cross-referencing `attached_instance` against the AWS console if needed.

If no Britive credentials are available in this environment, skip this step —
Task 1 and Task 2's mock-based verification already exercise every code path.

---

## Plan Self-Review Notes

- **Spec coverage:** New `attached_instance_name` column (Task 2 Steps 3-5),
  owner fallback (Task 2 Step 4), cache reuse across volumes sharing an
  instance (Task 1 Step 1's cache-hit assertion + `call_count == 1`), non-fatal
  error handling on lookup failure (Task 1 Step 1's `ClientError` case), RDS
  schema consistency (Task 2 Step 5) — all covered.
- **Placeholder scan:** No TBD/TODO; every step has literal code and exact
  run commands.
- **Type consistency:** `_get_instance_info` returns `{'name': str, 'owner': str}`
  in Task 1 and is consumed with `info['name']` / `info['owner']` in Task 2 —
  matches. `_scan_ebs` signature gains `instance_cache: dict` in Task 2 Step 4
  and `scan()` is updated in the same task (Step 6) to match — no other caller
  exists.
