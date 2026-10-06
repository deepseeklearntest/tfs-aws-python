# Unencrypted Resources — Owner Fallback & Instance Name — Design Spec
**Date:** 2026-07-29
**Status:** Approved

## Problem

`wave4_security/33_detect_unencrypted_resources.py` derives `owner` purely from
each resource's own tags (`common/tags.owner_from_tags`, invoked implicitly by
`common/output.py::FindingsWriter.write`). For EBS volumes this under-attributes
findings: many volumes carry no `Owner` tag themselves even though the EC2
instance they're attached to does.

Measured against the latest findings CSV (`33_detect_unencrypted_resources_20260721_121553.csv`,
1,430 rows):

- EBS: 1,412 rows, 193 (13.7%) blank owner. Of those, **174 are attached to an
  instance** — a fallback lookup would very likely recover most of them.
- RDS: 18 rows, 13 (72%) blank owner. No attached-instance concept exists for
  RDS, so this is out of scope here (DB team follow-up handles it separately).

Separately, the `detail` column shows the attached EC2 instance ID but not its
`Name` tag, which is the human-readable identifier people actually recognize
when triaging.

## Goal

For EBS findings only:
1. Add a new `attached_instance_name` column (the attached instance's `Name` tag).
2. When the volume's own owner tag is blank, fall back to the attached
   instance's owner tag.

No pivot/reporting deliverable is in scope — the enriched CSV is pivot-ready
as-is (Excel PivotTable on `owner`, `attached_instance_name`, etc.).

## Design

### New per-region lookup cache

Mirrors the existing `_get_associated_resources` / `eni_cache` pattern already
in this file for a different lookup:

```python
def _get_instance_info(ec2, instance_id: str, cache: dict) -> dict:
    """Return {'name': ..., 'owner': ...} for instance_id, from cache or API."""
```

- Cache key: `instance_id`. Populated lazily on first encounter — multiple
  volumes attached to the same instance (e.g. root + data volumes) share one
  `describe_instances` call.
- On success: `name = tagutil.tag_value(inst.get('Tags'), 'Name')`,
  `owner = tagutil.owner_from_tags(inst.get('Tags'))`.
- On `ClientError` (e.g. instance terminated between volume read and this
  lookup): log a warning, cache and return `{'name': '', 'owner': ''}`. Must
  not raise — a single missing instance must not abort the region scan.
- Requires `from common import tags as tagutil` added to the imports.

### `_scan_ebs` changes

```python
instance_cache: dict[str, dict] = {}   # passed in from scan(), one per region call

...
attached_instance = attachments[0]['InstanceId'] if attachments else ''

instance_name = ''
instance_owner = ''
if attached_instance:
    info = _get_instance_info(ec2, attached_instance, instance_cache)
    instance_name = info['name']
    instance_owner = info['owner']

vol_owner = tagutil.owner_from_tags(vol.get('Tags')) or instance_owner

writer.write(
    ...,
    owner=vol_owner,                        # explicit override (see common/output.py)
    attached_instance=attached_instance,
    attached_instance_name=instance_name,
    ...
)
```

`instance_cache` is created once in `scan()` (per account/region call, same
lifetime as the existing pattern) and threaded into `_scan_ebs`.

### `_scan_rds` changes

None to owner logic (RDS has no attached-instance fallback available). Add
`attached_instance_name=''` to its `writer.write()` call for schema
consistency across the shared `EXTRA_FIELDS` columns — mirrors how it already
passes `''` for EBS-only fields like `volume_type`.

### `EXTRA_FIELDS`

Insert `'attached_instance_name'` immediately after `'attached_instance'`.

### Scope confirmation

- Only `wave4_security/33_detect_unencrypted_resources.py` changes.
- No other script reads this file's extra columns (confirmed via repo-wide
  grep), so no ripple effects into `generate_report.py`, `build_dataset.py`,
  or `continuous/54_inventory_refresh.py` — they consume `finding`/`detail`/
  `estimated_monthly_savings_usd` generically.
- `common/tags.py` (`owner_from_tags`, `tag_value`) is reused as-is, no changes.

## Verification

1. Run against a sample account/region with known unencrypted, instance-attached,
   untagged-at-volume-level EBS volumes:
   ```
   python wave4_security/33_detect_unencrypted_resources.py --accounts <id> --max-regions 2
   ```
2. In the output CSV, spot-check:
   - A volume with its own `Owner` tag → `owner` column matches the volume's tag
     (fallback not triggered).
   - A volume with no `Owner` tag but an attached, tagged instance → `owner`
     column now populated from the instance, `attached_instance_name` populated.
   - An unattached volume → `attached_instance` and `attached_instance_name`
     both blank, `owner` blank unless the volume itself is tagged.
   - Two volumes attached to the same instance → only one `describe_instances`
     call in the debug/log output (cache hit on the second).
3. RDS rows: `attached_instance_name` column present and blank; owner behavior
   unchanged from before this change.
4. Confirm no crash when an attached instance ID no longer exists (simulate by
   checking the `ClientError` catch path logs a warning and continues).
