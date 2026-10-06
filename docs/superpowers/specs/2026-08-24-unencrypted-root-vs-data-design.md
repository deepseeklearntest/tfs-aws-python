# Unencrypted Resources — Root vs Data Volumes & Per-Instance Grouping — Design Spec
**Date:** 2026-08-24
**Status:** Implemented

## Problem

`wave4_security/33_detect_unencrypted_resources.py` emits one flat row per unencrypted
EBS volume / RDS instance (1,406 EBS + 18 RDS in the latest run,
`findings/wave4_security/33_..._20260730_063456.csv`). Every row is treated identically,
which hides two facts that matter for remediation planning:

1. Encrypting an EBS volume always requires snapshot → copy-encrypted → new volume →
   swap. For a **data** volume that's a detach/attach window; for a **root** volume the
   instance must be **stopped**, which needs a change ticket and an outage window. These
   are different pieces of work but look identical in the CSV today.
2. Volume rows do not equal remediation units — many volumes belong to the same EC2
   instance, and there was no way to see the unique-instance count or visually group an
   instance's volumes together.

## Goal

Add columns so the CSV can (a) tell root from data exactly, (b) state the downtime
consequence per row, and (c) drive an Excel instance-banding + role-tint conditional
format applied by hand (no new Excel-writing code in the detector). Stay consistent with
the precedent in `2026-07-29-unencrypted-owner-fallback-design.md`: enrich the existing
CSV, keep it pivot-ready, no new sheet/report code.

## Design

### Root detection: match volume IDs, not device strings

Comparing the attachment's `Device` (`/dev/xvda`) against the instance's `RootDeviceName`
was rejected — those strings disagree across AMI families (`/dev/sda1` vs `/dev/xvda`)
and would misclassify silently.

`_get_instance_info`'s existing `describe_instances` call (already made for the owner
fallback) also returns `BlockDeviceMappings`. The mapping entry whose `DeviceName` equals
`RootDeviceName` gives `Ebs.VolumeId` — the root volume, by exact ID match, at no extra
API cost.

`_get_instance_info` now returns `{'name', 'owner', 'root_volume_id', 'root_device',
'lookup_ok'}`. `lookup_ok` is required, not optional: an instance-store-backed instance
has a `RootDeviceName` with no matching `BlockDeviceMappings` entry, so its
`root_volume_id` is legitimately `''` even though the lookup succeeded — that's
indistinguishable from a failed lookup (terminated instance) unless the success/failure
of the API call is tracked separately.

```python
def _volume_role(vol_id, attachments, root_volume_id, lookup_ok) -> str:
    if not attachments:
        return 'unattached'
    if not lookup_ok:
        return 'unknown'
    if root_volume_id == vol_id:
        return 'root'
    return 'data'
```

`downtime_impact` is a 1:1 map from `volume_role` (`root`→`instance-stop`,
`data`→`detach-window`, `unattached`→`none`, `rds-storage`→`db-snapshot-restore`,
`unknown`→`unknown`) — kept as an explicit `DOWNTIME_IMPACT` dict next to the roles so the
ticket-relevant meaning is visible in one place.

### Grouping computed in-process, per region

`group_size`/`group_seq`/`group_band` can't be computed row-by-row, so `_scan_ebs` and
`_scan_rds` changed from write-as-you-go to **returning a list of row dicts**. `scan()`
merges both lists and hands them to a new `_emit_grouped(writer, rows)`, which buckets by
`group_key` (attached instance ID, or the resource's own ID when unattached/RDS), assigns
`group_band = index % 2` over `sorted(groups)`, sorts each group root-first
(`(volume_role != 'root', device, resource_id)`) for `group_seq`, then calls
`writer.write(**row)` per row.

`group_band` alternates over sorted group keys, not write order — rows from concurrent
account/region threads interleave in the raw CSV (`FindingsWriter.write` takes a lock per
row), so contiguous banding only appears after sorting the CSV by
`(account_id, region, group_key, group_seq)` in Excel. That sort is step 1 of the
conditional-formatting recipe in `Next_Actions.md`.

### New columns

Inserted after `attached_instance_name`: `device`, `volume_role`, `downtime_impact`.
Appended at the end: `group_key`, `group_size`, `group_seq`, `group_band`. RDS rows set
`device=''`, `volume_role='rds-storage'`, `group_key=db_id` (RDS has no attached-instance
concept, so its "group" is always itself, `group_size=1`).

`generate_report.write_wave_sheet` auto-discovers extra columns by name
(`generate_report.py:407-446`), so these 7 columns appear on the existing Wave 4 sheet
automatically — no report code changed.

## Scope confirmation

- Only `wave4_security/33_detect_unencrypted_resources.py` changes.
- Severity is unchanged: `common/findings_io.severity_of` and
  `generate_report.rag_security` both match the substring `unencrypted` and rate every
  script-33 finding High/red regardless of role. Downgrading `data`/`unattached` rows was
  considered and rejected for this change — it would shift the `dataset/findings_dataset.csv`
  trend line; left as a follow-up decision.
- No `.xlsx` output from the detector, no new report sheet — see auto-discovery above.
- No change to the owner-fallback logic from the prior spec.

## Verification

Mock-based (`unittest.mock`, `importlib.util.spec_from_file_location` since the module
name starts with a digit — no test framework in this repo):

1. `_get_instance_info` resolves `root_volume_id` by ID match; caches (`describe_instances`
   called once for two volumes on the same instance); an instance-store instance (no
   matching `BlockDeviceMappings` entry) returns `root_volume_id='' , lookup_ok=True`; a
   `ClientError` returns `lookup_ok=False` without raising.
2. `_volume_role` covers root / data / unattached / unknown, and specifically confirms the
   instance-store case (`lookup_ok=True`, `root_volume_id=''`) classifies as `data`, not
   `unknown` — the case the naive "empty root_volume_id" rule would have gotten wrong.
3. `scan()` end-to-end with mocks: 3 volumes on one instance (1 root, 2 data) + 1
   unattached volume + 1 RDS row → correct `group_size`/`group_seq`/`group_band` per row,
   root sorted first in its group, `downtime_impact` matching `volume_role` per row.
4. `python -m py_compile wave4_security/33_detect_unencrypted_resources.py` — passes.
5. `python generate_report.py` — completes successfully against the existing (pre-change
   schema) CSV; confirms no regression for consumers of this script's output.

All of the above were run during implementation and passed.
