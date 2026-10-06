#!/usr/bin/env python3
"""Task 33 — Unencrypted EBS Volumes and RDS Instances

Sweeps every region for EBS volumes and RDS instances that have encryption
disabled.

Run: python 33_detect_unencrypted_resources.py --accounts 123456789012,234567890123
"""
from __future__ import annotations

import logging
import sys
from pathlib import Path

from botocore.exceptions import ClientError

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from common import cli, session, tags as tagutil

SCRIPT_NAME = '33_detect_unencrypted_resources'
EXTRA_FIELDS = [
    'resource_subtype',
    'volume_type',
    'size_gib',
    'state',
    'attached_instance',
    'attached_instance_name',
    'device',
    'volume_role',
    'downtime_impact',
    'engine',
    'engine_version',
    'instance_class',
    'multi_az',
    'group_key',
    'group_size',
    'group_seq',
    'group_band',
]

# volume_role -> the ticket-relevant consequence of encrypting it. Kept as an
# explicit map (rather than computed inline) so the remediation meaning is
# visible in one place next to the roles themselves.
DOWNTIME_IMPACT = {
    'root': 'instance-stop',
    'data': 'detach-window',
    'unattached': 'none',
    'unknown': 'unknown',
    'rds-storage': 'db-snapshot-restore',
}

log = logging.getLogger(SCRIPT_NAME)


def _get_instance_info(ec2, instance_id: str, cache: dict) -> dict:
    """Return {'name', 'owner', 'root_volume_id', 'root_device', 'lookup_ok'}
    for instance_id, from cache or API.

    root_volume_id is resolved by matching BlockDeviceMappings against
    RootDeviceName (exact volume-ID match) rather than comparing device-name
    strings like '/dev/sda1' vs '/dev/xvda', which disagree across AMI
    families and would misclassify silently. Instance-store-backed instances
    have no matching mapping, so root_volume_id stays '' even though the
    lookup itself succeeded (lookup_ok=True) — that distinction is what lets
    _volume_role tell "no EBS root volume exists" apart from "the instance
    lookup failed" (e.g. terminated instance), both of which would otherwise
    look identical as an empty root_volume_id.

    Never raises — a missing/terminated instance must not abort the scan.
    """
    if instance_id in cache:
        return cache[instance_id]

    info = {'name': '', 'owner': '', 'root_volume_id': '', 'root_device': '', 'lookup_ok': False}
    try:
        resp = ec2.describe_instances(InstanceIds=[instance_id])
        for reservation in resp.get('Reservations', []):
            for inst in reservation.get('Instances', []):
                root_device = inst.get('RootDeviceName', '')
                root_volume_id = ''
                for bdm in inst.get('BlockDeviceMappings', []):
                    if bdm.get('DeviceName') == root_device:
                        root_volume_id = bdm.get('Ebs', {}).get('VolumeId', '')
                        break
                info = {
                    'name': tagutil.tag_value(inst.get('Tags'), 'Name'),
                    'owner': tagutil.owner_from_tags(inst.get('Tags')),
                    'root_volume_id': root_volume_id,
                    'root_device': root_device,
                    'lookup_ok': True,
                }
    except ClientError as exc:
        log.warning("describe_instances failed for %s: %s", instance_id, exc)

    cache[instance_id] = info
    return info


def _volume_role(vol_id: str, attachments: list, root_volume_id: str, lookup_ok: bool) -> str:
    """Classify a volume as root / data / unattached / unknown.

    'unknown' means the volume is attached but the instance lookup failed
    (e.g. terminated between the volume read and this lookup) — distinct
    from an instance-store-backed instance, which has a legitimately empty
    root_volume_id but a successful lookup (lookup_ok=True) and so still
    correctly classifies its attached EBS volumes as 'data'.
    """
    if not attachments:
        return 'unattached'
    if not lookup_ok:
        return 'unknown'
    if root_volume_id == vol_id:
        return 'root'
    return 'data'


def _scan_ebs(ec2, account_id: str, region: str, instance_cache: dict) -> list[dict]:
    """Return one row dict per unencrypted EBS volume in the region.

    Rows are collected rather than written directly because group_key /
    group_size / group_seq / group_band (assigned by _emit_grouped) require
    seeing every row for the region up front.
    """
    rows: list[dict] = []
    try:
        paginator = ec2.get_paginator('describe_volumes')
        for page in paginator.paginate(
            Filters=[{'Name': 'encrypted', 'Values': ['false']}]
        ):
            for vol in page.get('Volumes', []):
                vol_id = vol['VolumeId']
                attachments = vol.get('Attachments', [])
                attached_instance = attachments[0]['InstanceId'] if attachments else ''
                device = attachments[0].get('Device', '') if attachments else ''

                instance_name = ''
                instance_owner = ''
                root_volume_id = ''
                lookup_ok = False
                if attached_instance:
                    info = _get_instance_info(ec2, attached_instance, instance_cache)
                    instance_name = info['name']
                    instance_owner = info['owner']
                    root_volume_id = info['root_volume_id']
                    lookup_ok = info['lookup_ok']

                vol_owner = tagutil.owner_from_tags(vol.get('Tags')) or instance_owner
                role = _volume_role(vol_id, attachments, root_volume_id, lookup_ok)

                detail = (
                    f"Size={vol.get('Size', '')} GiB  "
                    f"Type={vol.get('VolumeType', '')}  "
                    f"State={vol.get('State', '')}  "
                    f"AttachedTo={attached_instance or 'none'}  "
                    f"Device={device or 'n/a'}  "
                    f"Role={role}"
                )
                rows.append(dict(
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
                    device=device,
                    volume_role=role,
                    downtime_impact=DOWNTIME_IMPACT[role],
                    engine='',
                    engine_version='',
                    instance_class='',
                    multi_az='',
                    group_key=attached_instance or vol_id,
                ))
    except ClientError as exc:
        if session.is_skippable(exc):
            log.warning("%s/%s EBS: skipped — %s", account_id, region, exc.response['Error']['Code'])
            return rows
        raise
    return rows


def _scan_rds(rds, account_id: str, region: str) -> list[dict]:
    """Return one row dict per unencrypted RDS instance in the region."""
    rows: list[dict] = []
    try:
        paginator = rds.get_paginator('describe_db_instances')
        for page in paginator.paginate():
            for db in page.get('DBInstances', []):
                if db.get('StorageEncrypted', True):
                    continue
                db_id = db['DBInstanceIdentifier']
                multi_az = str(db.get('MultiAZ', False))
                detail = (
                    f"Engine={db.get('Engine', '')} {db.get('EngineVersion', '')}  "
                    f"Class={db.get('DBInstanceClass', '')}  "
                    f"MultiAZ={multi_az}"
                )
                rows.append(dict(
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
                    device='',
                    volume_role='rds-storage',
                    downtime_impact=DOWNTIME_IMPACT['rds-storage'],
                    engine=db.get('Engine', ''),
                    engine_version=db.get('EngineVersion', ''),
                    instance_class=db.get('DBInstanceClass', ''),
                    multi_az=multi_az,
                    group_key=db_id,
                ))
    except ClientError as exc:
        if session.is_skippable(exc):
            log.warning("%s/%s RDS: skipped — %s", account_id, region, exc.response['Error']['Code'])
            return rows
        raise
    return rows


def _emit_grouped(writer, rows: list[dict]) -> None:
    """Assign group_size/group_seq/group_band across rows and write them all.

    Rows are bucketed by group_key (the attached instance ID, or the
    resource's own ID when unattached/RDS). Bands alternate over the sorted
    group keys so an Excel sort by (account_id, region, group_key, group_seq)
    reproduces the intended band order even though rows from concurrent
    region threads interleave in the raw CSV.
    """
    groups: dict[str, list[dict]] = {}
    for row in rows:
        groups.setdefault(row['group_key'], []).append(row)

    for band, key in enumerate(sorted(groups)):
        members = groups[key]
        members.sort(key=lambda r: (r['volume_role'] != 'root', r['device'], r['resource_id']))
        for seq, row in enumerate(members, start=1):
            row['group_size'] = len(members)
            row['group_seq'] = seq
            row['group_band'] = band % 2
            writer.write(**row)


def scan(sess, account_id: str, region: str, writer) -> None:
    ec2 = sess.client('ec2', region_name=region)
    rds = sess.client('rds', region_name=region)

    instance_cache: dict[str, dict] = {}
    rows = _scan_ebs(ec2, account_id, region, instance_cache)
    rows += _scan_rds(rds, account_id, region)
    _emit_grouped(writer, rows)


def main() -> None:
    parser = cli.make_parser(__doc__)
    args = parser.parse_args()
    cli.run(args, SCRIPT_NAME, scan, extra_fields=EXTRA_FIELDS)


if __name__ == '__main__':
    main()
