#!/usr/bin/env python3
"""Task 36 — GuardDuty / Security Hub / Config Not Enabled

Checks whether each of the three core AWS security services is active in
every region of every account.  A single finding is written per service
per region whenever the service is absent or its recorder has been stopped.

Run: python 36_detect_security_services_gaps.py --accounts 123456789012,234567890123
"""
from __future__ import annotations

import logging
import sys
from pathlib import Path

from botocore.exceptions import ClientError

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from common import cli, session

SCRIPT_NAME = '36_detect_security_services_gaps'
EXTRA_FIELDS = ['service', 'status_detail', 'account_alias']

log = logging.getLogger(SCRIPT_NAME)


def _fetch_account_alias(sess) -> str:
    try:
        iam = sess.client('iam', region_name='us-east-1')
        aliases = iam.list_account_aliases().get('AccountAliases', [])
        return aliases[0] if aliases else ''
    except ClientError:
        return ''


def _check_guardduty(sess, account_id: str, region: str, writer, account_alias: str = '') -> None:
    gd = sess.client('guardduty', region_name=region)
    try:
        ids = gd.list_detectors().get('DetectorIds', [])
    except ClientError as exc:
        code = exc.response['Error']['Code']
        if session.is_skippable(exc) or code in ('BadRequestException',):
            log.debug("%s/%s GuardDuty list_detectors skipped — %s", account_id, region, code)
            return
        # Region may not support GuardDuty — treat as not enabled
        log.debug("%s/%s GuardDuty unavailable — %s", account_id, region, code)
        _write_gap(writer, account_id, region, 'guardduty', 'guardduty-not-enabled',
                   f"GuardDuty API error in {region}: {code}", f"API error: {code}", account_alias)
        return

    if not ids:
        _write_gap(writer, account_id, region, 'guardduty', 'guardduty-not-enabled',
                   f"GuardDuty has no detector configured in {region}", 'no detector', account_alias)
        return

    try:
        det = gd.get_detector(DetectorId=ids[0])
        if det.get('Status', '').upper() != 'ENABLED':
            status = det.get('Status', 'unknown')
            _write_gap(writer, account_id, region, 'guardduty', 'guardduty-not-enabled',
                       f"GuardDuty detector status={status} in {region}", f"status={status}", account_alias)
    except ClientError as exc:
        code = exc.response['Error']['Code']
        if session.is_skippable(exc):
            log.debug("%s/%s GuardDuty get_detector skipped — %s", account_id, region, code)
        else:
            log.warning("%s/%s GuardDuty get_detector error — %s", account_id, region, exc)


def _check_securityhub(sess, account_id: str, region: str, writer, account_alias: str = '') -> None:
    sh = sess.client('securityhub', region_name=region)
    try:
        sh.describe_hub()
        # Success — Security Hub is enabled; nothing to report.
    except ClientError as exc:
        code = exc.response['Error']['Code']
        if code in ('InvalidAccessException', 'ResourceNotFoundException'):
            _write_gap(writer, account_id, region, 'securityhub', 'securityhub-not-enabled',
                       f"Security Hub is not enabled in {region}", f"error code: {code}", account_alias)
        elif session.is_skippable(exc):
            log.debug("%s/%s SecurityHub skipped — %s", account_id, region, code)
        else:
            log.warning("%s/%s SecurityHub describe_hub error — %s", account_id, region, exc)


def _check_config(sess, account_id: str, region: str, writer, account_alias: str = '') -> None:
    cfg = sess.client('config', region_name=region)
    try:
        recorders = cfg.describe_configuration_recorders().get('ConfigurationRecorders', [])
    except ClientError as exc:
        if session.is_skippable(exc):
            log.debug("%s/%s Config skipped — %s", account_id, region, exc.response['Error']['Code'])
            return
        log.warning("%s/%s Config describe_configuration_recorders error — %s", account_id, region, exc)
        return

    if not recorders:
        _write_gap(writer, account_id, region, 'config', 'config-not-enabled',
                   f"AWS Config has no configuration recorder in {region}", 'no recorder', account_alias)
        return

    # Check recorder status
    try:
        status_resp = cfg.describe_configuration_recorder_status()
        for status in status_resp.get('ConfigurationRecordersStatus', []):
            if not status.get('recording', False):
                recorder_name = status.get('name', 'unknown')
                _write_gap(writer, account_id, region, 'config', 'config-recorder-stopped',
                           f"AWS Config recorder '{recorder_name}' is not recording in {region}",
                           f"recorder={recorder_name} recording=False", account_alias)
    except ClientError as exc:
        if session.is_skippable(exc):
            log.debug("%s/%s Config recorder status skipped — %s",
                      account_id, region, exc.response['Error']['Code'])
        else:
            log.warning("%s/%s Config recorder status error — %s", account_id, region, exc)


def _write_gap(writer, account_id: str, region: str, service: str,
               finding: str, detail: str, status_detail: str, account_alias: str = '') -> None:
    resource_id = f"{account_id}/{region}/{service}"
    writer.write(
        account_id=account_id,
        region=region,
        resource_id=resource_id,
        resource_type='Security Service',
        finding=finding,
        detail=detail,
        estimated_monthly_savings_usd=0,
        tags=None,
        service=service,
        status_detail=status_detail,
        account_alias=account_alias,
    )


def scan(sess, account_id: str, region: str, writer) -> None:
    account_alias = _fetch_account_alias(sess)
    _check_guardduty(sess, account_id, region, writer, account_alias)
    _check_securityhub(sess, account_id, region, writer, account_alias)
    _check_config(sess, account_id, region, writer, account_alias)


def main() -> None:
    parser = cli.make_parser(__doc__)
    args = parser.parse_args()
    cli.run(args, SCRIPT_NAME, scan, extra_fields=EXTRA_FIELDS)


if __name__ == '__main__':
    main()
