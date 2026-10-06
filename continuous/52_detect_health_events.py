#!/usr/bin/env python3
"""Task 52 - AWS Health Dashboard Events

Account-level scan that surfaces open and upcoming AWS Health events:
retirement notices, scheduled maintenance windows, deprecation
announcements, and active service issues.

When run against a management/payer account that has Health org integration
enabled (Business or Enterprise Support), uses describe_events_for_organization
to sweep all member accounts in one pass. Falls back to per-account
describe_events for non-management or non-Business-support accounts.

Requires Business or Enterprise Support for full access; accounts on Basic
support receive a warning and produce no findings.

Run: python 52_detect_health_events.py --accounts 123456789012,234567890123
"""
from __future__ import annotations

import logging
import sys
from pathlib import Path

from botocore.exceptions import ClientError

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from common import cli, session

SCRIPT_NAME = '52_detect_health_events'

EXTRA_FIELDS = [
    'event_arn',
    'event_type_code',
    'event_type_category',
    'service',
    'event_status',
    'start_time',
    'end_time',
    'last_updated',
    'entity_value',
]

log = logging.getLogger(SCRIPT_NAME)

_DETAIL_MAX = 300
_EVENT_CATEGORIES = ['scheduledChange', 'accountNotification', 'issue']
_SUBSCRIPTION_ERRORS = {'SubscriptionRequiredException', 'OrganizationNotInAllFeaturesMode'}


def _finding_code(event_type_code: str, event_type_category: str) -> str:
    if 'RETIREMENT' in event_type_code.upper():
        return 'retirement-notice'
    if event_type_category == 'scheduledChange':
        return 'scheduled-change'
    if event_type_category == 'issue':
        return 'service-issue'
    return 'account-notification'


def _iso(dt) -> str:
    return dt.date().isoformat() if dt else ''


def _fetch_descriptions(health, arns: list[str]) -> dict[str, str]:
    """Return {arn: latestDescription} for up to 10 event ARNs (per-account API)."""
    try:
        resp = health.describe_event_details(eventArns=arns)
        return {
            d['event']['arn']: (d.get('eventDescription', {}).get('latestDescription') or '')[:_DETAIL_MAX]
            for d in resp.get('successfulSet', [])
        }
    except ClientError as exc:
        log.debug('describe_event_details failed: %s', exc)
        return {}


def _iter_entities(health, event_arn: str):
    """Yield entity values affected by an event (per-account API)."""
    try:
        paginator = health.get_paginator('describe_affected_entities')
        for page in paginator.paginate(filter={'eventArns': [event_arn]}):
            for entity in page.get('entities', []):
                yield entity.get('entityValue', '')
    except ClientError as exc:
        log.debug('describe_affected_entities failed for %s: %s', event_arn, exc)


def _write_finding(writer, account_id, region, arn, entity_value,
                   finding_code, detail, type_code, type_category,
                   service, status, start_time, end_time, last_updated) -> None:
    writer.write(
        account_id=account_id,
        region=region,
        resource_id=entity_value or arn,
        resource_type='Health Event',
        finding=finding_code,
        detail=detail,
        estimated_monthly_savings_usd=None,
        tags=None,
        event_arn=arn,
        event_type_code=type_code,
        event_type_category=type_category,
        service=service,
        event_status=status,
        start_time=start_time,
        end_time=end_time,
        last_updated=last_updated,
        entity_value=entity_value,
    )


def _scan_org(health, mgmt_account_id: str, writer) -> bool:
    """Org-wide sweep via describe_events_for_organization.

    Returns True if the org API was available and the scan completed.
    Returns False to signal the caller to fall back to per-account scan.
    """
    try:
        paginator = health.get_paginator('describe_events_for_organization')
        all_events: list[dict] = []
        for page in paginator.paginate(
            filter={
                'eventStatusCodes': ['open', 'upcoming'],
                'eventTypeCategories': _EVENT_CATEGORIES,
            }
        ):
            all_events.extend(page.get('events', []))
    except ClientError as exc:
        code = exc.response['Error']['Code']
        if code in _SUBSCRIPTION_ERRORS or code == 'AccessDeniedException':
            return False
        if session.is_skippable(exc):
            return False
        raise

    if not all_events:
        log.info('%s: no open/upcoming Health org events', mgmt_account_id)
        return True

    for event in all_events:
        arn = event['arn']
        type_code = event.get('eventTypeCode', '')
        type_category = event.get('eventTypeCategory', '')
        finding_code = _finding_code(type_code, type_category)
        event_region = event.get('region') or 'global'
        service = event.get('service', '')
        status = event.get('statusCode', '')
        start_time = _iso(event.get('startTime'))
        end_time = _iso(event.get('endTime'))
        last_updated = _iso(event.get('lastUpdatedTime'))

        # Accounts affected by this org-level event
        affected_accounts: list[str] = []
        try:
            next_token = None
            while True:
                kwargs: dict = {'eventArn': arn}
                if next_token:
                    kwargs['nextToken'] = next_token
                resp = health.describe_affected_accounts_for_organization(**kwargs)
                affected_accounts.extend(resp.get('affectedAccounts', []))
                next_token = resp.get('nextToken')
                if not next_token:
                    break
        except ClientError as exc:
            log.debug('describe_affected_accounts_for_organization failed for %s: %s', arn, exc)

        if not affected_accounts:
            affected_accounts = [mgmt_account_id]

        # Event description — fetch once using the management account
        description = ''
        try:
            detail_resp = health.describe_event_details_for_organization(
                organizationEventDetailFilters=[
                    {'eventArn': arn, 'awsAccountId': mgmt_account_id}
                ]
            )
            for d in detail_resp.get('successfulSet', []):
                description = (d.get('eventDescription', {}).get('latestDescription') or '')[:_DETAIL_MAX]
                break
        except ClientError as exc:
            log.debug('describe_event_details_for_organization failed for %s: %s', arn, exc)

        for affected_acct in affected_accounts:
            entities: list[str] = []
            try:
                entity_paginator = health.get_paginator('describe_affected_entities_for_organization')
                for ep in entity_paginator.paginate(
                    organizationEntityFilters=[
                        {'eventArn': arn, 'awsAccountId': affected_acct}
                    ]
                ):
                    entities.extend(e.get('entityValue', '') for e in ep.get('entities', []))
            except ClientError as exc:
                log.debug('describe_affected_entities_for_organization failed for %s/%s: %s',
                          arn, affected_acct, exc)

            if not entities:
                _write_finding(writer, affected_acct, event_region, arn, '',
                               finding_code, description, type_code, type_category,
                               service, status, start_time, end_time, last_updated)
            else:
                for entity_value in entities:
                    _write_finding(writer, affected_acct, event_region, arn, entity_value,
                                   finding_code, description, type_code, type_category,
                                   service, status, start_time, end_time, last_updated)

    return True


def scan(sess, account_id: str, writer) -> None:
    health = sess.client('health', region_name='us-east-1')

    # Prefer org-wide sweep; falls back if account lacks org Health integration
    if _scan_org(health, account_id, writer):
        return

    # Per-account fallback
    try:
        paginator = health.get_paginator('describe_events')
        pages = paginator.paginate(
            filter={
                'eventStatusCodes': ['open', 'upcoming'],
                'eventTypeCategories': _EVENT_CATEGORIES,
            }
        )
    except ClientError as exc:
        code = exc.response['Error']['Code']
        if code == 'SubscriptionRequiredException':
            log.warning('%s: Health API unavailable -- account requires Business/Enterprise Support', account_id)
            return
        if session.is_skippable(exc):
            log.warning('%s: Health API skipped -- %s', account_id, code)
            return
        raise

    try:
        all_events: list[dict] = []
        for page in pages:
            all_events.extend(page.get('events', []))
    except ClientError as exc:
        code = exc.response['Error']['Code']
        if code == 'SubscriptionRequiredException':
            log.warning('%s: Health API unavailable -- account requires Business/Enterprise Support', account_id)
            return
        if session.is_skippable(exc):
            log.warning('%s: Health API pagination skipped -- %s', account_id, code)
            return
        raise

    if not all_events:
        log.info('%s: no open/upcoming Health events', account_id)
        return

    descriptions: dict[str, str] = {}
    for i in range(0, len(all_events), 10):
        batch_arns = [e['arn'] for e in all_events[i:i + 10]]
        descriptions.update(_fetch_descriptions(health, batch_arns))

    for event in all_events:
        arn = event['arn']
        type_code = event.get('eventTypeCode', '')
        type_category = event.get('eventTypeCategory', '')
        finding_code = _finding_code(type_code, type_category)
        event_region = event.get('region') or 'global'
        service = event.get('service', '')
        status = event.get('statusCode', '')
        start_time = _iso(event.get('startTime'))
        end_time = _iso(event.get('endTime'))
        last_updated = _iso(event.get('lastUpdatedTime'))
        description = descriptions.get(arn, '')

        entities = list(_iter_entities(health, arn))

        if not entities:
            _write_finding(writer, account_id, event_region, arn, '',
                           finding_code, description, type_code, type_category,
                           service, status, start_time, end_time, last_updated)
        else:
            for entity_value in entities:
                _write_finding(writer, account_id, event_region, arn, entity_value,
                               finding_code, description, type_code, type_category,
                               service, status, start_time, end_time, last_updated)


def main() -> None:
    parser = cli.make_parser(__doc__, account_level=True)
    args = parser.parse_args()
    cli.run(args, SCRIPT_NAME, scan, extra_fields=EXTRA_FIELDS, account_level=True)


if __name__ == '__main__':
    main()
