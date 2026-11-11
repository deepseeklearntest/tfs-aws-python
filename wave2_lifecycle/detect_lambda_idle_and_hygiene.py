#!/usr/bin/env python3
"""Read-only Lambda hygiene and potential inactivity assessment.

Place under wave2_lifecycle/ in the existing repository and run with
python wave2_lifecycle/detect_lambda_idle_and_hygiene.py --accounts 123456789012
No AWS resources are changed. Findings are candidates for owner review, NOT deletion.
"""
from __future__ import annotations

import logging
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from common import cli, session, tags as tagutil

SCRIPT_NAME = 'detect_lambda_idle_and_hygiene'
FIELDS = ['function_name', 'runtime', 'package_type', 'environment', 'last_modified',
          'activity_status', 'invocations_90d', 'invocations_180d', 'errors_180d',
          'last_observed_invocation_period', 'trigger_evidence', 'event_source_mapping_count',
          'alias_count', 'published_version_count', 'published_code_bytes',
          'provisioned_concurrency_allocated', 'log_retention_days', 'log_stored_bytes',
          'execution_role', 'assessment', 'confidence', 'recommended_review']
log = logging.getLogger(SCRIPT_NAME)


def pages(client: Any, operation: str, key: str, **kwargs: Any) -> list[dict]:
    return [item for page in client.get_paginator(operation).paginate(**kwargs)
            for item in page.get(key, [])]


def metrics(cw: Any, name: str, now: datetime) -> dict:
    """Sum unique CloudWatch daily points across pagination; missing data is unknown."""
    start = now - timedelta(days=180)
    queries = []
    for i, metric in enumerate(('Invocations', 'Errors')):
        queries.append({'Id': f'm{i}', 'MetricStat': {'Metric': {
            'Namespace': 'AWS/Lambda', 'MetricName': metric,
            'Dimensions': [{'Name': 'FunctionName', 'Value': name}]},
            'Period': 86400, 'Stat': 'Sum'}, 'ReturnData': True})
    points: dict[str, dict[datetime, float]] = {'m0': {}, 'm1': {}}
    states: dict[str, str] = {}
    token = None
    seen_tokens: set[str] = set()
    while True:
        args = {'MetricDataQueries': queries, 'StartTime': start,
                'EndTime': now, 'ScanBy': 'TimestampAscending'}
        if token:
            args['NextToken'] = token
        result = cw.get_metric_data(**args)
        for series in result.get('MetricDataResults', []):
            ident = series.get('Id')
            if ident not in points:
                session.mark_incomplete(f'Unexpected metric query ID for {name}')
                continue
            states[ident] = series.get('StatusCode', 'Complete')
            timestamps, values = series.get('Timestamps', []), series.get('Values', [])
            if len(timestamps) != len(values):
                session.mark_incomplete(f'Metric point mismatch for {name}:{ident}')
                continue
            for timestamp, value in zip(timestamps, values):
                if timestamp in points[ident] and points[ident][timestamp] != value:
                    session.mark_incomplete(f'Conflicting metric datapoint for {name}:{ident}')
                points[ident][timestamp] = float(value)
        next_token = result.get('NextToken')
        if not next_token:
            break
        if next_token in seen_tokens:
            session.mark_incomplete(f'Repeated CloudWatch pagination token for {name}')
            break
        seen_tokens.add(next_token)
        token = next_token
    if set(states) != set(points) or any(s != 'Complete' for s in states.values()):
        session.mark_incomplete(f'Unresolved CloudWatch metric result for {name}')
        return {'status': 'incomplete', 'inv90': '', 'inv180': '', 'err180': '', 'last': ''}
    if not any(points.values()):
        return {'status': 'no-data', 'inv90': '', 'inv180': '', 'err180': '', 'last': ''}
    cutoff90 = now - timedelta(days=90)
    invoked = [t for t, v in points['m0'].items() if v > 0]
    return {'status': 'available',
            'inv90': str(int(sum(v for t, v in points['m0'].items() if t >= cutoff90))),
            'inv180': str(int(sum(points['m0'].values()))),
            'err180': str(int(sum(points['m1'].values()))),
            'last': max(invoked).isoformat() if invoked else ''}


def assess(activity: dict, trigger_evidence: list[str], concurrency: int) -> tuple[str, str]:
    if activity['status'] != 'available':
        return 'Insufficient Evidence', 'Low'
    if int(activity['inv180']) > 0:
        return 'Observed Active', 'High'
    if concurrency > 0 or trigger_evidence:
        return 'No Observed Activity - Configured Dependencies', 'Medium'
    return 'Potentially Idle - Owner Review', 'Medium'


def scan(sess: Any, account_id: str, region: str, writer: Any) -> None:
    lam = sess.client('lambda', region_name=region)
    cw = sess.client('cloudwatch', region_name=region)
    logs = sess.client('logs', region_name=region)
    now = datetime.now(timezone.utc)
    try:
        functions = pages(lam, 'list_functions', 'Functions')
        mappings = pages(lam, 'list_event_source_mappings', 'EventSourceMappings')
    except ClientError as exc:
        if session.is_skippable(exc):
            return
        raise
    mappings_by_function: dict[str, list[dict]] = {}
    for mapping in mappings:
        arn = mapping.get('FunctionArn', '')
        base = arn.split(':function:')[-1].split(':')[0]
        mappings_by_function.setdefault(base, []).append(mapping)
    for fn in functions:
        name = fn['FunctionName']
        arn = fn['FunctionArn']
        try:
            versions = pages(lam, 'list_versions_by_function', 'Versions', FunctionName=name)
            aliases = pages(lam, 'list_aliases', 'Aliases', FunctionName=name)
            provisioned = pages(lam, 'list_provisioned_concurrency_configs',
                                'ProvisionedConcurrencyConfigs', FunctionName=name)
            tags = lam.list_tags(Resource=arn).get('Tags') or {}
            policy = None
            try:
                policy = lam.get_policy(FunctionName=name).get('Policy')
            except ClientError as exc:
                if exc.response['Error']['Code'] not in ('ResourceNotFoundException',):
                    raise
            log_groups = logs.describe_log_groups(logGroupNamePrefix=f'/aws/lambda/{name}').get('logGroups', [])
            log_group = next((g for g in log_groups if g.get('logGroupName') == f'/aws/lambda/{name}'), {})
            activity = metrics(cw, name, now)
        except ClientError as exc:
            if session.is_skippable(exc):
                continue
            raise
        except Exception:
            log.exception('Assessment failed for %s/%s/%s', account_id, region, name)
            raise
        mapping_count = len(mappings_by_function.get(name, []))
        trigger_evidence = []
        if mapping_count:
            trigger_evidence.append('event-source-mapping')
        if policy:
            trigger_evidence.append('resource-policy-present')
        if aliases:
            trigger_evidence.append('aliases-present')
        allocated = sum(int(p.get('AllocatedProvisionedConcurrentExecutions') or 0)
                        for p in provisioned)
        if allocated:
            trigger_evidence.append('provisioned-concurrency')
        status, confidence = assess(activity, trigger_evidence, allocated)
        environment = tagutil.tag_value(tags, 'Environment')
        owner = tagutil.owner_from_tags(tags)
        published = [v for v in versions if str(v.get('Version')) != '$LATEST']
        common = dict(account_id=account_id, region=region, resource_id=arn,
                      resource_type='Lambda Function', tags=tags, owner=owner,
                      function_name=name, runtime=fn.get('Runtime', ''),
                      package_type=fn.get('PackageType', 'Zip'), environment=environment,
                      last_modified=fn.get('LastModified', ''),
                      activity_status=activity['status'], invocations_90d=activity['inv90'],
                      invocations_180d=activity['inv180'], errors_180d=activity['err180'],
                      last_observed_invocation_period=activity['last'],
                      trigger_evidence=';'.join(trigger_evidence),
                      event_source_mapping_count=mapping_count, alias_count=len(aliases),
                      published_version_count=len(published),
                      published_code_bytes=sum(int(v.get('CodeSize') or 0) for v in published),
                      provisioned_concurrency_allocated=allocated,
                      log_retention_days=log_group.get('retentionInDays', ''),
                      log_stored_bytes=log_group.get('storedBytes', ''),
                      execution_role=fn.get('Role', ''), assessment=status, confidence=confidence,
                      recommended_review='Validate business ownership, triggers, DR and seasonal use before any change.',
                      estimated_monthly_savings_usd=None)
        findings = []
        if status == 'Potentially Idle - Owner Review':
            findings.append('potentially-idle-180d')
        elif status.startswith('No Observed Activity'):
            findings.append('no-observed-activity-with-dependencies')
        elif status == 'Insufficient Evidence':
            findings.append('activity-evidence-unavailable')
        if allocated:
            findings.append('provisioned-concurrency-cost-review')
        if len(published) >= 20:
            findings.append('published-version-accumulation')
        if log_group and 'retentionInDays' not in log_group:
            findings.append('log-retention-not-configured')
        if not owner:
            findings.append('owner-tag-missing')
        if not environment:
            findings.append('environment-tag-missing')
        if not trigger_evidence:
            findings.append('no-known-trigger-evidence')
        for finding in findings:
            writer.write(**common, finding=finding,
                         detail=f'{status}; evidence={";".join(trigger_evidence) or "none-discovered"}')


def main() -> None:
    parser = cli.make_parser(__doc__)
    args = parser.parse_args()
    cli.run(args, SCRIPT_NAME, scan, extra_fields=FIELDS)


if __name__ == '__main__':
    main()
