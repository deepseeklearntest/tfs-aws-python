#!/usr/bin/env python3
"""Task 15 - Lambda Runtime Lifecycle and Security-Risk Assessment

Read-only inventory of Lambda runtimes, published versions, aliases, and
optional CloudWatch activity. Findings require business review; this script
never changes AWS resources or triggers external workflows.

Run: python 15_detect_lambda_deprecated_runtimes.py --accounts 123456789012
"""
from __future__ import annotations

import json
import logging
import sys
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

from botocore.exceptions import ClientError

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from common import cli, session, tags as tagutil

SCRIPT_NAME = '15_detect_lambda_deprecated_runtimes'
EXTRA_FIELDS = [
    'function_name', 'runtime', 'last_modified', 'memory_mb',
    'severity', 'eol_date', 'days_past_eol', 'days_until_eol',
    'lifecycle_status', 'lifecycle_urgency', 'risk_level', 'risk_reason',
    'days_until_deprecation', 'days_past_deprecation',
    'deprecation_date', 'creation_block_date', 'update_block_date',
    'creation_block_status', 'update_block_status',
    'lifecycle_reference_verified_on', 'lifecycle_data_status',
    'version_inventory_status',
    'function_version', 'alias_name', 'alias_references',
    'alias_traffic_weight', 'alias_inventory_status',
    'package_type', 'environment', 'function_owner',
    'last_invoked', 'activity_status',
    'invocations_7d', 'errors_7d',
    'invocations_30d', 'errors_30d',
    'invocations_90d', 'errors_90d',
    'recommended_action',
]

# Deprecation and create/update block dates were checked against the current
# supported and deprecated runtime tables on 2026-10-27.
LIFECYCLE_REFERENCE_VERIFIED_ON = date(2026, 10, 27)
LIFECYCLE_REFERENCE_STATUS = 'verified'
LIFECYCLE_REFERENCE_URL = 'https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html'
LIFECYCLE_REFERENCE_MAX_AGE_DAYS = 90
RUNTIME_EOL: dict[str, date] = {
    'nodejs': date(2016, 8, 30), 'nodejs4.3': date(2020, 3, 5),
    'nodejs4.3-edge': date(2020, 3, 5), 'nodejs6.10': date(2019, 8, 12),
    'nodejs8.10': date(2020, 3, 6), 'nodejs10.x': date(2021, 7, 30),
    'nodejs12.x': date(2023, 3, 31), 'nodejs14.x': date(2023, 12, 4),
    'nodejs16.x': date(2024, 6, 12), 'nodejs18.x': date(2025, 9, 1),
    'nodejs20.x': date(2026, 4, 30), 'nodejs22.x': date(2027, 4, 30),
    'nodejs24.x': date(2028, 4, 30),
    'python2.7': date(2021, 7, 15), 'python3.6': date(2022, 7, 18),
    'python3.7': date(2023, 12, 4), 'python3.8': date(2024, 10, 14),
    'python3.9': date(2025, 12, 15), 'python3.10': date(2026, 10, 31),
    'python3.11': date(2027, 6, 30), 'python3.12': date(2028, 10, 31),
    'python3.13': date(2029, 6, 30), 'python3.14': date(2029, 6, 30),
    'ruby2.5': date(2021, 7, 30), 'ruby2.7': date(2023, 12, 7),
    'ruby3.2': date(2026, 3, 31), 'ruby3.3': date(2027, 3, 31),
    'ruby3.4': date(2028, 3, 31), 'ruby4.0': date(2029, 3, 31),
    'dotnetcore1.0': date(2019, 6, 27), 'dotnetcore2.0': date(2019, 5, 30),
    'dotnetcore2.1': date(2022, 1, 5), 'dotnetcore3.1': date(2023, 4, 3),
    'dotnet6': date(2024, 12, 20), 'dotnet8': date(2026, 11, 10),
    'dotnet10': date(2028, 11, 14),
    'java8': date(2024, 1, 8), 'java8.al2': date(2027, 6, 30),
    'java11': date(2027, 6, 30), 'java17': date(2027, 6, 30),
    'java8.al2023': date(2029, 6, 30), 'java11.al2023': date(2029, 6, 30),
    'java17.al2023': date(2029, 6, 30), 'java21': date(2029, 6, 30),
    'java25': date(2029, 6, 30), 'go1.x': date(2024, 1, 8),
    'provided': date(2024, 1, 8), 'provided.al2': date(2026, 7, 31),
    'provided.al2023': date(2029, 6, 30),
}
UNSCHEDULED_RUNTIMES = {'nodejs26.x', 'python3.15'}
RUNTIME_CREATE_BLOCK: dict[str, date] = {
    'nodejs': date(2016, 9, 30), 'nodejs4.3': date(2020, 2, 3),
    'nodejs4.3-edge': date(2019, 3, 31), 'nodejs6.10': date(2019, 7, 12),
    'nodejs8.10': date(2020, 2, 4), 'nodejs10.x': date(2021, 7, 30),
    'nodejs12.x': date(2023, 3, 31), 'nodejs14.x': date(2024, 1, 9),
    'nodejs16.x': date(2027, 7, 29), 'nodejs18.x': date(2027, 7, 29),
    'nodejs20.x': date(2027, 7, 29),
    'nodejs24.x': date(2028, 6, 1), 'nodejs22.x': date(2027, 7, 29),
    'python2.7': date(2021, 7, 15), 'python3.6': date(2022, 7, 18),
    'python3.7': date(2024, 1, 9), 'python3.8': date(2027, 7, 29),
    'python3.9': date(2027, 7, 29),
    'python3.14': date(2029, 7, 31), 'python3.13': date(2029, 7, 31),
    'python3.12': date(2028, 11, 30), 'python3.11': date(2027, 7, 29),
    'python3.10': date(2027, 7, 29),
    'ruby2.5': date(2021, 7, 30), 'ruby2.7': date(2024, 1, 9),
    'ruby3.2': date(2027, 7, 29),
    'dotnetcore1.0': date(2019, 6, 30), 'dotnetcore2.0': date(2019, 4, 30),
    'dotnetcore2.1': date(2022, 1, 5), 'dotnetcore3.1': date(2023, 4, 3),
    'dotnet6': date(2027, 7, 29),
    'java25': date(2029, 7, 31), 'java21': date(2029, 7, 31),
    'java17.al2023': date(2029, 7, 31), 'java11.al2023': date(2029, 7, 31),
    'java8.al2023': date(2029, 7, 31),
    'java8': date(2024, 2, 8), 'go1.x': date(2024, 2, 8),
    'provided': date(2024, 2, 8), 'provided.al2': date(2027, 7, 29),
    'java17': date(2027, 7, 29), 'java11': date(2027, 7, 29),
    'java8.al2': date(2027, 7, 29),
    'dotnet10': date(2028, 12, 14), 'dotnet8': date(2027, 7, 29),
    'ruby4.0': date(2029, 4, 30), 'ruby3.4': date(2028, 4, 30),
    'ruby3.3': date(2027, 7, 29), 'provided.al2023': date(2029, 7, 31),
}
RUNTIME_UPDATE_BLOCK: dict[str, date] = {
    'nodejs': date(2016, 10, 31), 'nodejs4.3': date(2020, 3, 5),
    'nodejs4.3-edge': date(2019, 4, 30), 'nodejs6.10': date(2019, 8, 12),
    'nodejs8.10': date(2020, 3, 6), 'nodejs10.x': date(2022, 2, 14),
    'nodejs12.x': date(2023, 4, 30), 'nodejs14.x': date(2027, 8, 31),
    'nodejs16.x': date(2027, 8, 31), 'nodejs18.x': date(2027, 8, 31),
    'nodejs20.x': date(2027, 8, 31),
    'nodejs24.x': date(2028, 7, 1), 'nodejs22.x': date(2027, 8, 31),
    'python2.7': date(2022, 5, 30), 'python3.6': date(2022, 8, 29),
    'python3.7': date(2027, 8, 31), 'python3.8': date(2027, 8, 31),
    'python3.9': date(2027, 8, 31),
    'python3.14': date(2029, 8, 31), 'python3.13': date(2029, 8, 31),
    'python3.12': date(2029, 1, 10), 'python3.11': date(2027, 8, 31),
    'python3.10': date(2027, 8, 31),
    'ruby2.5': date(2022, 3, 31), 'ruby2.7': date(2027, 8, 31),
    'ruby3.2': date(2027, 8, 31),
    'dotnetcore1.0': date(2019, 7, 30), 'dotnetcore2.0': date(2019, 5, 30),
    'dotnetcore2.1': date(2022, 4, 13), 'dotnetcore3.1': date(2023, 5, 3),
    'dotnet6': date(2027, 8, 31),
    'java25': date(2029, 8, 31), 'java21': date(2029, 8, 31),
    'java17.al2023': date(2029, 8, 31), 'java11.al2023': date(2029, 8, 31),
    'java8.al2023': date(2029, 8, 31),
    'java8': date(2027, 8, 31), 'go1.x': date(2027, 8, 31),
    'provided': date(2027, 8, 31), 'provided.al2': date(2027, 8, 31),
    'java17': date(2027, 8, 31), 'java11': date(2027, 8, 31),
    'java8.al2': date(2027, 8, 31),
    'dotnet10': date(2029, 1, 15), 'dotnet8': date(2027, 8, 31),
    'ruby4.0': date(2029, 5, 31), 'ruby3.4': date(2028, 5, 31),
    'ruby3.3': date(2027, 8, 31), 'provided.al2023': date(2029, 8, 31),
}

WARN_SOON_DAYS = 180
URGENCY_30_DAYS = 30
URGENCY_90_DAYS = 90
METRIC_WINDOWS = (7, 30, 90)
METRIC_QUERY_BATCH_SIZE = 500
log = logging.getLogger(SCRIPT_NAME)


def _classify(runtime: str, today: date) -> tuple[str, str, str, str, str] | None:
    """Keep the original classification API for existing callers and tests."""
    eol = RUNTIME_EOL.get(runtime)
    if eol is None:
        return None

    eol_str = eol.isoformat()
    delta = (eol - today).days
    if delta <= 0:
        return 'deprecated', 'deprecated-runtime', eol_str, str(-delta), ''
    if delta <= WARN_SOON_DAYS:
        return 'eol-soon', 'runtime-eol-soon', eol_str, '', str(delta)
    return None


def _lifecycle_data_status(today: date) -> str:
    if LIFECYCLE_REFERENCE_STATUS != 'verified':
        return 'unverified'
    if (today - LIFECYCLE_REFERENCE_VERIFIED_ON).days > LIFECYCLE_REFERENCE_MAX_AGE_DAYS:
        return 'stale'
    return 'verified'


def _assess_runtime(runtime: str, package_type: str, today: date) -> dict[str, Any]:
    if package_type == 'Image':
        return {
            'status': 'container-image-assessment-required',
            'finding': 'container-image-runtime-assessment-required',
            'urgency': 'not-applicable',
            'deprecation_date': '',
            'days_until': '',
            'days_past': '',
        }

    lifecycle = _classify(runtime, today)
    if lifecycle is None:
        if runtime in UNSCHEDULED_RUNTIMES:
            return {
                'status': 'deprecation-date-unannounced',
                'finding': 'runtime-lifecycle-date-unannounced',
                'urgency': 'not-scheduled',
                'deprecation_date': '', 'days_until': '', 'days_past': '',
            }
        if runtime in RUNTIME_EOL:
            return {
                'status': 'supported', 'finding': '', 'urgency': 'none',
                'deprecation_date': RUNTIME_EOL[runtime].isoformat(),
                'days_until': str((RUNTIME_EOL[runtime] - today).days),
                'days_past': '',
            }
        return {
            'status': 'unknown-runtime', 'finding': 'unknown-runtime',
            'urgency': 'unknown', 'deprecation_date': '',
            'days_until': '', 'days_past': '',
        }

    status, finding, deprecation_date, days_past, days_until = lifecycle
    if status == 'deprecated':
        urgency = 'past-deprecation'
        days_until = ''
    else:
        days = int(days_until)
        urgency = (
            'within-30-days' if days <= URGENCY_30_DAYS
            else 'within-90-days' if days <= URGENCY_90_DAYS
            else 'within-180-days'
        )
    return {
        'status': 'deprecated' if status == 'deprecated' else 'deprecation-approaching',
        'finding': finding, 'urgency': urgency,
        'deprecation_date': deprecation_date,
        'days_until': days_until, 'days_past': days_past,
    }


def _base_risk(
    assessment: dict[str, Any],
    environment: str,
    function_version: str,
    alias_references: list[tuple[str, float]],
    activity: dict[str, Any] | None = None,
) -> tuple[str, str]:
    status = assessment['status']
    if status == 'container-image-assessment-required':
        reasons = ['Image-based function: base image and bundled runtime are not inspected']
        risk = 'Review Required'
    elif status == 'deprecation-date-unannounced':
        reasons = ['AWS has not announced a deprecation date for this runtime']
        risk = 'Review Required'
    elif status == 'unknown-runtime':
        reasons = ['Runtime is missing or not present in the maintained lifecycle table']
        risk = 'Review Required'
    elif status == 'deprecated':
        reasons = [
            f"Runtime deprecation date passed ({assessment['deprecation_date']})",
            'Lifecycle exposure is not proof of a vulnerability',
        ]
        if environment.strip().lower() == 'production':
            active_aliases = [weight for _, weight in alias_references if weight > 0]
            observed_invocations = bool(
                activity
                and activity.get('activity_status') == 'available'
                and any(
                    int(activity.get(f'invocations_{window}d') or 0) > 0
                    for window in METRIC_WINDOWS
                )
            )
            if active_aliases or observed_invocations:
                risk = 'High'
                evidence = 'active alias routing' if active_aliases else 'observed invocations'
                reasons.append(
                    f'Production environment is explicitly tagged and {evidence} confirms exposure'
                )
            else:
                risk = 'Review Required'
                reasons.append(
                    'Production is explicitly tagged but current usage is not confirmed; '
                    'missing activity data does not prove disuse'
                )
        else:
            risk = 'Review Required'
            reasons.append('Production impact is not established by explicit environment metadata')
    elif status == 'deprecation-approaching':
        days = int(assessment['days_until'])
        risk = 'Medium' if days <= URGENCY_90_DAYS else 'Low'
        reasons = [f"Runtime is scheduled for deprecation in {days} day(s)"]
    else:
        risk = ''
        reasons = []
    return risk, '; '.join(reasons)


def _block_date_status(
    runtime: str,
    package_type: str,
    dates: dict[str, date],
    today: date,
) -> str:
    if package_type == 'Image':
        return 'not-applicable'
    if runtime in UNSCHEDULED_RUNTIMES:
        return 'not-scheduled'
    if runtime not in RUNTIME_EOL:
        return 'unknown'
    block_date = dates.get(runtime)
    if block_date is None:
        return 'not-recorded'
    return 'passed' if block_date <= today else 'scheduled'


def _function_arn(function_arn: str) -> str:
    parts = function_arn.split(':')
    return ':'.join(parts[:7]) if len(parts) > 7 else function_arn


def _fetch_pages(client: Any, operation: str, result_key: str, **kwargs: Any) -> list[dict[str, Any]]:
    paginator = client.get_paginator(operation)
    return [
        item
        for page in paginator.paginate(**kwargs)
        for item in page.get(result_key, [])
    ]


def _metric_queries(
    versions: list[dict[str, Any]], function_name: str,
) -> tuple[list[dict[str, Any]], dict[str, tuple[str, str]]]:
    queries: list[dict[str, Any]] = []
    query_map: dict[str, tuple[str, str]] = {}
    for version in versions:
        version_id = str(version.get('Version', '$LATEST'))
        resource = f'{function_name}:{version_id}'
        for metric_name in ('Invocations', 'Errors'):
            query_id = f'm{len(queries):08d}'
            queries.append({
                'Id': query_id,
                'MetricStat': {
                    'Metric': {
                        'Namespace': 'AWS/Lambda',
                        'MetricName': metric_name,
                        'Dimensions': [
                            {'Name': 'FunctionName', 'Value': function_name},
                            {'Name': 'Resource', 'Value': resource},
                        ],
                    },
                    'Period': 86400,
                    'Stat': 'Sum',
                },
                'ReturnData': True,
            })
            query_map[query_id] = (version_id, metric_name)
    return queries, query_map


def _collect_metrics(
    cloudwatch: Any,
    versions: list[dict[str, Any]],
    function_name: str,
    now: datetime,
    windows: tuple[int, ...],
) -> dict[str, dict[str, Any]]:
    """Read daily version metrics in bounded GetMetricData batches."""
    output: dict[str, dict[str, Any]] = {}
    for version in versions:
        version_id = str(version.get('Version', '$LATEST'))
        output[version_id] = {
            'activity_status': 'no-data',
            'last_invoked': '',
        }
        for window in windows:
            output[version_id][f'invocations_{window}d'] = ''
            output[version_id][f'errors_{window}d'] = ''

    queries, query_map = _metric_queries(versions, function_name)
    start_time = now - timedelta(days=max(windows))
    for offset in range(0, len(queries), METRIC_QUERY_BATCH_SIZE):
        batch = queries[offset:offset + METRIC_QUERY_BATCH_SIZE]
        batch_map = {query['Id']: query_map[query['Id']] for query in batch}
        datapoints: dict[str, dict[datetime, float]] = {
            query_id: {} for query_id in batch_map
        }
        query_status: dict[str, str] = {}
        token = None
        returned_query_ids: set[str] = set()
        while True:
            params: dict[str, Any] = {
                'MetricDataQueries': batch,
                'StartTime': start_time,
                'EndTime': now,
                'ScanBy': 'TimestampAscending',
            }
            if token:
                params['NextToken'] = token
            response = cloudwatch.get_metric_data(**params)
            for result in response.get('MetricDataResults', []):
                query_id = result['Id']
                returned_query_ids.add(query_id)
                query_status[query_id] = result.get('StatusCode', 'Complete')
                timestamps = result.get('Timestamps', [])
                values = result.get('Values', [])
                for timestamp, value in zip(timestamps, values):
                    # Preserve one value per metric period when pages overlap.
                    datapoints[query_id].setdefault(timestamp, value)
            token = response.get('NextToken')
            if not token:
                break

        for query_id, (version_id, metric_name) in batch_map.items():
            if query_id not in returned_query_ids:
                session.mark_incomplete(
                    f"CloudWatch {metric_name} metric result missing for "
                    f"{function_name}:{version_id}"
                )
                output[version_id]['activity_status'] = 'unavailable'
                continue

            status = query_status.get(query_id, 'Complete')
            if status != 'Complete':
                session.mark_incomplete(
                    f"CloudWatch {metric_name} metric query unresolved "
                    f"({status}) for {function_name}:{version_id}"
                )
                if output[version_id]['activity_status'] != 'unavailable':
                    output[version_id]['activity_status'] = 'partial'

            points = datapoints[query_id]
            if points and output[version_id]['activity_status'] not in (
                'partial', 'unavailable',
            ):
                output[version_id]['activity_status'] = 'available'
            if metric_name == 'Invocations':
                observed = [
                    timestamp for timestamp, value in points.items() if value > 0
                ]
                if observed:
                    # CloudWatch timestamps identify metric periods, not exact invokes.
                    output[version_id]['last_invoked'] = max(observed).isoformat()
            for window in windows:
                cutoff = now - timedelta(days=window)
                total = sum(
                    value for timestamp, value in points.items()
                    if timestamp >= cutoff
                )
                if points:
                    output[version_id][f'{metric_name.lower()}_{window}d'] = str(int(total))
    return output


def _alias_targets(aliases: list[dict[str, Any]]) -> dict[str, list[tuple[str, float]]]:
    references: dict[str, list[tuple[str, float]]] = {}
    for alias in aliases:
        alias_name = str(alias.get('Name', ''))
        primary_version = str(alias.get('FunctionVersion', ''))
        additional = (alias.get('RoutingConfig') or {}).get(
            'AdditionalVersionWeights', {}
        )
        additional_total = sum(float(weight) for weight in additional.values())
        primary_weight = max(0.0, 1.0 - additional_total)
        if primary_version:
            references.setdefault(primary_version, []).append((alias_name, primary_weight))
        for version, weight in additional.items():
            references.setdefault(str(version), []).append((alias_name, float(weight)))
    return references


def _risk_for_version(
    assessment: dict[str, Any],
    environment: str,
    version_id: str,
    references: list[tuple[str, float]],
    owner: str,
    alias_status: str,
    activity: dict[str, Any],
) -> tuple[str, str]:
    risk, reason = _base_risk(
        assessment, environment, version_id, references, activity
    )
    if not risk:
        return '', ''
    reasons = [reason]
    if assessment['status'] in ('deprecated', 'deprecation-approaching') and not owner:
        if risk != 'High':
            risk = 'Review Required'
        reasons.append('No recognized owner tag was available')
    if alias_status != 'available':
        if risk != 'High':
            risk = 'Review Required'
        reasons.append('Alias inventory is incomplete')
    if version_id != '$LATEST' and not references:
        if risk != 'High':
            risk = 'Review Required'
        reasons.append('No alias reference found; direct qualified-ARN invocation cannot be excluded')
    elif references:
        reasons.append('Alias routing: ' + ', '.join(
            f'{name}={weight:.4f}' for name, weight in references
        ))
    if activity.get('activity_status') == 'available':
        last_period = activity.get('last_invoked') or 'not observed'
        invocation_counts = ', '.join(
            f"{window}d={activity.get(f'invocations_{window}d', '')}"
            for window in METRIC_WINDOWS
            if activity.get(f'invocations_{window}d', '') != ''
        )
        reasons.append(
            f"CloudWatch activity available; last observed invocation period={last_period}"
            + (f'; invocations {invocation_counts}' if invocation_counts else '')
        )
    return risk, '; '.join(reasons)


def _emit_finding(
    writer: Any,
    account_id: str,
    region: str,
    function_name: str,
    function_arn: str,
    function: dict[str, Any],
    tags: dict[str, str],
    version_id: str,
    references: list[tuple[str, float]],
    alias_status: str,
    version_inventory_status: str,
    today: date,
    reference_status: str,
    reference_verified_on: str,
    activity: dict[str, Any],
) -> None:
    runtime = str(function.get('Runtime') or '')
    package_type = str(function.get('PackageType') or 'Zip')
    assessment = _assess_runtime(runtime, package_type, today)
    if not assessment['finding']:
        return

    environment = tagutil.tag_value(tags, 'Environment')
    owner = tagutil.owner_from_tags(tags)
    risk, risk_reason = _risk_for_version(
        assessment, environment, version_id, references, owner, alias_status,
        activity,
    )
    if reference_status != 'verified':
        risk = 'Review Required'
        risk_reason = '; '.join(filter(None, [
            risk_reason,
            f'Lifecycle reference data is {reference_status}',
        ]))
    if version_inventory_status != 'available':
        risk = 'Review Required'
        risk_reason = '; '.join(filter(None, [
            risk_reason, 'Published-version inventory is incomplete',
        ]))
    aliases = [name for name, _ in references]
    alias_weights = {name: weight for name, weight in references}
    days_until = assessment['days_until']
    days_past = assessment['days_past']
    legacy_severity = (
        'deprecated' if assessment['status'] == 'deprecated'
        else 'eol-soon' if assessment['status'] == 'deprecation-approaching'
        else risk.lower().replace(' ', '-')
    )
    detail = (
        f"function={function_name} version={version_id} runtime={runtime or 'missing'} "
        f"package_type={package_type} lifecycle={assessment['status']} "
        f"risk={risk} aliases={','.join(aliases) or 'none'}"
    )
    writer.write(
        account_id=account_id,
        region=region,
        resource_id=str(function.get('FunctionArn') or function_arn),
        resource_type='Lambda Function',
        finding=assessment['finding'],
        detail=detail,
        estimated_monthly_savings_usd=0,
        tags=tags,
        owner=owner,
        function_name=function_name,
        runtime=runtime,
        last_modified=function.get('LastModified', ''),
        memory_mb=function.get('MemorySize', ''),
        severity=legacy_severity,
        eol_date=assessment['deprecation_date'],
        days_past_eol=days_past,
        days_until_eol=days_until,
        lifecycle_status=assessment['status'],
        lifecycle_urgency=assessment['urgency'],
        risk_level=risk,
        risk_reason=risk_reason,
        days_until_deprecation=days_until,
        days_past_deprecation=days_past,
        deprecation_date=assessment['deprecation_date'],
        creation_block_date=(
            RUNTIME_CREATE_BLOCK.get(runtime).isoformat()
            if runtime in RUNTIME_CREATE_BLOCK else ''
        ),
        creation_block_status=_block_date_status(
            runtime, package_type, RUNTIME_CREATE_BLOCK, today
        ),
        update_block_date=(
            RUNTIME_UPDATE_BLOCK.get(runtime).isoformat()
            if runtime in RUNTIME_UPDATE_BLOCK else ''
        ),
        update_block_status=_block_date_status(
            runtime, package_type, RUNTIME_UPDATE_BLOCK, today
        ),
        lifecycle_reference_verified_on=reference_verified_on,
        lifecycle_data_status=reference_status,
        version_inventory_status=version_inventory_status,
        function_version=version_id,
        alias_name=';'.join(aliases),
        alias_references=json.dumps(alias_weights, sort_keys=True),
        alias_traffic_weight=json.dumps(alias_weights, sort_keys=True),
        alias_inventory_status=alias_status,
        package_type=package_type,
        environment=environment,
        function_owner=owner,
        last_invoked=activity.get('last_invoked', ''),
        activity_status=activity.get('activity_status', 'not-requested'),
        invocations_7d=activity.get('invocations_7d', ''),
        errors_7d=activity.get('errors_7d', ''),
        invocations_30d=activity.get('invocations_30d', ''),
        errors_30d=activity.get('errors_30d', ''),
        invocations_90d=activity.get('invocations_90d', ''),
        errors_90d=activity.get('errors_90d', ''),
        recommended_action=(
            'Review runtime lifecycle and plan an application-owner-approved '
            'migration; no changes were made by this scanner.'
        ),
    )


def make_scan(
    cloudwatch_metrics: bool = False,
    metric_windows: tuple[int, ...] = METRIC_WINDOWS,
    today_provider: Callable[[], date] = date.today,
    now_provider: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> Callable:
    """Build the standard CLI scan callable with optional read-only metrics."""
    if not metric_windows or any(window not in METRIC_WINDOWS for window in metric_windows):
        raise ValueError('metric_windows must contain one or more of 7, 30, or 90')

    def scan(sess: Any, account_id: str, region: str, writer: Any) -> None:
        lambda_client = sess.client('lambda', region_name=region)
        today = today_provider()
        reference_status = _lifecycle_data_status(today)
        reference_date = LIFECYCLE_REFERENCE_VERIFIED_ON.isoformat()
        if reference_status != 'verified':
            session.mark_incomplete(
                f"Lifecycle reference data is {reference_status}; verify "
                f"{LIFECYCLE_REFERENCE_URL} before treating lifecycle results as current"
            )

        try:
            functions = _fetch_pages(lambda_client, 'list_functions', 'Functions')
        except ClientError as exc:
            if session.is_skippable(exc):
                log.info('%s/%s Lambda inventory inaccessible (%s)', account_id, region,
                         exc.response['Error']['Code'])
                return
            raise

        for listed_function in functions:
            function_name = str(listed_function['FunctionName'])
            function_arn = _function_arn(str(listed_function['FunctionArn']))
            package_type = str(listed_function.get('PackageType') or 'Zip')
            latest = dict(listed_function)
            latest.setdefault('Version', '$LATEST')
            version_status = 'available'
            try:
                versions = _fetch_pages(
                    lambda_client, 'list_versions_by_function', 'Versions',
                    FunctionName=function_name,
                )
            except ClientError as exc:
                if session.is_skippable(exc):
                    version_status = 'unavailable'
                    versions = []
                else:
                    raise
            versions_by_id = {str(version.get('Version', '$LATEST')): version for version in versions}
            versions_by_id.setdefault('$LATEST', latest)
            all_versions = list(versions_by_id.values())
            assessments = {
                version_id: _assess_runtime(
                    str(version.get('Runtime') or ''),
                    str(version.get('PackageType') or package_type),
                    today,
                )
                for version_id, version in versions_by_id.items()
            }
            if not any(
                assessment['finding'] for assessment in assessments.values()
            ):
                continue

            alias_status = 'available'
            try:
                aliases = _fetch_pages(
                    lambda_client, 'list_aliases', 'Aliases',
                    FunctionName=function_name,
                )
            except ClientError as exc:
                if session.is_skippable(exc):
                    alias_status = 'unavailable'
                    aliases = []
                else:
                    raise
            references = _alias_targets(aliases)

            tags: dict[str, str] = {}
            try:
                tags = lambda_client.list_tags(Resource=function_arn).get('Tags') or {}
            except ClientError as exc:
                if not session.is_skippable(exc):
                    raise

            activity_by_version: dict[str, dict[str, Any]] = {}
            metric_versions = [
                version for version in all_versions
                if assessments[str(version.get('Version', '$LATEST'))]['finding']
            ]
            if cloudwatch_metrics and metric_versions:
                cloudwatch = sess.client('cloudwatch', region_name=region)
                try:
                    activity_by_version = _collect_metrics(
                        cloudwatch, metric_versions, function_name,
                        now_provider(), metric_windows,
                    )
                except ClientError as exc:
                    if not session.is_skippable(exc):
                        raise
                    activity_by_version = {
                        str(version.get('Version', '$LATEST')): {
                            'activity_status': 'unavailable',
                        }
                        for version in metric_versions
                    }

            for version_id, version in versions_by_id.items():
                version.setdefault('PackageType', package_type)
                assessment = assessments[version_id]
                if assessment['status'] == 'unknown-runtime':
                    session.mark_incomplete(
                        f"Unknown or missing Lambda runtime for {function_name}:{version_id}"
                    )
                _emit_finding(
                    writer, account_id, region, function_name, function_arn,
                    version, tags, version_id, references.get(version_id, []),
                    alias_status, version_status, today, reference_status,
                    reference_date, activity_by_version.get(
                        version_id, {'activity_status': 'not-requested'}
                    ),
                )

    return scan


def _parse_metric_windows(value: str) -> tuple[int, ...]:
    try:
        windows = tuple(dict.fromkeys(int(item.strip()) for item in value.split(',')))
    except ValueError as exc:
        raise ValueError('--metric-windows must be a comma-separated subset of 7,30,90') from exc
    if not windows or any(window not in METRIC_WINDOWS for window in windows):
        raise ValueError('--metric-windows must be a comma-separated subset of 7,30,90')
    return windows


def main() -> None:
    parser = cli.make_parser(__doc__)
    parser.add_argument(
        '--cloudwatch-metrics', action='store_true',
        help='Read optional per-version invocation/error metrics from CloudWatch',
    )
    parser.add_argument(
        '--metric-windows', default='7,30,90',
        help='Comma-separated CloudWatch windows to collect (subset of 7,30,90; default: 7,30,90)',
    )
    args = parser.parse_args()
    try:
        windows = _parse_metric_windows(args.metric_windows)
    except ValueError as exc:
        parser.error(str(exc))
    cli.run(
        args, SCRIPT_NAME,
        make_scan(args.cloudwatch_metrics, windows),
        extra_fields=EXTRA_FIELDS,
    )


if __name__ == '__main__':
    main()
