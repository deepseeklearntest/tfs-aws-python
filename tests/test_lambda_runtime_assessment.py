"""Offline tests for the read-only Lambda lifecycle detector."""
import ast
import csv
import importlib.util
import tempfile
import unittest
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock, patch

from common import output, session
import boto3
from botocore.exceptions import ClientError

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    'lambda_runtime_assessment',
    ROOT / 'wave2_lifecycle' / '15_detect_lambda_deprecated_runtimes.py',
)
lam = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(lam)


class Paginator:
    def __init__(self, pages=None, page_factory=None):
        self.pages = pages
        self.page_factory = page_factory

    def paginate(self, **kwargs):
        if self.page_factory:
            return iter(self.page_factory(**kwargs))
        return iter(self.pages)


def fixture_client():
    client = Mock()
    functions = [
        {'Functions': [{
            'FunctionName': 'orders',
            'FunctionArn': 'arn:aws:lambda:us-east-1:123456789012:function:orders',
            'Runtime': 'python3.10', 'PackageType': 'Zip',
            'Version': '$LATEST', 'LastModified': '2026-01-01T00:00:00.000+0000',
        }]},
        {'Functions': [{
            'FunctionName': 'image-job',
            'FunctionArn': 'arn:aws:lambda:us-east-1:123456789012:function:image-job',
            'PackageType': 'Image', 'Version': '$LATEST',
        }]},
    ]

    def paginator(operation):
        if operation == 'list_functions':
            return Paginator(functions)
        if operation == 'list_versions_by_function':
            def version_pages(FunctionName):
                if FunctionName == 'orders':
                    return [{'Versions': [
                    {'FunctionName': 'orders', 'FunctionArn': 'arn:aws:lambda:us-east-1:123456789012:function:orders:$LATEST',
                     'Runtime': 'python3.10', 'PackageType': 'Zip', 'Version': '$LATEST'},
                    {'FunctionName': 'orders', 'FunctionArn': 'arn:aws:lambda:us-east-1:123456789012:function:orders:2',
                     'Runtime': 'python3.8', 'PackageType': 'Zip', 'Version': '2'},
                    {'FunctionName': 'orders', 'FunctionArn': 'arn:aws:lambda:us-east-1:123456789012:function:orders:3',
                     'Runtime': 'python3.12', 'PackageType': 'Zip', 'Version': '3'},
                    {'FunctionName': 'orders', 'FunctionArn': 'arn:aws:lambda:us-east-1:123456789012:function:orders:4',
                     'Runtime': 'python3.8', 'PackageType': 'Zip', 'Version': '4'},
                    ]}]
                return [{'Versions': [
                    {'FunctionName': 'image-job', 'FunctionArn': 'arn:aws:lambda:us-east-1:123456789012:function:image-job:$LATEST',
                     'PackageType': 'Image', 'Version': '$LATEST'},
                ]}]
            return Paginator(page_factory=version_pages)
        if operation == 'list_aliases':
            def alias_pages(FunctionName):
                aliases = ([{
                    'Name': 'production', 'FunctionVersion': '2',
                    'RoutingConfig': {'AdditionalVersionWeights': {'4': 0.25}},
                }] if FunctionName == 'orders' else [])
                return [{'Aliases': aliases}]
            return Paginator(page_factory=alias_pages)
        raise AssertionError(f'Unexpected paginator: {operation}')

    client.get_paginator.side_effect = paginator

    def tags(Resource):
        if Resource.endswith(':orders'):
            return {'Tags': {'Environment': 'production', 'Owner': 'payments'}}
        return {'Tags': {'Environment': 'staging'}}

    client.list_tags.side_effect = tags
    return client


class LambdaRuntimeAssessmentTests(unittest.TestCase):
    def test_deprecation_thresholds_and_supported_runtime(self):
        runtime = 'unit-test-runtime'
        original = lam.RUNTIME_EOL.get(runtime)
        lam.RUNTIME_EOL[runtime] = date(2026, 12, 31)
        self.addCleanup(
            lambda: lam.RUNTIME_EOL.pop(runtime, None)
            if original is None else lam.RUNTIME_EOL.__setitem__(runtime, original)
        )
        eol = date(2026, 12, 31)
        for days, urgency, risk in (
            (30, 'within-30-days', 'Medium'),
            (90, 'within-90-days', 'Medium'),
            (180, 'within-180-days', 'Low'),
        ):
            with self.subTest(days=days):
                assessment = lam._assess_runtime(runtime, 'Zip', eol - timedelta(days=days))
                self.assertEqual(assessment['urgency'], urgency)
                self.assertEqual(lam._base_risk(assessment, 'staging', '$LATEST', [])[0], risk)
        self.assertEqual(
            lam._assess_runtime('python3.12', 'Zip', date(2026, 10, 6))['status'],
            'supported',
        )
        self.assertEqual(
            lam._assess_runtime(runtime, 'Zip', eol)['status'],
            'deprecated',
        )

    def test_unknown_missing_runtime_and_image_require_review(self):
        today = date(2026, 10, 6)
        for runtime, package_type, expected in (
            ('future-runtime', 'Zip', 'unknown-runtime'),
            ('', 'Zip', 'unknown-runtime'),
            ('', 'Image', 'container-image-assessment-required'),
            ('nodejs26.x', 'Zip', 'deprecation-date-unannounced'),
        ):
            with self.subTest(runtime=runtime, package_type=package_type):
                result = lam._assess_runtime(runtime, package_type, today)
                self.assertEqual(result['status'], expected)
                self.assertEqual(
                    lam._base_risk(result, '', '$LATEST', [])[0],
                    'Review Required',
                )

    def test_version_alias_weight_and_unreferenced_risk(self):
        refs = lam._alias_targets([{
            'Name': 'prod', 'FunctionVersion': '2',
            'RoutingConfig': {'AdditionalVersionWeights': {'4': 0.25}},
        }])
        self.assertEqual(refs['2'], [('prod', 0.75)])
        self.assertEqual(refs['4'], [('prod', 0.25)])
        assessment = lam._assess_runtime('python3.8', 'Zip', date(2026, 10, 6))
        alias_risk, alias_reason = lam._risk_for_version(
            assessment, 'production', '2', refs['2'], 'team', 'available', {}
        )
        historical_risk, reason = lam._risk_for_version(
            assessment, 'production', '3', [], 'team', 'available', {}
        )
        self.assertEqual(alias_risk, 'High')
        self.assertIn('not proof of a vulnerability', alias_reason)
        self.assertEqual(historical_risk, 'Review Required')
        self.assertIn('direct qualified-ARN invocation cannot be excluded', reason)

    def test_production_risk_requires_explicit_tag_and_usage_evidence(self):
        assessment = lam._assess_runtime('python3.8', 'Zip', date(2026, 10, 6))
        inactive = lam._base_risk(assessment, 'production', '$LATEST', [])
        observed = lam._base_risk(
            assessment, 'production', '$LATEST', [],
            {'activity_status': 'available', 'invocations_30d': '1'},
        )
        untagged = lam._base_risk(
            assessment, '', '$LATEST', [],
            {'activity_status': 'available', 'invocations_30d': '1'},
        )
        self.assertEqual(inactive[0], 'Review Required')
        self.assertEqual(observed[0], 'High')
        self.assertEqual(untagged[0], 'Review Required')

    def test_reference_data_is_unverified_and_stale_dates_are_detected(self):
        self.assertEqual(lam._lifecycle_data_status(date(2026, 10, 27)), 'verified')
        with patch.object(lam, 'LIFECYCLE_REFERENCE_STATUS', 'unverified'):
            self.assertEqual(lam._lifecycle_data_status(date(2026, 10, 27)), 'unverified')
        with patch.object(lam, 'LIFECYCLE_REFERENCE_STATUS', 'verified'):
            self.assertEqual(lam._lifecycle_data_status(date(2027, 2, 1)), 'stale')

    def test_create_and_update_block_dates_have_distinct_statuses(self):
        today = date(2026, 10, 27)
        self.assertEqual(
            lam._block_date_status('python3.8', 'Zip', lam.RUNTIME_CREATE_BLOCK, today),
            'scheduled',
        )
        self.assertEqual(
            lam._block_date_status('python2.7', 'Zip', lam.RUNTIME_UPDATE_BLOCK, today),
            'passed',
        )
        self.assertEqual(
            lam._block_date_status('nodejs26.x', 'Zip', lam.RUNTIME_CREATE_BLOCK, today),
            'not-scheduled',
        )
        self.assertEqual(
            lam._block_date_status('anything', 'Image', lam.RUNTIME_CREATE_BLOCK, today),
            'not-applicable',
        )

    def test_paginated_scan_reports_versions_aliases_unknown_and_images(self):
        aws = fixture_client()
        sess = Mock()
        sess.client.return_value = aws
        writer = Mock()
        with patch.object(lam, 'LIFECYCLE_REFERENCE_STATUS', 'unverified'), \
                patch.object(lam.session, 'mark_incomplete') as mark_incomplete:
            lam.make_scan(today_provider=lambda: date(2026, 10, 6))(
                sess, '123456789012', 'us-east-1', writer
            )
        aws.get_paginator.assert_any_call('list_functions')
        calls = [call.kwargs for call in writer.write.call_args_list]
        rows = {row['function_version']: row for row in calls if row['function_name'] == 'orders'}
        self.assertIn('2', rows)
        self.assertIn('4', rows)
        self.assertEqual(rows['2']['risk_level'], 'Review Required')
        self.assertEqual(rows['2']['alias_name'], 'production')
        self.assertEqual(rows['2']['alias_traffic_weight'], '{"production": 0.75}')
        self.assertEqual(rows['4']['alias_traffic_weight'], '{"production": 0.25}')
        self.assertEqual(rows['2']['lifecycle_data_status'], 'unverified')
        self.assertEqual(rows['2']['version_inventory_status'], 'available')
        self.assertEqual(rows['2']['creation_block_date'], '2027-07-29')
        self.assertEqual(rows['2']['update_block_date'], '2027-08-31')
        latest = rows['$LATEST']
        self.assertEqual(latest['creation_block_date'], '2027-07-29')
        self.assertEqual(latest['creation_block_status'], 'scheduled')
        self.assertTrue(any(
            row['finding'] == 'container-image-runtime-assessment-required'
            for row in calls
        ))
        self.assertTrue(any('Lifecycle reference data is unverified' in c.args[0]
                            for c in mark_incomplete.call_args_list))

    def test_container_image_finding_does_not_incomplete_inventory(self):
        aws = fixture_client()
        sess = Mock()
        sess.client.return_value = aws
        writer = Mock()
        with patch.object(lam, 'LIFECYCLE_REFERENCE_STATUS', 'verified'):
            outcomes = session.run_parallel(
                [(sess, '123456789012', 'us-east-1', writer)],
                lam.make_scan(today_provider=lambda: date(2026, 10, 6)),
                max_workers=1,
            )
        self.assertTrue(outcomes[0].complete)
        image_finding = next(
            call.kwargs for call in writer.write.call_args_list
            if call.kwargs['function_name'] == 'image-job'
        )
        self.assertEqual(
            image_finding['finding'],
            'container-image-runtime-assessment-required',
        )
        self.assertEqual(image_finding['risk_level'], 'Review Required')

    def test_deprecated_production_version_with_alias_is_high_risk(self):
        aws = fixture_client()
        sess = Mock()
        sess.client.return_value = aws
        writer = Mock()
        with patch.object(lam, 'LIFECYCLE_REFERENCE_STATUS', 'verified'):
            lam.make_scan(today_provider=lambda: date(2026, 10, 6))(
                sess, '123456789012', 'us-east-1', writer
            )
        rows = [call.kwargs for call in writer.write.call_args_list]
        version_two = next(row for row in rows if row['function_version'] == '2')
        self.assertEqual(version_two['risk_level'], 'High')
        self.assertEqual(version_two['severity'], 'deprecated')
        self.assertEqual(version_two['environment'], 'production')
        self.assertEqual(version_two['function_owner'], 'payments')

    def test_access_denied_inventory_is_marked_incomplete(self):
        client = Mock()
        client.get_paginator.side_effect = ClientError(
            {'Error': {'Code': 'AccessDenied', 'Message': 'Not authorized'}},
            'ListFunctions',
        )
        sess = Mock()
        sess.client.return_value = client
        writer = Mock()
        with patch.object(lam.session, 'mark_incomplete') as mark_incomplete:
            lam.make_scan(today_provider=lambda: date(2026, 10, 6))(
                sess, '123456789012', 'us-east-1', writer
            )
        writer.write.assert_not_called()
        self.assertTrue(mark_incomplete.called)

    def test_version_coverage_gap_is_separate_from_lifecycle_data(self):
        aws = fixture_client()
        original_paginator = aws.get_paginator.side_effect

        def paginator(operation):
            if operation == 'list_versions_by_function':
                failed = Mock()
                failed.paginate.side_effect = ClientError(
                    {'Error': {'Code': 'AccessDenied', 'Message': 'Not authorized'}},
                    'ListVersionsByFunction',
                )
                return failed
            return original_paginator(operation)

        aws.get_paginator.side_effect = paginator
        sess = Mock()
        sess.client.return_value = aws
        writer = Mock()
        with patch.object(lam, 'LIFECYCLE_REFERENCE_STATUS', 'verified'):
            lam.make_scan(today_provider=lambda: date(2026, 10, 6))(
                sess, '123456789012', 'us-east-1', writer
            )
        row = next(call.kwargs for call in writer.write.call_args_list
                   if call.kwargs['function_name'] == 'orders')
        self.assertEqual(row['lifecycle_data_status'], 'verified')
        self.assertEqual(row['version_inventory_status'], 'unavailable')
        self.assertEqual(row['risk_level'], 'Review Required')

    def test_throttling_error_is_not_silently_suppressed(self):
        client = Mock()
        client.get_paginator.side_effect = ClientError(
            {'Error': {'Code': 'ThrottlingException', 'Message': 'Retry exhausted'}},
            'ListFunctions',
        )
        sess = Mock()
        sess.client.return_value = client
        with self.assertRaises(ClientError):
            lam.make_scan(today_provider=lambda: date(2026, 10, 6))(
                sess, '123456789012', 'us-east-1', Mock()
            )

    def test_boto_session_keeps_sdk_retry_policy_enabled(self):
        aws_session = boto3.Session(
            aws_access_key_id='testing', aws_secret_access_key='testing'
        )
        client = aws_session.client('lambda', region_name='us-east-1')
        self.assertIn(client.meta.config.retries['mode'], ('legacy', 'standard'))

    def test_incomplete_task_cannot_be_published_as_complete(self):
        client = Mock()
        client.get_paginator.side_effect = ClientError(
            {'Error': {'Code': 'AccessDenied', 'Message': 'Not authorized'}},
            'ListFunctions',
        )
        sess = Mock()
        sess.client.return_value = client
        scan = lam.make_scan(today_provider=lambda: date(2026, 10, 6))
        with self.assertRaises(session.IncompleteScanError) as caught:
            session.run_parallel(
                [(sess, '123456789012', 'us-east-1', Mock())],
                scan,
                max_workers=1,
            )
        self.assertFalse(caught.exception.outcomes[0].complete)
        self.assertTrue(any(
            'AWS access skipped: AccessDenied' in issue
            for issue in caught.exception.outcomes[0].issues
        ))

    def test_cloudwatch_metrics_are_batched_and_missing_metrics_are_blank(self):
        now = datetime(2026, 10, 27, tzinfo=timezone.utc)
        versions = [{'Version': '$LATEST'}, {'Version': '4'}]
        cloudwatch = Mock()
        cloudwatch.get_metric_data.return_value = {
            'MetricDataResults': [
                {
                    'Id': 'm00000000', 'StatusCode': 'Complete',
                    'Timestamps': [now - timedelta(days=1)],
                    'Values': [5.0],
                },
                {
                    'Id': 'm00000001', 'StatusCode': 'Complete',
                    'Timestamps': [now - timedelta(days=1)],
                    'Values': [1.0],
                },
                {'Id': 'm00000002', 'StatusCode': 'Complete', 'Timestamps': [], 'Values': []},
                {'Id': 'm00000003', 'StatusCode': 'Complete', 'Timestamps': [], 'Values': []},
            ],
        }
        result = lam._collect_metrics(
            cloudwatch, versions, 'orders', now, (7, 30, 90)
        )
        self.assertEqual(result['$LATEST']['invocations_7d'], '5')
        self.assertEqual(result['$LATEST']['errors_7d'], '1')
        self.assertEqual(result['$LATEST']['activity_status'], 'available')
        self.assertEqual(result['4']['activity_status'], 'no-data')
        cloudwatch.get_metric_data.assert_called_once()

    def test_cloudwatch_pagination_accumulates_values_and_latest_period(self):
        now = datetime(2026, 10, 27, tzinfo=timezone.utc)
        older = now - timedelta(days=2)
        latest = now - timedelta(days=1)
        cloudwatch = Mock()
        cloudwatch.get_metric_data.side_effect = [
            {
                'MetricDataResults': [
                    {'Id': 'm00000000', 'StatusCode': 'PartialData',
                     'Timestamps': [older], 'Values': [5.0]},
                    {'Id': 'm00000001', 'StatusCode': 'Complete',
                     'Timestamps': [], 'Values': []},
                ],
                'NextToken': 'page-2',
            },
            {
                'MetricDataResults': [
                    {'Id': 'm00000000', 'StatusCode': 'Complete',
                     'Timestamps': [latest], 'Values': [7.0]},
                    {'Id': 'm00000001', 'StatusCode': 'Complete',
                     'Timestamps': [], 'Values': []},
                ],
            },
        ]
        with patch.object(lam.session, 'mark_incomplete') as mark_incomplete:
            result = lam._collect_metrics(
                cloudwatch, [{'Version': '$LATEST'}], 'orders', now, (7, 30, 90)
            )
        self.assertEqual(result['$LATEST']['invocations_7d'], '12')
        self.assertEqual(result['$LATEST']['invocations_30d'], '12')
        self.assertEqual(
            result['$LATEST']['last_invoked'],
            latest.isoformat(),
        )
        self.assertEqual(result['$LATEST']['activity_status'], 'available')
        mark_incomplete.assert_not_called()
        self.assertEqual(cloudwatch.get_metric_data.call_count, 2)
        self.assertEqual(
            cloudwatch.get_metric_data.call_args_list[1].kwargs['NextToken'],
            'page-2',
        )

    def test_cloudwatch_duplicate_timestamps_do_not_inflate_totals(self):
        now = datetime(2026, 10, 27, tzinfo=timezone.utc)
        timestamp = now - timedelta(days=1)
        cloudwatch = Mock()
        cloudwatch.get_metric_data.side_effect = [
            {
                'MetricDataResults': [
                    {'Id': 'm00000000', 'StatusCode': 'PartialData',
                     'Timestamps': [timestamp], 'Values': [5.0]},
                    {'Id': 'm00000001', 'StatusCode': 'Complete',
                     'Timestamps': [], 'Values': []},
                ],
                'NextToken': 'page-2',
            },
            {
                'MetricDataResults': [
                    {'Id': 'm00000000', 'StatusCode': 'Complete',
                     'Timestamps': [timestamp], 'Values': [5.0]},
                    {'Id': 'm00000001', 'StatusCode': 'Complete',
                     'Timestamps': [], 'Values': []},
                ],
            },
        ]
        result = lam._collect_metrics(
            cloudwatch, [{'Version': '$LATEST'}], 'orders', now, (7,)
        )
        self.assertEqual(result['$LATEST']['invocations_7d'], '5')
        self.assertEqual(result['$LATEST']['last_invoked'], timestamp.isoformat())
        self.assertEqual(result['$LATEST']['activity_status'], 'available')

    def test_unresolved_cloudwatch_partial_result_marks_incomplete(self):
        now = datetime(2026, 10, 27, tzinfo=timezone.utc)
        cloudwatch = Mock()
        cloudwatch.get_metric_data.return_value = {
            'MetricDataResults': [
                {'Id': 'm00000000', 'StatusCode': 'PartialData',
                 'Timestamps': [now - timedelta(days=1)], 'Values': [5.0]},
                {'Id': 'm00000001', 'StatusCode': 'Complete',
                 'Timestamps': [], 'Values': []},
            ],
        }
        with patch.object(lam.session, 'mark_incomplete') as mark_incomplete:
            result = lam._collect_metrics(
                cloudwatch, [{'Version': '$LATEST'}], 'orders', now, (7,)
            )
        self.assertEqual(result['$LATEST']['activity_status'], 'partial')
        self.assertEqual(result['$LATEST']['invocations_7d'], '5')
        mark_incomplete.assert_called_once()
        self.assertIn('unresolved (PartialData)', mark_incomplete.call_args.args[0])

    def test_access_denied_cloudwatch_metrics_are_visible_and_incomplete(self):
        aws = fixture_client()
        sess = Mock()
        sess.client.side_effect = lambda service, region_name: (
            aws if service == 'lambda' else Mock(
                get_metric_data=Mock(side_effect=ClientError(
                    {'Error': {'Code': 'AccessDenied', 'Message': 'No metric permission'}},
                    'GetMetricData',
                ))
            )
        )
        writer = Mock()
        with patch.object(lam, 'LIFECYCLE_REFERENCE_STATUS', 'verified'), \
                patch.object(lam.session, 'mark_incomplete') as mark_incomplete:
            lam.make_scan(
                cloudwatch_metrics=True,
                today_provider=lambda: date(2026, 10, 6),
            )(sess, '123456789012', 'us-east-1', writer)
        row = next(call.kwargs for call in writer.write.call_args_list
                   if call.kwargs['function_version'] == '2')
        self.assertEqual(row['activity_status'], 'unavailable')
        self.assertTrue(mark_incomplete.called)

    def test_csv_schema_appends_fields_without_losing_common_fields(self):
        with tempfile.TemporaryDirectory() as folder:
            with output.FindingsWriter(
                folder, lam.SCRIPT_NAME, extra_fields=lam.EXTRA_FIELDS
            ) as writer:
                writer.write(
                    account_id='123456789012', region='us-east-1',
                    resource_id='arn:aws:lambda:us-east-1:123456789012:function:demo',
                    resource_type='Lambda Function', finding='unknown-runtime',
                    function_name='demo', risk_level='Review Required',
                )
            path = writer._path
            with path.open(newline='', encoding='utf-8') as file:
                reader = csv.DictReader(file)
                self.assertEqual(reader.fieldnames, output.COMMON_FIELDS + lam.EXTRA_FIELDS)
                row = next(reader)
                self.assertEqual(row['function_name'], 'demo')
                self.assertEqual(row['account_id'], '123456789012')

    def test_source_has_no_lambda_write_or_invoke_calls(self):
        source = (ROOT / 'wave2_lifecycle' / '15_detect_lambda_deprecated_runtimes.py').read_text(
            encoding='utf-8'
        )
        tree = ast.parse(source)
        called_attributes = {
            node.func.attr.lower()
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        }
        forbidden = {
            'update_function_configuration', 'update_function_code',
            'delete_function', 'publish_version', 'update_alias', 'invoke',
        }
        self.assertFalse(called_attributes & forbidden)


if __name__ == '__main__':
    unittest.main()
