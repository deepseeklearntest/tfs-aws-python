"""Offline unit tests; no AWS credentials required."""
import ast
import importlib.util
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock, patch

PATH = Path(__file__).parents[1] / 'wave2_lifecycle' / 'detect_lambda_idle_and_hygiene.py'
spec = importlib.util.spec_from_file_location('lambda_hygiene', PATH)
module = importlib.util.module_from_spec(spec)
with patch.dict('sys.modules', {'common': Mock(), 'common.cli': Mock(), 'common.session': Mock(), 'common.tags': Mock()}):
    spec.loader.exec_module(module)


class Tests(unittest.TestCase):
    def test_assessment(self):
        self.assertEqual(module.assess({'status': 'no-data'}, [], 0)[0], 'Insufficient Evidence')
        self.assertEqual(module.assess({'status': 'available', 'inv180': '0'}, [], 0)[0], 'Potentially Idle - Owner Review')
        self.assertEqual(module.assess({'status': 'available', 'inv180': '2'}, [], 0)[0], 'Observed Active')
        self.assertIn('Dependencies', module.assess({'status': 'available', 'inv180': '0'}, ['alias'], 0)[0])

    def test_metric_pagination(self):
        now = datetime(2026, 10, 28, tzinfo=timezone.utc)
        day1, day2 = now-timedelta(days=2), now-timedelta(days=1)
        cw = Mock()
        cw.get_metric_data.side_effect = [
            {'MetricDataResults': [{'Id':'m0','StatusCode':'PartialData','Timestamps':[day1],'Values':[5]},
                                   {'Id':'m1','StatusCode':'PartialData','Timestamps':[],'Values':[]}], 'NextToken':'next'},
            {'MetricDataResults': [{'Id':'m0','StatusCode':'Complete','Timestamps':[day2],'Values':[7]},
                                   {'Id':'m1','StatusCode':'Complete','Timestamps':[],'Values':[]}]},
        ]
        result = module.metrics(cw, 'test', now)
        self.assertEqual(result['inv180'], '12')
        self.assertEqual(result['inv90'], '12')
        self.assertEqual(result['last'], day2.isoformat())

    def test_no_mutating_calls(self):
        tree = ast.parse(PATH.read_text())
        calls = {node.func.attr for node in ast.walk(tree)
                 if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)}
        self.assertFalse(calls & {'invoke','delete_function','update_function_code',
                                  'update_function_configuration','put_rule','put_targets'})


if __name__ == '__main__':
    unittest.main()
