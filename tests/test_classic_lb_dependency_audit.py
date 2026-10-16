import csv
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from audit_classic_lb_dependencies import (
    _matches_reference,
    _normalise_dns,
    _read_candidates,
)


class ClassicLoadBalancerDependencyAuditTests(unittest.TestCase):
    def test_normalises_dualstack_dns_targets(self):
        self.assertEqual(
            _normalise_dns("dualstack.my-clb-123.us-east-1.elb.amazonaws.com."),
            "my-clb-123.us-east-1.elb.amazonaws.com",
        )

    def test_matches_exact_dns_and_clb_name_references(self):
        dns_name = "my-clb-123.us-east-1.elb.amazonaws.com"
        self.assertTrue(_matches_reference(f"dualstack.{dns_name}.", "my-clb", dns_name))
        self.assertTrue(_matches_reference("production-my-clb-output", "my-clb", dns_name))
        self.assertFalse(_matches_reference("other-clb.example.com", "my-clb", dns_name))

    def test_reads_only_zero_30_and_60_day_candidates_from_complete_scan(self):
        with tempfile.TemporaryDirectory() as directory:
            csv_path = Path(directory) / "findings.csv"
            csv_path.with_suffix(".json").write_text(json.dumps({
                "status": "complete",
                "scope": {"accounts": ["123456789012"], "regions": "enabled"},
            }), encoding="utf-8")
            columns = [
                "account_id", "region", "resource_id", "request_count_30d",
                "request_count_60d", "request_count_90d", "deletion_confidence",
            ]
            with csv_path.open("w", encoding="utf-8", newline="") as stream:
                writer = csv.DictWriter(stream, fieldnames=columns)
                writer.writeheader()
                writer.writerow({
                    "account_id": "123456789012", "region": "us-east-1",
                    "resource_id": "candidate", "request_count_30d": "0",
                    "request_count_60d": "0", "request_count_90d": "0",
                    "deletion_confidence": "HIGH",
                })
                writer.writerow({
                    "account_id": "123456789012", "region": "us-east-1",
                    "resource_id": "active", "request_count_30d": "1",
                    "request_count_60d": "0", "request_count_90d": "0",
                    "deletion_confidence": "LOW",
                })

            candidates, _ = _read_candidates(csv_path, expected_count=1)

        self.assertEqual([item["resource_id"] for item in candidates], ["candidate"])


if __name__ == "__main__":
    unittest.main()
