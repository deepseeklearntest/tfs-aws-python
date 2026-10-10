# AWS proactive audit toolkit

Multi-account AWS detectors for cost, lifecycle, reliability, security,
performance, and operational checks. Scripts report findings; they do not apply
AWS remediation. Authentication uses temporary credentials copied from Britive.

## Setup and use

Python 3.10 or newer is required. CI targets Python 3.10–3.12.

```bash
python -m venv .venv
# Activate the virtual environment for your shell, then:
python -m pip install -r requirements.txt
python wave4_security/30_detect_open_security_groups.py --accounts 123456789012
python continuous/54_inventory_refresh.py
python generate_report.py
python build_dataset.py
python generate_dashboard.py
```

Put temporary credentials in the gitignored `britive_creds.json` using the format
in [CLAUDE.md](CLAUDE.md), or use the interactive prompts. Never commit credentials.
Use read-only permissions for the services scanned; the detectors need their
service-specific List/Describe/Get calls, CloudWatch metric reads, STS
GetCallerIdentity, and EC2 DescribeRegions for region discovery.

IAM role scan #37 requires `iam:GetRole` in addition to listing roles/policies.
Tagging scan #43 additionally requires `resource-explorer-2:GetDefaultView`,
`resource-explorer-2:GetView`, and `resource-explorer-2:Search`, plus
`tag:GetResources`. Configure an unrestricted Resource Explorer default view
including the `tags` property in each scanned region before running #43.
The scanner does not create indexes or views. Coverage is limited to resources
indexed and supported by AWS Resource Explorer and the configured type shards;
global resources are searched from us-east-1. Index updates are eventually
consistent. A missing/filtered view or truncated search fails the scan instead of
claiming complete coverage. See [AWS's search documentation](https://docs.aws.amazon.com/resource-explorer/latest/apireference/API_Search.html).

## Complete, sampled, and incomplete runs

Findings are staged during a sweep and published atomically after it finishes.
Each run has a JSON manifest recording scope, task outcomes, and timestamps.

- Completed sweeps use `<script>_YYYYMMDD_HHMMSS.csv` and `.json`.
- Samples use `.sample.csv` and `.sample.json`.
- Failed/interrupted sweeps use `.incomplete.csv` and `.incomplete.json` and exit
  with an error. Scan warnings/errors and skipped AWS access are conservatively
  treated as incomplete coverage.

Only completed runs are consumed by the dataset, inventory, Excel report, and
SG comparison tools. Successful zero-finding scans retire old findings.
`--max-accounts`, `--max-regions`, or an explicit `--regions` selection produces a
sample. A smaller account set than the previous complete run also stays a sample.
Use a separate `--output-dir` for a deliberately different long-term scope.
Inspect sample CSVs directly; they are intentionally excluded from aggregate
reports. Default retention prunes only completed runs and their manifests;
samples and incomplete runs remain available for diagnosis.

Existing timestamped CSVs without manifests remain readable for compatibility;
their completeness cannot be verified. Re-run detectors to migrate them. A report
may still show an older completed scan after a failure: check source timestamps
and heed the incomplete-run warning. Never infer current health solely from the
absence of findings. Dataset `snapshot_date` is the aggregation date; `scan_time`
records when each source finding was observed.

## Interpretation and maintenance

Savings are directional estimates, not invoiced amounts or validated business
cases. Opportunities can overlap, particularly the instance IOPS ceiling check
(#38) and volume IOPS utilization check (#40). Deduplicate and validate them before
using aggregate dollar totals. Confirm workload peaks and dependencies before
reducing capacity or deleting an idle candidate. Missing metrics are unknown,
not measured zero usage.

The Lambda runtime date table was verified against [AWS runtime documentation](https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html)
on 2026-10-06. Forecast dates can change. Review it at least every 90 days; stale
tables produce a scan warning. Unknown runtimes make the scan incomplete.

Generated HTML escapes resource/tag text, and Excel treats external strings as
literal text. Raw CSVs preserve their data; open the generated Excel report
instead of importing untrusted CSV cells as formulas.

[Next_Actions.md](Next_Actions.md) describes remediation and stakeholder guidance;
[ROADMAP.md](ROADMAP.md) tracks work scope. Legacy `vault.py` is not part of the
active authentication path.

## Tests

```bash
python -m unittest discover -s tests -v
```

Tests use botocore Stubber and mocks with synthetic credentials. They do not make
live AWS calls or require account access. CI runs the same command. Live validation
against known resources in a small account is still required before operational
rollout.
