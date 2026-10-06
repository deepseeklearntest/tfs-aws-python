# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Purpose

AWS FinOps and proactive monitoring toolkit for Thermo Fisher Scientific CloudOps. The goal is to build boto3 scripts that sweep across all AWS accounts and regions to surface cost, reliability, security, and performance findings. `proactive.md` is the authoritative task list (54 items ranked by execution wave); `britive.py` provides the credential plumbing.

## LLM Council

Every time I present an idea, system, setup or ask for an advice, act like an LLM council with below traits with a multi agent setup:
1. The contrarian - only looks at what will fail. Every reason this goes wrong.
2. The First-Principles thinker - rips apart every assumption you didn't realize you were making.
3. The Expansionist - finds the upside and the options you're not seeing.
4. The Outsider - knows nothing about your field, asks the dumb questions that turnout to be the smart ones.
5. The Executor - ignores theory and only cares about what you'll actually do Monday morning.

## Dependencies

```bash
pip install -r requirements.txt
```

- `boto3` / `botocore` — AWS SDK
- `truststore` — injects Windows certificate store into Python SSL (required for corporate TLS inspection proxy). Injected once in `common/session.py` before boto3 imports — do NOT add it to individual scripts.
- `openpyxl` — Excel report generation (`generate_report.py` only)

No build system, no test suite, no CI.

## Running a Detection Script

```bash
python wave1_cost/06_detect_nat_gateway_hotpaths.py --accounts 123456789012,234567890123
```

All scripts accept the same standard CLI flags (from `common/cli.py`):

| Flag | Default | Purpose |
|---|---|---|
| `--accounts` | (required) | Comma-separated AWS account IDs to scan |
| `--creds-file` | `britive_creds.json` | JSON file with saved Britive credentials (falls back to interactive prompt per account if missing) |
| `--output-dir` | `findings` | Directory for CSV output |
| `--max-accounts` | (all) | Sample mode: first N of the specified accounts |
| `--workers` | 10 | Thread pool size; use 1 for sequential debug |
| `--regions` | (all enabled) | Comma-separated region list (regional scripts only) |
| `--max-regions` | (all) | Sample mode: first N regions per account (regional scripts only) |
| `--keep-runs` | 10 | Number of most-recent CSVs to retain per script; older ones are pruned automatically after each run |
| `--no-prune` | off | Disable automatic CSV retention for this run (keep every run's CSV forever) |

Output lands in `findings/<wave_subfolder>/<script_name>_<timestamp>.csv` (wave subfolder resolved from the script's numeric prefix via `WAVE_MAP` in `common/findings_io.py`; ad-hoc scripts with no numeric prefix land directly in `findings/`) and `findings/logs/<script_name>_<timestamp>.log`. Each script's CSVs are automatically pruned to the `--keep-runs` most recent (default 10) — every downstream consumer (`generate_report.py`, `build_dataset.py`, `continuous/54_inventory_refresh.py`) only ever reads the newest CSV per script, so this is safe. The actual historical trend store is `dataset/findings_dataset.csv` (append-only, one row set per `snapshot_date`, built by `build_dataset.py`) — that is untouched by pruning.

## Saved Credentials

Create `britive_creds.json` in the project root (gitignored):

```json
{
  "123456789012": {
    "aws_access_key_id": "ASIA...",
    "aws_secret_access_key": "...",
    "aws_session_token": "..."
  }
}
```

Credentials are STS-verified on load. Expired entries fall back to the interactive prompt for that account. Britive credentials expire naturally — update the file before each scanning session.

## Remediation Guidance

`Next_Actions.md` contains per-script remediation steps and management pitches for each implemented detector. Consult it when triaging findings or preparing stakeholder reports.

## Generating the Excel Report

```bash
python generate_report.py
python generate_report.py --findings-dir findings --output-dir reports
python generate_report.py --from-inventory          # faster: reads consolidated inventory_*.csv
```

Reads the latest CSV per script from `findings/`, aggregates all waves, and writes a manager-ready Excel workbook to `reports/aws_proactive_report_YYYYMMDD_HHMMSS.xlsx`. No AWS credentials required. See `docs/superpowers/specs/2026-05-26-excel-report-design.md` for full sheet/column/RAG spec.

`--from-inventory` skips individual CSVs and loads from the latest `inventory_*.csv` produced by `54_inventory_refresh.py`. Requires that script to have been run first.

## Consolidating Findings

```bash
python continuous/54_inventory_refresh.py
python continuous/54_inventory_refresh.py --since 7    # only CSVs modified in last 7 days
```

Standalone aggregator (no AWS auth, stdlib-only). Reads all findings CSVs from `findings/`, merges them into `findings/inventory_YYYYMMDD_HHMMSS.csv`, and prints a summary by resource type, finding code, and top savings. Script 28 (`28_dr_runbook_tracker.py`) is similarly auth-free — it reads a local registry file `wave3_reliability/28_dr_runbook_registry.csv` rather than querying AWS.

## Generating the Dashboard

```bash
python build_dataset.py
python build_dataset.py --findings-dir findings --dataset-file dataset/findings_dataset.csv
```

Reads the latest CSV per script from `findings/`, normalises each row to a flat schema with `snapshot_date`, `severity`, and org-tag columns, and appends idempotently to `dataset/findings_dataset.csv`. Re-running on the same day replaces that day's snapshot; running after a new scan cycle appends a new one.

```bash
python generate_dashboard.py
python generate_dashboard.py --dataset-file dataset/findings_dataset.csv --output-dir reports
```

Reads `dataset/findings_dataset.csv` and writes a single self-contained HTML dashboard to `reports/dashboard_YYYYMMDD_HHMMSS.html`. No AWS credentials required. The Trends section appears automatically once the dataset contains ≥2 distinct `snapshot_date` values. See `docs/powerbi_dashboard_guide.md` for the Power BI Desktop workflow.

## Generating the Task-List Excel

```bash
python generate_proactive_excel.py
```

Separate from `generate_report.py` — this reads `proactive.md` (the task spec, not findings CSVs) and writes `proactive.xlsx`, a colour-coded workbook of all 54 tasks for stakeholder review.

## Project Skills

Four custom Claude skills are in `.claude/skills/`:

| Skill | Invoke | Purpose |
|---|---|---|
| `new-detector` | `/new-detector <num> <slug>` | Scaffold a new detection script from a proactive.md task |
| `wave-status` | `/wave-status` | Show implemented vs pending tasks across all 54 |
| `run-scan` | `/run-scan <script-or-num>` | Run a script with safe sampling defaults (1 account, 2 regions, sequential) |
| `findings-report` | `/findings-report` | Aggregate all CSVs and produce a savings summary |

## Architecture: common/ Package

- **`session.py`** — Injects `truststore` at import time (before boto3 loads). `AccountIterator` context manager collects Britive credentials once then iterates accounts/regions. `run_parallel()` fans tasks over `ThreadPoolExecutor`. `SKIP_CODES` lists `ClientError` codes to silently skip. `chunked()` batches CloudWatch metric queries.
- **`cli.py`** — `make_parser()` + `run()` compose argparse boilerplate and wire `AccountIterator` → `FindingsWriter` → `run_parallel()`.
- **`output.py`** — Thread-safe `FindingsWriter` writing to a timestamped CSV. All scripts share `COMMON_FIELDS`; script-specific columns added via `extra_fields`.
- **`pricing.py`** — Region-aware pricing helpers (EBS, EIP, LB, NAT, RDS, EC2). Base prices are us-east-1 × `REGION_MULTIPLIER`. Use `pricing.<helper>(region)` — never hardcode prices.
- **`logging_config.py`** — Dual console + file logging; silences boto3/botocore/urllib3 at WARNING.

## Authentication Model

All AWS access flows through Britive. `britive.py` handles credential collection.

`AccountIterator.__enter__` calls `BritiveKeychain.collect_creds()` which:
1. Checks `britive_creds.json` (or `--creds-file` path) for pre-saved credentials
2. STS-verifies each loaded credential
3. Falls back to interactive copy-paste prompt for any account not in the file or with expired credentials

For interactive prompts: open the Britive portal → find the account → **Check Out → CLI tab** → paste the three values. Type `skip` to skip an account.

`revoke_all_leases()` is a no-op — Britive credentials expire naturally.

## Anatomy of a Detection Script

Every script follows this exact pattern:

```python
#!/usr/bin/env python3
"""Task N - <description>  Run: python NN_<name>.py --accounts 123456789012"""
import sys
from pathlib import Path
from botocore.exceptions import ClientError

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # .resolve() is required
from common import cli, pricing, session

SCRIPT_NAME = 'NN_<name>'
EXTRA_FIELDS = ['field1', 'field2']   # appended after COMMON_FIELDS in CSV

def scan(sess, account_id: str, region: str, writer) -> None:
    client = sess.client('<service>', region_name=region)
    try:
        # ... paginate / describe ...
        writer.write(
            account_id=account_id, region=region,
            resource_id=..., resource_type=...,
            finding=..., detail=...,
            estimated_monthly_savings_usd=...,
            tags=...,
            field1=..., field2=...,
        )
    except ClientError as exc:
        if session.is_skippable(exc):
            return
        raise

def main() -> None:
    parser = cli.make_parser(__doc__)
    args = parser.parse_args()
    cli.run(args, SCRIPT_NAME, scan, extra_fields=EXTRA_FIELDS)

if __name__ == '__main__':
    main()
```

**Critical:** `sys.path.insert` must use `.resolve()` — without it, running from within the script's own directory produces a relative path and causes `ImportError` from site-packages.

For account-level scans (no region loop): pass `account_level=True` to both `make_parser()` and `cli.run()`, and define `scan(sess, account_id, writer)`.

For scripts needing extra CLI args, use the `make_scan(param)` factory pattern — `make_scan()` returns a `scan` closure capturing the extra parameter.

For scripts that need to fan out into sub-tasks per region (e.g. scanning disjoint resource-type shards to avoid Tagging API token expiry), pass a `task_expander` to `cli.run()`. The expander receives a `(sess, account_id, region)` base tuple and returns an iterable of expanded tuples; the expanded signature must match `scan()`. All expanded tasks are submitted as flat work units to the shared thread pool — no nested pools.

## Temporal Awareness

The session context always injects `currentDate` (today's date). Every agent and script decision that involves time **must** use this value — never rely on training-data assumptions about what year or month it is.

**For scripts at runtime:**
- Always use `date.today()` / `datetime.now(timezone.utc)` — never hardcode date literals.
- The `_days_since()` pattern in script 28 is the model: compute the gap dynamically at runtime, not at write time.
- Threshold comparisons (e.g. "older than 180 days", "EOL before today") must derive from `date.today()` so the script stays correct as time passes.

**For Claude when implementing scripts:**
- Use `currentDate` from session context as "today" when reasoning about whether a runtime is EOL, a resource is stale, or a date dict needs updating.
- When writing or reviewing EOL/deprecation date dicts (e.g. script 15's runtime EOL map), verify each date against current AWS documentation — do not trust training-data snapshots of those dates.
- If a proactive.md task references a deprecation or end-of-support date, look it up fresh rather than assuming it matches what was true when the task was written.

## AWS Currency

AWS services, APIs, instance types, regions, and supported versions change continuously. Always prefer live AWS data over hardcoded lists.

**Prefer AWS APIs for dynamic enumerations:**
- Regions: `ec2.describe_regions()` rather than a hardcoded list.
- Lambda runtimes: `lambda.list_layers()` / AWS docs — the EOL date dict in script 15 must be kept current.
- RDS engine versions: `rds.describe_db_engine_versions()`.
- EC2 instance types, EKS/ECS supported versions: fetch from the relevant describe API where practical.

**When hardcoded lists are unavoidable** (e.g. pricing multipliers, service quota service codes), treat them as needing a review pass each time the script is revisited — add a comment with the date they were last verified.

**When implementing from proactive.md:**
- The task spec captures intent and example API calls, but exact parameter names, filter keys, and response shapes may have evolved. Cross-check against current AWS documentation before writing.
- If an AWS API call in proactive.md looks unfamiliar or the parameter names feel off, verify with the boto3 docs for that service before implementing.

## Key Conventions

- All strings in scripts must use straight ASCII quotes (`"` / `'`). The Edit tool can silently introduce curly quotes (`"` / `"`) — run a sanity check if you see `SyntaxError: invalid character`.
- `botocore.config` (and any module that transitively imports `botocore.httpsession`) must be imported **after** `from common import cli, session`. Importing it before truststore injection causes `ssl.SSLContext`'s options setter to recurse infinitely on Python 3.11 + Windows. See `wave4_security/37_detect_iam_risky_roles.py` and `continuous/43_detect_tagging_compliance.py` for correct ordering.
- `estimated_monthly_savings_usd` must be a number or `None` — never an empty string. Security/reliability findings that have no dollar savings use `None` or `0`.
- Cost Explorer `GetCostAndUsage` dimension filters only support `EQUALS`, `CASE_SENSITIVE`, and `ABSENT` as `MatchOptions` — `CONTAINS` throws `ValidationException`. Filter in Python after fetching.
- For EOL/deprecation scripts (e.g. script 15), classify runtimes dynamically from a date dict rather than hardcoded sets — sets go stale as EOL dates pass. Verify all EOL dates against current AWS docs at implementation time (see Temporal Awareness above).
- Tag-based filtering uses org tags: `CostCenter`, `Environment`, `Owner`, `Application`.
- Production accounts are identified by the `Environment=production` tag on resources.
- `vault.py` is legacy — it used HashiCorp Vault (`hvac`) for credential retrieval before the Britive migration. Do not use or extend it.
- Ad-hoc scripts (e.g. `wave4_security/ppd_era_iam_users.py`) may live in a wave directory without a numeric prefix. They follow the same anatomy but `SCRIPT_NAME` is a descriptive slug rather than a number prefix, and they are not listed in `WAVE_MAP` in `generate_report.py`.
- When implementing a new numbered script, add its 2-digit prefix to `WAVE_MAP` in `common/findings_io.py` — that is now the single source of truth. `generate_report.py` and `continuous/54_inventory_refresh.py` import it from there.

## Implemented Scripts

| Wave | Scripts | Notes |
|---|---|---|
| Wave 1 – Cost | 06, 07, 10, 13 | NAT Gateway hotpaths, cross-AZ transfer, Athena buckets, Spot opportunities |
| Wave 2 – Lifecycle | 15, 16 | Lambda deprecated runtimes, Classic Load Balancers |
| Wave 3 – Reliability | 26, 28 | DR quota drift, DR runbook tracker |
| Wave 4 – Security | 30, 31, 33, 34, 35, 36, 37 | Open SGs, IAM user hygiene, unencrypted resources, KMS rotation, CloudTrail, security services, IAM roles |
| Wave 5 – Performance | 38, 39, 40, 41 | EBS/network mismatch, CPU/memory mismatch, idle provisioned IOPS, CloudFront low cache-hit |
| Continuous | 43, 46, 48, 49, 54 | Tagging compliance, unmonitored resources, quota utilization, custom quotas, inventory refresh |

## Task Reference (proactive.md)

`proactive.md` documents all 54 detection tasks with exact boto3 API calls, filters, and payoff estimates. The waves indicate priority order:

- **Wave 1** — Cost fast wins
- **Wave 2** — End-of-support / lifecycle exposure
- **Wave 3** — Reliability / fault tolerance
- **Wave 4** — Security posture
- **Wave 5** — Performance
- **Continuous** — Tagging, quota monitoring, patch compliance
