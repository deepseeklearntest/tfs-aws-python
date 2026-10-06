---
name: new-detector
description: Scaffold a new AWS detection script from a proactive.md task. Use when asked to implement, create, or add a new detector.
argument-hint: <task-number> <script-slug>
arguments: [task_num, script_slug]
disable-model-invocation: true
allowed-tools: Read Glob Write
---

Implement task $task_num as `$task_slug`.

1. Read `proactive.md` and find task $task_num. Extract: title, wave assignment, exact boto3 API calls, filters, metric names, and payoff estimate.

2. Determine the wave directory:
   - Wave 1 → `wave1_cost/`
   - Wave 2 → `wave2_lifecycle/` (create if needed)
   - Wave 3 → `wave3_reliability/` (create if needed)
   - Wave 4 → `wave4_security/` (create if needed)
   - Wave 5 → `wave5_performance/` (create if needed)
   - Continuous → `continuous/` (create if needed)

3. **Check temporal and AWS currency before writing any code:**
   - Note today's date from the `currentDate` session context. Use it to verify every EOL/deprecation date referenced in the task spec — do not trust training-data snapshots of AWS EOL dates.
   - If the task involves a list of AWS regions, instance types, runtime versions, or engine versions, prefer fetching these from AWS APIs at runtime (e.g. `ec2.describe_regions()`, `rds.describe_db_engine_versions()`) over hardcoded lists.
   - If a hardcoded lookup table (e.g. EOL date dict) is unavoidable, add an inline comment with the date it was last verified against AWS docs.
   - Cross-check the exact boto3 parameter names and response shapes in the task spec against current boto3/AWS documentation — the spec captures intent but API details may have evolved.

4. Create `<wave_dir>/$task_num_$script_slug.py` following the anatomy in CLAUDE.md. Rules:
   - Set `SCRIPT_NAME = '$task_num_$script_slug'`
   - Populate `EXTRA_FIELDS` with script-specific CSV columns beyond COMMON_FIELDS
   - Implement `scan()` using the exact boto3 calls specified in proactive.md for this task
   - Wrap every boto3 call: `except ClientError as exc: if session.is_skippable(exc): return; raise`
   - Use `pricing.<helper>(region)` for all cost estimates — never hardcode prices
   - Use `get_paginator()` for all list/describe calls
   - For account-level scans (no region loop): pass `account_level=True` to both `cli.make_parser()` and `cli.run()`, and define `scan(sess, account_id, writer)`
   - All date/age comparisons must use `date.today()` or `datetime.now(timezone.utc)` — never hardcode date literals

5. Confirm the output file path and show the first 50 lines.
