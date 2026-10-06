---
name: run-scan
description: Run a detection script with safe sampling defaults. Use when asked to run, test, or execute a scan script.
argument-hint: <script-path-or-task-number> [extra-flags]
disable-model-invocation: true
allowed-tools: Glob Bash(python *)
---

Run detection script: $ARGUMENTS

## Steps

1. Resolve the target script from $ARGUMENTS:
   - If it contains `.py`, use it as the path directly.
   - If it is a 1-2 digit number (e.g. `1` or `01`), glob `wave*/*.py` and find the script whose filename starts with that zero-padded number.
   - If it is a name fragment (e.g. `gp2`), glob `wave*/*$ARGUMENTS*.py` and use the first match.

2. Run with these safe sampling defaults **unless $ARGUMENTS already includes overrides**:
   - `--max-accounts 1` — scan only 1 account
   - `--max-regions 2` — scan only 2 regions per account
   - `--workers 1` — sequential mode for readable output

   Example: `python wave1_cost/01_detect_gp2_volumes.py --max-accounts 1 --max-regions 2 --workers 1`

3. After the run completes, report:
   - The findings CSV path (from `findings/`) and row count
   - Any ERROR or WARNING lines from the output
   - Total elapsed time
