# Task Log

Append an entry here each time the Judge approves a task.
Format: `## YYYY-MM-DD — <task title>`

---

## 2026-07-29 — #33 owner fallback + attached instance name for EBS findings

**Changes to `wave4_security/33_detect_unencrypted_resources.py`:**
- Added `_get_instance_info(ec2, instance_id, cache)` — per-region lookup cache resolving an attached EC2 instance's `Name` tag and owner tag via `describe_instances`, cached by `instance_id` so volumes sharing an instance (root + data disks) reuse one API call
- New `attached_instance_name` column in `EXTRA_FIELDS` (EBS: resolved name; RDS: blank for schema parity, no attached-instance concept there)
- EBS owner resolution now falls back to the attached instance's owner tag when the volume's own tags have none, passed explicitly via `owner=` to `FindingsWriter.write()` (the override mechanism `common/output.py` already documents) — volume's own tag always wins when present
- RDS owner attribution deliberately unchanged — DB team's separate review path is unaffected
- Recovers owner attribution for ~174 of 193 previously-blank-owner EBS findings (measured against `33_detect_unencrypted_resources_20260721_121553.csv`)
- No pivot-table script built — CSV is pivot-ready as-is (Owner/Attached Instance Name/Resource Subtype columns); one-time triage, not a recurring job
- Spec: `docs/superpowers/specs/2026-07-29-unencrypted-owner-fallback-design.md`; Plan: `docs/superpowers/plans/2026-07-29-unencrypted-owner-fallback.md`
- Implemented via subagent-driven-development, adapted for this repo having no git (file-snapshot diffs instead of git diffs, no worktree/ledger-by-commit): 2 tasks, both task reviews clean, final whole-change review approved with no blocking findings

---

## 2026-07-28 — #30 fix: ICMP rules no longer misclassified as sensitive-port exposures

**Changes to `wave4_security/30_detect_open_security_groups.py`:**
- ICMP/ICMPv6 rules (`ICMP_PROTOCOLS`) are now routed to their own finding code `icmp-open-to-internet` before reaching `_overlaps_sensitive`, instead of having their type/code fields misread as an unbounded TCP/UDP port range
- Root cause: AWS reuses `FromPort`/`ToPort` as ICMP type/code; the old code's `to_port == -1 -> 65535` fallback made any ICMP-open rule appear to expose every sensitive port (e.g. `Ports=8--1` was being read as "ports 8 through 65535 open", flagging SSH/RDP/3306/etc. that were never actually open)
- Added `_format_icmp_type_code()` — renders e.g. `Type=8 Code=all` instead of the ambiguous `8--1` string
- Confirmed no downstream break: `generate_report.py::rag_security` and `common/findings_io.py::severity_of` both keyword-match on the `finding` field; neither `open-to-internet` nor the new `icmp-open-to-internet` matches their red/amber keyword lists, so severity classification is unchanged before and after

---

## 2026-07-27 — Cross-check tool: compare_sg_findings.py vs security team's Wiz export

**New file `wave4_security/compare_sg_findings.py`** (standalone, auth-free, stdlib-only — no Britive/session.py):
- Reconciles script 30's open-SG findings against the security team's Wiz export (`ec2_filtered_findings.csv`, SSH/RDP-only) at `(account_id, sg_id, port)` granularity
- Three output categories: `OVERLAP` (security team already owns it — SSH/RDP match), `OURS-ONLY` (other 9 sensitive ports, or SSH/RDP not in their file — our action list), `THEIRS-ONLY` (their finding, our scan never caught it — coverage-gap signal)
- An all-traffic rule can land in both OVERLAP and OURS-ONLY simultaneously (recorded via separate `covered_ports`/`uncovered_ports` columns) since it may cover 22/3389 (covered) and DB/cache ports (not covered) at once
- `_parse_our_ports()` mirrors script 30's own `_overlaps_sensitive` ICMP fallback semantics (`to_port == -1 -> 65535`) so historical CSVs with the pre-fix `8--1`-style port_range still reconcile correctly instead of being silently dropped
- Output CSV written with `utf-8-sig` (BOM) so Excel renders the Wiz `Wiz Status` emoji column correctly instead of cp1252 mojibake
- Verified against current sample data (2-account CSV): 18 OVERLAP + 24 OURS-ONLY = 42 (all rows accounted for), 4,570 THEIRS-ONLY — noted that this last number is mostly a coverage artifact of the 2-account sample, not a real gap; needs an org-wide script 30 run to be meaningful

---

## 2026-06-15 — Fix severity_of continuous wave in common/findings_io.py

**Changes to `common/findings_io.py`:**
- Replaced stale substring keywords in `severity_of` continuous branch with exact set membership matching `rag_continuous` in `generate_report.py`
- HIGH: quota-at-80pct, service-issue, retirement-notice, no-cloudwatch-agent
- MEDIUM: quota-at-70pct, custom-quota-threshold-reached, scheduled-change, missing-required-tags, inconsistent-tag-key, enhanced-monitoring-disabled, access-logs-disabled, account-notification
- `dataset/findings_dataset.csv` severity column now correct for all continuous findings
- Reviewed via subagent-driven-development: spec compliant, code quality approved

---

## 2026-06-15 — #54 first report: fix rag_continuous — all continuous findings were GREEN

**Changes to `generate_report.py`:**
- Replaced stale keyword check (`'critical'`, `'unmonitored'`, `'warning'`) in `rag_continuous` with exact finding-code sets
- All 13 finding codes from scripts 43/46/48/49/52 now have correct RAG colours:
  - RED: quota-at-80pct, service-issue, retirement-notice, no-cloudwatch-agent
  - AMBER: quota-at-70pct, custom-quota-threshold-reached, scheduled-change, missing-required-tags, inconsistent-tag-key, enhanced-monitoring-disabled, access-logs-disabled, account-notification
- Confirmed extra-column auto-discovery picks up new columns (protects, priority, environment, production_impact) in wave sheets

---

## 2026-06-15 — #34 actions doc: protects + priority triage columns for KMS keys

**Changes to `wave4_security/34_detect_kms_rotation_disabled.py`:**
- Added `protects` and `priority` to EXTRA_FIELDS
- Added `_PROTECTS_MAP` (11 resource-type entries) and env-keyword sets
- Added `_classify_key(alias, description)` - pure function, no AWS calls; infers what the key protects and assigns high/medium/low priority
- Priority rules: RDS/Secrets/S3/EKS always high; prod env tag escalates to high; dev/test/staging + non-critical resource = low; otherwise medium
- `detail` field now includes Protects= and Priority= for at-a-glance column visibility
- Directly implements xlsx remediation step: "Prioritize by age and what the key protects"

---

## 2026-06-15 — #48 impact doc: production_impact column in quota utilization

**Changes to `continuous/48_detect_quota_utilization.py`:**
- Added `production_impact` to `EXTRA_FIELDS` - new CSV column on every finding row
- Added `_IMPACT_HINTS` dict (27 entries, keyword-matched) covering all 14 services in DEFAULT_SERVICES
- Added `_SERVICE_FALLBACK` dict for coarse per-service coverage when no keyword matches
- Added `_impact(service_code, quota_name)` lookup function
- All impact strings are ASCII-safe; comment marks last-verified date for maintenance
- Directly addresses xlsx comment: "list of issues anticipated once service quota reached"

---

## 2026-06-15 — #46 non-prod check: environment column + ELB tags fix

**Changes to `continuous/46_detect_unmonitored_resources.py`:**
- Added `environment` to `EXTRA_FIELDS` — CSV now has explicit `Environment` column for filtering by prod/non-prod
- Added `_env_tag()` helper shared by all three sub-scanners
- Fixed silent bug: `describe_load_balancers()` does not return tags; added batch `describe_tags()` call (up to 20 ARNs per call) so ELB tags and `environment` are now populated correctly
- Script already scanned all environments; this change makes that verifiable in the CSV output

---

## 2026-06-15 — #52 improve: Health Events org-wide sweep + issue category

**Changes to `continuous/52_detect_health_events.py`:**
- Added `issue` event type category (active service disruptions were silently skipped before)
- Added `service-issue` finding code branch in `_finding_code()`
- Added `_scan_org()`: tries `describe_events_for_organization` first for org-wide coverage from the management account; falls back gracefully to per-account scan on subscription/access errors
- Extracted `_write_finding()` helper to eliminate duplicated `writer.write()` calls
- All existing per-account logic and CSV columns preserved

---

## 2026-06-15 — Baseline: 25 in-scope scripts implemented

All 25 tasks in `proactive.xlsx` → Current_Work sheet have detection scripts.

| # | Script | Status |
|---|--------|--------|
| 6 | `wave1_cost/06_detect_nat_gateway_hotpaths.py` | Implemented |
| 7 | `wave1_cost/07_detect_cross_az_transfer.py` | Implemented |
| 10 | `wave1_cost/10_detect_athena_result_buckets.py` | Implemented |
| 13 | `wave1_cost/13_detect_spot_opportunities.py` | Implemented |
| 15 | `wave2_lifecycle/15_detect_lambda_deprecated_runtimes.py` | Implemented |
| 16 | `wave2_lifecycle/16_detect_classic_load_balancers.py` | Implemented |
| 26 | `wave3_reliability/26_detect_quota_drift_dr.py` | Implemented |
| 28 | `wave3_reliability/28_dr_runbook_tracker.py` | Implemented |
| 30 | `wave4_security/30_detect_open_security_groups.py` | Implemented |
| 31 | `wave4_security/31_detect_iam_user_hygiene.py` | Implemented |
| 33 | `wave4_security/33_detect_unencrypted_resources.py` | Implemented |
| 34 | `wave4_security/34_detect_kms_rotation_disabled.py` | Implemented |
| 35 | `wave4_security/35_detect_cloudtrail_gaps.py` | Implemented |
| 36 | `wave4_security/36_detect_security_services_gaps.py` | Implemented |
| 37 | `wave4_security/37_detect_iam_risky_roles.py` | Implemented |
| 38 | `wave5_performance/38_detect_ebs_network_mismatch.py` | Implemented |
| 39 | `wave5_performance/39_detect_cpu_memory_mismatch.py` | Implemented |
| 40 | `wave5_performance/40_detect_idle_provisioned_iops.py` | Implemented |
| 41 | `wave5_performance/41_detect_cloudfront_low_cache_hit.py` | Implemented |
| 43 | `continuous/43_detect_tagging_compliance.py` | Implemented |
| 46 | `continuous/46_detect_unmonitored_resources.py` | Implemented |
| 48 | `continuous/48_detect_quota_utilization.py` | Implemented |
| 49 | `continuous/49_detect_custom_quotas.py` | Implemented |
| 52 | `continuous/52_detect_health_events.py` | Implemented |
| 54 | `continuous/54_inventory_refresh.py` | Implemented |
