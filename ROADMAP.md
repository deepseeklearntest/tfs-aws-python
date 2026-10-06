# AWS Proactive — Roadmap

Scope: tasks in `proactive.xlsx` → **Current_Work** sheet only.
Tasks outside that sheet are deferred (owned by other teams).

---

## Milestone 1 — Script Enhancements & Validation

All 25 in-scope scripts have a detection implementation. This milestone covers
follow-up work flagged in the Current_Work Comments / Detailed Actions columns.

### Enhancement Tasks

- [x] **#52 improve** — `continuous/52_detect_health_events.py`: Added `issue` category, `service-issue` finding code, org-wide sweep via `describe_events_for_organization`, and `_write_finding()` helper. *(2026-06-15)*
- [x] **#34 actions doc** — Added `protects` + `priority` CSV columns. `_classify_key()` infers resource type from alias/description and assigns high/medium/low priority. `detail` field now includes both for at-a-glance triage. *(2026-06-15)*
- [x] **#48 impact doc** — Added `production_impact` CSV column with 27 keyword-matched impact descriptions + per-service fallbacks covering all 14 scanned services. *(2026-06-15)*
- [x] **#46 non-prod check** — Added `environment` CSV column + fixed ELB tags (were always `None`). Script already covered all environments; now verifiable in output. *(2026-06-15)*
- [x] **#54 first report** — Fixed `rag_continuous`: 13 finding codes now map to correct RED/AMBER/GREEN; previously all continuous findings rendered GREEN. Confirmed extra columns auto-discovered. *(2026-06-15)*
- [ ] **#7 account list** — Cross-AZ transfer: run against cgdc-test, cgdc-dev, cgdc-stage, cgdc-prod and validate findings. *(requires AWS credentials — run manually)*
- [x] **Security cross-check tool** — `wave4_security/compare_sg_findings.py`: reconciles #30 open-SG findings against the security team's Wiz SSH/RDP export at (account, sg, port) granularity; outputs OVERLAP / OURS-ONLY / THEIRS-ONLY. *(2026-07-27)*
- [x] **#30 ICMP fix** — ICMP/ICMPv6 rules now reported as their own `icmp-open-to-internet` finding instead of being misread as exposing every sensitive TCP port (AWS reuses FromPort/ToPort as ICMP type/code). *(2026-07-28)*
- [x] **#33 owner fallback** — EBS findings fall back to the attached EC2 instance's owner tag when the volume itself has none, and add an `attached_instance_name` column. Recovers ~174 of 193 previously-blank owners. *(2026-07-29)*

### Deferred / Blocked

| # | Title | Reason |
|---|-------|--------|
| 6 | NAT Gateway Egress Hot Paths | Owned by network team |
| 28 | Untested DR Runbooks | Waiting on full DR list from stakeholders |
| 30 | Open Security Groups | Cross-check tool built (`compare_sg_findings.py`) against security team's SSH/RDP list; still need an org-wide #30 run before the reconciliation numbers (currently 2-account sample) are meaningful |
| 36 | GuardDuty / Security Hub / Config | Need cost assessment + check for alternatives |

---

## Stop Conditions

Autonomous loop pauses when:
- Task requires a human decision or stakeholder input
- Tests cannot pass after 3 repair attempts
- Work would exceed the current milestone scope
- Credentials, paid services, or external access are needed
