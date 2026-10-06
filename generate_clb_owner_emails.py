#!/usr/bin/env python3
"""Classic Load Balancer owner-notification email generator.

Reads the latest 16_detect_classic_load_balancers CSV, groups findings by
resource owner, and writes one plain-text email draft per owner covering all
their Classic Load Balancers (deletion candidates and migration candidates
listed separately within the same email).

Standalone, stdlib-only — no boto3, no AWS auth required.

Run: python generate_clb_owner_emails.py
     python generate_clb_owner_emails.py --findings-dir findings --output-dir reports/clb_owner_emails
"""
from __future__ import annotations

import argparse
import csv
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common.findings_io import discover_latest_csvs

UNKNOWN_OWNER = "UNASSIGNED - needs manual owner lookup"
MIXED_OWNER = "MIXED - registered instances disagree on owner, needs manual check"


def _sanitize_filename(name: str) -> str:
    keep = "".join(c if c.isalnum() or c in "-_.@" else "_" for c in name)
    return keep.strip("_") or "unknown"


def _find_clb_csv(findings_dir: str) -> Path:
    for path in discover_latest_csvs(findings_dir):
        if path.stem.startswith("16_detect_classic_load_balancers"):
            return path
    raise FileNotFoundError(
        f"No 16_detect_classic_load_balancers CSV found under {findings_dir}. "
        "Run wave2_lifecycle/16_detect_classic_load_balancers.py first."
    )


def _load_rows(csv_path: Path) -> list[dict]:
    with open(csv_path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def _group_by_owner(rows: list[dict]) -> dict[str, list[dict]]:
    groups: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        owner = (row.get("owner") or "").strip()
        if not owner:
            key = UNKNOWN_OWNER
        elif owner.lower() == "mixed":
            key = MIXED_OWNER
        else:
            key = owner
        groups[key].append(row)
    return groups


def _lb_line(row: dict) -> str:
    return (
        f"  - {row.get('resource_id', '')}  "
        f"(Account: {row.get('account_id', '')}, Region: {row.get('region', '')}, "
        f"Age: {row.get('age_days', '?')} days, "
        f"Traffic last 30d: {row.get('request_count_30d', 'unknown')} requests)"
    )


def _build_email(owner: str, rows: list[dict]) -> str:
    delete_rows = [r for r in rows if "deletion candidate" in r.get("finding", "")]
    migrate_rows = [r for r in rows if "migrate to alb or nlb" in r.get("finding", "").lower()]

    lines: list[str] = []
    lines.append("Subject: Action Required - Classic Load Balancer(s) in your AWS Account")
    lines.append("")
    lines.append("Dear Team,")
    lines.append("")
    lines.append("Greetings from CloudOps Team.")
    lines.append("")
    lines.append(
        "During our regular AWS review, we found the below Classic Load Balancer(s) "
        "(CLB) running under your account(s)/tags. Please note that AWS recommends "
        "moving away from Classic Load Balancers in favour of Application Load "
        "Balancer (ALB) or Network Load Balancer (NLB), as CLB is a legacy type and "
        "does not support many modern features (path-based routing, WAF, HTTP/2, "
        "container targets, etc.). CLB is still supported by AWS today, but it is "
        "not recommended for continued use, so we request you to plan the below "
        "actions at your convenience."
    )
    lines.append("")

    if delete_rows:
        lines.append(
            f"1) No traffic / no instances attached - please confirm and DELETE "
            f"if not required ({len(delete_rows)} load balancer(s)):"
        )
        for r in delete_rows:
            lines.append(_lb_line(r))
        lines.append("")

    if migrate_rows:
        lines.append(
            f"2) Actively serving traffic - please plan to MIGRATE to "
            f"ALB/NLB ({len(migrate_rows)} load balancer(s)):"
        )
        for r in migrate_rows:
            target = r.get("migration_target", "ALB/NLB")
            lines.append(_lb_line(r) + f"  -> Recommended target: {target}")
        lines.append("")

    lines.append(
        "Kindly review the above and let us know your tentative timeline. In case "
        "you need any help or clarification from our side, please feel free to "
        "reach out, we are happy to assist."
    )
    lines.append("")
    lines.append("Please do the needful at the earliest.")
    lines.append("")
    lines.append("Thanks and Regards,")
    lines.append("CloudOps Team - Thermo Fisher Scientific")
    lines.append("")

    if owner in (UNKNOWN_OWNER, MIXED_OWNER):
        lines.insert(
            0,
            f"[INTERNAL NOTE - do not send as-is: owner could not be resolved "
            f"automatically ({owner}). Check the 'detail' column in the source CSV "
            f"for owner_candidates, or confirm with the account team before sending.]\n",
        )

    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--findings-dir", default="findings")
    parser.add_argument("--output-dir", default="reports/clb_owner_emails")
    args = parser.parse_args()

    csv_path = _find_clb_csv(args.findings_dir)
    rows = _load_rows(csv_path)
    if not rows:
        print(f"No rows in {csv_path} - nothing to do.")
        return

    groups = _group_by_owner(rows)
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"Source: {csv_path}")
    print(f"Owners found: {len(groups)}")
    print("-" * 60)

    for owner, owner_rows in sorted(groups.items()):
        filename = _sanitize_filename(owner) + ".txt"
        out_path = out_dir / filename
        out_path.write_text(_build_email(owner, owner_rows), encoding="utf-8")
        flag = "  <-- NEEDS MANUAL OWNER CHECK" if owner in (UNKNOWN_OWNER, MIXED_OWNER) else ""
        print(f"  {len(owner_rows):3d} LB(s)  ->  {owner}{flag}")
        print(f"           {out_path}")

    print("-" * 60)
    print(f"Wrote {len(groups)} email draft(s) to {out_dir}")


if __name__ == "__main__":
    main()
