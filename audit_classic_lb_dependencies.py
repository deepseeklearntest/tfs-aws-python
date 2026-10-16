#!/usr/bin/env python3
"""Read-only dependency audit for zero-traffic Classic Load Balancers.

Usage:
    python reports/CLB/audit_classic_lb_dependencies.py ^
        --findings-file findings/phase2/wave2_lifecycle/16_detect_classic_load_balancers_YYYYMMDD_HHMMSS.csv

The source findings CSV must have a matching complete-run JSON manifest. Candidates
are rows with zero RequestCount in both the 30-day and 60-day windows. The audit
checks the live CLB, its tags, Route 53 records across the credentialed accounts,
CloudFormation resources/exports in the CLB's account and region, registered EC2
instances, and the CLB's security groups. It makes no AWS changes.
"""
from __future__ import annotations

import argparse
import csv
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from common import session  # noqa: E402
from botocore.exceptions import ClientError  # noqa: E402

LOG = logging.getLogger("classic_lb_dependency_audit")
SCRIPT_NAME = "classic_lb_dependency_audit"
CF_SCOPE_NOTE = (
    "All non-deleted CloudFormation stack resources in the CLB account and region "
    "were checked for an AWS::ElasticLoadBalancing::LoadBalancer physical ID "
    "matching the CLB name or DNS name. Direct exports matching the CLB name/DNS "
    "and imports of exports owned by a matching stack are reported."
)


def _error(exc: Exception) -> dict[str, str]:
    if isinstance(exc, ClientError):
        return {
            "code": str(exc.response.get("Error", {}).get("Code", "ClientError")),
            "message": str(exc.response.get("Error", {}).get("Message", exc)),
        }
    return {"code": type(exc).__name__, "message": str(exc)}


def _status(errors: list[dict[str, str]]) -> str:
    return "partial" if errors else "complete"


def _normalise_dns(value: str | None) -> str:
    result = (value or "").strip().lower().rstrip(".")
    while result.startswith("dualstack."):
        result = result[len("dualstack."):]
    return result


def _matches_reference(value: str | None, name: str, dns_name: str) -> bool:
    text = (value or "").strip().lower()
    if not text:
        return False
    dns = _normalise_dns(dns_name)
    normalised = _normalise_dns(text)
    return (
        normalised == _normalise_dns(name)
        or (dns and normalised == dns)
        or name.lower() in text
        or (dns and dns in normalised)
    )


def _read_candidates(findings_file: Path, expected_count: int | None) -> tuple[list[dict], dict]:
    if not findings_file.is_file():
        raise FileNotFoundError(f"Findings CSV does not exist: {findings_file}")
    manifest_path = findings_file.with_suffix(".json")
    if not manifest_path.is_file():
        raise ValueError(f"Run manifest is missing: {manifest_path}")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("status") != "complete":
        raise ValueError(
            f"Source scan is not complete (status={manifest.get('status')!r}): "
            f"{manifest_path}"
        )
    scope = manifest.get("scope", {})
    if scope.get("regions") != "enabled" or manifest.get("sample") is True:
        raise ValueError("Source scan must be a complete, non-sampled regional scan")

    with findings_file.open(encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        required = {
            "account_id", "region", "resource_id", "request_count_30d",
            "request_count_60d", "request_count_90d", "deletion_confidence",
        }
        missing = required - set(reader.fieldnames or [])
        if missing:
            raise ValueError(f"Findings CSV is missing required fields: {sorted(missing)}")
        candidates = [
            row for row in reader
            if row["request_count_30d"].strip() == "0"
            and row["request_count_60d"].strip() == "0"
        ]

    keys = [
        (row["account_id"].strip(), row["region"].strip(), row["resource_id"].strip())
        for row in candidates
    ]
    if any(not all(key) for key in keys):
        raise ValueError("A zero-traffic candidate is missing account, region, or CLB name")
    if len(keys) != len(set(keys)):
        raise ValueError("Source findings contain duplicate zero-traffic CLBs")
    if not candidates:
        raise ValueError("No zero-traffic CLBs were found in the source findings")
    if expected_count is not None and len(candidates) != expected_count:
        raise ValueError(
            f"Expected {expected_count} zero-traffic CLBs, found {len(candidates)}"
        )

    manifest_accounts = set(scope.get("accounts", []))
    candidate_accounts = {key[0] for key in keys}
    if not candidate_accounts.issubset(manifest_accounts):
        raise ValueError("Candidate account IDs are outside the source scan manifest scope")
    return candidates, manifest


def _paginate(client, operation: str, result_key: str, **kwargs: Any) -> list[dict]:
    paginator = client.get_paginator(operation)
    return [
        item
        for page in paginator.paginate(**kwargs)
        for item in page.get(result_key, [])
    ]


def _route53_inventory(
    account_sessions: dict[str, Any],
) -> tuple[dict[str, list[dict]], dict[str, list[dict]], dict[str, int]]:
    records_by_account: dict[str, list[dict]] = {}
    errors_by_account: dict[str, list[dict]] = {}
    zone_counts: dict[str, int] = {}
    for account_id, aws_session in account_sessions.items():
        records_by_account[account_id] = []
        errors_by_account[account_id] = []
        zone_counts[account_id] = 0
        try:
            client = aws_session.client("route53")
            zones = _paginate(client, "list_hosted_zones", "HostedZones")
        except Exception as exc:
            LOG.exception("Unable to list Route 53 hosted zones in account %s", account_id)
            errors_by_account[account_id].append(_error(exc))
            continue
        zone_counts[account_id] = len(zones)
        for zone in zones:
            zone_id = zone.get("Id", "").split("/")[-1]
            if not zone_id:
                continue
            try:
                records = _paginate(
                    client, "list_resource_record_sets", "ResourceRecordSets",
                    HostedZoneId=zone_id,
                )
                for record in records:
                    target_names = []
                    alias = record.get("AliasTarget", {}).get("DNSName")
                    if alias:
                        target_names.append(alias)
                    target_names.extend(
                        entry.get("Value", "")
                        for entry in record.get("ResourceRecords", [])
                    )
                    records_by_account[account_id].append({
                        "hosted_zone_id": zone_id,
                        "hosted_zone_name": zone.get("Name", ""),
                        "record_name": record.get("Name", ""),
                        "record_type": record.get("Type", ""),
                        "targets": target_names,
                    })
            except Exception as exc:
                LOG.exception(
                    "Unable to list Route 53 records in account %s, zone %s",
                    account_id, zone_id,
                )
                errors_by_account[account_id].append(_error(exc))
    return records_by_account, errors_by_account, zone_counts


def _cloudformation_inventory(
    aws_session: Any, region: str,
) -> tuple[list[dict], list[dict], list[dict]]:
    client = aws_session.client("cloudformation", region_name=region)
    errors: list[dict] = []
    try:
        exports = _paginate(client, "list_exports", "Exports")
    except Exception as exc:
        LOG.exception("Unable to list CloudFormation exports in %s", region)
        exports = []
        errors.append(_error(exc))
    try:
        stack_summaries = _paginate(client, "list_stacks", "StackSummaries")
    except Exception as exc:
        LOG.exception("Unable to list CloudFormation stacks in %s", region)
        stack_summaries = []
        errors.append(_error(exc))

    stacks = []
    for summary in stack_summaries:
        if summary.get("StackStatus") == "DELETE_COMPLETE":
            continue
        stack_id = summary.get("StackId") or summary.get("StackName")
        if not stack_id:
            continue
        try:
            resources = client.describe_stack_resources(StackName=stack_id).get(
                "StackResources", []
            )
            stacks.append({
                "stack_name": summary.get("StackName", ""),
                "stack_id": stack_id,
                "stack_status": summary.get("StackStatus", ""),
                "resources": resources,
            })
        except Exception as exc:
            LOG.exception("Unable to inspect CloudFormation stack %s", stack_id)
            errors.append(_error(exc))
    return exports, stacks, errors


def _audit_cloudformation(
    aws_session: Any,
    region: str,
    name: str,
    dns_name: str,
    tags: list[dict],
    inventory: tuple[list[dict], list[dict], list[dict]],
) -> tuple[dict, dict]:
    exports, stacks, inventory_errors = inventory
    errors = list(inventory_errors)
    related_exports = []
    stack_resource_matches = []
    tag_indicated_stacks = []
    exports_owned_by_matching_stacks = []
    matching_stack_ids: set[str] = set()

    for stack in stacks:
        if any(
            tag.get("Key", "").casefold() == "aws:cloudformation:stack-name"
            and tag.get("Value") == stack["stack_name"]
            for tag in tags
        ) or any(
            tag.get("Key", "").casefold() == "aws:cloudformation:stack-id"
            and tag.get("Value") == stack["stack_id"]
            for tag in tags
        ):
            tag_indicated_stacks.append({
                "stack_name": stack["stack_name"],
                "stack_id": stack["stack_id"],
                "stack_status": stack["stack_status"],
            })
            matching_stack_ids.add(stack["stack_id"])

        for resource in stack["resources"]:
            if (
                resource.get("ResourceType") == "AWS::ElasticLoadBalancing::LoadBalancer"
                and _matches_reference(
                    resource.get("PhysicalResourceId", ""), name, dns_name
                )
            ):
                stack_resource_matches.append({
                    "stack_name": stack["stack_name"],
                    "stack_id": stack["stack_id"],
                    "logical_resource_id": resource.get("LogicalResourceId", ""),
                    "physical_resource_id": resource.get("PhysicalResourceId", ""),
                    "resource_type": resource.get("ResourceType", ""),
                })
                matching_stack_ids.add(stack["stack_id"])

    for export in exports:
        export_name = export.get("Name", "")
        export_value = export.get("Value", "")
        if _matches_reference(export_name, name, dns_name) or _matches_reference(
            export_value, name, dns_name
        ):
            related_exports.append({
                "name": export_name,
                "value": export_value,
                "exporting_stack_id": export.get("ExportingStackId", ""),
            })
        if export.get("ExportingStackId") in matching_stack_ids:
            imports = []
            try:
                imports = _paginate(
                    aws_session.client("cloudformation", region_name=region),
                    "list_imports", "Imports", ExportName=export_name,
                )
            except Exception as exc:
                LOG.exception("Unable to list imports for export %s", export_name)
                errors.append(_error(exc))
            exports_owned_by_matching_stacks.append({
                "name": export_name,
                "value": export_value,
                "exporting_stack_id": export.get("ExportingStackId", ""),
                "imports": imports,
            })

    evidence = {
        "related_exports": related_exports,
        "stack_resource_matches": stack_resource_matches,
        "tag_indicated_stacks": tag_indicated_stacks,
        "exports_owned_by_matching_stacks": exports_owned_by_matching_stacks,
    }
    check = {
        "status": _status(errors),
        "region": region,
        "exports_examined": len(exports),
        "errors": errors,
        "scope_note": CF_SCOPE_NOTE,
    }
    return check, evidence


def _inspect_candidate(
    aws_session: Any,
    candidate: dict,
    route53_records: dict[str, list[dict]],
    route53_errors: dict[str, list[dict]],
    route53_zone_counts: dict[str, int],
    cf_inventory: tuple[list[dict], list[dict], list[dict]],
) -> dict:
    account_id = candidate["account_id"].strip()
    region = candidate["region"].strip()
    name = candidate["resource_id"].strip()
    result: dict[str, Any] = {
        "account_id": account_id,
        "region": region,
        "load_balancer_name": name,
        "prior_deletion_confidence": candidate.get("deletion_confidence", ""),
        "prior_request_counts": {
            "30d": candidate.get("request_count_30d", ""),
            "60d": candidate.get("request_count_60d", ""),
            "90d": candidate.get("request_count_90d", ""),
        },
        "checks": {},
        "load_balancer": None,
        "clb_tags": [],
        "cloudformation": {
            "related_exports": [],
            "stack_resource_matches": [],
            "tag_indicated_stacks": [],
            "exports_owned_by_matching_stacks": [],
        },
        "registered_instances": {"registered_ids": [], "details": []},
        "route53_records": [],
        "security_groups": {"clb_group_ids": [], "groups": []},
    }
    checks = result["checks"]
    elb = aws_session.client("elb", region_name=region)
    ec2 = aws_session.client("ec2", region_name=region)
    errors: list[dict[str, str]] = []
    load_balancer = None
    try:
        descriptions = elb.describe_load_balancers(LoadBalancerNames=[name]).get(
            "LoadBalancerDescriptions", []
        )
        load_balancer = next(
            (item for item in descriptions if item.get("LoadBalancerName") == name),
            None,
        )
        if load_balancer is None:
            raise LookupError(f"Load balancer {name!r} was not returned by ELB")
        result["load_balancer"] = {
            "dns_name": load_balancer.get("DNSName", ""),
            "scheme": load_balancer.get("Scheme", ""),
            "created_time": (
                load_balancer["CreatedTime"].isoformat()
                if load_balancer.get("CreatedTime") else None
            ),
            "listeners": load_balancer.get("ListenerDescriptions", []),
            "health_check": load_balancer.get("HealthCheck", {}),
            "instances": load_balancer.get("Instances", []),
            "security_groups": load_balancer.get("SecurityGroups", []),
            "availability_zones": load_balancer.get("AvailabilityZones", []),
            "vpc_id": load_balancer.get("VPCId", ""),
        }
        checks["load_balancer"] = {"status": "complete", "error": None}
    except Exception as exc:
        LOG.exception("Unable to describe CLB %s in %s", name, account_id)
        checks["load_balancer"] = {"status": "partial", "error": _error(exc)}

    tags: list[dict] = []
    tag_errors: list[dict[str, str]] = []
    if load_balancer is not None:
        try:
            tag_response = elb.describe_tags(LoadBalancerNames=[name])
            if tag_response.get("TagDescriptions"):
                tags = tag_response["TagDescriptions"][0].get("Tags", [])
        except Exception as exc:
            LOG.exception("Unable to retrieve tags for CLB %s", name)
            tag_errors.append(_error(exc))
    else:
        tag_errors.append({
            "code": "NotAudited",
            "message": "CLB tags could not be checked because its live description failed",
        })
    result["clb_tags"] = tags
    checks["clb_tags"] = {
        "status": _status(tag_errors),
        "error": tag_errors[0] if tag_errors else None,
    }

    dns_name = (
        result["load_balancer"].get("dns_name", "")
        if result["load_balancer"] else ""
    )
    cf_check, cf_evidence = _audit_cloudformation(
        aws_session, region, name, dns_name, tags, cf_inventory,
    )
    checks["cloudformation"] = cf_check
    result["cloudformation"] = cf_evidence

    hosted_zone_count = sum(route53_zone_counts.values())
    route53_match_errors: list[dict[str, str]] = []
    for route53_account, records in route53_records.items():
        account_errors = route53_errors.get(route53_account, [])
        route53_match_errors.extend(
            {"account_id": route53_account, **error} for error in account_errors
        )
        for record in records:
            if dns_name and any(
                _normalise_dns(target) == _normalise_dns(dns_name)
                for target in record["targets"]
            ):
                result["route53_records"].append({
                    "account_id": route53_account,
                    **record,
                })
    if not dns_name:
        route53_match_errors.append({
            "account_id": account_id,
            "code": "NotAudited",
            "message": "Route 53 DNS-target matching requires the live CLB DNS name",
        })
    checks["route53"] = {
        "status": _status(route53_match_errors),
        "hosted_zone_count": hosted_zone_count,
        "errors": route53_match_errors,
        "match_method": (
            "exact CLB DNS target; dualstack prefix accepted; all credentialed accounts"
        ),
    }

    registered_ids = sorted(
        item.get("InstanceId", "")
        for item in (load_balancer or {}).get("Instances", [])
        if item.get("InstanceId")
    )
    instance_details: list[dict] = []
    instance_errors: list[dict[str, str]] = []
    for start in range(0, len(registered_ids), 100):
        batch = registered_ids[start:start + 100]
        try:
            response = ec2.describe_instances(InstanceIds=batch)
            for reservation in response.get("Reservations", []):
                for instance in reservation.get("Instances", []):
                    name_tag = next(
                        (
                            tag.get("Value", "")
                            for tag in instance.get("Tags", [])
                            if tag.get("Key", "").casefold() == "name"
                        ),
                        "",
                    )
                    instance_details.append({
                        "instance_id": instance.get("InstanceId", ""),
                        "state": instance.get("State", {}).get("Name", "unknown"),
                        "instance_type": instance.get("InstanceType", ""),
                        "launch_time": (
                            instance["LaunchTime"].isoformat()
                            if instance.get("LaunchTime") else None
                        ),
                        "private_ip": instance.get("PrivateIpAddress"),
                        "public_ip": instance.get("PublicIpAddress"),
                        "vpc_id": instance.get("VpcId"),
                        "subnet_id": instance.get("SubnetId"),
                        "availability_zone": instance.get("Placement", {}).get(
                            "AvailabilityZone"
                        ),
                        "name": name_tag,
                        "tags": instance.get("Tags", []),
                    })
        except Exception as exc:
            LOG.exception("Unable to inspect registered EC2 instances for CLB %s", name)
            instance_errors.append(_error(exc))
    found_instance_ids = {item["instance_id"] for item in instance_details}
    for instance_id in registered_ids:
        if instance_id not in found_instance_ids:
            instance_details.append({
                "instance_id": instance_id,
                "state": "unknown",
                "instance_type": "",
                "launch_time": None,
                "private_ip": None,
                "public_ip": None,
                "vpc_id": None,
                "subnet_id": None,
                "availability_zone": None,
                "name": "",
                "tags": [],
            })
    result["registered_instances"] = {
        "registered_ids": registered_ids,
        "details": sorted(instance_details, key=lambda item: item["instance_id"]),
    }
    checks["registered_ec2"] = {
        "status": _status(instance_errors),
        "error": instance_errors[0] if instance_errors else None,
    }
    if load_balancer is None:
        checks["registered_ec2"] = {
            "status": "partial",
            "error": {
                "code": "NotAudited",
                "message": "Registered instances could not be checked without a live CLB description",
            },
        }

    group_ids = sorted(set((load_balancer or {}).get("SecurityGroups", [])))
    groups: list[dict] = []
    security_group_errors: list[dict[str, str]] = []
    for start in range(0, len(group_ids), 100):
        try:
            response = ec2.describe_security_groups(
                GroupIds=group_ids[start:start + 100]
            )
            for group in response.get("SecurityGroups", []):
                groups.append({
                    "group_id": group.get("GroupId", ""),
                    "group_name": group.get("GroupName", ""),
                    "description": group.get("Description", ""),
                    "vpc_id": group.get("VpcId", ""),
                    "tags": group.get("Tags", []),
                    "ingress": group.get("IpPermissions", []),
                    "egress": group.get("IpPermissionsEgress", []),
                })
        except Exception as exc:
            LOG.exception("Unable to inspect security groups for CLB %s", name)
            security_group_errors.append(_error(exc))
    result["security_groups"] = {"clb_group_ids": group_ids, "groups": groups}
    checks["security_groups"] = {
        "status": _status(security_group_errors),
        "error": security_group_errors[0] if security_group_errors else None,
    }
    if load_balancer is None:
        checks["security_groups"] = {
            "status": "partial",
            "error": {
                "code": "NotAudited",
                "message": "Security groups could not be checked without a live CLB description",
            },
        }
    return result


def _timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--findings-file", required=True, type=Path)
    parser.add_argument("--creds-file", type=Path, default=PROJECT_ROOT / "britive_creds.json")
    parser.add_argument("--output-dir", type=Path, default=PROJECT_ROOT / "findings" / "phase2")
    parser.add_argument("--expected-count", type=int)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
    )

    candidates, manifest = _read_candidates(args.findings_file, args.expected_count)
    accounts = sorted({row["account_id"].strip() for row in candidates})
    scope = {
        "accounts": accounts,
        "candidate_count": len(candidates),
        "source_scan_started_at": manifest.get("started_at"),
        "source_scan_finished_at": manifest.get("finished_at"),
        "criteria": "request_count_30d == 0 and request_count_60d == 0",
    }
    if args.dry_run:
        print(json.dumps(scope, indent=2))
        return 0

    with session.AccountIterator(accounts, creds_file=str(args.creds_file)) as iterator:
        account_sessions = {
            account_id: aws_session
            for aws_session, account_id in iterator.iter_accounts()
        }
        route53_records, route53_errors, route53_zone_counts = _route53_inventory(
            account_sessions
        )
        cf_inventories: dict[tuple[str, str], tuple[list[dict], list[dict], list[dict]]] = {}
        results = []
        for candidate in candidates:
            account_id = candidate["account_id"].strip()
            region = candidate["region"].strip()
            cache_key = (account_id, region)
            if cache_key not in cf_inventories:
                cf_inventories[cache_key] = _cloudformation_inventory(
                    account_sessions[account_id], region,
                )
            LOG.info("Auditing %s/%s/%s", account_id, region, candidate["resource_id"])
            results.append(_inspect_candidate(
                account_sessions[account_id],
                candidate,
                route53_records,
                route53_errors,
                route53_zone_counts,
                cf_inventories[cache_key],
            ))

    output = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_findings": str(args.findings_file.resolve()),
        "audit_scope": scope,
        "results": results,
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    output_path = args.output_dir / f"{SCRIPT_NAME}_{_timestamp()}.json"
    output_path.write_text(json.dumps(output, indent=2, default=str) + "\n", encoding="utf-8")
    LOG.info("Wrote %d audit result(s) to %s", len(results), output_path)
    incomplete = sum(
        check.get("status") != "complete"
        for result in results
        for check in result["checks"].values()
    )
    LOG.info("Checks incomplete or partial: %d", incomplete)
    return 0 if incomplete == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
