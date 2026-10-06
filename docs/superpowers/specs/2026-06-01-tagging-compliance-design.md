# Task 43 — Tagging Compliance Detection Script Design

**Date:** 2026-06-01  
**Script:** `continuous/43_detect_tagging_compliance.py`  
**Type:** Regional scan (account × region)

---

## Goal

Identify AWS resources that are missing one or more of the four mandatory organisational tags. This is a legacy-backfill audit — Tag Policies at the Org level enforce compliance going forward; this script surfaces existing non-compliant resources.

**Mandatory tags:** `CostCenter`, `Environment`, `Owner`, `Application`

---

## Context: Replacing Existing Implementation

A per-service implementation already exists at `continuous/43_detect_tagging_compliance.py` covering EC2, RDS, Lambda, EKS, and S3. This design replaces it with the Resource Groups Tagging API approach for broader resource coverage. The existing file will be rewritten in place.

---

## Scan Architecture

Regional scan using `resourcegroupstaggingapi` (`get_resources()` paginator). A single paginated call per region returns every taggable resource with its ARN, `ResourceType`, and current tag set — no per-service API calls required.

- One finding row per non-compliant resource (not per missing tag)
- A resource is flagged if any of the four mandatory tag keys are absent or have an empty string value
- Tag value content is not validated — key presence only
- `REQUIRED_TAGS` is a list (not a set) to preserve stable ordering in `missing_tags` / `present_tags` output

---

## Noise Filtering (Two Layers)

### Layer 1 — Excluded Resource Types

Infrastructure primitives that teams do not own or tag are dropped by exact `ResourceType` match:

```python
EXCLUDED_RESOURCE_TYPES = {
    'ec2:network-interface',
    'ec2:security-group',
    'ec2:subnet',
    'ec2:vpc',
    'ec2:route-table',
    'ec2:internet-gateway',
    'ec2:egress-only-internet-gateway',
    'ec2:dhcp-options',
    'ec2:network-acl',
    'ec2:key-pair',
    'ec2:snapshot',
    'ec2:prefix-list',
    'ec2:spot-instances-request',
}
```

All other resource types pass through automatically, including: `ec2:instance`, `ec2:volume`, `rds:db`, `rds:cluster`, `lambda:function`, `elasticloadbalancing:loadbalancer`, `eks:cluster`, `eks:nodegroup`, `autoscaling:autoScalingGroup`, `s3`, `dynamodb:table`, `sqs:queue`, `sns:topic`, and any future resource types the Tagging API surfaces.

### Layer 2 — AWS-Managed Tag Check

If a resource has any tag key beginning with `aws:` (e.g., `aws:cloudformation:stack-name`, `aws:eks:cluster-name`), it is AWS-managed infrastructure and is skipped.

---

## Finding Structure

| Field | Value |
|---|---|
| `finding` | `missing-required-tags` (always) |
| `resource_type` | Tagging API `ResourceType` string (e.g., `ec2:instance`) |
| `resource_id` | Full ARN returned by the Tagging API |
| `detail` | `"Missing: Owner, CostCenter (2/4 required tags absent)"` |
| `estimated_monthly_savings_usd` | `0` |
| `tags` | Raw tag list converted to `[{'Key': k, 'Value': v}]` format |

---

## Extra CSV Columns

| Column | Type | Example | Purpose |
|---|---|---|---|
| `missing_tags` | string | `Owner, CostCenter` | Which required tags are absent |
| `present_tags` | string | `Environment, Application` | Which required tags are present |
| `missing_count` | string | `2` | Numeric sort/filter for worst offenders |
| `total_tag_count` | string | `5` | Total tags currently on the resource |

---

## Resource Name

The Tagging API returns ARNs only — no friendly names. The last segment of the ARN (after the final `/` or `:`) is used as a human-readable name approximation. This is surfaced in the `detail` field rather than a dedicated column.

Example: `arn:aws:lambda:us-east-1:123:function:my-function` → name `my-function`.

---

## S3 Handling

The Tagging API returns S3 buckets in the region they reside. Scanning all regions will return each bucket exactly once (in its home region) — no deduplication needed.

---

## Error Handling

- `session.is_skippable(exc)` → log at WARNING, skip region (consistent with all other scripts)
- Non-skippable `ClientError` → re-raise
- No per-resource error handling needed — the Tagging API returns a flat list; individual resource failures are not surfaced by the API

---

## Script Anatomy

Follows the standard regional pattern:

```python
REQUIRED_TAGS = ['CostCenter', 'Environment', 'Owner', 'Application']

EXCLUDED_RESOURCE_TYPES = { ... }

def scan(sess, account_id: str, region: str, writer) -> None:
    tagging = sess.client('resourcegroupstaggingapi', region_name=region)
    paginator = tagging.get_paginator('get_resources')
    for page in paginator.paginate():
        for resource in page.get('ResourceTagMappingList', []):
            resource_type = resource.get('ResourceType', '')
            if resource_type in EXCLUDED_RESOURCE_TYPES:
                continue
            tags = resource.get('Tags', [])
            if any(t['Key'].startswith('aws:') for t in tags):
                continue
            # check missing required tags, write finding if any
```

`account_level=False` — regional scan, not account-level.

---

## Out of Scope

- Tag value validation (e.g., `Environment` must be `prod/dev/test`) — deferred to a follow-on
- Auto-remediation (applying missing tags)
- Custom per-team tag requirements beyond the four mandatory tags
