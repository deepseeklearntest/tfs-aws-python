#!/usr/bin/env python3
"""Generate proactive.xlsx — one sheet per wave/pillar from proactive.md task list."""

from pathlib import Path
import openpyxl
from openpyxl.styles import (
    PatternFill, Font, Alignment, Border, Side
)
from openpyxl.utils import get_column_letter

OUT = Path(__file__).parent / "proactive.xlsx"

# ── colour palette ────────────────────────────────────────────────────────────
HEADER_FILLS = {
    "Wave 1":      "1F4E79",   # dark blue
    "Wave 2":      "833C00",   # dark orange/brown
    "Wave 3":      "375623",   # dark green
    "Wave 4":      "4A235A",   # dark purple
    "Wave 5":      "0D4B5E",   # dark teal
    "Operational": "1C3A4A",   # slate blue
    "Quotas":      "3B3B3B",   # dark grey
    "Process":     "1A4731",   # forest green
}
ROW_ALT = {
    "Wave 1":      "D6E4F0",
    "Wave 2":      "FCE5CD",
    "Wave 3":      "D9EAD3",
    "Wave 4":      "E8D5F5",
    "Wave 5":      "D4EEF5",
    "Operational": "D6E4F0",
    "Quotas":      "EBEBEB",
    "Process":     "D5F0E4",
}
WHITE = "FFFFFF"

COLUMNS = ["#", "Title", "What to Detect", "How to Detect (API / Query)", "Action"]
COL_WIDTHS = [5, 32, 42, 52, 42]

# ── task data ─────────────────────────────────────────────────────────────────
SHEETS = [
    {
        "key": "Wave 1",
        "title": "Wave 1 — Cost: Fast Wins",
        "tasks": [
            (1,  "gp2 → gp3 EBS Conversion",
             "EBS volumes using the older gp2 volume type that can be converted to gp3 for reduced baseline cost.",
             "describe_volumes(Filters=[{'Name':'volume-type','Values':['gp2']}]) per account/region; capture volume ID, size, current IOPS, account, and attachment state.",
             "Convert online via modify_volume() preserving existing IOPS/throughput settings. For non-Nitro instance families, detach before converting, then reattach."),

            (2,  "Unattached EBS Volumes & Old Snapshots",
             "EBS volumes not attached to any instance, and orphaned snapshots older than 180 days with no associated AMI.",
             "describe_volumes(Filters=[{'Name':'status','Values':['available']}]); describe_snapshots(OwnerIds=['self']) filtered for age >180d and no AMI reference.",
             "Run as a weekly sweep. Delete confirmed orphan volumes and snapshots after verifying no dependency."),

            (3,  "Unassociated Elastic IPs",
             "Elastic IP addresses allocated but not associated with any resource.",
             "describe_addresses(); flag any record without an AssociationId.",
             "Release unassociated EIPs. Each incurs a charge while idle."),

            (4,  "Idle Load Balancers (CLB / ALB / NLB)",
             "Load balancers that have received zero requests over the past 14 days.",
             "describe_load_balancers(); cross-reference with CloudWatch RequestCount metric over 14 days. Use v1 API for CLB, v2 for ALB/NLB.",
             "Decommission zero-traffic load balancers. Any Classic Load Balancer found is also a migration candidate to ALB or NLB (see Task 16)."),

            (5,  "Old-Generation EC2 Instance Families",
             "EC2 instances running on outdated families (m3, m4, c4, t2, r3, r4) or non-Nitro hypervisor types.",
             "describe_instances(); flag instances whose InstanceType prefix matches m3, m4, c4, t2, r3, or r4. Also tag any non-Nitro families.",
             "Migrate to current-generation equivalents or Graviton. These are right-sizing and architecture upgrade candidates simultaneously."),

            (6,  "NAT Gateway Egress Hot Paths",
             "High-volume NAT Gateway traffic (>150 GB/month/AZ) destined for AWS services that could instead use VPC endpoints.",
             "Query VPC Flow Logs or CUR lineItem/UsageType matching NatGateway-Bytes, grouped by destination service.",
             "Create Gateway or Interface VPC endpoints for identified AWS services (e.g. S3, DynamoDB, ECR) to eliminate the associated NAT Gateway data transfer charges."),

            (7,  "Cross-AZ Data Transfer Top Sources",
             "Top 20 resource IDs generating the most cross-AZ (regional) data transfer charges.",
             "CUR query: lineItem/UsageType LIKE '%DataTransfer-Regional-Bytes%' grouped by lineItem/ResourceId.",
             "Investigate top offenders for misconfigured ELBs or service-mesh routing policies and correct to same-AZ traffic patterns where possible."),

            (8,  "CloudWatch Log Groups Without Retention",
             "CloudWatch log groups with no retention policy, accumulating storage costs indefinitely.",
             "describe_log_groups(); filter for records where retentionInDays is None.",
             "Apply a default retention period via put_retention_policy(). Deploy an EventBridge rule on CreateLogGroup events to auto-apply retention to new groups."),

            (9,  "S3 Buckets Without Lifecycle Rules",
             "S3 buckets lacking any lifecycle configuration, especially those with a high proportion of incomplete multipart uploads.",
             "list_buckets() then get_bucket_lifecycle_configuration() per bucket; NoSuchLifecycleConfiguration response = flag. Use Storage Lens to identify high incomplete-MPU buckets.",
             "Apply lifecycle rules to transition or expire objects at defined ages. Add an MPU abort rule to clean up incomplete uploads."),

            (10, "Athena Query Result Buckets Without Expiration",
             "S3 buckets used for Athena query results (aws-athena-query-results-*) that lack object expiration lifecycle rules.",
             "List buckets matching the aws-athena-query-results-* prefix; check get_bucket_lifecycle_configuration() on each.",
             "Apply a 7-day object expiration rule and a 7-day incomplete multipart upload abort rule to each identified bucket."),

            (11, "Idle / Over-Provisioned RDS Instances",
             "RDS instances with zero database connections for 14+ days (idle) or CPU utilization consistently below 5% peak (over-provisioned).",
             "describe_db_instances() cross-referenced with CloudWatch DatabaseConnections (zero for 14d) and CPUUtilization (<5% peak over 14d). Compute Optimizer covers this if enabled.",
             "Stop or delete idle instances. Right-size over-provisioned instances to a smaller instance class."),

            (12, "Reserved Instance / Savings Plan Coverage Gap",
             "Stable, predictable workloads with less than 60% coverage by Reserved Instances or Savings Plans.",
             "Cost Explorer API: get_savings_plans_coverage() and get_reservation_coverage(). Flag any stable workload below 60% coverage.",
             "Purchase appropriate RI or Savings Plan commitments for workloads confirmed as long-running and stable."),

            (13, "Spot Adoption Opportunities",
             "Non-production ASGs and EKS node groups running 100% on-demand capacity that are suitable for Spot Instances.",
             "Enumerate ASGs and EKS managed node groups; filter for Environment=dev/test/nonprod or equivalent tag; check capacity purchase option.",
             "Configure mixed-instance Spot capacity for CI/CD runners, batch jobs, and dev environments."),

            (14, "Dev/Test Instances Running 24/7",
             "Non-production EC2 instances running continuously outside of business hours.",
             "describe_instances() with tag filter Environment=dev|test|nonprod (or equivalent); cross-reference with current instance state.",
             "Schedule stop/start via SSM Automation (AWS-StopEC2Instance / AWS-StartEC2Instance): off at 5 PM, on at 9 AM weekdays; off all weekend."),
        ],
    },
    {
        "key": "Wave 2",
        "title": "Wave 2 — End-of-Support / Lifecycle Exposure",
        "tasks": [
            (15, "Lambda Deprecated Runtimes",
             "Lambda functions using runtimes that are deprecated or approaching deprecation (e.g. python3.7, python3.8, nodejs14.x, nodejs16.x, nodejs18.x).",
             "list_functions() per region; flag any Runtime value in the deprecated or soon-to-be-deprecated runtime list.",
             "Tier functions by criticality and upgrade runtimes. Functions continue to invoke after deprecation but receive no security patches."),

            (16, "Classic Load Balancers",
             "Any Classic Load Balancers (CLB) still in use, which represent a modernization gap.",
             "describe_load_balancers() using the v1 (CLB) API.",
             "Plan migration of each CLB to Application Load Balancer or Network Load Balancer as appropriate for the traffic type."),

            (17, "Windows Server 2012 R2 / 2016 End-of-Support",
             "EC2 instances running Windows Server versions that have reached or are approaching end-of-support.",
             "describe_instances() filtered on AMI platform/description; cross-reference AMI metadata via describe_images() to confirm OS version.",
             "Upgrade OS versions. Windows Server 2012 R2 on EC2 incurs Extended Support charges."),

            (18, "RDS Engine Versions on Extended Support",
             "RDS instances running engine versions past their standard support end date, incurring Extended Support fees.",
             "describe_db_instances() per account; cross-reference EngineVersion against AWS's EOL matrix. Extended Support charges appear as a distinct CUR line item.",
             "Plan and execute engine version upgrades to eliminate Extended Support fees."),

            (19, "AMI Age / Golden Image Drift",
             "EC2 instances launched from AMIs older than 365 days, indicating a stale security patching baseline.",
             "For each running EC2, call describe_images() on its source AMI; flag if CreationDate > 365 days ago.",
             "Rebuild golden AMIs with current patches and update instances or launch templates to use the new images."),

            (20, "EKS Cluster Versions on Extended Support",
             "EKS clusters running Kubernetes versions more than two minor versions behind the current release (N-2), triggering Extended Support billing.",
             "list_clusters() then describe_cluster(); flag any cluster with a version below current minus two.",
             "Upgrade clusters in order. AWS bills Extended Support fees for out-of-standard-support EKS versions."),

            (21, "Aurora / RDS Engine Families Approaching EOL",
             "RDS and Aurora instances running MySQL 5.7, PostgreSQL ≤13, or other engine families approaching end-of-life with upcoming Extended Support fees.",
             "Same detection pattern as Task 18 — describe_db_instances() per account; cross-reference EngineVersion against the AWS EOL matrix.",
             "Plan engine version upgrades. Prioritise by upgrade complexity and proximity to EOL date."),
        ],
    },
    {
        "key": "Wave 3",
        "title": "Wave 3 — Reliability / Fault Tolerance",
        "tasks": [
            (22, "Single-AZ RDS in Production",
             "Production RDS instances not configured for Multi-AZ deployment, creating a single point of failure.",
             "describe_db_instances(); flag any instance where MultiAZ=False in accounts or for resources tagged Environment=production.",
             "Enable Multi-AZ on all production RDS instances. Plan for the brief failover window during conversion."),

            (23, "ASGs with Single-AZ Subnet Config",
             "Auto Scaling Groups configured to launch instances in only one Availability Zone.",
             "describe_auto_scaling_groups(); check AvailabilityZones list; flag any group with a count of 1.",
             "Update ASG VPC zone identifiers to include subnets in at least two AZs."),

            (24, "Missing or Stale RDS Backups",
             "Production RDS instances with backup retention under 7 days, or whose most recent automated snapshot is more than 24 hours old.",
             "describe_db_instances() — flag BackupRetentionPeriod < 7 for production instances. describe_db_snapshots() — flag instances with no snapshot in the last 24 hours.",
             "Increase backup retention to ≥7 days. Investigate and resolve snapshot gaps."),

            (25, "EBS Volumes Without Recent Snapshots",
             "Production EBS volumes whose most recent snapshot is older than 7 days.",
             "For volumes attached to production-tagged instances, describe_snapshots(Filters=[{'Name':'volume-id','Values':[volume_id]}]); flag if the most recent snapshot is >7 days old.",
             "Enable automated snapshot schedules via Amazon Data Lifecycle Manager for all production volumes."),

            (26, "Quota Drift Between Active and DR Regions",
             "Service quota limits in the DR (passive) region that are lower than in the primary region, which would cause failover to fail under load.",
             "service-quotas:get_service_quota() per region pair; compare values for all in-use services. Flag any quota that is lower in the DR region.",
             "Request quota increases in the DR region to match or exceed primary region limits before a failover is needed."),

            (27, "Route 53 Health Checks on Critical Endpoints",
             "Public-facing ALBs and NLBs that do not have an associated Route 53 health check, leaving no automated failover signal.",
             "list_health_checks(); cross-reference with all public-facing ALBs and NLBs to identify gaps.",
             "Create Route 53 health checks for each uncovered critical endpoint to enable DNS-based failover."),

            (28, "Untested DR Runbooks",
             "Disaster recovery runbooks that have not been executed successfully within the past 180 days.",
             "Process-level tracking — record the date of the last successful failover test per workload.",
             "Schedule and execute DR tests for any workload whose runbook has not been validated in over 180 days."),
        ],
    },
    {
        "key": "Wave 4",
        "title": "Wave 4 — Security Posture",
        "tasks": [
            (29, "Public S3 Buckets",
             "S3 buckets that are publicly accessible, whether by intent or misconfiguration.",
             "list_buckets() + get_public_access_block() + get_bucket_policy() + get_bucket_acl() per bucket. Cross-reference with IAM Access Analyzer findings.",
             "Apply S3 Block Public Access where public access is not explicitly required. Tighten bucket policies and ACLs for any bucket that must remain public."),

            (30, "Security Groups with 0.0.0.0/0 on Sensitive Ports",
             "Security group rules allowing unrestricted inbound access (0.0.0.0/0 or ::/0) on sensitive ports: 22, 3389, 3306, 5432, 1433, 6379, 27017.",
             "describe_security_groups(); filter for rules where CidrIp == '0.0.0.0/0' (or '::/0') and FromPort is in the sensitive port list.",
             "Restrict source ranges to known CIDRs or specific security groups. For confirmed unauthorized rules, auto-remediate via SSM Automation."),

            (31, "IAM Users with Stale or Unused Access Keys",
             "IAM users whose access keys are older than 90 days, or keys that have never been used.",
             "list_users() then list_access_keys() per user; check CreateDate. Call get_access_key_last_used() to identify keys with no LastUsedDate.",
             "Rotate keys older than 90 days. Deactivate and delete keys that have never been used. Flag any remaining IAM users as policy violations if machine identity federation is the standard."),

            (32, "Root Account MFA / Access Key Existence",
             "AWS accounts where root MFA is not enabled or where root access keys exist.",
             "get_account_summary() per account; check AccountMFAEnabled == 1 and AccountAccessKeysPresent == 0.",
             "Enable MFA on the root account in every non-compliant account. Delete any existing root access keys immediately."),

            (33, "Unencrypted EBS Volumes, RDS, and S3",
             "EBS volumes, RDS instances, and S3 buckets without encryption at rest enabled.",
             "describe_volumes() — flag Encrypted=False. describe_db_instances() — flag StorageEncrypted=False. S3: check server-side encryption configuration per bucket.",
             "Enable encryption. For EBS: snapshot → copy with encryption enabled → create encrypted volume from snapshot. Enable encryption by default at the account level to prevent new unencrypted volumes."),

            (34, "KMS Key Rotation Disabled",
             "Customer-managed KMS keys without automatic annual key rotation enabled.",
             "list_keys() then get_key_rotation_status() per key; flag customer-managed keys where rotation is disabled.",
             "Enable automatic key rotation for all customer-managed KMS keys."),

            (35, "CloudTrail Not Fully Configured",
             "Accounts or regions where CloudTrail is not enabled, lacks multi-region coverage, has log file validation disabled, or excludes global service events.",
             "describe_trails() per account; check IsMultiRegionTrail, LogFileValidationEnabled, and IncludeGlobalServiceEvents flags.",
             "Create or update trails to be multi-region, include global service events, and enable log file validation."),

            (36, "GuardDuty / Security Hub / Config Not Enabled",
             "Regions and accounts where GuardDuty, Security Hub, or AWS Config is not active.",
             "get_detector() (GuardDuty), describe_hub() (Security Hub), describe_configuration_recorders() (Config) — per region per account. Note: Config cannot detect its own disablement.",
             "Enable all three services in every region for every account. Deploy a custom Lambda + EventBridge to alert on ConfigurationRecorderStopped events."),

            (37, "IAM Roles with Wildcard Policies or Unused >90 Days",
             "IAM roles with Action:* / Resource:* in attached policies, or roles that have not been used in 90+ days.",
             "list_roles() + list_attached_role_policies(); scan policy documents for wildcard actions/resources. get_role() returns RoleLastUsed.LastUsedDate — flag roles unused for 90+ days.",
             "Remove wildcard permissions; replace with least-privilege policies. Submit unused roles for cleanup approval."),
        ],
    },
    {
        "key": "Wave 5",
        "title": "Wave 5 — Performance",
        "tasks": [
            (38, "Network Bandwidth vs EBS IOPS Mismatch",
             "Instances where the total provisioned EBS IOPS or throughput exceeds the instance's network bandwidth ceiling, making the provisioned capacity unreachable.",
             "describe_instance_types() to get NetworkPerformance per family; compare against aggregate provisioned IOPS and throughput of all attached EBS volumes.",
             "Right-size EBS provisioning to match the instance network limit, or upgrade to a higher-bandwidth instance family if the IOPS are genuinely needed."),

            (39, "EC2 Instances: Low CPU but High Memory Utilization",
             "Instances with <10% peak CPU utilization over 14 days yet >70% memory utilization — indicating wrong instance family, not just wrong size.",
             "CloudWatch CPUUtilization <10% peak (14d) combined with memory utilization >70% (requires CloudWatch agent). Compute Optimizer surfaces these candidates.",
             "Migrate to a memory-optimized instance family (r-series) sized for actual memory demand."),

            (40, "Provisioned IOPS Volumes with Low Utilization",
             "io1 or io2 EBS volumes where actual IOPS consumed are significantly below provisioned levels.",
             "describe_volumes() for io1/io2 types; CloudWatch VolumeReadOps + VolumeWriteOps over 14 days to determine actual utilization.",
             "Reduce provisioned IOPS to match actual peak usage, or convert to gp3 if the workload doesn't require io1/io2 guarantees."),

            (41, "CloudFront Distributions with Low Cache-Hit Ratio",
             "CloudFront distributions with a cache-hit ratio below 70%, causing unnecessary origin egress traffic and cost.",
             "CloudWatch CacheHitRate metric per distribution; flag any below 70% over the evaluation period.",
             "Review and optimize cache behaviors: increase TTLs, remove unnecessary query string or header forwarding, and align cache key configuration with actual content variability."),

            (42, "RDS Performance Insights — Top SQL by Load",
             "RDS instances where specific SQL queries account for a disproportionate share of database load, potentially driving over-provisioning.",
             "describe_db_instances() to identify PI-enabled instances; pi:get_resource_metrics() for top SQL statements by db.load.avg.",
             "Tune or optimize the identified high-load queries. Resolution often eliminates the apparent need for a larger instance class."),
        ],
    },
    {
        "key": "Operational",
        "title": "Continuous — Operational Excellence",
        "tasks": [
            (43, "Tagging Compliance",
             "Resources missing mandatory organizational tags: CostCenter, Environment, Owner, Application.",
             "Per-resource describe/list API calls across all services; check for presence of each mandatory tag key.",
             "Apply Tag Policies at the AWS Organizations level for enforcement going forward. Run a one-time backfill sweep on legacy resources."),

            (44, "CloudFormation Drift Across Stacks",
             "CloudFormation stacks where deployed resources have been manually modified and no longer match their template definitions.",
             "detect_stack_drift() per stack; poll describe_stack_drift_detection_status() for completion; report stacks with status DRIFTED. Prioritise production stacks.",
             "Review each drift finding and either reconcile the template to reflect intentional changes or revert the manual change."),

            (45, "AWS Config Recorder Disabled",
             "Accounts or regions where the AWS Config configuration recorder has been stopped. Config cannot detect its own disablement.",
             "Custom Lambda triggered by EventBridge ConfigurationRecorderStarted / ConfigurationRecorderStopped events.",
             "Alert immediately on any recorder stoppage. Re-enable and investigate the cause. Separate from Task 36, which handles initial enablement."),

            (46, "Resources Without Monitoring",
             "EC2 instances without the CloudWatch agent installed, RDS instances without enhanced monitoring enabled, and ELBs without access logs enabled.",
             "Identify EC2 instances with no CloudWatch agent metrics in the last 24h; describe_db_instances() checking MonitoringInterval == 0; describe_load_balancers() checking access log attributes.",
             "Enable CloudWatch agent, RDS enhanced monitoring, and ELB access logs for all identified resources."),

            (47, "SSM Patch Compliance",
             "EC2 instances with outstanding non-compliant patches or that have not completed a post-patch reboot in over 30 days.",
             "ssm:describe_instance_patch_states(); flag instances with NonCompliantCount > 0 or LastNoRebootInstallOperationTime > 30 days ago.",
             "Trigger patch remediation via SSM Patch Manager. Coordinate required reboots with application owners."),
        ],
    },
    {
        "key": "Quotas",
        "title": "Continuous — Service Quotas / Limits",
        "tasks": [
            (48, "All Quotas at >70% Utilization",
             "Service quotas across all accounts and regions that have reached 70% or more of their limit, providing runway before impact.",
             "service-quotas:list_service_quotas() and list_aws_default_service_quotas(); cross-reference each quota with current usage from the respective service API. Alert at both 70% and 80% thresholds.",
             "Request quota increases ahead of limits. Deploy the AWS Quota Monitor solution (hub-and-spoke with EventBridge) as central infrastructure."),

            (49, "Quotas Not Exposed by the Service Quotas API",
             "Service limits that are not surfaced through the standard Service Quotas API, such as KMS API call rates, S3 buckets per account, Lambda VPC ENIs (default 250), and STS rate limits.",
             "Custom Lambda iterating a QuotaList.json configuration file, calling the relevant Describe* or GetAccountLimit APIs for each non-standard quota.",
             "Alert when any custom-tracked limit approaches its threshold. Maintain the QuotaList.json as new limits are discovered."),

            (50, "VPC IP Exhaustion",
             "Subnets — especially in EKS clusters using awsvpc networking — with fewer than 10% of IP addresses remaining.",
             "describe_subnets() per VPC; check AvailableIpAddressCount against total capacity; flag any subnet below 10% available.",
             "Expand affected subnets or add secondary VPC CIDRs before exhaustion causes instance or pod scheduling failures."),
        ],
    },
    {
        "key": "Process",
        "title": "Process / Cross-Cutting",
        "tasks": [
            (51, "Monthly Compute Optimizer Recommendation Export",
             "Compute Optimizer recommendations for EC2 and EBS that have not yet been actioned.",
             "export_ec2_instance_recommendations() and export_ebs_volume_recommendations() to S3; query via Athena; feed into a ticket queue.",
             "Require all 'very low risk' and 'low risk' recommendations to be reviewed and actioned within 30 days of the monthly export."),

            (52, "AWS Health Dashboard Event Subscription",
             "Deprecation announcements, scheduled maintenance events, and resource retirement notices from AWS Health at the organization level.",
             "health:describe_events() with org-wide scope; subscribe to event type categories: accountNotification, scheduledChange, issue.",
             "Route events via EventBridge to the team notification channel (Slack/email). Ensure deprecation and retirement events trigger immediate triage."),

            (53, "CUR 2.0 + Athena + QuickSight Dashboards",
             "Lack of a centralized Cost and Usage Report foundation with queryable data and dashboards for ongoing FinOps visibility.",
             "Deploy CUR 2.0 export to S3 in the cost/audit account; configure Athena data source; deploy CUDOS / CID / TAO / KPI dashboard sets in QuickSight.",
             "Establish as the persistent foundation for all cost analysis, anomaly detection, and FinOps reporting across the organization."),

            (54, "Inventory Dashboard Refresh Cadence",
             "Stale or missing monthly snapshot of AWS resources in use across accounts, needed for capacity planning and executive reporting.",
             "Aggregate CSV outputs from Wave 1–3 detection scripts into a single consolidated inventory snapshot per month.",
             "Publish the monthly inventory snapshot as the authoritative 'current AWS services in use' deliverable for stakeholder reporting."),
        ],
    },
]


def thin_border():
    side = Side(style="thin", color="CCCCCC")
    return Border(left=side, right=side, top=side, bottom=side)


def make_fill(hex_color):
    return PatternFill("solid", fgColor=hex_color)


def write_sheet(wb, sheet_def):
    key = sheet_def["key"]
    safe_title = sheet_def["title"].replace(":", "").replace("/", "-")[:31].strip()
    ws = wb.create_sheet(title=safe_title)

    header_fill = make_fill(HEADER_FILLS[key])
    alt_fill    = make_fill(ROW_ALT[key])
    white_fill  = make_fill(WHITE)

    # ── header row ────────────────────────────────────────────────────────────
    header_font = Font(bold=True, color=WHITE, size=11)
    for col_idx, (col_name, width) in enumerate(zip(COLUMNS, COL_WIDTHS), start=1):
        cell = ws.cell(row=1, column=col_idx, value=col_name)
        cell.fill    = header_fill
        cell.font    = header_font
        cell.border  = thin_border()
        cell.alignment = Alignment(horizontal="center", vertical="center",
                                   wrap_text=True)
        ws.column_dimensions[get_column_letter(col_idx)].width = width

    ws.row_dimensions[1].height = 22
    ws.freeze_panes = "A2"

    # ── data rows ─────────────────────────────────────────────────────────────
    data_font    = Font(size=10)
    num_font     = Font(bold=True, size=10)
    title_font   = Font(bold=True, size=10)

    for row_offset, (num, title, what, how, action) in enumerate(sheet_def["tasks"]):
        row = row_offset + 2
        fill = alt_fill if row_offset % 2 else white_fill

        values = [num, title, what, how, action]
        for col_idx, val in enumerate(values, start=1):
            cell = ws.cell(row=row, column=col_idx, value=val)
            cell.fill   = fill
            cell.border = thin_border()
            cell.alignment = Alignment(horizontal="left", vertical="top",
                                       wrap_text=True)
            if col_idx == 1:
                cell.font = num_font
                cell.alignment = Alignment(horizontal="center",
                                           vertical="top")
            elif col_idx == 2:
                cell.font = title_font
            else:
                cell.font = data_font

        ws.row_dimensions[row].height = 72

    # ── auto-filter on header ─────────────────────────────────────────────────
    ws.auto_filter.ref = f"A1:{get_column_letter(len(COLUMNS))}1"


def main():
    wb = openpyxl.Workbook()
    wb.remove(wb.active)   # remove default blank sheet

    for sheet_def in SHEETS:
        write_sheet(wb, sheet_def)

    wb.save(OUT)
    print(f"Saved: {OUT}")


if __name__ == "__main__":
    main()
