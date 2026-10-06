# AWS Proactive Task List

Complete proactive task list, distilled from research and ranked by execution order. Each entry covers: what to detect, how to detect it (script-level), and the rough payoff.

---

## Wave 1 — Cost: Fast Wins

### 1. gp2 → gp3 EBS Conversion
`describe_volumes(Filters=[{'Name':'volume-type','Values':['gp2']}])` per account/region; output volume ID, size, IOPS, account, attachment state. Convert online via `modify_volume()` matching IOPS/throughput. Watch for non-Nitro families that need detach/attach. ~20% baseline savings per converted volume.

### 2. Unattached EBS Volumes & Old Snapshots
`describe_volumes(Filters=[{'Name':'status','Values':['available']}])` for orphans; `describe_snapshots(OwnerIds=['self'])` filtered for snapshots >180d with no AMI reference. Weekly sweep. Common to find 5–15% of EBS spend in dead volumes alone.

### 3. Unassociated Elastic IPs
`describe_addresses()`; flag any without `AssociationId`. $3.65/mo each — small individually, embarrassing in aggregate when you find 200 of them.

### 4. Idle Classic Load Balancers + Idle ALB/NLB
`describe_load_balancers()`; cross-reference with CloudWatch `RequestCount` over 14d. Zero-request LBs are pure waste. Bonus: any CLB found is also a modernization candidate (see #16).

### 5. Old-Generation EC2 Instance Families
`describe_instances()`; flag m3, m4, c4, t2, r3, r4. Also tag any non-Nitro families. These are right-sizing + Graviton candidates rolled into one. Pinterest got 38% compute reduction + 47% cost savings on this exact pattern.

### 6. NAT Gateway Egress Hot Paths
Pull VPC Flow Logs (or CUR `lineItem/UsageType` matching `NatGateway-Bytes`) by destination service; anything >150 GB/month/AZ to an AWS service is a VPC endpoint candidate. DoorDash and several others have published 60–80% data-transfer reductions from this.

### 7. Cross-AZ Data Transfer Top Sources
CUR query: `lineItem/UsageType LIKE '%DataTransfer-Regional-Bytes%'` grouped by `lineItem/ResourceId`. Flag the top 20. Often points at a single misconfigured ELB or service-mesh policy.

### 8. CloudWatch Log Groups with No Retention
`describe_log_groups()`; filter `retentionInDays is None`. Apply default retention via `put_retention_policy()`. EventBridge rule on `CreateLogGroup` for new ones. 30–60% CloudWatch storage reduction is typical.

### 9. S3 Buckets Without Lifecycle Rules
`list_buckets()` then `get_bucket_lifecycle_configuration()` (`NoSuchLifecycleConfiguration` = flag). Especially target buckets with high incomplete-MPU share (Storage Lens metric). DoorDash saved millions here.

### 10. Athena Query Result Buckets
Find buckets matching `aws-athena-query-results-*`; check lifecycle. Apply 7-day expiration + 7-day MPU abort. Small but always present.

### 11. RDS Idle / Over-Provisioned
`describe_db_instances()` cross-referenced with CloudWatch `DatabaseConnections` (zero for 14d = idle) and `CPUUtilization` (under 5% peak = over-provisioned). Compute Optimizer covers this if enabled.

### 12. Reserved Instance / Savings Plan Coverage Gap
Pull from Cost Explorer API: `get_savings_plans_coverage()` and `get_reservation_coverage()`. Anything below 60% on stable workloads is leaving 30%+ on the table.

### 13. Spot Adoption Opportunities
Identify ASGs and EKS node groups currently 100% on-demand for non-prod. Robinhood used Spot for CI for 70–90% savings. Easy starting target: build runners, batch jobs, dev environments.

### 14. Dev/Test Instances Running 24/7
`describe_instances()` with tag filter `Environment=dev|test|nonprod` (or your tagging convention); cross-reference with state. Schedule via SSM `AWS-StopEC2Instance` / `AWS-StartEC2Instance` automation. 65% savings on schedulable instances (off 5pm–9am weekdays + weekends).

---

## Wave 2 — End-of-Support / Lifecycle Exposure

### 15. Lambda Deprecated Runtimes
`list_functions()` per region; flag `Runtime` in `[python3.7, python3.8, nodejs14.x, nodejs16.x, nodejs18.x, ...]`. Tier by criticality. Use AWS Transform or Amazon Q Developer for upgrades. AWS gives 180-day notice — but invocations continue indefinitely with no patches, so the security exposure is silent.

### 16. Classic Load Balancers
`describe_load_balancers()` (note: v1 API is for CLB; v2 for ALB/NLB). Each one is a migration candidate to ALB or NLB.

### 17. Windows Server 2012 R2 / 2016 EOS
`describe_instances()` filter on AMI Platform/Description; cross-reference AMI metadata with `describe_images()`. 2012 R2 incurs extended-support fees on EC2; 2016 is on its way out. Memory leak issues already observed on SPECSid become much harder when AWS isn't shipping fixes.

### 18. RDS Engine Versions on Extended Support
`describe_db_instances()` per account; cross-reference `EngineVersion` against AWS's EOL matrix. AWS published an Athena-on-CUR-2.0 query specifically for this. Extended Support fees are a separate CUR line item — surface them.

### 19. AMI Age / Golden Image Drift
For each running EC2, `describe_images()` on the source AMI; if `CreationDate` >365d, flag. Particularly critical for security patching baseline.

### 20. EKS Cluster Versions
`list_clusters()` then `describe_cluster()`; flag any version <N-2 from current. AWS bills Extended Support for EKS now.

### 21. Aurora / RDS Engine Families Approaching EOL
MySQL 5.7 EOL, PostgreSQL ≤13 EOL with Extended Support fees. Same pattern as #18.

---

## Wave 3 — Reliability / Fault Tolerance

### 22. Single-AZ RDS in Production
`describe_db_instances()`; flag `MultiAZ=False` in any account tagged production. CUDOS dashboard has this as a built-in widget; replicate via boto3.

### 23. Auto Scaling Groups with Single-AZ Subnet Config
`describe_auto_scaling_groups()`; check `AvailabilityZones count == 1`.

### 24. Missing or Stale RDS Backups
`describe_db_instances()` — flag `BackupRetentionPeriod < 7` for prod. `describe_db_snapshots()` — flag instances whose latest snapshot is >24h old.

### 25. EBS Volumes Without Recent Snapshots
For volumes attached to prod-tagged instances, check `describe_snapshots()` filtered by `VolumeId`. Anything >7 days old in prod, flag.

### 26. Quota Drift Between Active and Passive DR Regions
`service-quotas:get_service_quota()` per region pair; compare. Asymmetric quotas mean failover will fail at exactly the wrong moment. AWS Well-Architected REL01-BP02.

### 27. Route 53 Health Checks on Critical Endpoints
`list_health_checks()`; cross-reference with public-facing ALBs/NLBs. Endpoints without health checks = no failover signal.

### 28. Untested DR Runbooks
Process item, not boto3. Track date of last successful failover test per workload. Anything >180d, flag.

---

## Wave 4 — Security Posture

### 29. Public S3 Buckets (Intentional or Not)
`list_buckets()` + `get_public_access_block()` + `get_bucket_policy()` + `get_bucket_acl()`. Cross-reference with IAM Access Analyzer findings.

### 30. Security Groups with 0.0.0.0/0 on Sensitive Ports
`describe_security_groups()`; filter rules where `CidrIp == '0.0.0.0/0'` and `FromPort in [22, 3389, 3306, 5432, 1433, 6379, 27017]`. Auto-remediate via SSM Automation for known unauthorized cases.

### 31. IAM Users with Active Access Keys >90 Days Old
`list_users()` then `list_access_keys()` per user; check `CreateDate`. Plus: keys never used (`get_access_key_last_used` returns no `LastUsedDate`). Britive should be removing the need for IAM users entirely — flag any that exist as policy violations.

### 32. Root Account MFA / Access Key Existence
`get_account_summary()`; check `AccountMFAEnabled` and `AccountAccessKeysPresent`. Per account, every time. This is non-negotiable.

### 33. Unencrypted EBS Volumes
`describe_volumes()`; flag `Encrypted=False`. Same for unencrypted RDS and unencrypted S3 buckets.

### 34. KMS Key Rotation Disabled
`list_keys()` then `get_key_rotation_status()`; flag customer-managed keys with rotation disabled.

### 35. CloudTrail Not Enabled / Log File Validation Off
`describe_trails()`; check `IsMultiRegionTrail`, `LogFileValidationEnabled`, `IncludeGlobalServiceEvents`. Per account.

### 36. GuardDuty / Security Hub / Config Not Enabled
`get_detector()` for GuardDuty, `describe_hub()` for Security Hub, `describe_configuration_recorders()` for Config — per region per account. Especially watch for the "someone disabled the recorder" failure — Config can't catch its own disablement.

### 37. IAM Roles with Wildcard Policies or Unused for >90d
`list_roles()` + `list_attached_role_policies()`; check for `*` actions on `*` resources. `get_role()` exposes `RoleLastUsed.LastUsedDate` — anything with no usage for 90d, flag for cleanup.

---

## Wave 5 — Performance

### 38. Network Bandwidth vs EBS IOPS Mismatch
The case leadership called out. For each instance, look up the family's `NetworkPerformance` from `describe_instance_types()` and compare with attached EBS aggregate IOPS/throughput. Flag where EBS provisioned exceeds what the network can deliver — pure waste.

### 39. EC2 Instances with Low CPU but Mis-Sized Memory
Compute Optimizer finds these, but you can pre-stage candidates: instances <10% CPU peak over 14d AND >70% memory used → wrong family, not just wrong size.

### 40. Provisioned IOPS Volumes with Low Utilization
`describe_volumes()` for io1/io2; CloudWatch `VolumeReadOps` + `VolumeWriteOps` over 14d. Provisioned IOPS unused = direct overspend.

### 41. CloudFront Distributions with Low Cache-Hit Ratio
CloudWatch `CacheHitRate` < 70% means origin egress costs that shouldn't exist. Per-distribution analysis.

### 42. RDS Performance Insights Findings
Where enabled, pull `describe_db_instances()` then `pi:get_resource_metrics()` for top SQL by load. Often surfaces single-query problems behind whole-instance over-provisioning.

---

## Continuous — Operational Excellence

### 43. Tagging Compliance
Define mandatory tags (`CostCenter`, `Environment`, `Owner`, `Application`). Per-resource scan; flag missing. Tag Policies at the Org level enforce going forward; this is for the legacy backfill.

### 44. CloudFormation Drift Across Stacks
`detect_stack_drift()` per stack; report DRIFTED stacks. Focus on production stacks first.

### 45. AWS Config Recorder Disabled
Already covered in #36 — called out separately because it's the Config-can't-catch-itself problem. Custom Lambda + EventBridge `ConfigurationRecorderStarted`/`Stopped` events.

### 46. Resources Without Monitoring
EC2 instances without CloudWatch agent, RDS without enhanced monitoring, ELBs without access logs enabled.

### 47. Patch Compliance (SSM)
`ssm:describe_instance_patch_states()`; flag instances `NonCompliantCount > 0` or `LastNoRebootInstallOperationTime` >30d.

---

## Continuous — Service Quotas / Limits

### 48. All Quotas at >70% Utilization
`service-quotas:list_service_quotas()` and `list_aws_default_service_quotas()`; cross-reference with current usage from each respective service API. Alert at 70% as well as 80% — gives runway. Deploy AWS's open-source Quota Monitor for AWS solution as the central infrastructure (hub-and-spoke with EventBridge).

### 49. Quotas Not Exposed by Service Quotas API
KMS API rates, S3 buckets per account, Lambda VPC ENIs (250 default), STS rate limits, etc. Custom Lambda iterating a `QuotaList.json` config calling `Describe*` APIs.

### 50. VPC IP Exhaustion (Especially EKS with awsvpc Networking)
`describe_subnets()`; check `AvailableIpAddressCount` per subnet. Flag <10% remaining. Has caused real EKS scaling outages industry-wide.

---

## Process / Cross-Cutting (Build Alongside Scripts)

### 51. Monthly Compute Optimizer Recommendation Export
`export_ec2_instance_recommendations()` and `export_ebs_volume_recommendations()` to S3 → Athena → ticket queue. Require "very low risk" + "low risk" recommendations be acted on within 30 days.

### 52. AWS Health Dashboard Event Subscription
`health:describe_events()` org-wide. Subscribe to deprecation announcements, scheduled maintenance, retirement notices. EventBridge → Slack/email. This is your radar for everything in the EOL section above before AWS sends the customer email.

### 53. CUR 2.0 + Athena + QuickSight (CUDOS/CID/TAO/KPI Dashboards)
Foundation for everything FinOps-adjacent. Deploy in your audit/cost account.

### 54. Inventory Dashboard Refresh Cadence
Aggregate the boto3 outputs from Waves 1–3 into a single inventory snapshot per month. This is the "current AWS offerings/services in use" deliverable from your meeting.

---

## boto3 + Vault Setup Template

Rough template per task — most of the script is identical, only the detection logic changes:

```python
def for_each_account_region(task_fn, regions=None):
    """Iterate accounts via vault, run task_fn(session, account_id, region)."""
    for account_id in accounts_from_vault():
        try:
            session = vault_session(account_id, role="ADFS-CloudOps")
        except Exception as e:
            log.error(f"{account_id}: vault auth failed - {e}")
            continue
        for region in regions or session.get_available_regions("ec2"):
            try:
                yield task_fn(session, account_id, region)
            except ClientError as e:
                if e.response["Error"]["Code"] in ("AuthFailure", "UnauthorizedOperation"):
                    log.warning(f"{account_id}/{region}: skipped - {e.response['Error']['Code']}")
                    continue
                raise
```
