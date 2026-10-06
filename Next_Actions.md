# Next Actions — Post-Scan Remediation Guide

What to do with findings from each script, and how to pitch it to management.

---

## wave1

### 6. NAT Gateway Egress Hot Paths

1. **Idle gateways** (`< 1 GB/30d`): Delete them. Each costs ~$32.85/mo in existence charges with no traffic. Confirm no route tables still reference the gateway before deleting.
2. **High-egress gateways** (`> 150 GB/30d`): Add VPC Gateway Endpoints for S3 and DynamoDB (free), and Interface Endpoints for STS, ECR, and SSM. Route tables update automatically after endpoint creation.
3. Set a Cost Anomaly Detection alert on `NatGateway-Bytes` so new hot paths surface within 24 hours rather than waiting for the next scan.

**Pitch:** Idle gateways are $X/mo for zero traffic — pure waste. High-egress ones are paying AWS for data that could travel free over a private endpoint. Other companies have published 60–80% data-transfer reductions from this exact change.

---

### 7. Cross-AZ Data Transfer Top Sources

1. This script gives account-level magnitude only. Use `usage_type` and `total_cost_usd` to rank accounts, then drill into CUR 2.0 + Athena for resource-level attribution on the top 3.
2. Common root causes: ELB in one AZ targeting instances in another, service-mesh sidecars ignoring AZ locality, RDS primary in AZ-a with app servers in AZ-b.
3. Fix at the architecture layer — enable AZ-affinity in ELB target groups, configure Istio/Envoy locality load balancing, or co-locate read replicas with their app tier.

**Pitch:** Cross-AZ transfer is invisible in the console but shows up as a steady line item in CUR. $X/mo is flowing between AZs unnecessarily. Fixing the top offender typically eliminates 70–80% of the cost because it's almost always one misconfigured resource.

---

### 10. Athena Query Result Buckets Without Lifecycle Rules

1. For each flagged bucket, add two lifecycle rules: 7-day expiration on all objects, and 7-day abort on incomplete multipart uploads. This is a 2-minute console change or one `put_bucket_lifecycle_configuration` API call.
2. Sort by `oldest_object_days` — buckets with results hundreds of days old are incurring the most cost right now.
3. For active Athena workgroups, also set the output location expiry in the workgroup config so future results inherit the rule automatically.

**Pitch:** Query results nobody looks at after a week are accumulating in S3 Standard storage indefinitely. The `size_gb` column tells us exactly what we're paying for stale data. This is a 5-minute fix per bucket that eliminates the cost entirely.

---

### 13. Spot Adoption Opportunities

1. Start with the lowest-risk workloads: CI/CD runners, batch jobs, dev environments. Use `resource_kind` — EKS node groups are often easier to migrate than ASGs since capacity type is a single field.
2. For ASGs: add a `MixedInstancesPolicy` with `OnDemandPercentageAboveBaseCapacity=20` to keep an on-demand base while running the majority on Spot. Diversify across 3+ instance families to reduce interruption risk.
3. For EKS node groups: create a new Spot node group, cordon the on-demand group, and drain workloads across. Use Karpenter or Cluster Autoscaler with Spot-aware diversification.
4. Enable Spot interruption handling — use the EC2 metadata 2-minute warning to drain gracefully before reclamation.

**Pitch:** These non-prod workloads are running 100% on-demand 24/7. Spot adoption delivers 70–90% savings with zero reliability impact in non-prod — interruptions in dev/test are acceptable. Robinhood used this pattern for CI and cut compute costs by that margin.

---

## wave2

### 15. Lambda Deprecated Runtimes

1. Sort by `days_past_eol` descending — longest overdue first.
2. Check `last_modified` to identify the owning team. Functions not modified in 6+ months are candidates for deletion rather than upgrade — verify with the owner first.
3. Upgrade path: update the `Runtime` field in function configuration, then test. Amazon Q Developer can assist with code changes needed for major version jumps (e.g. Python 3.8 → 3.12).
4. Add an EventBridge rule on Lambda `UpdateFunctionConfiguration` events to alert when a deprecated runtime is deployed — catch regressions at deploy time.

**Pitch:** Functions on EOL runtimes receive no security patches. AWS will eventually block new deployments to these functions (invocations continue, but silently unpatched). The `eol_date` column shows exactly how long each function has been running without patches.

---

### 16. Classic Load Balancers

1. **Zero-traffic CLBs** (`request_count_30d = 0`): Delete immediately. No traffic means no blast radius.
2. **Active CLBs**: The `migration_target` column tells you exactly where to go — `ALB` for HTTP/HTTPS listeners, `NLB` for TCP/UDP/SSL.
3. Migration steps: create the new LB, update the Route 53 alias record, monitor traffic for one full cycle, then delete the CLB. Keep both running in parallel until you're confident.
4. CLBs also lack WAF integration, advanced routing rules, and gRPC support — migration unlocks all of these at no additional cost.

**Pitch:** Classic Load Balancers are a legacy product with no new feature development. We can't add WAF or path-based routing to a CLB. Zero-traffic ones are pure cost with no value. We already have the migration target recommendation for each one in the CSV — the analysis work is done.

---

## wave3

### 26. Quota Drift Between Active and Passive DR Regions

1. For each flagged quota, submit a Service Quotas increase request for the DR region to match the primary value. Most increases auto-approve within minutes; EC2 vCPU limits may take 1–3 business days.
2. Sort by `gap` descending — largest gaps are most likely to cause failover failure under real load.
3. After raising quotas, re-run the script to confirm parity. Schedule a quarterly re-run since primary-region quotas drift upward as environments grow.

**Pitch:** If we fail over to DR today, these services will hit quota limits under normal primary-region load. The failover would succeed — then degrade or fail minutes later as capacity requests are rejected. Quota increases are free and the request takes 5 minutes to submit.

---

### 28. Untested DR Runbooks

1. **`runbook-never-tested`**: Schedule a failover test within the next 30 days. An untested plan is not a plan.
2. **`untested-runbook`**: Schedule tests in the next quarterly DR exercise. Update `28_dr_runbook_registry.csv` with results immediately after each test.
3. Where full failover is too disruptive, run a tabletop exercise as an interim measure — but schedule the real test within 90 days and record it.
4. Automate registry updates: add a post-test step in your runbook that updates the CSV and commits it to source control.

**Pitch:** Auditors ask one question about DR: "When did you last test it?" The `runbook-never-tested` findings mean we have workloads with no evidence of ever having been recovered. That is an audit finding waiting to happen.

---

## wave4

### 31. IAM Users with Active Access Keys >90 Days

1. **`console-no-mfa`**: Enforce MFA immediately. Add an IAM policy condition (`aws:MultiFactorAuthPresent: false` → Deny) to force MFA at console login. For service accounts that somehow have a console profile, delete the profile entirely — they should authenticate via API keys only.
2. **`stale-key-90d`**: Rotate the key. Create a new key, update the application or pipeline credential, verify the new key is active, then deactivate the old key. Wait 24 hours, confirm `key_last_used` has not updated, then delete.
3. **`key-never-used`**: Delete immediately. A key that has never been called has no active consumer — zero blast radius removal.
4. **`dormant-user`**: Disable the user (not delete — preserve audit history). Remove all group memberships, then schedule deletion after 30 days if no owner objects. Use `account_alias` to confirm which account before acting.
5. The broader goal is zero native IAM users for human access — each finding here is a Britive migration ticket. Use `user_type` to separate human users (direct policy violations) from service accounts (investigate whether the workload can use an IAM role or OIDC federation instead).

**Pitch:** Every IAM user with a stale key or no MFA is a permanent credential that doesn't expire. Britive is supposed to have replaced all human console access. The `user_type` column separates clean deletes from conversations with app teams. `key_last_used` tells us which keys are live consumers vs abandoned.

---

### 30. Security Groups with 0.0.0.0/0 on Sensitive Ports

1. Sort by `associated_resources != 'none'` first — open SGs attached to nothing are low urgency; ones attached to production EC2 or RDS instances are immediate.
2. Replace `0.0.0.0/0` with specific CIDR ranges (office IPs, VPN CIDR) or reference a known-good SG instead of a CIDR.
3. Use `sg_rule_id` for direct API remediation: `ec2.revoke_security_group_ingress(SecurityGroupRuleIds=[sg_rule_id])`.
4. Add AWS Config rules (`restricted-ssh`, `restricted-common-ports`) for ongoing detection. Pair with an SCP denying `ec2:AuthorizeSecurityGroupIngress` with `0.0.0.0/0` on sensitive ports to prevent recurrence org-wide.

**Pitch:** These are direct internet exposure of sensitive ports. The `associated_resources` column tells us which findings are active attack surface right now. SSH and RDP open to the internet are on every automated scanner's target list — assume they are being probed continuously.

---

### 33. Unencrypted EBS Volumes and RDS Instances

**EBS:** Encryption cannot be enabled in-place. Process: create snapshot → copy with encryption → restore new volume → swap attachment → delete unencrypted volume and snapshot.

**RDS:** Create encrypted snapshot → restore new encrypted DB instance → update connection strings → failover → delete unencrypted instance. Use blue/green deployment for production to minimise downtime.

The CSV now carries `volume_role` (`root` / `data` / `unattached` / `rds-storage` / `unknown`) and `downtime_impact` (`instance-stop` / `detach-window` / `none` / `db-snapshot-restore` / `unknown`) per row, plus `group_key`/`group_size`/`group_seq`/`group_band` so every volume attached to the same EC2 instance can be consolidated into one remediation unit instead of counted per-volume.

1. Triage in this order — `unattached` (no downtime, often just deletable), then `data` (detach/reattach window), then `root` (requires an instance stop — batch these into a change ticket per `owner`).
2. Count unique instances needing work as rows where `group_seq = 1` and `volume_role <> 'unattached'` — that's the real remediation count, not the row count.
3. Enable account-level EBS encryption by default (`ec2.enable_ebs_encryption_by_default()`) so all new volumes are encrypted automatically going forward.
4. Set encryption as the default in RDS parameter groups so new instances inherit it.

**Excel view (root/data grouping, colour-coded):**
1. Sort the CSV by `account_id`, `region`, `group_key`, `group_seq` — this makes each instance's volumes contiguous and makes `group_band` alternate correctly.
2. Select the data range → Conditional Formatting → New Rule → formula `=$AA2=1` (adjust the row-2 reference to your `group_band` column) → light grey fill. Bands one instance's volumes off from the next.
3. Select the `volume_role` column → Conditional Formatting → Highlight Cells Rules → Equal To, one rule per value: `root`/`rds-storage` → red (`FFC7CE` fill / `9C0006` font), `data` → amber (`FFEB9C` / `9C6500`), `unattached` → green (`C6EFCE` / `276221`) — the same RAG palette `generate_report.py` uses.
4. PivotTable: rows `attached_instance_name`, values Count of `resource_id`, filter `volume_role` — or rows `owner` × columns `volume_role` for a per-owner work split.

**Pitch:** Unencrypted storage is readable if physical media is compromised or someone gains unauthorized access at the hypervisor layer. This is also a direct compliance gap — PCI-DSS, HIPAA, and SOC 2 all require encryption at rest. The remediation is a scheduled migration, not an emergency, but it needs a deadline.

---

### 34. KMS Key Rotation Disabled

1. Enable automatic rotation on all flagged keys — one-click in the console or a single API call per key. Zero downtime, zero re-encryption required — AWS handles key material rotation transparently while keeping the same key ID and ARN. Cost is near-zero.
2. Prioritize by `days_since_creation` descending — cross-reference `description` and `key_alias` to identify which keys protect production databases, secrets, or S3 buckets. Those go first.
3. Set a guardrail so new keys can't be created without rotation — an AWS Config rule (`kms-key-rotation-enabled`) flags non-compliant keys automatically going forward. Pair it with a Service Control Policy (SCP) if you want to enforce it org-wide at the account level.

**Pitch:** Unrotated keys mean the same cryptographic material has been encrypting data for years. The `days_since_creation` column makes the blast radius concrete. Enabling rotation is a single API call per key — the remediation cost is trivial relative to the audit risk under SOC 2 / PCI-DSS.

---

### 35. CloudTrail Not Enabled / Log File Validation Off

1. **`trail-not-logging`**: Highest priority — re-enable logging immediately. Also check `latest_delivery_error` for trails that show `IsLogging=True` but are silently failing to deliver to S3.
2. **`no-trail-in-region`**: Enable a multi-region org trail from the management account. Check `is_organization_trail` — if an org trail exists but is paused, that gap affects every account.
3. **`global-events-excluded`**: Enable `IncludeGlobalServiceEvents`. Without it, IAM, STS, CloudFront, and Route 53 API calls are invisible — exactly what you need for incident response.
4. **`log-validation-disabled`**: Enable `LogFileValidationEnabled` on every trail. One checkbox, cryptographic proof that logs haven't been tampered with. No reason not to have it.
5. Enable Object Lock (Compliance mode, 365-day minimum) on CloudTrail S3 buckets. Note: Object Lock cannot be added to an existing bucket — create a new bucket with Object Lock enabled and point the trail to it.
6. Apply lifecycle rules to CloudTrail buckets: S3-IA at 90 days, Glacier at 180 days, delete at 7 years (or your compliance framework's retention requirement). This saves money while satisfying retention.

**Pitch:** CloudTrail is your only source of truth for "who did what in AWS." Blind spots mean incidents are uninvestigable. Log tampering means evidence can be deleted. Both are direct audit findings under SOC 2, PCI-DSS, and ISO 27001. The `is_organization_trail` column tells us if a gap affects one account or every account in the org.

---

### 36. GuardDuty / Security Hub / Config Not Enabled

1. Sort by `service` to batch remediation — GuardDuty, Security Hub, and Config each have different owners and enablement flows.
2. **`guardduty-not-enabled`**: Enable from the management account using `guardduty.create_detector(Enable=True)`. For org-wide coverage, delegate administration to your security account (`organizations.enable_aws_service_access(ServicePrincipal='guardduty.amazonaws.com')`). Enable S3 Protection and EKS Runtime Monitoring at the same time — both are disabled by default on new detectors.
3. **`securityhub-not-enabled`**: Enable via `securityhub.enable_security_hub()`. Activate the AWS Foundational Security Best Practices (FSBP) standard immediately — it delivers 200+ automated compliance checks across all accounts and regions. Aggregate findings to a central security account using a Security Hub delegated administrator.
4. **`config-not-enabled`**: Create a configuration recorder in each region (`config.put_configuration_recorder()`). Use `ALL_SUPPORTED_RESOURCE_TYPES` — partial recording creates blind spots and false confidence. Delegate to a Config aggregator in your audit account for org-wide visibility.
5. **`config-recorder-stopped`**: Treat as critical. Re-enable immediately and investigate who stopped it: `cloudtrail.lookup_events(LookupAttributes=[{'AttributeKey': 'EventName', 'AttributeValue': 'StopConfigurationRecorder'}])`. A stopped recorder means configuration change history has a gap that cannot be reconstructed.
6. Any region showing all three services disabled is an unmonitored blast radius — prioritize those accounts/regions regardless of other sorting.

**Pitch:** GuardDuty, Security Hub, and Config are the three pillars of AWS security monitoring. Without them, threat detection, compliance scoring, and configuration change history are all absent. A `config-recorder-stopped` finding means the answer to "what changed on this resource before the incident?" is gone for that time window. These are prerequisites for incident response, not optional enhancements.

---

### 37. IAM Roles with Wildcard Policies or Unused for >90d

1. **`wildcard-policy`**: Check `trust_principal` first — a wildcard role with `Principal: AWS: *` (any account) is critical; one scoped to a specific service is lower risk but still needs remediation. For each flagged role, inspect `policy_name` and `policy_type` to locate the offending statement. Use IAM Access Analyzer's policy generation feature to produce a least-privilege replacement from actual CloudTrail usage data.
2. Check `permission_boundary_arn` — if set, effective permissions may be narrower than the wildcard policy implies. Still remediate, but the boundary reduces immediate blast radius.
3. **`role-never-used`**: Before deleting, confirm the role is not referenced in CloudFormation stacks, CDK apps, or instance profiles (`iam.list_instance_profiles_for_role()`). If no references exist, delete — it has never been assumed so there is no active consumer.
4. **`unused-role-90d`**: Sort by `days_unused` descending. Roles unused >365 days with no attached resources should be deleted. Roles in the 90–365 day range need owner confirmation before removal. Check `trust_principal` — a role trusted by `ec2.amazonaws.com` may be attached to a stopped instance, not truly abandoned.
5. Exercise caution with paths matching `/aws-service-role/` — AWS-managed service-linked roles may appear unused but are required for background operations. Do not delete these.

**Pitch:** A role with `Action: * Resource: *` is admin-equivalent access waiting to be exploited. If it gets compromised, the blast radius is every resource in the account. The `days_unused` column identifies dead weight, and `trust_principal` shows who can assume each one. IAM Access Analyzer generates a scoped-down replacement policy from actual usage data — the analysis work takes about two minutes per role.

---

### PPD-Era IAM Users Audit

1. **`ppd-era-console`** (era=pre-sso): These users existed before the Britive cutover (2026-03-31) and still have native console access — this is a policy violation. Identify the owner via `account_alias` and `username`. Remove the console login profile (`iam.delete_login_profile(UserName=...)`), confirm the user can authenticate via Britive, then close the ticket.
2. **`post-sso-console`** (era=post-sso): Users created after the SSO cutover that still have native console access should not exist. Escalate to the team that created them — either a provisioning process was bypassed or an emergency account was never cleaned up.
3. **`stale-key-90d`**: Follow the same rotation process as script 31: new key → update consumer → verify → deactivate old key → delete after 24h.
4. **`active-key`** (key age <90 days, not yet stale): Investigate whether the key is legitimately needed for automation that cannot yet use IAM roles or OIDC federation. If justified, document the exception. If not, deactivate and delete.
5. Sort by `era=pre-sso` and `last_console_login` before the cutover date — users who have not logged in since migrating to Britive are the cleanest, lowest-risk deletions.

**Pitch:** The Britive migration was supposed to eliminate native IAM users for console access. `ppd-era-console` findings are the cleanup tail — accounts where the migration happened but the IAM user was never deleted. Each one is a shadow login path that bypasses Britive's time-bound lease model, audit trail, and SSO controls.

---

## wave5

### 38. Network Bandwidth vs EBS IOPS Mismatch

1. Sort by `estimated_monthly_savings_usd` descending — the savings figure is exact: `excess_iops × $0.065/month`.
2. Two remediation paths, choose based on whether the workload actually needs those IOPS:
   - **Right-size the instance** (workload needs the IOPS but the network is the bottleneck): upgrade to an instance family with a higher `EbsOptimizedInfo.MaximumIops` ceiling — for example, r5b has dramatically higher EBS bandwidth than m5 of the same size. No volume changes needed.
   - **Right-size the volumes** (workload doesn't reach the ceiling in practice): reduce provisioned IOPS via `ec2.modify_volume(VolumeId=..., Iops=<new_value>)`. This is online with no downtime. Cross-reference with script 40 findings — if the same volume also appears as underutilized there, downsizing the volume is the correct action.
3. Use the `volume_ids` column to identify which specific io1/io2 volumes to modify. After modification, volumes enter an `optimizing` state — confirm they return to `available` before closing.
4. Target `provisioned_iops` ≤ `instance_max_iops` when right-sizing volumes. AWS allows one modification per 6-hour window per volume.

**Pitch:** Every IOPS provisioned above the instance's network ceiling is invisible to the workload and directly wasted. The `excess_iops` column is the exact number of IOPS we're paying for that can never be delivered. At $0.065/IOPS/month, 10,000 excess IOPS is $650/month for zero performance benefit — it shows up in the bill but produces nothing.

---

### 39. EC2 Instances with Low CPU but Mis-Sized Memory

**Note:** This script requires the CloudWatch Agent. Instances without it are silently skipped — use script 46 findings to identify gaps before interpreting coverage here.

1. These are wrong-**family** problems, not wrong-size: `peak_cpu_pct < 10%` with `peak_mem_pct > 70%` means the workload needs a memory-optimized r-series instance, not just a larger general-purpose one (which would add idle CPU at higher cost).
2. Use Compute Optimizer to get the specific target instance type recommendation. This script surfaces the candidates; Compute Optimizer quantifies the exact size and savings with "very low risk" confidence ratings.
3. Sort by `peak_mem_pct` descending to find the most memory-pressured instances first — these are also at highest risk of OOM events.
4. Migration path: stop the instance, change the instance type, start. For production, use a blue/green approach — launch a new instance with the target family, validate for 24 hours, then cut over and terminate the old one.
5. Use `environment_tag` to start with non-prod instances — lower risk and builds team confidence before touching production.

**Pitch:** These instances are paying for CPU they never use while their workloads are under memory pressure. Migrating to r-family gives the same or more memory at the same or lower cost compared to oversizing a general-purpose instance. The `peak_cpu_pct` and `peak_mem_pct` columns make the misfit undeniable.

---

### 40. Provisioned IOPS Volumes with Low Utilization

1. Sort by `estimated_monthly_savings_usd` descending — the savings figure is `(provisioned_iops - actual_avg_iops) × $0.065/month`.
2. Check `attached_instance` — volumes with no attached instance are doubly wasteful: paying for both storage and provisioned IOPS with no workload. Snapshot and delete these unless an owner can justify keeping them warm.
3. Cross-reference with script 38 findings before acting. If the same volume appears in script 38 (IOPS exceed the instance's network ceiling), reducing provisioned IOPS is confirmed correct. If not in script 38, still safe to reduce.
4. Reduce provisioned IOPS via `ec2.modify_volume(VolumeId=..., Iops=<new_value>)` — online, no downtime. Target the new provisioned level at 150% of `actual_avg_iops` to preserve headroom for burst traffic. AWS allows one modification per 6-hour window per volume.
5. For volumes with `utilization_pct < 5%` on io2, also evaluate converting to gp3 (`ec2.modify_volume(VolumeType='gp3')`). gp3 includes 3,000 IOPS baseline at no extra charge — if actual usage stays below that, conversion eliminates the per-IOPS cost entirely while improving per-GB pricing.

**Pitch:** Provisioned IOPS cost $0.065/IOPS/month whether or not the storage subsystem does any work. The `actual_avg_iops` vs `provisioned_iops` columns make the waste concrete. Reducing provisioned IOPS on a running volume is a live, zero-downtime API call with immediate billing impact.

---

### 41. CloudFront Distributions with Low Cache-Hit Ratio

1. For each flagged distribution, check the `origins` column to understand what the cache is missing. Common causes: query strings or headers included in the cache key unnecessarily, `Cache-Control: no-cache` or `no-store` set by the origin, TTLs set too low at the origin.
2. Review the distribution's cache behaviours in the CloudFront console — ensure `Cache-Control` headers from the origin are being respected, and consider setting a minimum TTL override for static assets.
3. For API responses that legitimately can't be cached, consider splitting the distribution: one behaviour for static assets (high TTL) and one for dynamic API paths — this raises the overall `CacheHitRate` metric even if the API path will always miss.
4. Enable CloudFront Functions or Lambda@Edge to normalise cache keys (e.g. lowercase query strings, strip irrelevant headers) if the origin can't be changed.

**Pitch:** A `CacheHitRate` below 70% means more than 30% of requests are hitting the origin — paying for data transfer and origin compute that the cache should be absorbing. Each percentage point improvement in cache hit rate is a direct reduction in origin egress cost and latency. The `origins` column shows us which backends are absorbing the unnecessary load.

---

## continuous

### 43. Tagging Compliance

1. Sort findings by `missing_count` descending — resources missing all four tags are the highest priority for backfill since they produce zero cost attribution data.
2. Use `resource_subtype` to batch remediation by team — EC2 instances belong to infra, Lambda functions to app teams, EKS clusters to platform.
3. Apply tags in bulk using AWS Resource Groups Tagging API (`tag_resources()`) or Tag Editor in the console. For EC2 and RDS, tags can be applied without downtime.
4. Enable AWS Tag Policies at the Organizations level to enforce mandatory tags on new resources going forward. This script handles the legacy backfill — Tag Policies prevent the problem from recurring.
5. Set up a monthly re-run of this script and track the `missing_count` trend as a team KPI.

**Pitch:** Without `CostCenter` and `Owner` tags, we can't attribute spend to business units or hold teams accountable for their AWS costs. Every untagged resource is a cost that lands in the "unknown" bucket. Tag Policies enforce compliance on new resources; this script tells us the backfill scope. FinOps maturity starts here.

---

### 46. Resources Without Monitoring

1. **`no-cloudwatch-agent`** (resource_subtype=ec2): Without the CloudWatch Agent, OS-level metrics (memory, disk, CPU steal, swap) are invisible — and script 39 (CPU/memory mismatch) silently skips these instances. Install via SSM Run Command using the `AWS-ConfigureAWSPackage` document (`action=Install`, `name=AmazonCloudWatchAgent`). For persistent coverage, use Systems Manager State Manager with an association to keep the agent installed. Prioritize larger instance types first using the `detail2` column.
2. **`enhanced-monitoring-disabled`** (resource_subtype=rds): Enhanced monitoring provides 1-second granularity OS metrics directly from the RDS hypervisor host — memory, disk I/O, network, CPU steal — that standard CloudWatch cannot deliver. Enable via `rds.modify_db_instance(DBInstanceIdentifier=..., MonitoringInterval=60, MonitoringRoleArn=<arn>)`. No reboot required. The monitoring IAM role (`rds-monitoring-role`) must exist first; create it from the RDS console if missing.
3. **`access-logs-disabled`** (resource_subtype=elb): ELB access logs are required for traffic analysis, security forensics, and latency debugging. Enable via `elbv2.modify_load_balancer_attributes()` with `access_logs.s3.enabled=true` and the target bucket. The S3 bucket needs a policy granting write access to the ELB service principal for the region (`elasticloadbalancing.amazonaws.com`). Log storage cost is the only expense — the feature itself is free.
4. Route findings to the right team by `resource_subtype`: ec2 → infrastructure, rds → database team, elb → platform/networking.

**Pitch:** You can't right-size what you can't measure. The `no-cloudwatch-agent` findings explain why script 39 shows zero results on some accounts — the memory data simply isn't being collected. Enhanced monitoring on RDS costs nothing at 60-second intervals and is the only source of OS-level metrics on managed databases. ELB access logs are the first thing needed in any load balancer incident investigation.

---

### 48. All Quotas at >70% Utilization

1. Sort by `severity=critical` first (≥80%) — these have a short runway to a hard limit that will cause service disruptions with no gradual warning.
2. For each finding, submit a Service Quotas increase request: `service-quotas.request_service_quota_increase(ServiceCode=..., QuotaCode=..., DesiredValue=...)`. Most auto-approve within minutes; EC2 vCPU and some networking quotas require manual review (1–3 business days). Request 2× the current limit — a marginal increase will just re-trigger the alert within weeks.
3. Sort by `service_code` to batch related requests — multiple EC2 quota increases in the same account are often handled together.
4. For quotas consistently at 70%+ after increases, investigate the architectural pattern. Lambda concurrency at 80% may indicate a need for reserved concurrency on critical functions, not just a higher limit.
5. Set a recurring monthly scan (`/run-scan 48`) to catch new quota pressures before they cause incidents. The `quota_code` column is the direct key for the increase request API.

**Pitch:** AWS hard quota limits fail instantly and silently. A Lambda concurrency limit hit drops invocations with no retry. An EC2 vCPU limit hit blocks Auto Scaling during an incident. The `quota-at-80pct` findings in this CSV have less than 20% headroom before they can cause an outage. Quota increase requests are free and most auto-approve in minutes.

---

### 49. Quotas Not Exposed by Service Quotas API

These are hard limits invisible in the Service Quotas console — the kind that produce confusing errors when hit because the API response doesn't mention quotas.

1. **S3 bucket count** (quota_id=s3-bucket-count, default limit=100): Usually the surprise. Teams creating per-environment buckets can hit this quietly. Request an increase via AWS Support (not Service Quotas), or consolidate using bucket prefixes and paths.
2. **Lambda VPC ENI count** (quota_id=lambda-vpc-eni-count): Each VPC-attached Lambda function allocates ENIs in the function's subnets. Exhaustion causes Lambda cold starts to fail silently. Mitigations: use Lambda SnapStart (reduces ENI allocations), or remove the VPC attachment from functions that don't need it.
3. **IAM roles / policies** (quota_id=iam-role-count, iam-policy-count): IAM is global — checked once via us-east-1. IAM role sprawl from IaC is the common cause. Run script 37 results alongside this — unused roles are the fastest path to reducing count without a limit increase.
4. **VPC count** (default limit=5 per region): Easy to exhaust in multi-environment accounts. Request an increase, or consolidate using VPC sharing via Resource Access Manager.
5. **EIP count** (default limit=5 per region): Cross-reference with task 3 findings (unassociated EIPs) first — releasing unassociated EIPs is the free fix before requesting an increase.
6. Update `QuotaList.json` if your accounts have approved increases on any of these limits. Leaving stale default values will generate false-positive findings on accounts that already have higher approved quotas.

**Pitch:** These are the limits that catch teams completely off-guard — S3 bucket creation failures look like IAM errors, Lambda VPC failures look like timeouts. The `current_count` vs `limit` columns make the exposure visible. The fix is either a support ticket for a limit increase or a targeted cleanup using findings from other scripts in this suite.

---

### 52. AWS Health Dashboard Events

Findings from this script are your earliest warning of AWS-initiated changes — surfaced before the customer email arrives.

1. **`retirement-notice` (High)**: A specific resource (instance, RDS node, etc.) is being retired by AWS on the date in `end_time`. Open a ticket immediately to schedule replacement — AWS will hard-stop the resource on that date. Use `entity_value` as the resource ID; cross-reference with tags from script 43 to find the owner.
2. **`scheduled-change` (Medium)**: AWS is scheduling a maintenance window (patch, hardware migration, etc.) starting at `start_time`. Verify the window doesn't conflict with a release freeze or on-call rotation. Acknowledge in the AWS Health Dashboard to confirm awareness.
3. **`account-notification` (Medium)**: Deprecation or EOL announcement for a service or feature used in this account. Route to the relevant Wave 2 lifecycle backlog task (Lambda runtimes → script 15, EKS versions → script 20, RDS engine → scripts 18/21). Set a calendar reminder for 30 days before the `end_time`.

**Triage order:** Sort the CSV by `finding` descending (`retirement-notice` first), then `end_time` ascending (soonest deadline first). Any retirement notice with `end_time` within 30 days is P1.

**If no findings appear:** The account is on Basic Support and the Health API is unavailable. The script logs a warning and produces an empty CSV — this is expected. Upgrade to Business Support to unlock org-wide Health event access.

**Pitch:** AWS sends retirement and maintenance emails to the account root address — which no one reads. This script routes those signals into the same findings pipeline as security and cost findings, so they get triaged instead of ignored. A missed retirement notice means AWS hard-stops your resource with no warning on the deadline date.
