# Lambda runtime lifecycle assessment

`wave2_lifecycle/15_detect_lambda_deprecated_runtimes.py` is an inventory and
reporting tool only. It does not update Lambda functions, invoke functions,
change IAM, create tickets, or send notifications. All changes remain subject to
business approval and an owner-led change process.

## Run

The existing multi-account CLI and Britive authentication are unchanged:

```powershell
python wave2_lifecycle/15_detect_lambda_deprecated_runtimes.py --accounts 123456789012
python wave2_lifecycle/15_detect_lambda_deprecated_runtimes.py --accounts 123456789012 --cloudwatch-metrics --metric-windows 7,30,90
```

By default, the scanner reads Lambda inventory, published versions, aliases,
and tags. CloudWatch calls are opt-in. The 7-, 30-, and 90-day metrics are
per-version daily `Invocations` and `Errors` sums. `last_invoked` is the latest
observed CloudWatch metric period with invocations, not an exact invocation
timestamp. An empty metric series is reported as no data, not proof of disuse.

## Least-privilege read permissions

Replace the account ID and apply account/region restrictions consistent with
the organization's credential policy. `lambda:ListFunctions` and
`cloudwatch:GetMetricData` require `Resource: "*"`. The CloudWatch statement is
needed only when `--cloudwatch-metrics` is selected.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["lambda:ListFunctions"],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "lambda:ListVersionsByFunction",
        "lambda:ListAliases",
        "lambda:ListTags"
      ],
      "Resource": "arn:aws:lambda:*:123456789012:function:*"
    },
    {
      "Effect": "Allow",
      "Action": ["cloudwatch:GetMetricData"],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": ["ec2:DescribeRegions", "sts:GetCallerIdentity"],
      "Resource": "*"
    }
  ]
}
```

`ec2:DescribeRegions` and `sts:GetCallerIdentity` are used by the existing
shared account/region and Britive credential plumbing. The scanner makes no
AWS write API calls.

## Lifecycle and risk interpretation

The table differentiates runtime deprecation, function-creation block, and
function-update block dates. A blank block date is accompanied by a status.
`scheduled` and `passed` distinguish future from elapsed dates;
`not-recorded` means no explicit date is held for that runtime,
`not-scheduled` means AWS currently lists no date, and `unknown` means the
runtime is not recognized. The lifecycle date table was checked on 2026-10-27;
forecast dates can change and become stale after 90 days.

AWS states that deprecated runtimes may no longer receive runtime patches or
technical support, but functions can continue to be invoked indefinitely.
Deprecation alone is not proof of an exploitable vulnerability. This scanner
does not claim a function is vulnerable: it labels lifecycle exposure and
conservatively prioritizes explicit production tags, alias routing, ownership,
and optional activity evidence. An alias weight of zero is not treated as an
active route. A published version with no alias is not treated as unused,
because direct qualified-ARN invocation cannot be excluded.

Container-image functions require separate base-image and bundled-runtime
assessment. Unknown runtimes, image assessment gaps, missing lifecycle data,
and inventory access gaps are surfaced as `Review Required` or mark the run
incomplete. Check the run manifest before interpreting an empty CSV as clean.
The CSV keeps lifecycle-data validation (`lifecycle_data_status`) separate from
version and alias coverage (`version_inventory_status` and
`alias_inventory_status`); task outcomes in the run manifest record API access
failures.

## Sample CSV excerpt

The actual CSV retains all shared fields and every existing Lambda-specific
column, then appends the fields below. The row is illustrative.

```csv
account_id,region,resource_id,finding,owner,function_name,runtime,lifecycle_status,lifecycle_urgency,risk_level,risk_reason,deprecation_date,creation_block_date,creation_block_status,update_block_date,update_block_status,function_version,alias_name,alias_traffic_weight,package_type,environment,function_owner,activity_status,last_invoked,invocations_7d,errors_7d,recommended_action
123456789012,us-east-1,arn:aws:lambda:us-east-1:123456789012:function:orders:42,deprecated-runtime,payments,orders,python3.8,deprecated,past-deprecation,High,"Runtime deprecation date passed (2024-10-14); lifecycle exposure is not proof of a vulnerability; production environment is explicitly tagged and active alias routing confirms exposure; Alias routing: production=1.0000",2024-10-14,2027-07-29,scheduled,2027-08-31,scheduled,"42",production,"{""production"": 1.0}",Zip,production,payments,not-requested,,,,Review runtime lifecycle and plan an application-owner-approved migration; no changes were made by this scanner.
```

The current Lambda API calls are list/configuration/tag reads and optional
CloudWatch metric reads. AWS SDK retry behavior is used for transient service
errors; errors that remain after SDK retries are not suppressed and prevent the
run from being reported as complete.
