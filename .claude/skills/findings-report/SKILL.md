---
name: findings-report
description: Analyze findings CSVs from completed scans and produce a savings summary. Use when asked about scan results, estimated savings, top findings, or which resources to prioritize.
agent: general-purpose
allowed-tools: Glob Read Bash(python *)
---

Analyze all findings CSVs in the `findings/` directory (including its per-wave subfolders) and produce a summary report.

## Steps

1. Use Glob with pattern `findings/**/*.csv` to list available CSV files. If none exist, report that no scans have been run yet and stop.

2. Run this Python snippet to aggregate all CSVs at once and capture the output:

```
python -c "
import csv, glob
from collections import Counter, defaultdict

rows = []
for f in sorted(glob.glob('findings/**/*.csv', recursive=True)):
    if '/logs/' in f.replace('\\\\', '/') or '/inventory_' in f.replace('\\\\', '/') or f.split('/')[-1].startswith('inventory_'):
        continue
    with open(f, encoding='utf-8') as fh:
        rows.extend(list(csv.DictReader(fh)))

def safe_float(v):
    try: return float(v or 0)
    except: return 0.0

total_savings = sum(safe_float(r.get('estimated_monthly_savings_usd')) for r in rows)
by_finding = Counter(r['finding'] for r in rows)
by_account = defaultdict(float)
for r in rows:
    by_account[r['account_id']] += safe_float(r.get('estimated_monthly_savings_usd'))
top_resources = sorted(rows, key=lambda r: safe_float(r.get('estimated_monthly_savings_usd')), reverse=True)[:10]

print(f'TOTAL_ROWS={len(rows)}')
print(f'TOTAL_SAVINGS={total_savings:.2f}')
print('TOP_FINDINGS:')
for k, v in by_finding.most_common(15): print(f'  {v:5d}  {k}')
print('TOP_ACCOUNTS:')
for k, v in sorted(by_account.items(), key=lambda x: -x[1])[:10]: print(f'  {k}  {v:.2f}')
print('TOP_RESOURCES:')
for r in top_resources:
    print(f'  {r[\"resource_id\"]}  {r[\"resource_type\"]}  {r[\"finding\"]}  {safe_float(r.get(\"estimated_monthly_savings_usd\")):.2f}')
"
```

3. Using the data above, produce a markdown report with these sections:
   - **Summary**: total findings, total estimated monthly savings (USD/mo), accounts and regions scanned
   - **Findings by type** (table: Finding | Count | Total Savings USD/mo)
   - **Top 10 accounts** by total savings potential (table: Account ID | Savings USD/mo)
   - **Top 10 highest-value resources** (table: Resource ID | Type | Finding | Savings USD/mo)
   - **Recommended actions**: top 3 highest-ROI remediation steps, each with specific resource IDs from the data
