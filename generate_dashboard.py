#!/usr/bin/env python3
"""Generate a self-contained HTML dashboard from findings_dataset.csv.

Run: python generate_dashboard.py
     python generate_dashboard.py --dataset-file dataset/findings_dataset.csv --output-dir reports
"""
import argparse
import csv
import json
import sys
import urllib.request
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

CHARTJS_URL = "https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"

WAVE_LABELS = {
    "wave1_cost": "Wave 1 - Cost",
    "wave2_lifecycle": "Wave 2 - Lifecycle",
    "wave3_reliability": "Wave 3 - Reliability",
    "wave4_security": "Wave 4 - Security",
    "wave5_performance": "Wave 5 - Performance",
    "continuous": "Continuous",
    "": "Ad-hoc",
}


def load_dataset(dataset_file: str) -> list:
    """Read CSV, return all rows as list of dicts."""
    path = Path(dataset_file)
    if not path.exists():
        sys.exit(f"Dataset file not found: {dataset_file}")
    with open(path, encoding="utf-8-sig", newline="") as fh:
        return list(csv.DictReader(fh))


def latest_snapshot(rows: list) -> tuple:
    """Return (date_str, rows_for_that_date) for the most recent snapshot."""
    dates = sorted(set(r["snapshot_date"] for r in rows if r["snapshot_date"]))
    if not dates:
        sys.exit("No snapshot_date values found in dataset.")
    latest = dates[-1]
    return latest, [r for r in rows if r["snapshot_date"] == latest]


def all_snapshots(rows: list) -> list:
    """Return sorted list of distinct snapshot_date values."""
    return sorted(set(r["snapshot_date"] for r in rows if r["snapshot_date"]))


def ensure_chartjs(assets_dir: str) -> str | None:
    """Download/cache Chart.js; return JS string or None on failure."""
    assets = Path(assets_dir)
    assets.mkdir(parents=True, exist_ok=True)
    cache = assets / "chart.umd.min.js"
    if cache.exists():
        return cache.read_text(encoding="utf-8")
    print(f"Downloading Chart.js to {cache} ...")
    try:
        with urllib.request.urlopen(CHARTJS_URL, timeout=10) as resp:
            src = resp.read().decode("utf-8")
        cache.write_text(src, encoding="utf-8")
        print("Chart.js downloaded and cached.")
        return src
    except Exception as exc:
        print(f"WARNING: Could not download Chart.js ({exc}). Falling back to SVG charts.")
        return None


def _safe_float(v: str) -> float:
    try:
        return float(v) if v else 0.0
    except ValueError:
        return 0.0


def _wave_label(w: str) -> str:
    if w in WAVE_LABELS:
        return WAVE_LABELS[w]
    return w.replace("_", " ").title() if w else "Ad-hoc"


def _build_data(snapshot_date: str, snap_rows: list, all_rows: list) -> dict:
    real_accounts = {r["account_id"] for r in snap_rows if len(r["account_id"]) == 12 and r["account_id"].isdigit()}

    monthly_savings = sum(_safe_float(r["estimated_monthly_savings_usd"]) for r in snap_rows)
    annual_savings = sum(_safe_float(r["estimated_annual_savings_usd"]) for r in snap_rows)
    sev_counts = Counter(r["severity"] for r in snap_rows)

    wave_savings: dict = defaultdict(float)
    for r in snap_rows:
        wave_savings[_wave_label(r["wave"])] += _safe_float(r["estimated_monthly_savings_usd"])
    savings_by_wave = [
        {"wave": k, "monthly": round(v, 2)}
        for k, v in sorted(wave_savings.items(), key=lambda x: -x[1])
        if v > 0
    ]

    acct_savings: dict = defaultdict(float)
    for r in snap_rows:
        aid = r["account_id"]
        if len(aid) == 12 and aid.isdigit():
            acct_savings[aid] += _safe_float(r["estimated_monthly_savings_usd"])
    top_accounts = sorted(
        [{"account_id": k, "monthly": round(v, 2)} for k, v in acct_savings.items()],
        key=lambda x: -x["monthly"]
    )[:10]

    sec_rows = [r for r in snap_rows if r["wave"] == "wave4_security"]
    sec_ctr = Counter(r["finding"] for r in sec_rows)
    security_findings = [{"finding": k, "count": v} for k, v in sec_ctr.most_common(10)]

    sorted_snap = sorted(snap_rows, key=lambda r: -_safe_float(r["estimated_monthly_savings_usd"]))
    top10 = [
        {
            "account_id": r["account_id"],
            "region": r["region"],
            "resource_type": r["resource_type"],
            "resource_id": r["resource_id"],
            "finding": r["finding"],
            "monthly": _safe_float(r["estimated_monthly_savings_usd"]),
            "annual": _safe_float(r["estimated_annual_savings_usd"]),
        }
        for r in sorted_snap[:10]
    ]

    table_rows = [
        {
            "account_id": r["account_id"],
            "region": r["region"],
            "wave": _wave_label(r["wave"]),
            "resource_type": r["resource_type"],
            "resource_id": r["resource_id"],
            "finding": r["finding"],
            "detail": r["detail"],
            "owner": r["owner"],
            "severity": r["severity"],
            "monthly": _safe_float(r["estimated_monthly_savings_usd"]),
        }
        for r in snap_rows
    ]

    snapshots = all_snapshots(all_rows)
    trends = []
    for d in snapshots:
        d_rows = [r for r in all_rows if r["snapshot_date"] == d]
        d_sev = Counter(r["severity"] for r in d_rows)
        trends.append({
            "date": d,
            "monthly_savings": round(sum(_safe_float(r["estimated_monthly_savings_usd"]) for r in d_rows), 2),
            "High": d_sev.get("High", 0),
            "Medium": d_sev.get("Medium", 0),
            "Low": d_sev.get("Low", 0),
        })

    detectors = len(set(r["source_script"] for r in snap_rows if r["source_script"]))

    return {
        "snapshot_date": snapshot_date,
        "accounts": sorted(real_accounts),
        "kpi": {
            "monthly_savings": round(monthly_savings, 2),
            "annual_savings": round(annual_savings, 2),
            "total_findings": len(snap_rows),
            "high_severity": sev_counts.get("High", 0),
            "accounts_count": len(real_accounts),
            "detectors_run": detectors,
        },
        "savings_by_wave": savings_by_wave,
        "findings_by_severity": {
            "High": sev_counts.get("High", 0),
            "Medium": sev_counts.get("Medium", 0),
            "Low": sev_counts.get("Low", 0),
        },
        "top_accounts": top_accounts,
        "security_findings": security_findings,
        "top10": top10,
        "rows": table_rows,
        "trends": trends,
    }


def _svg_bar(items: list, key_x: str, key_y: str, title: str, color: str = "#1F4E79") -> str:
    if not items:
        return "<p style='color:#888'>No data</p>"
    max_v = max(item[key_y] for item in items) or 1
    bar_h = 24
    gap = 6
    label_w = 160
    chart_w = 360
    total_h = len(items) * (bar_h + gap) + 40
    bars = ""
    for i, item in enumerate(items):
        y = 30 + i * (bar_h + gap)
        bw = int((item[key_y] / max_v) * chart_w)
        label = str(item[key_x])[:22]
        val = ("$" + f"{item[key_y]:,.0f}") if isinstance(item[key_y], float) else str(item[key_y])
        bars += (
            '<text x="' + str(label_w - 4) + '" y="' + str(y + bar_h - 6) + '" text-anchor="end" font-size="11" fill="#333">' + label + '</text>'
            + '<rect x="' + str(label_w) + '" y="' + str(y) + '" width="' + str(bw) + '" height="' + str(bar_h) + '" fill="' + color + '" rx="2"/>'
            + '<text x="' + str(label_w + bw + 4) + '" y="' + str(y + bar_h - 6) + '" font-size="10" fill="#555">' + val + '</text>'
        )
    svg_w = label_w + chart_w + 80
    return (
        '<svg width="' + str(svg_w) + '" height="' + str(total_h) + '" xmlns="http://www.w3.org/2000/svg">'
        + '<text x="' + str(svg_w // 2) + '" y="16" text-anchor="middle" font-size="13" font-weight="bold" fill="#222">' + title + '</text>'
        + bars + '</svg>'
    )


_CSS = """
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Arial,sans-serif;background:#f4f6f8;color:#222;font-size:14px}
header{background:#1F4E79;color:#fff;padding:14px 24px;display:flex;align-items:center;gap:24px;flex-wrap:wrap}
header h1{font-size:20px;font-weight:700;letter-spacing:.5px}
header .meta{font-size:13px;opacity:.85}
.container{max-width:1400px;margin:0 auto;padding:20px 16px}
.kpi-row{display:flex;flex-wrap:wrap;gap:14px;margin-bottom:20px}
.kpi-tile{background:#fff;border-radius:6px;box-shadow:0 1px 4px rgba(0,0,0,.10);padding:16px 20px;flex:1;min-width:170px;border-left:4px solid #aaa}
.kpi-tile.green{border-left-color:#276221}
.kpi-tile.red{border-left-color:#9C0006;background:#fff5f5}
.kpi-tile.blue{border-left-color:#1F4E79}
.kpi-tile .label{font-size:12px;color:#666;text-transform:uppercase;letter-spacing:.5px}
.kpi-tile .value{font-size:22px;font-weight:700;margin-top:4px}
.kpi-tile.red .value{color:#9C0006}
.kpi-tile.green .value{color:#276221}
.kpi-tile.blue .value{color:#1F4E79}
.charts-row{display:flex;flex-wrap:wrap;gap:16px;margin-bottom:20px}
.chart-box{background:#fff;border-radius:6px;box-shadow:0 1px 4px rgba(0,0,0,.10);padding:16px;flex:1;min-width:280px}
.chart-box h3{font-size:13px;color:#444;margin-bottom:10px;text-transform:uppercase;letter-spacing:.4px}
.chart-canvas{position:relative;height:260px}
section{background:#fff;border-radius:6px;box-shadow:0 1px 4px rgba(0,0,0,.10);padding:16px;margin-bottom:20px}
section h2{font-size:15px;font-weight:700;color:#1F4E79;margin-bottom:12px;border-bottom:1px solid #e5e7eb;padding-bottom:8px}
table{width:100%;border-collapse:collapse;font-size:13px}
th{background:#1F4E79;color:#fff;padding:8px 10px;text-align:left;white-space:nowrap;cursor:pointer;user-select:none}
th:hover{background:#163d5e}
th .sort-icon{margin-left:4px;opacity:.6}
td{padding:7px 10px;border-bottom:1px solid #e5e7eb;vertical-align:top}
tr:nth-child(even) td{background:#f9fafb}
.sev-high{background:#FFC7CE;color:#9C0006;padding:2px 7px;border-radius:3px;font-size:12px;font-weight:600;white-space:nowrap}
.sev-medium{background:#FFEB9C;color:#9C6500;padding:2px 7px;border-radius:3px;font-size:12px;font-weight:600;white-space:nowrap}
.sev-low{background:#C6EFCE;color:#276221;padding:2px 7px;border-radius:3px;font-size:12px;font-weight:600;white-space:nowrap}
.filters{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:12px;align-items:center}
.filters select,.filters input{padding:6px 10px;border:1px solid #d1d5db;border-radius:4px;font-size:13px;background:#fff}
.filters input{min-width:220px}
.pagination{display:flex;align-items:center;gap:10px;margin-top:12px;justify-content:flex-end}
.pagination button{padding:5px 14px;border:1px solid #d1d5db;border-radius:4px;background:#fff;cursor:pointer;font-size:13px}
.pagination button:hover{background:#f3f4f6}
.pagination button:disabled{opacity:.45;cursor:not-allowed}
.pagination .page-info{font-size:13px;color:#555}
footer{text-align:center;padding:18px;color:#888;font-size:12px;border-top:1px solid #e5e7eb;margin-top:8px}
.money{font-variant-numeric:tabular-nums;text-align:right}
.trend-section{background:#fff;border-radius:6px;box-shadow:0 1px 4px rgba(0,0,0,.10);padding:16px;margin-bottom:20px}
.trend-section h2{font-size:15px;font-weight:700;color:#1F4E79;margin-bottom:12px;border-bottom:1px solid #e5e7eb;padding-bottom:8px}
.trend-charts{display:flex;flex-wrap:wrap;gap:16px}
.trend-chart-box{flex:1;min-width:300px}
.trend-chart-box .chart-canvas{height:220px}
"""

_JS_TABLE = r"""
(function() {
  var PAGE_SIZE = 50;
  var filtered = DATA.rows.slice();
  var sortCol = "monthly";
  var sortDir = -1;
  var page = 0;

  function populateFilters() {
    var waves = Array.from(new Set(DATA.rows.map(function(r){return r.wave;}))).sort();
    var accounts = DATA.accounts.slice().sort();
    var wSel = document.getElementById("filterWave");
    var aSel = document.getElementById("filterAccount");
    waves.forEach(function(w){ var o = document.createElement("option"); o.value = w; o.textContent = w; wSel.appendChild(o); });
    accounts.forEach(function(a){ var o = document.createElement("option"); o.value = a; o.textContent = a; aSel.appendChild(o); });
  }

  function sevClass(s) {
    if (s === "High") return "sev-high";
    if (s === "Medium") return "sev-medium";
    return "sev-low";
  }

  function fmtMoney(v) {
    if (v <= 0) return "-";
    return "$" + v.toFixed(2).replace(/\B(?=(\d{3})+(?!\d))/g, ",");
  }

  function applyFilters() {
    var wf = document.getElementById("filterWave").value;
    var af = document.getElementById("filterAccount").value;
    var sf = document.getElementById("filterSeverity").value;
    var q = document.getElementById("searchBox").value.toLowerCase();
    filtered = DATA.rows.filter(function(r) {
      if (wf && r.wave !== wf) return false;
      if (af && r.account_id !== af) return false;
      if (sf && r.severity !== sf) return false;
      if (q && !(r.finding.toLowerCase().indexOf(q) >= 0 || r.detail.toLowerCase().indexOf(q) >= 0 || r.resource_id.toLowerCase().indexOf(q) >= 0 || r.owner.toLowerCase().indexOf(q) >= 0)) return false;
      return true;
    });
    sortFiltered();
    page = 0;
    render();
  }

  function sortFiltered() {
    filtered.sort(function(a, b) {
      var av = a[sortCol], bv = b[sortCol];
      if (typeof av === "number") return sortDir * (av - bv);
      return sortDir * String(av).localeCompare(String(bv));
    });
  }

  function render() {
    var tbody = document.getElementById("findingsBody");
    var start = page * PAGE_SIZE;
    var slice = filtered.slice(start, start + PAGE_SIZE);
    tbody.innerHTML = slice.map(function(r) {
      return "<tr>"
        + "<td>" + r.account_id + "</td>"
        + "<td>" + r.region + "</td>"
        + "<td>" + r.wave + "</td>"
        + "<td>" + r.resource_type + "</td>"
        + "<td>" + r.finding + "</td>"
        + "<td>" + (r.owner || "-") + "</td>"
        + "<td><span class=\"" + sevClass(r.severity) + "\">" + r.severity + "</span></td>"
        + "<td class=\"money\">" + fmtMoney(r.monthly) + "</td>"
        + "</tr>";
    }).join("");
    var total = filtered.length;
    var pages = Math.ceil(total / PAGE_SIZE) || 1;
    document.getElementById("pageInfo").textContent = "Page " + (page + 1) + " of " + pages + " (" + total + " rows)";
    document.getElementById("btnPrev").disabled = (page === 0);
    document.getElementById("btnNext").disabled = (page >= pages - 1);
  }

  window.prevPage = function() { if (page > 0) { page--; render(); } };
  window.nextPage = function() { var pages = Math.ceil(filtered.length / PAGE_SIZE); if (page < pages - 1) { page++; render(); } };

  document.querySelectorAll("#findingsTable th[data-col]").forEach(function(th) {
    th.addEventListener("click", function() {
      var col = this.dataset.col;
      if (sortCol === col) { sortDir = -sortDir; }
      else { sortCol = col; sortDir = (col === "monthly") ? -1 : 1; }
      sortFiltered();
      page = 0;
      render();
    });
  });

  ["filterWave","filterAccount","filterSeverity","searchBox"].forEach(function(id) {
    document.getElementById(id).addEventListener("input", applyFilters);
  });

  populateFilters();
  applyFilters();
})();
"""

_JS_CHARTS = r"""
function buildCharts() {
  var waveLabs = DATA.savings_by_wave.map(function(d){return d.wave;});
  var waveVals = DATA.savings_by_wave.map(function(d){return d.monthly;});
  new Chart(document.getElementById("chartWave"), {
    type: "bar",
    data: {
      labels: waveLabs,
      datasets: [{ label: "Monthly Savings ($)", data: waveVals, backgroundColor: "#1F4E79", borderRadius: 3 }]
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: { y: { ticks: { callback: function(v){ return "$" + v.toLocaleString(); } } } }
    }
  });

  var sevBg = { High: "#FFC7CE", Medium: "#FFEB9C", Low: "#C6EFCE" };
  var sevBorder = { High: "#9C0006", Medium: "#9C6500", Low: "#276221" };
  var sevKeys = ["High", "Medium", "Low"];
  new Chart(document.getElementById("chartSev"), {
    type: "doughnut",
    data: {
      labels: sevKeys,
      datasets: [{
        data: sevKeys.map(function(k){ return DATA.findings_by_severity[k] || 0; }),
        backgroundColor: sevKeys.map(function(k){ return sevBg[k]; }),
        borderColor: sevKeys.map(function(k){ return sevBorder[k]; }),
        borderWidth: 1
      }]
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { position: "bottom" } }
    }
  });

  var acctLabs = DATA.top_accounts.map(function(d){return d.account_id;});
  var acctVals = DATA.top_accounts.map(function(d){return d.monthly;});
  new Chart(document.getElementById("chartAccounts"), {
    type: "bar",
    data: {
      labels: acctLabs,
      datasets: [{ label: "Monthly Savings ($)", data: acctVals, backgroundColor: "#276221", borderRadius: 3 }]
    },
    options: {
      indexAxis: "y",
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: { x: { ticks: { callback: function(v){ return "$" + v.toLocaleString(); } } } }
    }
  });

  var secLabs = DATA.security_findings.map(function(d){return d.finding;});
  var secVals = DATA.security_findings.map(function(d){return d.count;});
  new Chart(document.getElementById("chartSecurity"), {
    type: "bar",
    data: {
      labels: secLabs,
      datasets: [{ label: "Count", data: secVals, backgroundColor: "#FFC7CE", borderColor: "#9C0006", borderWidth: 1, borderRadius: 3 }]
    },
    options: {
      indexAxis: "y",
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { display: false } }
    }
  });

  if (DATA.trends && DATA.trends.length >= 2) {
    var tDates = DATA.trends.map(function(d){return d.date;});
    new Chart(document.getElementById("chartTrendSavings"), {
      type: "line",
      data: {
        labels: tDates,
        datasets: [{
          label: "Monthly Savings ($)",
          data: DATA.trends.map(function(d){return d.monthly_savings;}),
          borderColor: "#1F4E79",
          backgroundColor: "rgba(31,78,121,.12)",
          fill: true,
          tension: 0.3
        }]
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { display: false }, title: { display: true, text: "Monthly Savings Over Time" } },
        scales: { y: { ticks: { callback: function(v){ return "$" + v.toLocaleString(); } } } }
      }
    });
    new Chart(document.getElementById("chartTrendSeverity"), {
      type: "line",
      data: {
        labels: tDates,
        datasets: [
          { label: "High", data: DATA.trends.map(function(d){return d.High;}), borderColor: "#9C0006", fill: false, tension: 0.3 },
          { label: "Medium", data: DATA.trends.map(function(d){return d.Medium;}), borderColor: "#9C6500", fill: false, tension: 0.3 },
          { label: "Low", data: DATA.trends.map(function(d){return d.Low;}), borderColor: "#276221", fill: false, tension: 0.3 }
        ]
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: { title: { display: true, text: "Findings by Severity Over Time" } }
      }
    });
  }
}
"""


def build_html(snapshot_rows: list, all_rows: list, chartjs_src: str | None) -> str:
    """Assemble the complete self-contained HTML string."""
    snapshot_date = snapshot_rows[0]["snapshot_date"] if snapshot_rows else ""
    data = _build_data(snapshot_date, snapshot_rows, all_rows)
    snapshots = all_snapshots(all_rows)
    show_trends = len(snapshots) >= 2
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M")
    data_json = json.dumps(data, ensure_ascii=False).replace("</", "<\\/")

    kpi = data["kpi"]
    has_chartjs = chartjs_src is not None

    if has_chartjs:
        charts_block = (
            '<div class="charts-row">'
            '<div class="chart-box"><h3>Monthly Savings by Wave</h3><div class="chart-canvas"><canvas id="chartWave"></canvas></div></div>'
            '<div class="chart-box"><h3>Findings by Severity</h3><div class="chart-canvas"><canvas id="chartSev"></canvas></div></div>'
            '<div class="chart-box"><h3>Top 10 Accounts by Monthly Savings</h3><div class="chart-canvas"><canvas id="chartAccounts"></canvas></div></div>'
            '<div class="chart-box"><h3>Security Finding Types (Top 10)</h3><div class="chart-canvas"><canvas id="chartSecurity"></canvas></div></div>'
            '</div>'
        )
    else:
        charts_block = (
            '<div class="charts-row">'
            + '<div class="chart-box">' + _svg_bar(data["savings_by_wave"], "wave", "monthly", "Monthly Savings by Wave") + '</div>'
            + '<div class="chart-box">' + _svg_bar(data["top_accounts"], "account_id", "monthly", "Top Accounts by Monthly Savings", "#276221") + '</div>'
            + '<div class="chart-box">' + _svg_bar(data["security_findings"], "finding", "count", "Security Finding Types", "#9C0006") + '</div>'
            + '</div>'
        )

    if show_trends and has_chartjs:
        trend_block = (
            '<div class="trend-section" id="trendSection">'
            '<h2>Trends (across ' + str(len(snapshots)) + ' snapshots)</h2>'
            '<div class="trend-charts">'
            '<div class="trend-chart-box"><div class="chart-canvas"><canvas id="chartTrendSavings"></canvas></div></div>'
            '<div class="trend-chart-box"><div class="chart-canvas"><canvas id="chartTrendSeverity"></canvas></div></div>'
            '</div></div>'
        )
    else:
        trend_block = ""

    top10_rows_html = "".join(
        "<tr>"
        + "<td>" + str(i + 1) + "</td>"
        + "<td>" + r["account_id"] + "</td>"
        + "<td>" + r["region"] + "</td>"
        + "<td>" + r["resource_type"] + "</td>"
        + "<td>" + r["finding"] + "</td>"
        + '<td class="money">$' + f'{r["monthly"]:,.2f}' + "</td>"
        + '<td class="money">$' + f'{r["annual"]:,.2f}' + "</td>"
        + "</tr>"
        for i, r in enumerate(data["top10"])
    )

    chartjs_script = ("<script>" + chartjs_src + "</script>") if has_chartjs else ""
    build_charts_call = "\nbuildCharts();\n" if has_chartjs else ""
    chart_fn_script = ("<script>" + _JS_CHARTS + "</script>") if has_chartjs else ""

    parts = [
        "<!DOCTYPE html>",
        '<html lang="en">',
        "<head>",
        '<meta charset="UTF-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1.0">',
        "<title>AWS Proactive Findings Dashboard</title>",
        "<style>" + _CSS + "</style>",
        "</head>",
        "<body>",
        "<header>",
        "  <h1>AWS Proactive Findings Dashboard</h1>",
        '  <span class="meta">Snapshot: ' + data["snapshot_date"] + "</span>",
        '  <span class="meta">Accounts: ' + str(kpi["accounts_count"]) + "</span>",
        '  <span class="meta">Detectors: ' + str(kpi["detectors_run"]) + "</span>",
        "</header>",
        '<div class="container">',
        "",
        '<div class="kpi-row">',
        '  <div class="kpi-tile green">',
        '    <div class="label">Total Monthly Savings</div>',
        '    <div class="value">$' + f'{kpi["monthly_savings"]:,.2f}' + "</div>",
        "  </div>",
        '  <div class="kpi-tile green">',
        '    <div class="label">Total Annual Savings</div>',
        '    <div class="value">$' + f'{kpi["annual_savings"]:,.2f}' + "</div>",
        "  </div>",
        '  <div class="kpi-tile blue">',
        '    <div class="label">Total Findings</div>',
        '    <div class="value">' + f'{kpi["total_findings"]:,}' + "</div>",
        "  </div>",
        '  <div class="kpi-tile red">',
        '    <div class="label">High Severity</div>',
        '    <div class="value">' + f'{kpi["high_severity"]:,}' + "</div>",
        "  </div>",
        '  <div class="kpi-tile blue">',
        '    <div class="label">Accounts Scanned</div>',
        '    <div class="value">' + str(kpi["accounts_count"]) + "</div>",
        "  </div>",
        "</div>",
        "",
        charts_block,
        "",
        "<section>",
        "  <h2>Top 10 Action Items (by Monthly Savings)</h2>",
        "  <table>",
        "    <thead><tr>",
        '      <th>#</th><th>Account</th><th>Region</th><th>Resource Type</th><th>Finding</th>',
        '      <th style="text-align:right">Monthly Savings</th><th style="text-align:right">Annual Savings</th>',
        "    </tr></thead>",
        "    <tbody>",
        top10_rows_html,
        "    </tbody>",
        "  </table>",
        "</section>",
        "",
        trend_block,
        "",
        "<section>",
        "  <h2>All Findings</h2>",
        '  <div class="filters">',
        '    <select id="filterWave"><option value="">All Waves</option></select>',
        '    <select id="filterAccount"><option value="">All Accounts</option></select>',
        '    <select id="filterSeverity">',
        '      <option value="">All Severities</option>',
        '      <option value="High">High</option>',
        '      <option value="Medium">Medium</option>',
        '      <option value="Low">Low</option>',
        "    </select>",
        '    <input type="text" id="searchBox" placeholder="Search finding / detail / resource ID / owner...">',
        "  </div>",
        '  <table id="findingsTable">',
        "    <thead><tr>",
        '      <th data-col="account_id">Account <span class="sort-icon">&#8597;</span></th>',
        '      <th data-col="region">Region <span class="sort-icon">&#8597;</span></th>',
        '      <th data-col="wave">Wave <span class="sort-icon">&#8597;</span></th>',
        '      <th data-col="resource_type">Resource Type <span class="sort-icon">&#8597;</span></th>',
        '      <th data-col="finding">Finding <span class="sort-icon">&#8597;</span></th>',
        '      <th data-col="owner">Owner <span class="sort-icon">&#8597;</span></th>',
        '      <th data-col="severity">Severity <span class="sort-icon">&#8597;</span></th>',
        '      <th data-col="monthly" style="text-align:right">Monthly Savings <span class="sort-icon">&#8597;</span></th>',
        "    </tr></thead>",
        '    <tbody id="findingsBody"></tbody>',
        "  </table>",
        '  <div class="pagination">',
        '    <button id="btnPrev" onclick="prevPage()">&#8592; Prev</button>',
        '    <span class="page-info" id="pageInfo"></span>',
        '    <button id="btnNext" onclick="nextPage()">Next &#8594;</button>',
        "  </div>",
        "</section>",
        "",
        "</div>",
        "<footer>Figures are estimated savings from pricing heuristics &mdash; not invoiced AWS amounts. Generated " + now_str + ".</footer>",
        "",
        "<script>",
        "const DATA = " + data_json + ";",
        "</script>",
        chartjs_script,
        chart_fn_script,
        "<script>" + _JS_TABLE + build_charts_call + "</script>",
        "</body>",
        "</html>",
    ]

    return "\n".join(parts)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset-file", default="dataset/findings_dataset.csv")
    parser.add_argument("--output-dir", default="reports")
    args = parser.parse_args()

    rows = load_dataset(args.dataset_file)
    snapshot_date, snap_rows = latest_snapshot(rows)
    print(f"Loaded {len(rows)} rows. Latest snapshot: {snapshot_date} ({len(snap_rows)} rows).")

    assets_dir = Path(__file__).resolve().parent / "assets"
    chartjs_src = ensure_chartjs(str(assets_dir))

    html = build_html(snap_rows, rows, chartjs_src)

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = output_dir / f"dashboard_{ts}.html"
    out_path.write_text(html, encoding="utf-8")
    size_kb = out_path.stat().st_size / 1024
    print(f"Dashboard written: {out_path} ({size_kb:.1f} KB)")


if __name__ == "__main__":
    main()
