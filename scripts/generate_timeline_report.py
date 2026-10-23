#!/usr/bin/env python3
"""
Generate timeline reports (HTML + JSON) from history analysis results.

Reads analysis_results.json, filters to successful commits with reachability
data, recomputes deltas from the chronological commit sequence, and generates
an interactive HTML report and a structured JSON file.

Usage:
    python3 generate_timeline_report.py <path/to/analysis_results.json | history_dir>
                                        [output_dir]

Default output: /home/yogya/projects/def-baudry/yogya/theo-all/client_final_changed_reports/<project>/
"""

import json
import sys
from pathlib import Path
from datetime import datetime


REPORTS_BASE = Path("/scratch/yogya/client-results/history")
DEFAULT_OUTPUT = Path("/home/yogya/projects/def-baudry/yogya/theo-all/client_final_changed_reports")

CATEGORIES = ["FILESYSTEM", "NETWORK", "PROCESS", "OTHER"]
CAT_COLORS = {
    "FILESYSTEM": {"line": "#e07a3a", "bg": "rgba(224,122,58,0.15)"},
    "NETWORK":    {"line": "#4a90d9", "bg": "rgba(74,144,217,0.15)"},
    "PROCESS":    {"line": "#d94a6b", "bg": "rgba(217,74,107,0.15)"},
    "OTHER":      {"line": "#7c7c7c", "bg": "rgba(124,124,124,0.15)"},
}


def load_results(path):
    p = Path(path)
    if p.is_dir():
        p = p / "analysis_results.json"
    if not p.exists():
        print(f"Not found: {p}", file=sys.stderr)
        sys.exit(1)
    with open(p) as f:
        return json.load(f), p.parent


def parse_date(date_str):
    """Parse git date string to sortable format."""
    if not date_str:
        return ""
    return date_str[:19]


def build_timeline(data):
    """Extract successful commits with reachability data, sorted by date."""
    commits = []
    skipped_no_changed = []
    skipped_no_reachability = []

    for c in data.get("commits", []):
        if c.get("analysisResult") not in ("success", "copied"):
            continue

        changed = c.get("changedModules", [])
        if not changed:
            skipped_no_changed.append(c["sha"][:8])
            continue

        if "reachability" not in c:
            skipped_no_reachability.append(c["sha"][:8])
            continue

        info = c.get("commitInfo", {})
        date_str = info.get("date", "")
        commits.append({
            "sha": c["sha"],
            "sha8": c["sha"][:8],
            "date": date_str[:10] if date_str else "",
            "dateSort": parse_date(date_str),
            "message": info.get("message", "")[:120],
            "changedModules": changed,
            "reachability": c["reachability"],
        })

    commits.sort(key=lambda c: c["dateSort"])

    if skipped_no_changed:
        print(f"  Skipped (no changedModules): {', '.join(skipped_no_changed)}")
    if skipped_no_reachability:
        print(f"  Skipped (no reachability):   {', '.join(skipped_no_reachability)}")

    return commits


def all_modules(timeline):
    mods = set()
    for c in timeline:
        mods.update(c["reachability"].keys())
    return sorted(mods)


def compute_deltas(timeline, modules):
    """Recompute deltas between consecutive commits in chronological order."""
    for i, commit in enumerate(timeline):
        if i == 0:
            commit["deltas"] = None
            continue

        prev = timeline[i - 1]
        deltas = {}
        for mod in modules:
            cur = commit["reachability"].get(mod, {})
            prv = prev["reachability"].get(mod, {})

            cur_total = cur.get("reachableApis", 0)
            prv_total = prv.get("reachableApis", 0)
            cur_deps = cur.get("reachableDeps", 0)
            prv_deps = prv.get("reachableDeps", 0)

            cur_by_cat = cur.get("reachableApisByCategory", {})
            prv_by_cat = prv.get("reachableApisByCategory", {})
            cat_deltas = {}
            for cat in CATEGORIES:
                diff = cur_by_cat.get(cat, 0) - prv_by_cat.get(cat, 0)
                if diff != 0:
                    cat_deltas[cat] = diff

            cur_dep_detail = cur.get("depsDetail", {})
            prv_dep_detail = prv.get("depsDetail", {})
            all_dep_keys = set(cur_dep_detail.keys()) | set(prv_dep_detail.keys())
            added_deps = []
            removed_deps = []
            changed_deps = []
            for dep in all_dep_keys:
                c_count = cur_dep_detail.get(dep, 0)
                p_count = prv_dep_detail.get(dep, 0)
                if p_count == 0 and c_count > 0:
                    added_deps.append({"dep": dep, "apis": c_count})
                elif c_count == 0 and p_count > 0:
                    removed_deps.append({"dep": dep, "apis": p_count})
                elif c_count != p_count:
                    changed_deps.append({"dep": dep, "from": p_count, "to": c_count})

            if cur_total != prv_total or cur_deps != prv_deps or cat_deltas or added_deps or removed_deps or changed_deps:
                deltas[mod] = {
                    "apisDelta": cur_total - prv_total,
                    "depsDelta": cur_deps - prv_deps,
                    "categoryDeltas": cat_deltas,
                    "addedDeps": sorted(added_deps, key=lambda d: -d["apis"]),
                    "removedDeps": sorted(removed_deps, key=lambda d: -d["apis"]),
                    "changedDeps": sorted(changed_deps, key=lambda d: -abs(d["to"] - d["from"])),
                }

        commit["deltas"] = deltas if deltas else None


def build_json_report(timeline, modules):
    """Build the structured JSON output."""
    first = timeline[0] if timeline else {}
    last = timeline[-1] if timeline else {}

    first_date = first.get("date", "")
    last_date = last.get("date", "")

    module_summaries = {}
    for mod in modules:
        first_r = first.get("reachability", {}).get(mod, {})
        last_r = last.get("reachability", {}).get(mod, {})
        module_summaries[mod] = {
            "firstApis": first_r.get("reachableApis", 0),
            "lastApis": last_r.get("reachableApis", 0),
            "firstDeps": first_r.get("reachableDeps", 0),
            "lastDeps": last_r.get("reachableDeps", 0),
            "firstByCategory": first_r.get("reachableApisByCategory", {}),
            "lastByCategory": last_r.get("reachableApisByCategory", {}),
        }

    return {
        "generated": datetime.now().isoformat(),
        "commitsAnalyzed": len(timeline),
        "dateRange": {"from": first_date, "to": last_date},
        "modules": modules,
        "moduleSummaries": module_summaries,
        "timeline": [
            {
                "sha": c["sha8"],
                "date": c["date"],
                "message": c["message"],
                "changedModules": c["changedModules"],
                "reachability": c["reachability"],
                "deltas": c["deltas"],
            }
            for c in timeline
        ],
    }


def generate_html(timeline, modules):
    labels = [f"{c['sha8']} ({c['date']})" for c in timeline]
    labels_js = json.dumps(labels)

    charts_html = []
    charts_js = []

    for mod in modules:
        mod_id = mod.replace(".", "root").replace("/", "_").replace("-", "_")

        # Reachable APIs by category (stacked area)
        api_datasets = []
        for cat in CATEGORIES:
            values = []
            for c in timeline:
                m = c["reachability"].get(mod, {})
                by_cat = m.get("reachableApisByCategory", {})
                values.append(by_cat.get(cat, 0))
            if any(v > 0 for v in values):
                col = CAT_COLORS.get(cat, CAT_COLORS["OTHER"])
                api_datasets.append({
                    "label": cat,
                    "data": values,
                    "borderColor": col["line"],
                    "backgroundColor": col["bg"],
                    "fill": True,
                    "tension": 0.3,
                })

        # Total reachable APIs
        total_apis = []
        for c in timeline:
            m = c["reachability"].get(mod, {})
            total_apis.append(m.get("reachableApis", 0))

        # Reachable deps
        total_deps = []
        for c in timeline:
            m = c["reachability"].get(mod, {})
            total_deps.append(m.get("reachableDeps", 0))

        # Top deps over time
        all_deps = {}
        for c in timeline:
            m = c["reachability"].get(mod, {})
            for dep, count in m.get("depsDetail", {}).items():
                all_deps[dep] = all_deps.get(dep, 0) + count
        top_deps = sorted(all_deps.items(), key=lambda x: -x[1])[:15]
        top_dep_names = [d[0] for d in top_deps]

        dep_table_data = []
        for dep in top_dep_names:
            row = []
            for c in timeline:
                m = c["reachability"].get(mod, {})
                row.append(m.get("depsDetail", {}).get(dep, 0))
            dep_table_data.append({"dep": dep, "values": row})

        # Deltas table
        delta_rows = []
        for c in timeline:
            if c["deltas"] and mod in c["deltas"]:
                d = c["deltas"][mod]
                delta_rows.append({
                    "sha": c["sha8"],
                    "date": c["date"],
                    "message": c["message"],
                    "apisDelta": d["apisDelta"],
                    "depsDelta": d["depsDelta"],
                    "categoryDeltas": d["categoryDeltas"],
                    "addedDeps": d["addedDeps"],
                    "removedDeps": d["removedDeps"],
                    "changedDeps": d["changedDeps"],
                })

        mod_label = mod if mod != "." else "(root)"

        charts_html.append(f"""
        <div class="module-section">
            <h2>{mod_label}</h2>
            <div class="chart-row">
                <div class="chart-container">
                    <h3>Reachable Sensitive APIs by Category</h3>
                    <canvas id="apis_{mod_id}"></canvas>
                </div>
                <div class="chart-container">
                    <h3>Reachable Deps / Total APIs</h3>
                    <canvas id="summary_{mod_id}"></canvas>
                </div>
            </div>
            <div class="table-container">
                <h3>Top Dependencies by Reachable Sensitive APIs</h3>
                <div id="deptable_{mod_id}" class="dep-table-wrap"></div>
            </div>
            <div class="table-container">
                <h3>Commits with Changes</h3>
                <div id="deltas_{mod_id}" class="delta-table-wrap"></div>
            </div>
        </div>
        """)

        charts_js.append(f"""
        // --- {mod_label} ---
        new Chart(document.getElementById('apis_{mod_id}'), {{
            type: 'line',
            data: {{ labels: {labels_js}, datasets: {json.dumps(api_datasets)} }},
            options: {{
                responsive: true,
                plugins: {{ legend: {{ position: 'bottom' }} }},
                scales: {{
                    x: {{ ticks: {{ maxRotation: 45, autoSkip: true, maxTicksLimit: 20 }} }},
                    y: {{ beginAtZero: true, title: {{ display: true, text: 'API count' }} }}
                }}
            }}
        }});

        new Chart(document.getElementById('summary_{mod_id}'), {{
            type: 'line',
            data: {{
                labels: {labels_js},
                datasets: [
                    {{
                        label: 'Total reachable APIs',
                        data: {json.dumps(total_apis)},
                        borderColor: '#2d6a4f',
                        backgroundColor: 'rgba(45,106,79,0.1)',
                        fill: true, tension: 0.3, yAxisID: 'y'
                    }},
                    {{
                        label: 'Deps with reachable APIs',
                        data: {json.dumps(total_deps)},
                        borderColor: '#6c4ab6',
                        backgroundColor: 'rgba(108,74,182,0.1)',
                        fill: true, tension: 0.3, yAxisID: 'y1'
                    }}
                ]
            }},
            options: {{
                responsive: true,
                plugins: {{ legend: {{ position: 'bottom' }} }},
                scales: {{
                    x: {{ ticks: {{ maxRotation: 45, autoSkip: true, maxTicksLimit: 20 }} }},
                    y: {{ beginAtZero: true, position: 'left', title: {{ display: true, text: 'APIs' }} }},
                    y1: {{ beginAtZero: true, position: 'right', grid: {{ drawOnChartArea: false }},
                           title: {{ display: true, text: 'Deps' }} }}
                }}
            }}
        }});

        // dep heatmap table
        (function() {{
            const deps = {json.dumps(dep_table_data)};
            const labels = {labels_js};
            if (deps.length === 0) return;
            let html = '<table><thead><tr><th class="dep-name">Dependency</th>';
            labels.forEach(l => html += '<th class="commit-col">' + l.split(' ')[0] + '</th>');
            html += '</tr></thead><tbody>';
            const maxVal = Math.max(...deps.flatMap(d => d.values), 1);
            deps.forEach(d => {{
                html += '<tr><td class="dep-name">' + d.dep + '</td>';
                d.values.forEach(v => {{
                    const intensity = v / maxVal;
                    const bg = v === 0 ? 'transparent'
                        : 'rgba(217,74,107,' + (0.15 + intensity * 0.65).toFixed(2) + ')';
                    html += '<td class="commit-col" style="background:' + bg + '">'
                        + (v > 0 ? v : '') + '</td>';
                }});
                html += '</tr>';
            }});
            html += '</tbody></table>';
            document.getElementById('deptable_{mod_id}').innerHTML = html;
        }})();

        // deltas table
        (function() {{
            const rows = {json.dumps(delta_rows)};
            if (rows.length === 0) {{
                document.getElementById('deltas_{mod_id}').innerHTML = '<p class="no-data">No changes detected between consecutive commits.</p>';
                return;
            }}
            let html = '<table><thead><tr><th>Commit</th><th>Date</th><th>APIs Δ</th><th>Deps Δ</th><th>Category Δ</th><th>Details</th></tr></thead><tbody>';
            rows.forEach(r => {{
                const apiClass = r.apisDelta > 0 ? 'delta-up' : r.apisDelta < 0 ? 'delta-down' : '';
                const depClass = r.depsDelta > 0 ? 'delta-up' : r.depsDelta < 0 ? 'delta-down' : '';
                const apiSign = r.apisDelta > 0 ? '+' : '';
                const depSign = r.depsDelta > 0 ? '+' : '';

                let catParts = [];
                for (const [cat, val] of Object.entries(r.categoryDeltas || {{}})) {{
                    const s = val > 0 ? '+' : '';
                    catParts.push(cat + ': ' + s + val);
                }}

                let details = [];
                r.addedDeps.forEach(d => details.push('<span class="delta-up">+ ' + d.dep.split(':').slice(0,2).join(':') + ' (' + d.apis + ' APIs)</span>'));
                r.removedDeps.forEach(d => details.push('<span class="delta-down">− ' + d.dep.split(':').slice(0,2).join(':') + ' (' + d.apis + ' APIs)</span>'));
                r.changedDeps.forEach(d => details.push('<span class="delta-change">↔ ' + d.dep.split(':').slice(0,2).join(':') + ' ' + d.from + '→' + d.to + '</span>'));

                html += '<tr>';
                html += '<td class="mono">' + r.sha + '</td>';
                html += '<td>' + r.date + '</td>';
                html += '<td class="' + apiClass + '">' + apiSign + r.apisDelta + '</td>';
                html += '<td class="' + depClass + '">' + depSign + r.depsDelta + '</td>';
                html += '<td class="cat-delta">' + (catParts.join(', ') || '—') + '</td>';
                html += '<td class="details-cell">' + (details.join('<br>') || '—') + '</td>';
                html += '</tr>';
            }});
            html += '</tbody></table>';
            document.getElementById('deltas_{mod_id}').innerHTML = html;
        }})();
        """)

    return _wrap_html("\n".join(charts_html), "\n".join(charts_js), len(timeline))


def _wrap_html(body, scripts, commit_count):
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sensitive API Reachability Timeline</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.7/chart.umd.min.js"></script>
<style>
:root {{
    --bg: #fafafa; --fg: #1a1a1a; --card: #fff; --border: #e0e0e0;
    --muted: #666; --green: #2d6a4f; --red: #c0392b; --blue: #2980b9;
}}
@media (prefers-color-scheme: dark) {{
    :root:not([data-theme="light"]) {{
        --bg: #181a1b; --fg: #d4d4d4; --card: #232526; --border: #3a3a3a;
        --muted: #999; --green: #52b788; --red: #e74c3c; --blue: #5dade2;
    }}
}}
:root[data-theme="dark"] {{
    --bg: #181a1b; --fg: #d4d4d4; --card: #232526; --border: #3a3a3a;
    --muted: #999; --green: #52b788; --red: #e74c3c; --blue: #5dade2;
}}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: var(--bg); color: var(--fg);
    padding: 24px 16px; max-width: 1400px; margin: 0 auto;
}}
h1 {{ margin-bottom: 4px; font-size: 1.5rem; }}
.subtitle {{ color: var(--muted); margin-bottom: 32px; font-size: 0.9rem; }}
.module-section {{
    background: var(--card); border: 1px solid var(--border);
    border-radius: 8px; padding: 24px; margin-bottom: 32px;
}}
.module-section h2 {{ font-size: 1.2rem; margin-bottom: 16px; }}
.module-section h3 {{ font-size: 0.95rem; color: var(--muted); margin-bottom: 8px; margin-top: 16px; }}
.chart-row {{ display: flex; gap: 24px; flex-wrap: wrap; margin-bottom: 24px; }}
.chart-container {{ flex: 1; min-width: 400px; }}
canvas {{ max-height: 320px; }}
.table-container {{ overflow-x: auto; margin-top: 16px; }}
.dep-table-wrap table, .delta-table-wrap table {{
    border-collapse: collapse; width: 100%; font-size: 0.82rem;
}}
.dep-table-wrap th, .dep-table-wrap td,
.delta-table-wrap th, .delta-table-wrap td {{
    border: 1px solid var(--border); padding: 4px 6px; text-align: center;
}}
.dep-table-wrap th, .delta-table-wrap th {{
    background: var(--bg); position: sticky; top: 0;
}}
.dep-name {{ text-align: left !important; white-space: nowrap; font-family: monospace; font-size: 0.78rem; }}
.commit-col {{ min-width: 44px; font-size: 0.78rem; }}
.mono {{ font-family: monospace; font-size: 0.82rem; }}
.delta-up {{ color: var(--red); font-weight: 600; }}
.delta-down {{ color: var(--green); font-weight: 600; }}
.delta-change {{ color: var(--blue); }}
.cat-delta {{ font-size: 0.78rem; white-space: nowrap; }}
.details-cell {{ text-align: left !important; font-size: 0.78rem; line-height: 1.5; }}
.no-data {{ color: var(--muted); font-style: italic; padding: 8px 0; }}
</style>
</head>
<body>
<h1>Sensitive API Reachability Timeline</h1>
<p class="subtitle">{commit_count} commits analyzed &middot; generated {datetime.now().strftime("%Y-%m-%d %H:%M")}</p>
{body}
<script>
Chart.defaults.color = getComputedStyle(document.documentElement).getPropertyValue('--fg').trim() || '#1a1a1a';
Chart.defaults.borderColor = getComputedStyle(document.documentElement).getPropertyValue('--border').trim() || '#e0e0e0';
{scripts}
</script>
</body>
</html>"""


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 generate_timeline_report.py <analysis_results.json | history_dir> [output_dir]",
              file=sys.stderr)
        sys.exit(1)

    data, src_dir = load_results(sys.argv[1])
    project_name = src_dir.name

    out_dir = Path(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_OUTPUT / project_name
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"Project: {project_name}")
    timeline = build_timeline(data)
    if not timeline:
        print("No successful commits with reachability data found.", file=sys.stderr)
        sys.exit(1)

    modules = all_modules(timeline)
    print(f"{len(timeline)} commits, {len(modules)} module(s): {modules}")

    compute_deltas(timeline, modules)

    # JSON report
    json_report = build_json_report(timeline, modules)
    json_path = out_dir / "timeline_data.json"
    with open(json_path, "w") as f:
        json.dump(json_report, f, indent=2)
    print(f"JSON: {json_path}")

    # HTML report
    html = generate_html(timeline, modules)
    html_path = out_dir / "timeline_report.html"
    html_path.write_text(html, encoding="utf-8")
    print(f"HTML: {html_path}")


if __name__ == "__main__":
    main()
