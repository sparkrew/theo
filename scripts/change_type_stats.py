#!/usr/bin/env python3
"""
Count and summarize dependency change types across a project's history.

For every commit with changes, each dependency event is classified as:
  - dep_removed:      a dependency disappeared entirely (no version of it remains)
  - dep_added:        a new dependency appeared (no prior version existed)
  - dep_updated:      same groupId:artifactId, but version changed (bump or downgrade)
  - client_code_change: same groupId:artifactId:version, but reachable API count changed
                        (client code started or stopped calling sensitive APIs on it)

Stats per project (computed per-dep, per-commit):
  - total, mean, median, max, min of each case across commits

Usage:
    python3 change_type_stats.py <timeline_data.json> [--output <output_dir>] [--project <name>]
"""

import argparse
import json
import statistics
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path


def load_json(path):
    with open(path) as f:
        return json.load(f)


def dep_ga(dep_key):
    """groupId:artifactId from groupId:artifactId:version."""
    parts = dep_key.split(":")
    return ":".join(parts[:2]) if len(parts) >= 2 else dep_key


def classify_commit(deltas):
    """Classify each dependency event in a commit's deltas.

    Returns a dict of lists:
      {case_name: [{"dep": ..., "apis": ..., ...}, ...]}
    """
    if not deltas:
        return None

    all_added = []    # (ga, full_key, apis)
    all_removed = []  # (ga, full_key, apis)
    all_changed = []  # (full_key, from, to)

    for mod, d in deltas.items():
        for ad in d.get("addedDeps", []):
            all_added.append((dep_ga(ad["dep"]), ad["dep"], ad.get("apis", 0)))
        for rd in d.get("removedDeps", []):
            all_removed.append((dep_ga(rd["dep"]), rd["dep"], rd.get("apis", 0)))
        for cd in d.get("changedDeps", []):
            all_changed.append((cd["dep"], cd.get("from", 0), cd.get("to", 0)))

    added_gas = {ga for ga, _, _ in all_added}
    removed_gas = {ga for ga, _, _ in all_removed}

    updated_gas = added_gas & removed_gas
    pure_added_gas = added_gas - updated_gas
    pure_removed_gas = removed_gas - updated_gas

    events = {
        "dep_removed": [],
        "dep_added": [],
        "dep_updated": [],
        "client_code_change": [],
    }

    for ga, full_key, apis in all_removed:
        if ga in updated_gas:
            pass  # handled below
        else:
            events["dep_removed"].append({
                "dep": full_key, "ga": ga, "apisLost": apis,
            })

    for ga, full_key, apis in all_added:
        if ga in updated_gas:
            pass  # handled below
        else:
            events["dep_added"].append({
                "dep": full_key, "ga": ga, "apisGained": apis,
            })

    for ga in updated_gas:
        old_keys = [(k, a) for g, k, a in all_removed if g == ga]
        new_keys = [(k, a) for g, k, a in all_added if g == ga]
        old_key, old_apis = old_keys[0] if old_keys else ("?", 0)
        new_key, new_apis = new_keys[0] if new_keys else ("?", 0)
        events["dep_updated"].append({
            "ga": ga,
            "oldDep": old_key, "newDep": new_key,
            "apisBefore": old_apis, "apisAfter": new_apis,
            "apisDelta": new_apis - old_apis,
        })

    for full_key, frm, to in all_changed:
        events["client_code_change"].append({
            "dep": full_key, "ga": dep_ga(full_key),
            "apisBefore": frm, "apisAfter": to,
            "apisDelta": to - frm,
        })

    return events


CASES = ["dep_removed", "dep_added", "dep_updated", "client_code_change"]


def compute_stats(per_commit_counts):
    """Given a list of per-commit count values, return summary stats."""
    if not per_commit_counts:
        return {"total": 0, "mean": 0, "median": 0, "max": 0, "min": 0,
                "commitCount": 0}
    total = sum(per_commit_counts)
    return {
        "total": total,
        "mean": round(statistics.mean(per_commit_counts), 2),
        "median": round(statistics.median(per_commit_counts), 2),
        "max": max(per_commit_counts),
        "min": min(per_commit_counts),
        "commitCount": len(per_commit_counts),
    }


def main():
    parser = argparse.ArgumentParser(
        description="Count dependency change types across a project's history.")
    parser.add_argument("timeline", help="Path to timeline_data.json")
    parser.add_argument("--output", help="Output directory (default: same as timeline)")
    parser.add_argument("--project", help="Project name")
    args = parser.parse_args()

    timeline_path = Path(args.timeline)
    if not timeline_path.exists():
        print(f"Not found: {timeline_path}", file=sys.stderr)
        sys.exit(1)

    data = load_json(timeline_path)
    timeline = data.get("timeline", [])
    project = args.project or timeline_path.parent.name

    # Classify every commit
    commit_records = []
    # per-commit counts for each case (only commits that have any change)
    counts_by_case = {c: [] for c in CASES}
    # also track per-commit counts including zeros for all commits with deltas
    all_commit_counts = {c: [] for c in CASES}
    # track per-dep aggregates
    dep_case_counts = defaultdict(lambda: defaultdict(int))

    for entry in timeline:
        deltas = entry.get("deltas")
        if not deltas:
            continue

        events = classify_commit(deltas)
        if events is None:
            continue

        commit_count = {c: len(events[c]) for c in CASES}
        has_any = any(commit_count[c] > 0 for c in CASES)

        if has_any:
            sha = entry.get("sha", "?")
            commit_records.append({
                "sha": sha,
                "date": entry.get("date", ""),
                "message": entry.get("message", "")[:100],
                "counts": commit_count,
                "events": events,
            })

        for c in CASES:
            all_commit_counts[c].append(commit_count[c])
            if commit_count[c] > 0:
                counts_by_case[c].append(commit_count[c])

            for ev in events[c]:
                ga = ev.get("ga", "?")
                dep_case_counts[ga][c] += 1

    # Overall stats per case
    case_stats = {}
    for c in CASES:
        case_stats[c] = {
            "acrossAllCommits": compute_stats(all_commit_counts[c]),
            "acrossCommitsWithThisCase": compute_stats(counts_by_case[c]),
        }

    # Top deps by total events
    dep_summaries = []
    for ga, case_map in dep_case_counts.items():
        total = sum(case_map.values())
        dep_summaries.append({
            "dep": ga,
            "total": total,
            **{c: case_map.get(c, 0) for c in CASES},
        })
    dep_summaries.sort(key=lambda d: -d["total"])

    # Grand totals
    grand_totals = {c: sum(all_commit_counts[c]) for c in CASES}
    grand_totals["all"] = sum(grand_totals.values())

    report = {
        "metadata": {
            "project": project,
            "generated": datetime.now().isoformat(),
            "timelineFile": str(timeline_path),
            "totalCommitsInTimeline": len(timeline),
            "commitsWithChanges": len(commit_records),
        },
        "grandTotals": grand_totals,
        "caseStats": case_stats,
        "perCommit": [
            {
                "sha": cr["sha"],
                "date": cr["date"],
                "message": cr["message"],
                "counts": cr["counts"],
            }
            for cr in commit_records
        ],
        "perDependency": dep_summaries[:50],
    }

    out_dir = Path(args.output) if args.output else timeline_path.parent
    out_dir.mkdir(parents=True, exist_ok=True)

    json_path = out_dir / "change_type_stats.json"
    with open(json_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"JSON: {json_path}")

    html_path = out_dir / "change_type_stats.html"
    html_path.write_text(generate_html(report), encoding="utf-8")
    print(f"HTML: {html_path}")

    # Print summary
    print(f"\nProject: {project}")
    print(f"Commits analyzed: {len(timeline)}, with changes: {len(commit_records)}")
    print(f"\nGrand totals:")
    for c in CASES:
        print(f"  {c:25s}: {grand_totals[c]:5d}")
    print(f"  {'total':25s}: {grand_totals['all']:5d}")
    print(f"\nPer-commit stats (across ALL commits with deltas):")
    for c in CASES:
        s = case_stats[c]["acrossAllCommits"]
        print(f"  {c:25s}:  mean={s['mean']:.2f}  median={s['median']:.2f}"
              f"  max={s['max']}  min={s['min']}")


def generate_html(report):
    meta = report["metadata"]
    totals = report["grandTotals"]
    stats = report["caseStats"]
    commits = report["perCommit"]
    deps = report["perDependency"]

    case_labels = {
        "dep_removed": "Dep Removed",
        "dep_added": "Dep Added",
        "dep_updated": "Dep Updated (version)",
        "client_code_change": "Client Code Change",
    }
    cases = list(case_labels.keys())

    # Cards
    cards = []
    colors = {
        "dep_removed": "--green", "dep_added": "--red",
        "dep_updated": "--blue", "client_code_change": "--orange",
    }
    for c in cases:
        col = colors[c]
        cards.append(f"""
        <div class="card">
            <div class="card-label">{case_labels[c]}</div>
            <div class="card-value" style="color:var({col})">{totals[c]}</div>
            <div class="card-sub">
                mean {stats[c]['acrossAllCommits']['mean']}/commit
                &middot; median {stats[c]['acrossAllCommits']['median']}
                &middot; max {stats[c]['acrossAllCommits']['max']}
            </div>
        </div>""")

    # Stats table
    stat_rows = []
    for c in cases:
        s_all = stats[c]["acrossAllCommits"]
        s_pos = stats[c]["acrossCommitsWithThisCase"]
        stat_rows.append(f"""
        <tr>
            <td style="font-weight:600">{case_labels[c]}</td>
            <td>{s_all['total']}</td>
            <td>{s_all['mean']}</td><td>{s_all['median']}</td>
            <td>{s_all['max']}</td><td>{s_all['min']}</td>
            <td>{s_all['commitCount']}</td>
            <td class="sep">{s_pos['mean']}</td><td>{s_pos['median']}</td>
            <td>{s_pos['max']}</td><td>{s_pos['min']}</td>
            <td>{s_pos['commitCount']}</td>
        </tr>""")

    # Per-commit table
    commit_rows = []
    for cr in commits:
        vals = [cr["counts"].get(c, 0) for c in cases]
        total = sum(vals)
        cells = "".join(f"<td>{v if v else ''}</td>" for v in vals)
        commit_rows.append(
            f"<tr><td class='mono'>{_esc(cr['sha'])}</td>"
            f"<td>{_esc(cr['date'])}</td>"
            f"<td>{_esc(cr['message'][:60])}</td>"
            f"{cells}<td style='font-weight:600'>{total}</td></tr>")

    # Per-dep table
    dep_rows = []
    for d in deps[:50]:
        cells = "".join(f"<td>{d.get(c, 0) or ''}</td>" for c in cases)
        dep_rows.append(
            f"<tr><td class='mono'>{_esc(d['dep'])}</td>"
            f"{cells}<td style='font-weight:600'>{d['total']}</td></tr>")

    # Chart data
    chart_labels = json.dumps([cr["sha"] for cr in commits])
    chart_datasets = []
    ds_colors = {
        "dep_removed": {"border": "#2d6a4f", "bg": "rgba(45,106,79,0.3)"},
        "dep_added": {"border": "#c0392b", "bg": "rgba(192,57,43,0.3)"},
        "dep_updated": {"border": "#2980b9", "bg": "rgba(41,128,185,0.3)"},
        "client_code_change": {"border": "#e07a3a", "bg": "rgba(224,122,58,0.3)"},
    }
    for c in cases:
        vals = [cr["counts"].get(c, 0) for cr in commits]
        col = ds_colors[c]
        chart_datasets.append({
            "label": case_labels[c], "data": vals,
            "borderColor": col["border"], "backgroundColor": col["bg"],
            "borderWidth": 1.5, "fill": True,
        })

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Change Type Stats — {_esc(meta.get('project', ''))}</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.4/chart.umd.min.js"></script>
<style>
:root {{
    --bg: #fafafa; --fg: #1a1a1a; --card: #fff; --border: #e0e0e0;
    --muted: #666; --green: #2d6a4f; --red: #c0392b; --blue: #2980b9; --orange: #e07a3a;
}}
@media (prefers-color-scheme: dark) {{
    :root:not([data-theme="light"]) {{
        --bg: #181a1b; --fg: #d4d4d4; --card: #232526; --border: #3a3a3a;
        --muted: #999; --green: #52b788; --red: #e74c3c; --blue: #5dade2; --orange: #e8945a;
    }}
}}
:root[data-theme="dark"] {{
    --bg: #181a1b; --fg: #d4d4d4; --card: #232526; --border: #3a3a3a;
    --muted: #999; --green: #52b788; --red: #e74c3c; --blue: #5dade2; --orange: #e8945a;
}}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: var(--bg); color: var(--fg);
    padding: 24px 16px; max-width: 1400px; margin: 0 auto;
}}
h1 {{ font-size: 1.5rem; margin-bottom: 4px; }}
.subtitle {{ color: var(--muted); font-size: 0.9rem; margin-bottom: 24px; }}
.cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 12px; margin-bottom: 24px; }}
.card {{
    background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 16px;
}}
.card-label {{ font-size: 0.78rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.5px; }}
.card-value {{ font-size: 1.8rem; font-weight: 700; margin-top: 4px; }}
.card-sub {{ font-size: 0.78rem; color: var(--muted); margin-top: 4px; }}
.section {{
    background: var(--card); border: 1px solid var(--border); border-radius: 8px;
    padding: 24px; margin-bottom: 24px;
}}
.section h2 {{ font-size: 1.1rem; margin-bottom: 16px; }}
table {{ border-collapse: collapse; width: 100%; font-size: 0.85rem; }}
th, td {{ border: 1px solid var(--border); padding: 6px 10px; text-align: center; }}
th {{ background: var(--bg); font-weight: 600; position: sticky; top: 0; }}
td:first-child {{ text-align: left; }}
.mono {{ font-family: monospace; font-size: 0.82rem; }}
.sep {{ border-left: 3px solid var(--border); }}
.chart-container {{ height: 350px; margin: 16px 0; }}
</style>
</head>
<body>

<h1>Change Type Statistics — {_esc(meta.get('project', ''))}</h1>
<p class="subtitle">
    {meta.get('commitsWithChanges', 0)} commits with changes out of {meta.get('totalCommitsInTimeline', 0)}
    &middot; {totals.get('all', 0)} total dependency change events
    &middot; generated {meta.get('generated', '')[:16]}
</p>

<div class="cards">
    {''.join(cards)}
</div>

<div class="section">
    <h2>Summary Statistics</h2>
    <p style="font-size:0.82rem;color:var(--muted);margin-bottom:12px">
        "Across all commits" includes commits with zero events of that type.
        "Across commits with case" only counts commits where at least one event of that type occurred.
    </p>
    <div style="overflow-x:auto">
    <table>
        <thead>
        <tr>
            <th rowspan="2">Case</th><th rowspan="2">Total</th>
            <th colspan="5">Across all commits with deltas</th>
            <th colspan="5" class="sep">Across commits with this case</th>
        </tr>
        <tr>
            <th>Mean</th><th>Median</th><th>Max</th><th>Min</th><th>N commits</th>
            <th class="sep">Mean</th><th>Median</th><th>Max</th><th>Min</th><th>N commits</th>
        </tr>
        </thead>
        <tbody>
            {''.join(stat_rows)}
        </tbody>
    </table>
    </div>
</div>

<div class="section">
    <h2>Change Types Over Time</h2>
    <div class="chart-container">
        <canvas id="timeChart"></canvas>
    </div>
</div>

<div class="section">
    <h2>Per-Commit Breakdown</h2>
    <div style="overflow-x:auto">
    <table>
        <thead><tr>
            <th>Commit</th><th>Date</th><th>Message</th>
            <th style="color:var(--green)">Removed</th>
            <th style="color:var(--red)">Added</th>
            <th style="color:var(--blue)">Updated</th>
            <th style="color:var(--orange)">Client</th>
            <th>Total</th>
        </tr></thead>
        <tbody>{''.join(commit_rows)}</tbody>
    </table>
    </div>
</div>

<div class="section">
    <h2>Per-Dependency Breakdown (top 50)</h2>
    <div style="overflow-x:auto">
    <table>
        <thead><tr>
            <th>Dependency (groupId:artifactId)</th>
            <th style="color:var(--green)">Removed</th>
            <th style="color:var(--red)">Added</th>
            <th style="color:var(--blue)">Updated</th>
            <th style="color:var(--orange)">Client</th>
            <th>Total</th>
        </tr></thead>
        <tbody>{''.join(dep_rows)}</tbody>
    </table>
    </div>
</div>

<script>
Chart.defaults.color = getComputedStyle(document.documentElement).getPropertyValue('--fg').trim() || '#1a1a1a';
Chart.defaults.borderColor = getComputedStyle(document.documentElement).getPropertyValue('--border').trim() || '#e0e0e0';

new Chart(document.getElementById('timeChart'), {{
    type: 'bar',
    data: {{
        labels: {chart_labels},
        datasets: {json.dumps(chart_datasets)}
    }},
    options: {{
        responsive: true, maintainAspectRatio: false,
        plugins: {{ legend: {{ position: 'bottom' }} }},
        scales: {{
            x: {{ stacked: true, ticks: {{ maxRotation: 45, autoSkip: true, maxTicksLimit: 30 }} }},
            y: {{ stacked: true, beginAtZero: true, title: {{ display: true, text: 'Events' }} }}
        }}
    }}
}});
</script>
</body>
</html>"""


def _esc(s):
    return (str(s).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


if __name__ == "__main__":
    main()
