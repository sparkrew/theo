#!/usr/bin/env python3
"""
Analyze sudden large changes in dependency reachability across a project's history.

Reads timeline_data.json (from generate_timeline_report.py) and optionally
analysis_results.json and snapshot files to produce a detailed report of the
largest reachability changes, including per-dependency category breakdowns,
change classifications, and GitHub links.

Usage:
    python3 analyze_big_changes.py <timeline_data.json>
        [--results <analysis_results.json>]
        [--snapshots <snapshots_dir>]
        [--repo-url <github_repo_url>]
        [--project <project_name>]
        [--top <N>]
        [--offset <N>]
        [--output <output_dir>]

Usage examples:
  # Basic — top 10 biggest changes
  python3 scripts/analyze_big_changes.py /path/to/timeline_data.json \
  # Basic — top 10 biggest changes
  python3 scripts/analyze_big_changes.py /path/to/timeline_data.json \
      --repo-url https://github.com/org/repo

  # With richer per-dep category data from snapshots
  python3 scripts/analyze_big_changes.py /path/to/timeline_data.json \
      --results /path/to/analysis_results.json \
      --repo-url https://github.com/org/repo

  # With richer per-dep category data from snapshots
  python3 scripts/analyze_big_changes.py /path/to/timeline_data.json \
      --results /path/to/analysis_results.json \
      --snapshots /path/to/theo-history-snapshots \
      --repo-url https://github.com/org/repo


  # Next 10 (pagination)
  python3 scripts/analyze_big_changes.py /path/to/timeline_data.json \
      --repo-url https://github.com/org/repo --offset 10

  # Custom output dir and count
  python3 scripts/analyze_big_changes.py /path/to/timeline_data.json \
      --top 20 --output /path/to/output
"""

import argparse
import json
import re
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

CATEGORIES = ["FILESYSTEM", "NETWORK", "PROCESS", "OTHER"]


def load_json(path):
    with open(path) as f:
        return json.load(f)


def load_snapshots_index(snapshots_dir):
    """Build index: (groupId__artifactId, label) -> path."""
    idx = {}
    if not snapshots_dir or not Path(snapshots_dir).exists():
        return idx
    for artifact_dir in Path(snapshots_dir).iterdir():
        if not artifact_dir.is_dir():
            continue
        for f in artifact_dir.glob("*.json"):
            parts = f.stem.split("__", 1)
            if len(parts) == 2:
                idx[(artifact_dir.name, parts[1])] = f
    return idx


def load_snapshot_api_detail(snap_path):
    """Return {dep_key: {category: count}} from a snapshot file."""
    try:
        with open(snap_path) as f:
            snap = json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}
    result = defaultdict(lambda: defaultdict(int))
    for entry in snap.get("reachableApis", []):
        dep_key = (f"{entry.get('depGroupId', '')}:"
                   f"{entry.get('depArtifactId', '')}:"
                   f"{entry.get('depVersion', '')}")
        cat = entry.get("category", "OTHER")
        result[dep_key][cat] += 1
    return {k: dict(v) for k, v in result.items()}



# Per-dep category from analysis_results.json snapshots on the server
def build_commit_dep_categories(results_data, snapshots_dir):
    """Build {sha8: {module: {dep: {cat: count}}}} from snapshot files."""
    snap_idx = load_snapshots_index(snapshots_dir)
    commit_dep_cats = {}
    if not snap_idx:
        return commit_dep_cats
    for c in results_data.get("commits", []):
        sha8 = c["sha"][:8]
        commit_dep_cats[sha8] = {}
        for mod in c.get("analyzedModules", []):
            for key, snap_path in snap_idx.items():
                if key[1] == sha8:
                    commit_dep_cats[sha8][mod] = load_snapshot_api_detail(snap_path)
                    break
    return commit_dep_cats



# Core analysis
def compute_total_delta(deltas):
    """Sum apisDelta across all modules for a commit's deltas dict."""
    if not deltas:
        return 0
    return sum(d.get("apisDelta", 0) for d in deltas.values())


def compute_total_deps_delta(deltas):
    if not deltas:
        return 0
    return sum(d.get("depsDelta", 0) for d in deltas.values())


def has_any_change(deltas):
    """True if at least one API was added or removed across all modules."""
    if not deltas:
        return False
    for d in deltas.values():
        added = d.get("addedDeps", [])
        removed = d.get("removedDeps", [])
        changed = d.get("changedDeps", [])
        if added or removed or changed:
            return True
        if d.get("apisDelta", 0) != 0:
            return True
    return False


def rank_changes(timeline):
    """Return timeline entries ranked by abs(total apisDelta), filtered to
    entries with at least one API add/remove."""
    ranked = []
    for entry in timeline:
        deltas = entry.get("deltas")
        if not has_any_change(deltas):
            continue
        total = compute_total_delta(deltas)
        if total == 0:
            continue
        ranked.append((abs(total), entry))
    ranked.sort(key=lambda x: -x[0])
    return ranked


def extract_pr_number(message):
    """Try to extract PR number from commit message like 'Fix foo (#1234)'."""
    m = re.search(r'\(#(\d+)\)', message or "")
    return int(m.group(1)) if m else None


def dep_ga(dep_key):
    """Extract groupId:artifactId from groupId:artifactId:version."""
    parts = dep_key.split(":")
    return ":".join(parts[:2]) if len(parts) >= 2 else dep_key


def dep_version(dep_key):
    parts = dep_key.split(":")
    return parts[2] if len(parts) >= 3 else ""


def find_possible_replacements(added_deps, removed_deps, cur_dep_cats, prev_dep_cats):
    """Heuristic: pair removed/added deps that share the same dominant category."""
    replacements = []

    def dominant_categories(dep_key, dep_cats):
        cats = dep_cats.get(dep_key, {})
        if not cats:
            return set()
        max_val = max(cats.values())
        if max_val == 0:
            return set()
        return {c for c, v in cats.items() if v >= max_val * 0.3}

    for rd in removed_deps:
        rd_cats = dominant_categories(rd["dep"], prev_dep_cats)
        if not rd_cats:
            continue
        for ad in added_deps:
            if dep_ga(ad["dep"]) == dep_ga(rd["dep"]):
                continue
            ad_cats = dominant_categories(ad["dep"], cur_dep_cats)
            shared = rd_cats & ad_cats
            if shared:
                size_ratio = min(ad["apis"], rd["apis"]) / max(ad["apis"], rd["apis"], 1)
                confidence = "medium" if size_ratio > 0.3 else "low"
                replacements.append({
                    "removed": rd["dep"],
                    "removedApis": rd["apis"],
                    "added": ad["dep"],
                    "addedApis": ad["apis"],
                    "sharedCategories": sorted(shared),
                    "confidence": confidence,
                })
    return replacements


def classify_dep_change(dep_entry, change_type, prev_dep_cats, cur_dep_cats):
    """Build a detailed dependency change record."""
    dep = dep_entry["dep"]
    record = {
        "dep": dep,
        "groupArtifact": dep_ga(dep),
        "version": dep_version(dep),
        "changeType": change_type,
    }

    if change_type == "added":
        record["apisInPrevious"] = 0
        record["apisInCurrent"] = dep_entry.get("apis", 0)
        record["apisDelta"] = dep_entry.get("apis", 0)
        cat_contrib = cur_dep_cats.get(dep, {})
    elif change_type == "removed":
        record["apisInPrevious"] = dep_entry.get("apis", 0)
        record["apisInCurrent"] = 0
        record["apisDelta"] = -dep_entry.get("apis", 0)
        cat_contrib = {c: -v for c, v in prev_dep_cats.get(dep, {}).items()}
    else:  # changed
        record["apisInPrevious"] = dep_entry.get("from", 0)
        record["apisInCurrent"] = dep_entry.get("to", 0)
        record["apisDelta"] = dep_entry.get("to", 0) - dep_entry.get("from", 0)
        cur_cats = cur_dep_cats.get(dep, {})
        prev_cats = prev_dep_cats.get(dep, {})
        cat_contrib = {}
        for cat in set(list(cur_cats.keys()) + list(prev_cats.keys())):
            diff = cur_cats.get(cat, 0) - prev_cats.get(cat, 0)
            if diff != 0:
                cat_contrib[cat] = diff

    if cat_contrib:
        record["categoryContribution"] = {c: v for c, v in cat_contrib.items() if v != 0}
    else:
        record["categoryContribution"] = {}

    return record


def find_version_bumps(changed_deps, prev_reachability, cur_reachability):
    """Identify deps in changedDeps that are version bumps (same GA, different version)."""
    bumps = []
    prev_detail = prev_reachability.get("depsDetail", {})
    cur_detail = cur_reachability.get("depsDetail", {})

    for cd in changed_deps:
        dep = cd["dep"]
        ga = dep_ga(dep)
        cur_version = dep_version(dep)
        prev_version = None
        for pd in prev_detail:
            if dep_ga(pd) == ga and pd != dep:
                prev_version = dep_version(pd)
                break
        if prev_version and prev_version != cur_version:
            bumps.append({
                "dep": ga,
                "from": prev_version,
                "to": cur_version,
            })
    return bumps


def detect_version_bumps_from_add_remove(added_deps, removed_deps):
    """Detect version bumps that appear as removed + added (same GA, different version)."""
    bumps = []
    added_by_ga = {}
    for ad in added_deps:
        ga = dep_ga(ad["dep"])
        added_by_ga[ga] = ad

    for rd in removed_deps:
        ga = dep_ga(rd["dep"])
        if ga in added_by_ga:
            ad = added_by_ga[ga]
            old_ver = dep_version(rd["dep"])
            new_ver = dep_version(ad["dep"])
            if old_ver != new_ver:
                bumps.append({
                    "dep": ga,
                    "from": old_ver,
                    "to": new_ver,
                    "apisBefore": rd.get("apis", 0),
                    "apisAfter": ad.get("apis", 0),
                })
    return bumps


def analyze_single_change(entry, prev_entry, commit_dep_cats, repo_url):
    """Analyze a single big-change commit."""
    deltas = entry.get("deltas", {})
    sha = entry["sha"]
    message = entry.get("message", "")
    date = entry.get("date", "")

    total_apis_delta = compute_total_delta(deltas)
    total_deps_delta = compute_total_deps_delta(deltas)

    commit_url = f"{repo_url}/commit/{sha}" if repo_url else None
    pr_number = extract_pr_number(message)
    pr_url = f"{repo_url}/pull/{pr_number}" if repo_url and pr_number else None

    # Aggregate across all modules
    total_added_apis = 0
    total_removed_apis = 0
    all_added_deps = []
    all_removed_deps = []
    all_changed_deps = []
    category_breakdown = defaultdict(lambda: {"delta": 0, "added": 0, "removed": 0})

    for mod, d in deltas.items():
        for ad in d.get("addedDeps", []):
            total_added_apis += ad.get("apis", 0)
            all_added_deps.append(ad)
        for rd in d.get("removedDeps", []):
            total_removed_apis += rd.get("apis", 0)
            all_removed_deps.append(rd)
        all_changed_deps.extend(d.get("changedDeps", []))

        for cat, val in d.get("categoryDeltas", {}).items():
            category_breakdown[cat]["delta"] += val
            if val > 0:
                category_breakdown[cat]["added"] += val
            else:
                category_breakdown[cat]["removed"] += abs(val)

    # Per-dep category data (from snapshots if available)
    cur_dep_cats = {}
    prev_dep_cats = {}
    for mod in deltas:
        cur_cats = commit_dep_cats.get(sha, {}).get(mod, {})
        prev_sha = prev_entry["sha"] if prev_entry else None
        prev_cats = commit_dep_cats.get(prev_sha, {}).get(mod, {}) if prev_sha else {}
        cur_dep_cats.update(cur_cats)
        prev_dep_cats.update(prev_cats)

    # Dependency details
    dep_details = []
    for ad in all_added_deps:
        dep_details.append(classify_dep_change(ad, "added", prev_dep_cats, cur_dep_cats))
    for rd in all_removed_deps:
        dep_details.append(classify_dep_change(rd, "removed", prev_dep_cats, cur_dep_cats))
    for cd in all_changed_deps:
        dep_details.append(classify_dep_change(cd, "changed", prev_dep_cats, cur_dep_cats))
    dep_details.sort(key=lambda d: -abs(d.get("apisDelta", 0)))

    # Version bumps from add/remove pairs
    version_bumps_from_pairs = detect_version_bumps_from_add_remove(
        all_added_deps, all_removed_deps)

    # Possible replacements
    replacements = find_possible_replacements(
        all_added_deps, all_removed_deps, cur_dep_cats, prev_dep_cats)

    # Client code change detection
    client_code_only = (not all_added_deps and not all_removed_deps
                        and not all_changed_deps and total_apis_delta != 0)

    # Change classification
    classification = {
        "depsAdded": [ad["dep"] for ad in all_added_deps],
        "depsRemoved": [rd["dep"] for rd in all_removed_deps],
        "versionBumps": version_bumps_from_pairs,
        "depsChanged": [cd["dep"] for cd in all_changed_deps],
        "possibleReplacements": replacements,
        "clientCodeChangeOnly": client_code_only,
    }

    # Net direction
    if total_apis_delta > 0:
        direction = "increased"
    elif total_apis_delta < 0:
        direction = "decreased"
    else:
        direction = "unchanged"

    return {
        "sha": sha,
        "date": date,
        "commitMessage": message,
        "commitUrl": commit_url,
        "prNumber": pr_number,
        "prUrl": pr_url,
        "changedModules": entry.get("changedModules", []),
        "direction": direction,
        "summary": {
            "totalApisDelta": total_apis_delta,
            "totalAbsApisDelta": abs(total_apis_delta),
            "totalDepsDelta": total_deps_delta,
            "apisAdded": total_added_apis,
            "apisRemoved": total_removed_apis,
            "depsAdded": len(all_added_deps),
            "depsRemoved": len(all_removed_deps),
            "depsChanged": len(all_changed_deps),
        },
        "categoryBreakdown": dict(category_breakdown),
        "dependencyDetails": dep_details,
        "changeClassification": classification,
    }


def build_project_summary(timeline, ranked, top_changes, top_n, offset):
    """Build project-level aggregate stats."""
    net_api = 0
    net_dep = 0
    cat_trend = defaultdict(int)
    commits_with_changes = 0

    for entry in timeline:
        deltas = entry.get("deltas")
        if not deltas:
            continue
        has_change = False
        for d in deltas.values():
            if d.get("apisDelta", 0) != 0:
                has_change = True
            net_api += d.get("apisDelta", 0)
            net_dep += d.get("depsDelta", 0)
            for cat, val in d.get("categoryDeltas", {}).items():
                cat_trend[cat] += val
        if has_change:
            commits_with_changes += 1

    # Most volatile deps: count how many top changes each dep appears in
    dep_appearances = defaultdict(int)
    for change in top_changes:
        seen = set()
        for dd in change["dependencyDetails"]:
            ga = dd["groupArtifact"]
            if ga not in seen:
                dep_appearances[ga] += 1
                seen.add(ga)

    most_volatile = sorted(dep_appearances.items(), key=lambda x: -x[1])[:10]

    return {
        "netApiChange": net_api,
        "netDepChange": net_dep,
        "categoryTrend": dict(cat_trend),
        "commitsWithChanges": commits_with_changes,
        "totalRankedChanges": len(ranked),
        "mostVolatileDeps": [
            {"dep": dep, "appearancesInTopChanges": count}
            for dep, count in most_volatile
        ],
    }



# HTML generation
def generate_html(report):
    meta = report["metadata"]
    summary = report["projectSummary"]
    changes = report["bigChanges"]

    cards_html = _build_summary_cards(meta, summary)
    table_html = _build_changes_table(changes)
    details_html = _build_change_details(changes)
    volatile_html = _build_volatile_table(summary)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Big Changes Analysis — {_esc(meta.get('project', 'Unknown'))}</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.4/chart.umd.min.js"></script>
<style>
:root {{
    --bg: #fafafa; --fg: #1a1a1a; --card: #fff; --border: #e0e0e0;
    --muted: #666; --green: #2d6a4f; --red: #c0392b; --blue: #2980b9;
    --orange: #e07a3a; --purple: #6c4ab6; --yellow: #d4a017;
    --badge-add: #e8f5e9; --badge-add-fg: #2e7d32;
    --badge-rm: #ffebee; --badge-rm-fg: #c62828;
    --badge-chg: #e3f2fd; --badge-chg-fg: #1565c0;
    --badge-repl: #fff3e0; --badge-repl-fg: #e65100;
    --badge-bump: #f3e5f5; --badge-bump-fg: #6a1b9a;
    --badge-client: #fce4ec; --badge-client-fg: #880e4f;
    --expand-bg: #f5f5f5;
}}
@media (prefers-color-scheme: dark) {{
    :root:not([data-theme="light"]) {{
        --bg: #181a1b; --fg: #d4d4d4; --card: #232526; --border: #3a3a3a;
        --muted: #999; --green: #52b788; --red: #e74c3c; --blue: #5dade2;
        --orange: #e8945a; --purple: #9b7fd4; --yellow: #f0c040;
        --badge-add: #1b3a1b; --badge-add-fg: #81c784;
        --badge-rm: #3a1b1b; --badge-rm-fg: #ef9a9a;
        --badge-chg: #1b2a3a; --badge-chg-fg: #90caf9;
        --badge-repl: #3a2a1b; --badge-repl-fg: #ffcc80;
        --badge-bump: #2a1b3a; --badge-bump-fg: #ce93d8;
        --badge-client: #3a1b2a; --badge-client-fg: #f48fb1;
        --expand-bg: #2a2c2e;
    }}
}}
:root[data-theme="dark"] {{
    --bg: #181a1b; --fg: #d4d4d4; --card: #232526; --border: #3a3a3a;
    --muted: #999; --green: #52b788; --red: #e74c3c; --blue: #5dade2;
    --orange: #e8945a; --purple: #9b7fd4; --yellow: #f0c040;
    --badge-add: #1b3a1b; --badge-add-fg: #81c784;
    --badge-rm: #3a1b1b; --badge-rm-fg: #ef9a9a;
    --badge-chg: #1b2a3a; --badge-chg-fg: #90caf9;
    --badge-repl: #3a2a1b; --badge-repl-fg: #ffcc80;
    --badge-bump: #2a1b3a; --badge-bump-fg: #ce93d8;
    --badge-client: #3a1b2a; --badge-client-fg: #f48fb1;
    --expand-bg: #2a2c2e;
}}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: var(--bg); color: var(--fg);
    padding: 24px 16px; max-width: 1400px; margin: 0 auto;
}}
h1 {{ font-size: 1.5rem; margin-bottom: 4px; }}
.subtitle {{ color: var(--muted); font-size: 0.9rem; margin-bottom: 24px; }}
.cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; margin-bottom: 24px; }}
.card {{
    background: var(--card); border: 1px solid var(--border); border-radius: 8px;
    padding: 16px;
}}
.card-label {{ font-size: 0.78rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.5px; }}
.card-value {{ font-size: 1.5rem; font-weight: 700; margin-top: 4px; }}
.card-value.positive {{ color: var(--red); }}
.card-value.negative {{ color: var(--green); }}
.card-value.neutral {{ color: var(--muted); }}
.card-sub {{ font-size: 0.78rem; color: var(--muted); margin-top: 4px; }}
.section {{ background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 24px; margin-bottom: 24px; }}
.section h2 {{ font-size: 1.1rem; margin-bottom: 16px; }}
.section h3 {{ font-size: 0.95rem; color: var(--muted); margin-bottom: 8px; margin-top: 16px; }}
table {{ border-collapse: collapse; width: 100%; font-size: 0.85rem; }}
th, td {{ border: 1px solid var(--border); padding: 8px 10px; text-align: left; }}
th {{ background: var(--bg); font-weight: 600; position: sticky; top: 0; }}
.mono {{ font-family: monospace; font-size: 0.82rem; }}
.delta-up {{ color: var(--red); font-weight: 600; }}
.delta-down {{ color: var(--green); font-weight: 600; }}
.clickable {{ cursor: pointer; }}
.clickable:hover {{ background: var(--expand-bg); }}
.expand-row {{ display: none; }}
.expand-row.open {{ display: table-row; }}
.expand-cell {{ padding: 16px 20px; background: var(--expand-bg); }}
.badge {{
    display: inline-block; padding: 2px 8px; border-radius: 4px;
    font-size: 0.75rem; font-weight: 600; margin: 2px 2px;
}}
.badge-added {{ background: var(--badge-add); color: var(--badge-add-fg); }}
.badge-removed {{ background: var(--badge-rm); color: var(--badge-rm-fg); }}
.badge-changed {{ background: var(--badge-chg); color: var(--badge-chg-fg); }}
.badge-replacement {{ background: var(--badge-repl); color: var(--badge-repl-fg); }}
.badge-bump {{ background: var(--badge-bump); color: var(--badge-bump-fg); }}
.badge-client {{ background: var(--badge-client); color: var(--badge-client-fg); }}
.dep-table {{ margin-top: 12px; }}
.dep-table td {{ font-size: 0.82rem; }}
.cat-bar {{ display: flex; gap: 2px; height: 20px; border-radius: 3px; overflow: hidden; min-width: 120px; }}
.cat-bar span {{ display: inline-block; height: 100%; min-width: 2px; }}
.cat-fs {{ background: var(--orange); }}
.cat-net {{ background: var(--blue); }}
.cat-proc {{ background: var(--red); }}
.cat-other {{ background: var(--muted); }}
a {{ color: var(--blue); text-decoration: none; }}
a:hover {{ text-decoration: underline; }}
.chart-container {{ height: 300px; margin: 16px 0; }}
.filter-bar {{ margin-bottom: 16px; display: flex; gap: 12px; align-items: center; flex-wrap: wrap; }}
.filter-bar input {{ padding: 6px 12px; border: 1px solid var(--border); border-radius: 4px; background: var(--card); color: var(--fg); font-size: 0.85rem; }}
.volatile-table td:first-child {{ font-family: monospace; font-size: 0.82rem; }}
.no-data {{ color: var(--muted); font-style: italic; padding: 8px 0; }}
.rank-badge {{ display: inline-block; width: 28px; height: 28px; line-height: 28px; text-align: center; border-radius: 50%; background: var(--blue); color: #fff; font-weight: 700; font-size: 0.82rem; }}
.commit-link {{ word-break: break-all; }}
</style>
</head>
<body>

<h1>Big Changes Analysis — {_esc(meta.get('project', 'Unknown'))}</h1>
<p class="subtitle">
    Ranks {meta.get('offset', 0) + 1}–{meta.get('offset', 0) + len(changes)} of {summary.get('totalRankedChanges', '?')} commits with changes
    &middot; {meta.get('totalCommitsAnalyzed', '?')} commits analyzed
    &middot; {meta.get('dateRange', {}).get('from', '?')} to {meta.get('dateRange', {}).get('to', '?')}
    &middot; generated {meta.get('generated', '')[:16]}
</p>

{cards_html}

<div class="section">
    <h2>Top Changes</h2>
    <div class="filter-bar">
        <input type="text" id="searchBox" placeholder="Filter by commit, dep, or message…" oninput="filterTable()">
    </div>
    {table_html}
</div>

{details_html}

{volatile_html}

<script>
Chart.defaults.color = getComputedStyle(document.documentElement).getPropertyValue('--fg').trim() || '#1a1a1a';
Chart.defaults.borderColor = getComputedStyle(document.documentElement).getPropertyValue('--border').trim() || '#e0e0e0';

function toggleDetail(idx) {{
    const row = document.getElementById('detail-' + idx);
    if (row) row.classList.toggle('open');
}}

function filterTable() {{
    const q = document.getElementById('searchBox').value.toLowerCase();
    document.querySelectorAll('.change-row').forEach(row => {{
        const text = row.textContent.toLowerCase();
        const idx = row.dataset.idx;
        const detail = document.getElementById('detail-' + idx);
        if (text.includes(q) || !q) {{
            row.style.display = '';
            // keep detail row visibility as-is
        }} else {{
            row.style.display = 'none';
            if (detail) detail.classList.remove('open');
        }}
    }});
}}

// Category breakdown charts
document.querySelectorAll('.cat-chart').forEach(canvas => {{
    const data = JSON.parse(canvas.dataset.chart);
    new Chart(canvas, {{
        type: 'bar',
        data: {{
            labels: data.labels,
            datasets: [
                {{
                    label: 'Added',
                    data: data.added,
                    backgroundColor: getComputedStyle(document.documentElement).getPropertyValue('--red').trim(),
                }},
                {{
                    label: 'Removed',
                    data: data.removed.map(v => -v),
                    backgroundColor: getComputedStyle(document.documentElement).getPropertyValue('--green').trim(),
                }}
            ]
        }},
        options: {{
            responsive: true, maintainAspectRatio: false,
            indexAxis: 'y',
            plugins: {{ legend: {{ position: 'bottom' }} }},
            scales: {{
                x: {{ title: {{ display: true, text: 'APIs' }} }}
            }}
        }}
    }});
}});
</script>
</body>
</html>"""


def _esc(s):
    return (str(s).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def _delta_class(val):
    if val > 0:
        return "delta-up"
    elif val < 0:
        return "delta-down"
    return ""


def _delta_sign(val):
    return f"+{val}" if val > 0 else str(val)


def _build_summary_cards(meta, summary):
    net = summary["netApiChange"]
    net_cls = "positive" if net > 0 else "negative" if net < 0 else "neutral"

    cat_parts = []
    for cat in CATEGORIES:
        val = summary.get("categoryTrend", {}).get(cat, 0)
        if val != 0:
            cat_parts.append(f"{cat}: {_delta_sign(val)}")

    return f"""
    <div class="cards">
        <div class="card">
            <div class="card-label">Net API Change</div>
            <div class="card-value {net_cls}">{_delta_sign(net)}</div>
            <div class="card-sub">across all commits</div>
        </div>
        <div class="card">
            <div class="card-label">Net Dep Change</div>
            <div class="card-value">{_delta_sign(summary['netDepChange'])}</div>
        </div>
        <div class="card">
            <div class="card-label">Commits with Changes</div>
            <div class="card-value">{summary['commitsWithChanges']}</div>
            <div class="card-sub">of {meta.get('totalCommitsAnalyzed', '?')} analyzed</div>
        </div>
        <div class="card">
            <div class="card-label">Category Trend</div>
            <div class="card-sub" style="margin-top:8px">{'<br>'.join(cat_parts) if cat_parts else '—'}</div>
        </div>
    </div>"""


def _cat_bar_html(cat_breakdown):
    total = sum(abs(v.get("delta", 0)) for v in cat_breakdown.values())
    if total == 0:
        return '<span class="no-data">—</span>'
    parts = []
    cat_css = {"FILESYSTEM": "cat-fs", "NETWORK": "cat-net", "PROCESS": "cat-proc", "OTHER": "cat-other"}
    for cat in CATEGORIES:
        val = abs(cat_breakdown.get(cat, {}).get("delta", 0))
        if val > 0:
            pct = max(val / total * 100, 3)
            css = cat_css.get(cat, "cat-other")
            parts.append(f'<span class="{css}" style="width:{pct:.0f}%" title="{cat}: {val}"></span>')
    return f'<div class="cat-bar">{"".join(parts)}</div>'


def _badges_html(classification):
    badges = []
    n_add = len(classification.get("depsAdded", []))
    n_rm = len(classification.get("depsRemoved", []))
    n_chg = len(classification.get("depsChanged", []))
    n_repl = len(classification.get("possibleReplacements", []))
    n_bump = len(classification.get("versionBumps", []))

    if n_add:
        badges.append(f'<span class="badge badge-added">+{n_add} dep{"s" if n_add > 1 else ""}</span>')
    if n_rm:
        badges.append(f'<span class="badge badge-removed">-{n_rm} dep{"s" if n_rm > 1 else ""}</span>')
    if n_chg:
        badges.append(f'<span class="badge badge-changed">{n_chg} changed</span>')
    if n_bump:
        badges.append(f'<span class="badge badge-bump">{n_bump} bump{"s" if n_bump > 1 else ""}</span>')
    if n_repl:
        badges.append(f'<span class="badge badge-replacement">{n_repl} replacement{"s" if n_repl > 1 else ""}?</span>')
    if classification.get("clientCodeChangeOnly"):
        badges.append('<span class="badge badge-client">client code</span>')
    return " ".join(badges)


def _build_changes_table(changes):
    rows = []
    for i, c in enumerate(changes):
        s = c["summary"]
        api_cls = _delta_class(s["totalApisDelta"])
        dep_cls = _delta_class(s["totalDepsDelta"])
        sha_display = c["sha"]
        if c.get("commitUrl"):
            sha_display = f'<a href="{_esc(c["commitUrl"])}" target="_blank">{_esc(c["sha"])}</a>'
        pr_display = ""
        if c.get("prUrl"):
            pr_display = f' <a href="{_esc(c["prUrl"])}" target="_blank">PR #{c["prNumber"]}</a>'

        msg = _esc(c.get("commitMessage", "")[:80])
        badges = _badges_html(c["changeClassification"])

        rows.append(f"""
        <tr class="change-row clickable" data-idx="{i}" onclick="toggleDetail({i})">
            <td><span class="rank-badge">{c['rank']}</span></td>
            <td class="mono">{sha_display}{pr_display}</td>
            <td>{_esc(c['date'])}</td>
            <td>{msg}</td>
            <td class="{api_cls}">{_delta_sign(s['totalApisDelta'])}</td>
            <td class="{dep_cls}">{_delta_sign(s['totalDepsDelta'])}</td>
            <td>{_cat_bar_html(c['categoryBreakdown'])}</td>
            <td>{badges}</td>
        </tr>
        <tr class="expand-row" id="detail-{i}">
            <td colspan="8" class="expand-cell" id="expand-cell-{i}"></td>
        </tr>""")

    return f"""
    <div style="overflow-x:auto;">
    <table id="changesTable">
        <thead><tr>
            <th>#</th><th>Commit</th><th>Date</th><th>Message</th>
            <th>APIs Δ</th><th>Deps Δ</th><th>Categories</th><th>Tags</th>
        </tr></thead>
        <tbody>{"".join(rows)}</tbody>
    </table>
    </div>"""


def _build_change_details(changes):
    sections = []
    for i, c in enumerate(changes):
        s = c["summary"]
        cat_b = c["categoryBreakdown"]
        deps = c["dependencyDetails"]
        cls = c["changeClassification"]

        # Category chart data
        labels = []
        added_vals = []
        removed_vals = []
        for cat in CATEGORIES:
            cb = cat_b.get(cat, {})
            if cb.get("added", 0) or cb.get("removed", 0):
                labels.append(cat)
                added_vals.append(cb.get("added", 0))
                removed_vals.append(cb.get("removed", 0))

        chart_data = json.dumps({"labels": labels, "added": added_vals, "removed": removed_vals})

        # Dependency detail rows
        dep_rows = []
        for dd in deps[:30]:
            chg_badge = {"added": "badge-added", "removed": "badge-removed", "changed": "badge-changed"}
            badge_cls = chg_badge.get(dd["changeType"], "")
            api_cls = _delta_class(dd["apisDelta"])
            cat_parts = []
            for cat, val in dd.get("categoryContribution", {}).items():
                cat_parts.append(f"{cat}: {_delta_sign(val)}")
            dep_rows.append(f"""
            <tr>
                <td class="mono">{_esc(dd['dep'])}</td>
                <td><span class="badge {badge_cls}">{dd['changeType']}</span></td>
                <td>{dd['apisInPrevious']}</td>
                <td>{dd['apisInCurrent']}</td>
                <td class="{api_cls}">{_delta_sign(dd['apisDelta'])}</td>
                <td style="font-size:0.78rem">{', '.join(cat_parts) if cat_parts else '—'}</td>
            </tr>""")

        # Version bumps
        bump_html = ""
        if cls.get("versionBumps"):
            bump_rows = []
            for b in cls["versionBumps"]:
                bump_rows.append(f"<tr><td class='mono'>{_esc(b['dep'])}</td>"
                                 f"<td>{_esc(b.get('from', '?'))}</td>"
                                 f"<td>{_esc(b.get('to', '?'))}</td>"
                                 f"<td>{b.get('apisBefore', '?')} → {b.get('apisAfter', '?')}</td></tr>")
            bump_html = f"""
            <h3>Version Bumps (same dependency, version changed)</h3>
            <table class="dep-table"><thead><tr><th>Dependency</th><th>From</th><th>To</th><th>APIs</th></tr></thead>
            <tbody>{''.join(bump_rows)}</tbody></table>"""

        # Replacements
        repl_html = ""
        if cls.get("possibleReplacements"):
            repl_rows = []
            for r in cls["possibleReplacements"]:
                repl_rows.append(
                    f"<tr><td class='mono'>{_esc(r['removed'])}</td>"
                    f"<td>{r['removedApis']}</td>"
                    f"<td class='mono'>{_esc(r['added'])}</td>"
                    f"<td>{r['addedApis']}</td>"
                    f"<td>{', '.join(r['sharedCategories'])}</td>"
                    f"<td>{r['confidence']}</td></tr>")
            repl_html = f"""
            <h3>Possible Replacements</h3>
            <table class="dep-table"><thead><tr>
                <th>Removed</th><th>APIs</th><th>Added</th><th>APIs</th><th>Shared Categories</th><th>Confidence</th>
            </tr></thead><tbody>{''.join(repl_rows)}</tbody></table>"""

        sha_link = c["sha"]
        if c.get("commitUrl"):
            sha_link = f'<a href="{_esc(c["commitUrl"])}" target="_blank">{_esc(c["sha"])}</a>'
        pr_link = ""
        if c.get("prUrl"):
            pr_link = f' &middot; <a href="{_esc(c["prUrl"])}" target="_blank">PR #{c["prNumber"]}</a>'

        sections.append(f"""
        <div class="section" id="change-detail-{i}">
            <h2><span class="rank-badge">{c['rank']}</span> &nbsp; {sha_link}{pr_link} &nbsp; <span style="font-weight:400;font-size:0.9rem;color:var(--muted)">{_esc(c['date'])}</span></h2>
            <p style="margin:8px 0;font-size:0.9rem">{_esc(c.get('commitMessage', ''))}</p>
            <p style="margin:4px 0;font-size:0.85rem;color:var(--muted)">
                APIs: <span class="{_delta_class(s['totalApisDelta'])}">{_delta_sign(s['totalApisDelta'])}</span>
                (added {s['apisAdded']}, removed {s['apisRemoved']})
                &middot; Deps: {_delta_sign(s['totalDepsDelta'])}
                (+{s['depsAdded']} / -{s['depsRemoved']} / ~{s['depsChanged']})
                &middot; Modules: {', '.join(c.get('changedModules', []))}
            </p>

            <div class="chart-container">
                <canvas class="cat-chart" data-chart='{_esc(chart_data)}'></canvas>
            </div>

            <h3>Dependency Details ({len(deps)} dependencies involved)</h3>
            <div style="overflow-x:auto">
            <table class="dep-table">
                <thead><tr><th>Dependency</th><th>Type</th><th>Before</th><th>After</th><th>Δ</th><th>Category Contribution</th></tr></thead>
                <tbody>{''.join(dep_rows)}</tbody>
            </table>
            </div>

            {bump_html}
            {repl_html}
        </div>""")

    return "\n".join(sections)


def _build_volatile_table(summary):
    volatile = summary.get("mostVolatileDeps", [])
    if not volatile:
        return ""
    rows = []
    for v in volatile:
        rows.append(f"<tr><td>{_esc(v['dep'])}</td><td>{v['appearancesInTopChanges']}</td></tr>")
    return f"""
    <div class="section">
        <h2>Most Volatile Dependencies</h2>
        <p class="card-sub" style="margin-bottom:12px">Dependencies appearing most frequently in the top changes above</p>
        <table class="volatile-table">
            <thead><tr><th>Dependency (groupId:artifactId)</th><th>Appearances</th></tr></thead>
            <tbody>{''.join(rows)}</tbody>
        </table>
    </div>"""



# Main
def main():
    parser = argparse.ArgumentParser(
        description="Analyze sudden large changes in dependency reachability.")
    parser.add_argument("timeline", help="Path to timeline_data.json")
    parser.add_argument("--results", help="Path to analysis_results.json (for richer data)")
    parser.add_argument("--snapshots", help="Path to snapshots directory (for per-dep category)")
    parser.add_argument("--repo-url", help="GitHub repo URL (e.g. https://github.com/org/repo)")
    parser.add_argument("--project", help="Project name (derived from path if omitted)")
    parser.add_argument("--top", type=int, default=10, help="Number of top changes (default: 10)")
    parser.add_argument("--offset", type=int, default=0, help="Skip first N changes (for pagination)")
    parser.add_argument("--output", help="Output directory (default: same as timeline)")
    args = parser.parse_args()

    # Load data
    timeline_path = Path(args.timeline)
    if not timeline_path.exists():
        print(f"Not found: {timeline_path}", file=sys.stderr)
        sys.exit(1)

    timeline_data = load_json(timeline_path)
    timeline = timeline_data.get("timeline", [])

    if not timeline:
        print("No timeline entries found.", file=sys.stderr)
        sys.exit(1)

    project_name = args.project or timeline_path.parent.name
    repo_url = args.repo_url.rstrip("/") if args.repo_url else None

    # Build per-dep category index from snapshots
    commit_dep_cats = {}
    if args.results and args.snapshots:
        results_data = load_json(args.results)
        commit_dep_cats = build_commit_dep_categories(results_data, args.snapshots)

    # Rank changes
    ranked = rank_changes(timeline)
    print(f"Project: {project_name}")
    print(f"Timeline: {len(timeline)} commits, {len(ranked)} with API changes")

    # Slice
    page = ranked[args.offset:args.offset + args.top]
    if not page:
        print(f"No changes in range offset={args.offset}, top={args.top}", file=sys.stderr)
        sys.exit(1)

    # Build index for finding previous commit
    sha_to_idx = {e["sha"]: i for i, e in enumerate(timeline)}

    # Analyze each
    big_changes = []
    for rank_pos, (abs_delta, entry) in enumerate(page, start=args.offset + 1):
        idx = sha_to_idx.get(entry["sha"])
        prev_entry = timeline[idx - 1] if idx and idx > 0 else None
        change = analyze_single_change(entry, prev_entry, commit_dep_cats, repo_url)
        change["rank"] = rank_pos
        big_changes.append(change)

    # Project summary
    project_summary = build_project_summary(timeline, ranked, big_changes, args.top, args.offset)

    # Build report
    report = {
        "metadata": {
            "project": project_name,
            "generated": datetime.now().isoformat(),
            "timelineFile": str(timeline_path),
            "totalCommitsAnalyzed": timeline_data.get("commitsAnalyzed", len(timeline)),
            "dateRange": timeline_data.get("dateRange", {}),
            "rankingMetric": "abs(totalApisDelta)",
            "topN": args.top,
            "offset": args.offset,
        },
        "projectSummary": project_summary,
        "bigChanges": big_changes,
    }

    # Output
    out_dir = Path(args.output) if args.output else timeline_path.parent
    out_dir.mkdir(parents=True, exist_ok=True)

    suffix = f"_offset{args.offset}" if args.offset > 0 else ""

    json_path = out_dir / f"big_changes{suffix}.json"
    with open(json_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"JSON: {json_path}")

    html_path = out_dir / f"big_changes{suffix}.html"
    html_path.write_text(generate_html(report), encoding="utf-8")
    print(f"HTML: {html_path}")


if __name__ == "__main__":
    main()
