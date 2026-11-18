#!/usr/bin/env python3
"""
Post-hoc attribution of sensitive API changes across project history.

For each pair of consecutive analyzed commits, determines whether each
added or removed sensitive API was caused by the client project, the
direct dependency, or an indirect dependency.

Reads reachable-detail.json and boundary-interactions.json produced by
Theo for each commit, alongside timeline_data.json for ordering and
dep version info.

Usage:
    python3 attribute_api_changes.py [<reports_base_dir>] [--output <dir>]
"""

import argparse
import json
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path


REPORTS_BASE = Path("/scratch/yogya/client-results/history")

CAUSES = [
    "CLIENT_INITIATED",
    "CLIENT_INITIATED_INDIRECT",
    "DEP_INITIATED",
    "DEP_INITIATED_INDIRECT",
    "INDIRECT_DEP_INITIATED",
]

CRITICALITY = {
    "CLIENT_INITIATED": 1,
    "CLIENT_INITIATED_INDIRECT": 2,
    "DEP_INITIATED": 3,
    "DEP_INITIATED_INDIRECT": 3,
    "INDIRECT_DEP_INITIATED": 4,
}


def load_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


def dep_ga(dep_key):
    """Extract groupId:artifactId from groupId:artifactId:version."""
    parts = dep_key.split(":")
    return ":".join(parts[:2]) if len(parts) >= 2 else dep_key


def dep_version(dep_key):
    """Extract version from groupId:artifactId:version."""
    parts = dep_key.split(":")
    return parts[2] if len(parts) >= 3 else ""


def build_boundary_set(boundary_data):
    """Build a set of boundary keys from boundary-interactions.json."""
    keys = set()
    if not boundary_data:
        return keys
    for bi in boundary_data:
        cm = bi.get("clientMethod", "")
        dm = bi.get("depMethod", "")
        ga = bi.get("depArtifactGa", "")
        if cm and dm and ga:
            keys.add(f"{cm}::{dm}::{ga}")
    return keys


def build_api_index(reachable_data):
    """Build {(dep_ga, sensitiveApi) → entry} from reachable-detail.json.

    reachable-detail.json maps dep GAV → list of SensitiveApiEntry.
    """
    index = {}
    if not reachable_data:
        return index
    for dep_gav, entries in reachable_data.items():
        ga = dep_ga(dep_gav)
        for entry in entries:
            api = entry.get("sensitiveApi", "")
            key = (ga, api)
            if key not in index:
                index[key] = (entry, dep_gav)
    return index


def dep_versions_by_ga(reachable_data):
    """Build {dep_ga → version} from the dep GAV keys in reachable data."""
    versions = {}
    if not reachable_data:
        return versions
    for dep_gav in reachable_data:
        ga = dep_ga(dep_gav)
        ver = dep_version(dep_gav)
        versions[ga] = ver
    return versions


def classify_change(entry, dep_ga_str, dep_version_changed, boundary_keys):
    """Classify a single API change using boundary stability."""
    full_path = entry.get("fullPath", [])
    if not full_path:
        return "CLIENT_INITIATED", "No path information available"

    client_method = full_path[0].get("method", "") if isinstance(full_path[0], dict) else full_path[0]
    dep_method = entry.get("entryPoint", "")
    access_type = entry.get("accessType", "DIRECT")
    is_indirect = access_type == "INDIRECT"

    boundary_key = f"{client_method}::{dep_method}::{dep_ga_str}"
    boundary_existed = boundary_key in boundary_keys

    if boundary_existed:
        if dep_version_changed:
            cause = "DEP_INITIATED_INDIRECT" if is_indirect else "DEP_INITIATED"
            explanation = f"Boundary stable, {dep_ga_str} version changed"
        else:
            cause = "INDIRECT_DEP_INITIATED"
            explanation = f"Boundary stable, {dep_ga_str} version unchanged"
    else:
        if is_indirect:
            cause = "CLIENT_INITIATED_INDIRECT"
            explanation = f"Client boundary changed, indirect access via {dep_ga_str}"
        else:
            cause = "CLIENT_INITIATED"
            explanation = f"Client boundary changed, direct access to {dep_ga_str}"

    return cause, explanation


def analyze_transition(prev_sha, curr_sha, project_dir, modules):
    """Analyze one commit transition across all modules."""
    changes = []

    for module in modules:
        prev_dir = project_dir / prev_sha / module
        curr_dir = project_dir / curr_sha / module

        prev_reachable = load_json(prev_dir / "reachable-detail.json")
        curr_reachable = load_json(curr_dir / "reachable-detail.json")
        prev_boundaries = load_json(prev_dir / "boundary-interactions.json")
        curr_boundaries = load_json(curr_dir / "boundary-interactions.json")

        if curr_reachable is None and prev_reachable is None:
            continue

        prev_index = build_api_index(prev_reachable)
        curr_index = build_api_index(curr_reachable)
        prev_boundary_set = build_boundary_set(prev_boundaries)
        curr_boundary_set = build_boundary_set(curr_boundaries)

        prev_versions = dep_versions_by_ga(prev_reachable)
        curr_versions = dep_versions_by_ga(curr_reachable)

        # Added APIs
        for key, (entry, dep_gav) in curr_index.items():
            if key not in prev_index:
                ga = key[0]
                prev_ver = prev_versions.get(ga, "")
                curr_ver = curr_versions.get(ga, "")
                version_changed = prev_ver != curr_ver
                cause, explanation = classify_change(
                    entry, ga, version_changed, prev_boundary_set)
                changes.append({
                    "sensitiveApi": key[1],
                    "depGa": ga,
                    "direction": "ADDED",
                    "rootCause": cause,
                    "criticality": CRITICALITY[cause],
                    "accessType": entry.get("accessType", "DIRECT"),
                    "category": entry.get("category"),
                    "explanation": explanation,
                    "module": module,
                })

        # Removed APIs
        for key, (entry, dep_gav) in prev_index.items():
            if key not in curr_index:
                ga = key[0]
                prev_ver = prev_versions.get(ga, "")
                curr_ver = curr_versions.get(ga, "")
                version_changed = prev_ver != curr_ver
                cause, explanation = classify_change(
                    entry, ga, version_changed, curr_boundary_set)
                changes.append({
                    "sensitiveApi": key[1],
                    "depGa": ga,
                    "direction": "REMOVED",
                    "rootCause": cause,
                    "criticality": CRITICALITY[cause],
                    "accessType": entry.get("accessType", "DIRECT"),
                    "category": entry.get("category"),
                    "explanation": explanation,
                    "module": module,
                })

    return changes


def analyze_project(project_dir):
    """Analyze a single project's full history."""
    name = project_dir.name
    timeline_data = load_json(project_dir / "timeline_data.json")
    if not timeline_data:
        print(f"  Skipping {name}: no timeline_data.json")
        return None

    timeline = timeline_data.get("timeline", [])
    if len(timeline) < 2:
        print(f"  Skipping {name}: fewer than 2 commits")
        return None

    modules = timeline_data.get("modules", ["."])

    transitions = []
    summary = defaultdict(int)
    summary["totalAdditions"] = 0
    summary["totalRemovals"] = 0

    for i in range(1, len(timeline)):
        prev_entry = timeline[i - 1]
        curr_entry = timeline[i]
        prev_sha = prev_entry.get("sha", "")[:8]
        curr_sha = curr_entry.get("sha", "")[:8]
        date = curr_entry.get("date", "")

        changes = analyze_transition(prev_sha, curr_sha, project_dir, modules)
        if not changes:
            continue

        for c in changes:
            summary[c["rootCause"]] += 1
            if c["direction"] == "ADDED":
                summary["totalAdditions"] += 1
            else:
                summary["totalRemovals"] += 1

        transitions.append({
            "prevSha": prev_sha,
            "currSha": curr_sha,
            "date": date,
            "changes": changes,
        })

    return {
        "project": name,
        "transitions": transitions,
        "summary": dict(summary),
    }


def generate_html(all_results, out_path):
    """Generate a summary HTML report across all projects."""
    totals = defaultdict(int)
    per_project = {}

    for result in all_results:
        name = result["project"]
        s = result["summary"]
        per_project[name] = s
        for cause in CAUSES:
            totals[cause] += s.get(cause, 0)
        totals["totalAdditions"] += s.get("totalAdditions", 0)
        totals["totalRemovals"] += s.get("totalRemovals", 0)

    grand_total = sum(totals.get(c, 0) for c in CAUSES)

    # Totals table rows
    total_rows = ""
    for cause in CAUSES:
        count = totals.get(cause, 0)
        pct = round(count / grand_total * 100, 1) if grand_total else 0
        total_rows += (f"<tr><td>{cause}</td><td>{count}</td>"
                       f"<td>{pct}%</td></tr>\n")

    # Per-project table rows
    proj_rows = ""
    for name in sorted(per_project.keys()):
        s = per_project[name]
        cells = "".join(f"<td>{s.get(c, 0)}</td>" for c in CAUSES)
        proj_total = sum(s.get(c, 0) for c in CAUSES)
        proj_rows += (f"<tr><td class='mono'>{_esc(name)}</td>"
                      f"{cells}<td><b>{proj_total}</b></td></tr>\n")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Attribution Analysis</title>
<style>
:root {{
    --bg: #fafafa; --fg: #1a1a1a; --card: #fff; --border: #e0e0e0;
    --muted: #666;
}}
@media (prefers-color-scheme: dark) {{
    :root:not([data-theme="light"]) {{
        --bg: #181a1b; --fg: #d4d4d4; --card: #232526; --border: #3a3a3a;
        --muted: #999;
    }}
}}
:root[data-theme="dark"] {{
    --bg: #181a1b; --fg: #d4d4d4; --card: #232526; --border: #3a3a3a;
    --muted: #999;
}}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: var(--bg); color: var(--fg);
    padding: 24px 16px; max-width: 1200px; margin: 0 auto;
}}
h1 {{ font-size: 1.5rem; margin-bottom: 4px; }}
h2 {{ font-size: 1.1rem; margin-top: 24px; margin-bottom: 12px; }}
.subtitle {{ color: var(--muted); font-size: 0.9rem; margin-bottom: 24px; }}
.section {{
    background: var(--card); border: 1px solid var(--border); border-radius: 8px;
    padding: 24px; margin-bottom: 24px;
}}
table {{ border-collapse: collapse; width: 100%; font-size: 0.85rem; }}
th, td {{ border: 1px solid var(--border); padding: 6px 10px; text-align: left; }}
th {{ background: var(--bg); font-weight: 600; }}
.mono {{ font-family: monospace; font-size: 0.82rem; }}
</style>
</head>
<body>

<h1>Sensitive API Change Attribution</h1>
<p class="subtitle">
    {len(all_results)} projects &middot; {grand_total} attributed changes
    ({totals.get('totalAdditions', 0)} additions, {totals.get('totalRemovals', 0)} removals)
    &middot; generated {datetime.now().isoformat()[:16]}
</p>

<div class="section">
    <h2>Attribution Totals</h2>
    <table>
        <thead><tr><th>Root Cause</th><th>Count</th><th>%</th></tr></thead>
        <tbody>
            {total_rows}
            <tr style="font-weight:700"><td>Total</td>
                <td>{grand_total}</td><td>100%</td></tr>
        </tbody>
    </table>
</div>

<div class="section">
    <h2>Per Project</h2>
    <div style="overflow-x:auto">
    <table>
        <thead><tr>
            <th>Project</th>
            {''.join(f'<th>{c}</th>' for c in CAUSES)}
            <th>Total</th>
        </tr></thead>
        <tbody>{proj_rows}</tbody>
    </table>
    </div>
</div>

</body>
</html>"""

    out_path.write_text(html, encoding="utf-8")


def _esc(s):
    return (str(s).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def main():
    parser = argparse.ArgumentParser(
        description="Attribute sensitive API changes across project history.")
    parser.add_argument("reports_dir", nargs="?", default=str(REPORTS_BASE),
                        help="Base directory with per-project report subdirs")
    parser.add_argument("--output", help="Output directory (default: reports_dir)")
    args = parser.parse_args()

    base = Path(args.reports_dir)
    if not base.exists():
        print(f"Not found: {base}", file=sys.stderr)
        sys.exit(1)

    out_dir = Path(args.output) if args.output else base
    out_dir.mkdir(parents=True, exist_ok=True)

    all_results = []
    for proj_dir in sorted(base.iterdir()):
        if not proj_dir.is_dir():
            continue
        print(f"Analyzing {proj_dir.name}...")
        result = analyze_project(proj_dir)
        if result:
            all_results.append(result)

            # Write per-project JSON
            proj_out = out_dir / proj_dir.name
            proj_out.mkdir(parents=True, exist_ok=True)
            json_path = proj_out / "attribution_results.json"
            with open(json_path, "w") as f:
                json.dump(result, f, indent=2)
            print(f"  → {json_path}")

    if not all_results:
        print("No projects with attribution data found.")
        sys.exit(0)

    # Aggregate JSON
    aggregate = {
        "generated": datetime.now().isoformat(),
        "projectCount": len(all_results),
        "projects": [r["project"] for r in all_results],
        "totals": {},
    }
    for cause in CAUSES:
        aggregate["totals"][cause] = sum(
            r["summary"].get(cause, 0) for r in all_results)
    aggregate["totals"]["totalAdditions"] = sum(
        r["summary"].get("totalAdditions", 0) for r in all_results)
    aggregate["totals"]["totalRemovals"] = sum(
        r["summary"].get("totalRemovals", 0) for r in all_results)

    agg_path = out_dir / "attribution_aggregate.json"
    with open(agg_path, "w") as f:
        json.dump(aggregate, f, indent=2)
    print(f"\nAggregate JSON: {agg_path}")

    # HTML report
    html_path = out_dir / "attribution_summary.html"
    generate_html(all_results, html_path)
    print(f"HTML: {html_path}")

    # Print summary
    grand = sum(aggregate["totals"].get(c, 0) for c in CAUSES)
    print(f"\n{len(all_results)} projects, {grand} total attributed changes:")
    for cause in CAUSES:
        count = aggregate["totals"].get(cause, 0)
        pct = round(count / grand * 100, 1) if grand else 0
        print(f"  {cause:30s}: {count:5d} ({pct}%)")


if __name__ == "__main__":
    main()
