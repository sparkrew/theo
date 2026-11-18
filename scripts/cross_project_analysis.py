#!/usr/bin/env python3
"""
Cross-project analysis across all Theo-tracked projects.

Reads the generated JSON reports (timeline_data.json, big_changes.json,
change_type_stats.json, cve_tracking.json) from each project's report
directory and produces aggregate statistics.

Usage:
    python3 cross_project_analysis.py <reports_base_dir>
        [--output <output_dir>]
        [--top-big <N>]          # top N big changes per project (default 3)

Expected directory structure:
    <reports_base_dir>/
        alibaba_nacos/
            timeline_data.json
            big_changes.json
            change_type_stats.json
            cve_tracking.json
        apache_tika/
            ...
"""

import argparse
import json
import re
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path


def load_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        print(f"  Warning: could not load {path}: {e}", file=sys.stderr)
        return None


CATEGORIES = ["FILESYSTEM", "NETWORK", "PROCESS"]
CAT_LABELS = {"FILESYSTEM": "FileAccess", "NETWORK": "Network", "PROCESS": "Process"}

SECURITY_KEYWORDS = re.compile(
    r'\b(secur|vulnerab|cve-|exploit|unsafe|patch.*vuln|fix.*vuln|'
    r'vuln.*fix|vuln.*patch)\b', re.IGNORECASE)


def dep_ga(dep_key):
    parts = dep_key.split(":")
    return ":".join(parts[:2]) if len(parts) >= 2 else dep_key


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

def load_all_projects(base_dir):
    base = Path(base_dir)
    projects = {}
    for proj_dir in sorted(base.iterdir()):
        if not proj_dir.is_dir():
            continue
        name = proj_dir.name
        timeline = load_json(proj_dir / "timeline_data.json")
        if not timeline:
            print(f"  Skipping {name}: no timeline_data.json")
            continue

        projects[name] = {
            "name": name,
            "dir": str(proj_dir),
            "timeline": timeline,
            "bigChanges": load_json(proj_dir / "big_changes.json"),
            "changeTypeStats": load_json(proj_dir / "change_type_stats.json"),
            "cveTracking": load_json(proj_dir / "cve_tracking.json"),
            "attribution": load_json(proj_dir / "attribution_results.json"),
        }
        print(f"  Loaded {name}")

    return projects


# ---------------------------------------------------------------------------
# 1. Change type totals across all projects
# ---------------------------------------------------------------------------

def analyze_change_types(projects):
    totals = {"dep_removed": 0, "dep_added": 0, "dep_updated": 0,
              "client_code_change": 0}
    per_project = {}

    for name, proj in projects.items():
        cts = proj.get("changeTypeStats")
        if not cts:
            continue
        gt = cts.get("grandTotals", {})
        proj_totals = {}
        for case_key in totals:
            count = gt.get(case_key, 0)
            totals[case_key] += count
            proj_totals[case_key] = count
        per_project[name] = proj_totals

    grand_total = sum(totals.values())
    return {
        "totals": totals,
        "grandTotal": grand_total,
        "percentages": {k: round(v / grand_total * 100, 1) if grand_total else 0
                        for k, v in totals.items()},
        "perProject": per_project,
    }


# ---------------------------------------------------------------------------
# 2. Top reasons for big changes
# ---------------------------------------------------------------------------

def analyze_big_change_reasons(projects, top_n):
    reason_counts = {"versionUpdate": 0, "depAdded": 0, "depRemoved": 0,
                     "clientCodeChange": 0, "mixed": 0}
    all_big_changes = []

    for name, proj in projects.items():
        bc = proj.get("bigChanges")
        if not bc:
            continue
        changes = bc.get("bigChanges", [])[:top_n]
        for change in changes:
            deps = change.get("dependencyDetails", [])
            types_seen = set()
            for d in deps:
                ct = d.get("changeType", "")
                if ct == "updated":
                    types_seen.add("versionUpdate")
                elif ct == "added":
                    types_seen.add("depAdded")
                elif ct == "removed":
                    types_seen.add("depRemoved")
                elif ct == "changed":
                    types_seen.add("clientCodeChange")

            if len(types_seen) > 1:
                dominant = max(types_seen,
                               key=lambda t: sum(1 for d in deps
                                                 if _dep_type_matches(d, t)))
                reason_counts[dominant] += 1
                reason_counts["mixed"] += 1
            elif len(types_seen) == 1:
                reason_counts[next(iter(types_seen))] += 1

            all_big_changes.append({
                "project": name,
                "sha": change.get("sha", ""),
                "date": change.get("date", ""),
                "message": change.get("commitMessage", "")[:80],
                "totalApisDelta": change.get("summary", {}).get("totalApisDelta", 0),
                "typesInvolved": sorted(types_seen),
                "depsChanged": len(deps),
            })

    total = sum(v for k, v in reason_counts.items() if k != "mixed")
    return {
        "reasonCounts": reason_counts,
        "total": total,
        "percentages": {k: round(v / total * 100, 1) if total else 0
                        for k, v in reason_counts.items() if k != "mixed"},
        "topNPerProject": top_n,
        "bigChanges": sorted(all_big_changes,
                             key=lambda x: (-abs(x["totalApisDelta"]),
                                            x["project"], x["sha"])),
    }


def _dep_type_matches(dep, type_key):
    ct = dep.get("changeType", "")
    mapping = {"versionUpdate": "updated", "depAdded": "added",
               "depRemoved": "removed", "clientCodeChange": "changed"}
    return ct == mapping.get(type_key, "")


# ---------------------------------------------------------------------------
# 3. Most volatile dependencies
# ---------------------------------------------------------------------------

def analyze_volatile_deps(projects):
    dep_events = defaultdict(lambda: {"projects": set(), "totalEvents": 0,
                                       "updated": 0, "added": 0, "removed": 0,
                                       "codeChange": 0})

    for name, proj in projects.items():
        cts = proj.get("changeTypeStats")
        if not cts:
            continue
        for dep_entry in cts.get("perDependency", []):
            ga = dep_entry.get("dep", "")
            if not ga:
                continue
            total = dep_entry.get("total", 0)
            if total == 0:
                continue
            info = dep_events[ga]
            info["projects"].add(name)
            info["totalEvents"] += total
            info["updated"] += dep_entry.get("dep_updated", 0)
            info["added"] += dep_entry.get("dep_added", 0)
            info["removed"] += dep_entry.get("dep_removed", 0)
            info["codeChange"] += dep_entry.get("client_code_change", 0)

    result = []
    for ga, info in dep_events.items():
        result.append({
            "dep": ga,
            "totalEvents": info["totalEvents"],
            "projectCount": len(info["projects"]),
            "projects": sorted(info["projects"]),
            "updated": info["updated"],
            "added": info["added"],
            "removed": info["removed"],
            "codeChange": info["codeChange"],
        })

    result.sort(key=lambda x: (-x["projectCount"], -x["totalEvents"]))
    return {"deps": result[:50], "totalUniqueDeps": len(dep_events)}


# ---------------------------------------------------------------------------
# 4. CVE + sensitive API coincidence (per dep, per commit, per category)
# ---------------------------------------------------------------------------

def analyze_cve_api_coincidence(projects):
    coincidences = []  # full list
    summary = {
        "cveIntroWithApiIncrease": {c: 0 for c in CATEGORIES},
        "cveIntroWithApiDecrease": {c: 0 for c in CATEGORIES},
        "cveIntroNoApiChange": {c: 0 for c in CATEGORIES},
        "cveResolvedWithApiDecrease": {c: 0 for c in CATEGORIES},
        "cveResolvedWithApiIncrease": {c: 0 for c in CATEGORIES},
        "cveResolvedNoApiChange": {c: 0 for c in CATEGORIES},
        "totalCveIntroductions": 0,
        "totalCveResolutions": 0,
    }

    for name, proj in projects.items():
        cve_data = proj.get("cveTracking")
        if not cve_data:
            continue

        for diff in cve_data.get("perCommit", []):
            if diff.get("isBaseline"):
                continue
            dep_details = diff.get("depDetails", [])
            if not dep_details:
                continue

            sha = diff.get("sha", "")
            date = diff.get("date", "")
            message = diff.get("message", "")

            for dd in dep_details:
                n_intro = len(dd.get("cvesIntroduced", []))
                n_res = len(dd.get("cvesResolved", []))
                if not n_intro and not n_res:
                    continue

                cat_before = dd.get("catBefore", {})
                cat_after = dd.get("catAfter", {})
                api_before = dd.get("apisBefore", 0)
                api_after = dd.get("apisAfter", 0)
                api_delta = dd.get("apisDelta", 0)

                cat_deltas = {}
                for cat in CATEGORIES:
                    d = cat_after.get(cat, 0) - cat_before.get(cat, 0)
                    if d != 0:
                        cat_deltas[cat] = d

                cve_ids_intro = [c.get("cveId", "") for c in
                                 dd.get("cvesIntroduced", [])]
                cve_ids_res = [c.get("cveId", "") for c in
                               dd.get("cvesResolved", [])]

                record = {
                    "project": name,
                    "sha": sha,
                    "date": date,
                    "message": message[:80],
                    "dep": dd.get("dep", ""),
                    "versionBefore": dd.get("versionBefore", ""),
                    "versionAfter": dd.get("versionAfter", ""),
                    "cvesIntroduced": cve_ids_intro,
                    "cvesResolved": cve_ids_res,
                    "apisBefore": api_before,
                    "apisAfter": api_after,
                    "apisDelta": api_delta,
                    "categoryDeltas": cat_deltas,
                    "hasSecurityKeyword": bool(
                        SECURITY_KEYWORDS.search(message)),
                }
                coincidences.append(record)

                # Classify per category (count per dep-commit event, not per CVE)
                if n_intro:
                    summary["totalCveIntroductions"] += n_intro
                    for cat in CATEGORIES:
                        cd = cat_deltas.get(cat, 0)
                        if cd > 0:
                            summary["cveIntroWithApiIncrease"][cat] += 1
                        elif cd < 0:
                            summary["cveIntroWithApiDecrease"][cat] += 1
                        else:
                            summary["cveIntroNoApiChange"][cat] += 1

                if n_res:
                    summary["totalCveResolutions"] += n_res
                    for cat in CATEGORIES:
                        cd = cat_deltas.get(cat, 0)
                        if cd < 0:
                            summary["cveResolvedWithApiDecrease"][cat] += 1
                        elif cd > 0:
                            summary["cveResolvedWithApiIncrease"][cat] += 1
                        else:
                            summary["cveResolvedNoApiChange"][cat] += 1

    return {"summary": summary, "details": coincidences}


# ---------------------------------------------------------------------------
# 4b. Statistical significance of CVE–API co-occurrence
# ---------------------------------------------------------------------------

def analyze_cve_api_significance(projects):
    """Build 2×2 contingency tables for CVE vs API change co-occurrence.

    For each consecutive pair of commits, for each dependency (by GA):
      - Did the dep have a CVE introduced or resolved?
      - Did the dep have a matching-direction API change?
        (CVE intro ↔ API increase, CVE resolved ↔ API decrease)

    Then test with Fisher's exact test whether co-occurrence is significant.

    Contingency table (per category, for CVE introductions):
                          | API increased | API not increased |
        CVE introduced    |      a        |        b          |
        No CVE introduced |      c        |        d          |

    Similar for CVE resolved ↔ API decreased.
    """
    # Collect all (dep, commit) transitions
    # For each: has_cve_intro, has_cve_resolved, api_delta per category
    all_transitions = []

    for name, proj in projects.items():
        cve_data = proj.get("cveTracking")
        tl = proj["timeline"]
        timeline = tl.get("timeline", [])
        if not cve_data or len(timeline) < 2:
            continue

        # Build CVE change index from cve_tracking perCommit
        # (sha, dep_ga) -> {intro: N, resolved: N}
        cve_index = {}
        for diff in cve_data.get("perCommit", []):
            if diff.get("isBaseline"):
                continue
            for dd in diff.get("depDetails", []):
                n_i = len(dd.get("cvesIntroduced", []))
                n_r = len(dd.get("cvesResolved", []))
                if n_i or n_r:
                    cve_index[(diff["sha"], dd["dep"])] = {
                        "intro": n_i, "resolved": n_r,
                        "catBefore": dd.get("catBefore", {}),
                        "catAfter": dd.get("catAfter", {}),
                    }

        # Walk consecutive commits, compute per-dep per-category changes
        for i in range(1, len(timeline)):
            cur = timeline[i]
            prev = timeline[i - 1]
            sha = cur.get("sha", "")

            # Collect per-dep API counts (by GA) for current and previous
            cur_deps = {}
            for _mod, md in cur.get("reachability", {}).items():
                for dk, cnt in md.get("depsDetail", {}).items():
                    ga = dep_ga(dk)
                    cur_deps[ga] = cur_deps.get(ga, 0) + cnt
            prev_deps = {}
            for _mod, md in prev.get("reachability", {}).items():
                for dk, cnt in md.get("depsDetail", {}).items():
                    ga = dep_ga(dk)
                    prev_deps[ga] = prev_deps.get(ga, 0) + cnt

            # Per-dep category totals (from reachableApisByCategory is
            # module-level, not dep-level; use catBefore/catAfter from
            # cve_tracking when available, otherwise just total API delta)
            all_gas = set(cur_deps.keys()) | set(prev_deps.keys())
            for ga in all_gas:
                cve_info = cve_index.get((sha, ga))
                has_cve_intro = cve_info["intro"] > 0 if cve_info else False
                has_cve_resolved = cve_info["resolved"] > 0 if cve_info else False

                total_delta = cur_deps.get(ga, 0) - prev_deps.get(ga, 0)

                # Per-category deltas (if available from cve_tracking)
                cat_deltas = {}
                if cve_info:
                    cb = cve_info.get("catBefore", {})
                    ca = cve_info.get("catAfter", {})
                    for cat in CATEGORIES:
                        cat_deltas[cat] = ca.get(cat, 0) - cb.get(cat, 0)

                all_transitions.append({
                    "has_cve_intro": has_cve_intro,
                    "has_cve_resolved": has_cve_resolved,
                    "total_delta": total_delta,
                    "cat_deltas": cat_deltas,
                })

    # Build contingency tables
    results = {"totalTransitions": len(all_transitions), "tests": {}}
    calc_steps = []

    # Test 1: CVE introduced ↔ total API increase
    a = sum(1 for t in all_transitions
            if t["has_cve_intro"] and t["total_delta"] > 0)
    b = sum(1 for t in all_transitions
            if t["has_cve_intro"] and t["total_delta"] <= 0)
    c = sum(1 for t in all_transitions
            if not t["has_cve_intro"] and t["total_delta"] > 0)
    d = sum(1 for t in all_transitions
            if not t["has_cve_intro"] and t["total_delta"] <= 0)

    calc_steps.append(
        "=== CVE Introduction ↔ Total Sensitive API Increase ===\n"
        f"Contingency table (all {len(all_transitions)} dep-commit transitions):\n"
        f"                     | API increased | API not increased |\n"
        f"  CVE introduced     | {a:>13} | {b:>17} |  row={a+b}\n"
        f"  No CVE introduced  | {c:>13} | {d:>17} |  row={c+d}\n"
        f"  column totals        {a+c:>13}   {b+d:>17}\n")

    test_intro = _fisher_test(a, b, c, d, "cve_intro_api_increase")
    results["tests"]["cveIntroApiIncrease"] = {
        "table": {"a": a, "b": b, "c": c, "d": d}, **test_intro}
    calc_steps.append(test_intro["calculation"])

    # Test 2: CVE resolved ↔ total API decrease
    a2 = sum(1 for t in all_transitions
             if t["has_cve_resolved"] and t["total_delta"] < 0)
    b2 = sum(1 for t in all_transitions
             if t["has_cve_resolved"] and t["total_delta"] >= 0)
    c2 = sum(1 for t in all_transitions
             if not t["has_cve_resolved"] and t["total_delta"] < 0)
    d2 = sum(1 for t in all_transitions
             if not t["has_cve_resolved"] and t["total_delta"] >= 0)

    calc_steps.append(
        "\n=== CVE Resolution ↔ Total Sensitive API Decrease ===\n"
        f"Contingency table:\n"
        f"                     | API decreased | API not decreased |\n"
        f"  CVE resolved       | {a2:>13} | {b2:>17} |  row={a2+b2}\n"
        f"  No CVE resolved    | {c2:>13} | {d2:>17} |  row={c2+d2}\n"
        f"  column totals        {a2+c2:>13}   {b2+d2:>17}\n")

    test_res = _fisher_test(a2, b2, c2, d2, "cve_resolved_api_decrease")
    results["tests"]["cveResolvedApiDecrease"] = {
        "table": {"a": a2, "b": b2, "c": c2, "d": d2}, **test_res}
    calc_steps.append(test_res["calculation"])

    # Also: how many API changes happen WITHOUT CVEs, and vice versa
    api_increase_no_cve = c
    api_decrease_no_cve = c2
    cve_intro_no_api_increase = b
    cve_resolved_no_api_decrease = b2
    no_cve_no_api_change = d  # for intro direction

    results["withoutCoOccurrence"] = {
        "apiIncreaseWithoutCveIntro": api_increase_no_cve,
        "apiDecreaseWithoutCveResolved": api_decrease_no_cve,
        "cveIntroWithoutApiIncrease": cve_intro_no_api_increase,
        "cveResolvedWithoutApiDecrease": cve_resolved_no_api_decrease,
    }

    calc_steps.append(
        f"\n=== Without co-occurrence ===\n"
        f"  API increases WITHOUT CVE introduction: {api_increase_no_cve}\n"
        f"  API decreases WITHOUT CVE resolution:   {api_decrease_no_cve}\n"
        f"  CVE introductions WITHOUT API increase:  {cve_intro_no_api_increase}\n"
        f"  CVE resolutions WITHOUT API decrease:    {cve_resolved_no_api_decrease}\n")

    results["calculationSteps"] = "\n".join(calc_steps)
    return results


def _fisher_test(a, b, c, d, label):
    """Run Fisher's exact test on a 2x2 table. Falls back to chi-squared."""
    n = a + b + c + d
    if n == 0:
        return {"pValue": None, "oddsRatio": None, "significant": False,
                "method": "none", "calculation": "No data.\n"}

    # Expected values under independence
    row1 = a + b
    row2 = c + d
    col1 = a + c
    col2 = b + d
    e_a = row1 * col1 / n if n else 0
    e_b = row1 * col2 / n if n else 0
    e_c = row2 * col1 / n if n else 0
    e_d = row2 * col2 / n if n else 0

    calc = (f"  Expected under independence (H0: CVE and API changes are independent):\n"
            f"    E(a)={e_a:.1f}  E(b)={e_b:.1f}  E(c)={e_c:.1f}  E(d)={e_d:.1f}\n")

    # Try Fisher's exact test first
    try:
        from scipy.stats import fisher_exact
        odds_ratio, p_value = fisher_exact([[a, b], [c, d]],
                                            alternative='two-sided')
        calc += (f"  Fisher's exact test (two-sided):\n"
                 f"    Odds ratio = {odds_ratio:.4f}\n"
                 f"    p-value = {p_value:.6f}\n"
                 f"    {'SIGNIFICANT' if p_value < 0.05 else 'NOT significant'}"
                 f" at α=0.05\n")
        if odds_ratio > 1:
            calc += f"    → CVE and API changes co-occur MORE than expected by chance.\n"
        elif odds_ratio < 1:
            calc += f"    → CVE and API changes co-occur LESS than expected by chance.\n"
        return {"pValue": p_value, "oddsRatio": odds_ratio,
                "significant": p_value < 0.05,
                "method": "fisher_exact", "calculation": calc}
    except ImportError:
        pass

    # Fallback: chi-squared with Yates correction
    calc += "  (scipy not available, using chi-squared with Yates correction)\n"
    chi2 = 0
    for obs, exp in [(a, e_a), (b, e_b), (c, e_c), (d, e_d)]:
        if exp > 0:
            chi2 += (abs(obs - exp) - 0.5) ** 2 / exp

    # Exact p-value for chi2 with df=1: P(X > chi2) = erfc(sqrt(chi2/2))
    import math
    if chi2 == 0:
        p_value = 1.0
    else:
        p_value = math.erfc(math.sqrt(chi2 / 2))

    odds_ratio = (a * d) / (b * c) if b * c > 0 else float('inf')

    calc += (f"  Chi-squared (Yates) = {chi2:.4f}, df=1\n"
             f"  Approximate p-value = {p_value:.6f}\n"
             f"  Odds ratio = {odds_ratio:.4f}\n"
             f"  {'SIGNIFICANT' if p_value < 0.05 else 'NOT significant'}"
             f" at α=0.05\n")

    return {"pValue": p_value, "oddsRatio": odds_ratio,
            "significant": p_value < 0.05,
            "method": "chi_squared_yates", "calculation": calc}


# ---------------------------------------------------------------------------
# 5. Sensitive API trends over time (per category, per year)
# ---------------------------------------------------------------------------

def analyze_api_trends(projects):
    year_cat_totals = defaultdict(lambda: {c: [] for c in CATEGORIES})
    per_project_trends = {}

    for name, proj in projects.items():
        tl = proj["timeline"]
        timeline = tl.get("timeline", [])
        proj_years = defaultdict(lambda: {c: 0 for c in CATEGORIES})

        for entry in timeline:
            date = entry.get("date", "")
            try:
                year = date[:4]
                if not year.isdigit():
                    continue
            except (IndexError, TypeError):
                continue

            cat_totals = {}
            for _mod, mod_data in entry.get("reachability", {}).items():
                for cat, cnt in mod_data.get(
                        "reachableApisByCategory", {}).items():
                    cat_totals[cat] = cat_totals.get(cat, 0) + cnt

            for cat in CATEGORIES:
                val = cat_totals.get(cat, 0)
                proj_years[year][cat] = max(proj_years[year][cat], val)

        # Compute deltas between first and last entry per year
        proj_trend = []
        for entry in timeline:
            date = entry.get("date", "")
            cat_totals = {}
            for _mod, mod_data in entry.get("reachability", {}).items():
                for cat, cnt in mod_data.get(
                        "reachableApisByCategory", {}).items():
                    cat_totals[cat] = cat_totals.get(cat, 0) + cnt
            proj_trend.append({"date": date, "cats": cat_totals})

        if len(proj_trend) >= 2:
            first = proj_trend[0]["cats"]
            last = proj_trend[-1]["cats"]
            per_project_trends[name] = {
                "firstDate": proj_trend[0]["date"],
                "lastDate": proj_trend[-1]["date"],
                "firstCats": {c: first.get(c, 0) for c in CATEGORIES},
                "lastCats": {c: last.get(c, 0) for c in CATEGORIES},
                "deltas": {c: last.get(c, 0) - first.get(c, 0)
                           for c in CATEGORIES},
                "direction": {c: ("increasing" if last.get(c, 0) > first.get(c, 0)
                                  else "decreasing" if last.get(c, 0) < first.get(c, 0)
                                  else "stable")
                              for c in CATEGORIES},
            }

        # Aggregate yearly data across projects
        sorted_years = sorted(proj_years.keys())
        for year in sorted_years:
            for cat in CATEGORIES:
                year_cat_totals[year][cat].append(proj_years[year][cat])

    # Compute per-year averages
    yearly_summary = {}
    for year in sorted(year_cat_totals.keys()):
        yearly_summary[year] = {}
        for cat in CATEGORIES:
            vals = year_cat_totals[year][cat]
            yearly_summary[year][cat] = {
                "sum": sum(vals),
                "mean": round(sum(vals) / len(vals), 1) if vals else 0,
                "count": len(vals),
            }

    # Overall direction
    overall_direction = {}
    increasing = 0
    decreasing = 0
    for cat in CATEGORIES:
        inc = sum(1 for p in per_project_trends.values()
                  if p["direction"][cat] == "increasing")
        dec = sum(1 for p in per_project_trends.values()
                  if p["direction"][cat] == "decreasing")
        sta = sum(1 for p in per_project_trends.values()
                  if p["direction"][cat] == "stable")
        overall_direction[cat] = {
            "increasing": inc, "decreasing": dec, "stable": sta}
        increasing += inc
        decreasing += dec

    return {
        "perProject": per_project_trends,
        "yearlySummary": yearly_summary,
        "overallDirection": overall_direction,
        "overallTrend": ("mostly increasing" if increasing > decreasing
                         else "mostly decreasing" if decreasing > increasing
                         else "mixed"),
    }


# ---------------------------------------------------------------------------
# 7. High-API dep trends (do they get replaced / reduced?)
# ---------------------------------------------------------------------------

def analyze_high_api_dep_trends(projects, min_apis=50):
    dep_histories = defaultdict(lambda: {
        "projects": set(), "history": [],
        "maxApis": 0, "lastApis": 0, "firstApis": 0,
    })

    for name, proj in projects.items():
        tl = proj["timeline"]
        timeline = tl.get("timeline", [])
        if not timeline:
            continue

        # Track each dep's API count across commits
        dep_per_commit = defaultdict(list)
        for entry in timeline:
            date = entry.get("date", "")
            for _mod, mod_data in entry.get("reachability", {}).items():
                for dep_key, api_count in mod_data.get(
                        "depsDetail", {}).items():
                    ga = dep_ga(dep_key)
                    dep_per_commit[(name, ga)].append({
                        "date": date, "apis": api_count,
                        "version": dep_key.split(":")[-1]
                                   if len(dep_key.split(":")) >= 3 else "",
                    })

        for (proj_name, ga), history in dep_per_commit.items():
            if not history:
                continue
            max_apis = max(h["apis"] for h in history)
            if max_apis < min_apis:
                continue

            info = dep_histories[ga]
            info["projects"].add(proj_name)
            info["history"].append({
                "project": proj_name,
                "firstApis": history[0]["apis"],
                "lastApis": history[-1]["apis"],
                "maxApis": max_apis,
                "firstVersion": history[0]["version"],
                "lastVersion": history[-1]["version"],
                "firstDate": history[0]["date"],
                "lastDate": history[-1]["date"],
                "dataPoints": len(history),
            })
            info["maxApis"] = max(info["maxApis"], max_apis)

    result = []
    for ga, info in dep_histories.items():
        histories = info["history"]
        trends = []
        for h in histories:
            delta = h["lastApis"] - h["firstApis"]
            if h["firstApis"] == 0 and h["lastApis"] == 0:
                trend = "absent"
            elif h["lastApis"] == 0:
                trend = "removed"
            elif delta < -h["firstApis"] * 0.2:
                trend = "decreasing"
            elif delta > h["firstApis"] * 0.2:
                trend = "increasing"
            else:
                trend = "stable"
            trends.append(trend)
            h["trend"] = trend

        # Classify dep lifecycle across projects
        dep_changes = set()
        for h in histories:
            if h["firstApis"] == 0 and h["lastApis"] > 0:
                dep_changes.add("added")
            elif h["firstApis"] > 0 and h["lastApis"] == 0:
                dep_changes.add("removed")
            elif h["firstVersion"] != h["lastVersion"]:
                dep_changes.add("updated")
            else:
                dep_changes.add("unchanged")

        result.append({
            "dep": ga,
            "projectCount": len(info["projects"]),
            "projects": sorted(info["projects"]),
            "maxApis": info["maxApis"],
            "depChanges": sorted(dep_changes),
            "trends": trends,
            "dominantTrend": max(set(trends), key=trends.count),
            "perProject": histories,
        })

    result.sort(key=lambda x: (-x["maxApis"], -x["projectCount"]))
    return {"deps": result[:50], "minApisThreshold": min_apis,
            "totalHighApiDeps": len(result)}


# ---------------------------------------------------------------------------
# 7. Probability of a commit introducing a sensitive API change
# ---------------------------------------------------------------------------

def analyze_change_probability(projects):
    """For each project and overall, compute the probability that an analyzed
    commit changes sensitive API reachability, per category."""
    per_project = {}
    total_commits = 0
    total_with_change = {c: 0 for c in CATEGORIES}
    total_with_any_change = 0

    for name, proj in projects.items():
        tl = proj["timeline"]
        timeline = tl.get("timeline", [])
        if len(timeline) < 2:
            continue

        n_transitions = len(timeline) - 1
        cat_changed = {c: 0 for c in CATEGORIES}
        any_changed = 0

        for i in range(1, len(timeline)):
            cur_cats = {}
            prev_cats = {}
            for _mod, md in timeline[i].get("reachability", {}).items():
                for cat, cnt in md.get(
                        "reachableApisByCategory", {}).items():
                    cur_cats[cat] = cur_cats.get(cat, 0) + cnt
            for _mod, md in timeline[i - 1].get("reachability", {}).items():
                for cat, cnt in md.get(
                        "reachableApisByCategory", {}).items():
                    prev_cats[cat] = prev_cats.get(cat, 0) + cnt

            commit_changed = False
            for cat in CATEGORIES:
                if cur_cats.get(cat, 0) != prev_cats.get(cat, 0):
                    cat_changed[cat] += 1
                    commit_changed = True
            if commit_changed:
                any_changed += 1

        per_project[name] = {
            "totalTransitions": n_transitions,
            "withAnyChange": any_changed,
            "probAnyChange": round(any_changed / n_transitions, 4)
                             if n_transitions else 0,
            "perCategory": {
                c: {
                    "changed": cat_changed[c],
                    "probability": round(cat_changed[c] / n_transitions, 4)
                                   if n_transitions else 0,
                }
                for c in CATEGORIES
            },
        }

        total_commits += n_transitions
        total_with_any_change += any_changed
        for c in CATEGORIES:
            total_with_change[c] += cat_changed[c]

    return {
        "perProject": per_project,
        "overall": {
            "totalTransitions": total_commits,
            "withAnyChange": total_with_any_change,
            "probAnyChange": round(total_with_any_change / total_commits, 4)
                             if total_commits else 0,
            "perCategory": {
                c: {
                    "changed": total_with_change[c],
                    "probability": round(total_with_change[c] / total_commits, 4)
                                   if total_commits else 0,
                }
                for c in CATEGORIES
            },
        },
    }


ROOT_CAUSE_KEYS = [
    "CLIENT_INITIATED", "CLIENT_INITIATED_INDIRECT",
    "DEP_INITIATED", "DEP_INITIATED_INDIRECT",
    "INDIRECT_DEP_INITIATED",
]
ROOT_CAUSE_LABELS = {
    "CLIENT_INITIATED": "Client Initiated",
    "CLIENT_INITIATED_INDIRECT": "Client Initiated (Indirect)",
    "DEP_INITIATED": "Dep Initiated",
    "DEP_INITIATED_INDIRECT": "Dep Initiated (Indirect)",
    "INDIRECT_DEP_INITIATED": "Indirect Dep Initiated",
}
ROOT_CAUSE_COLORS = {
    "CLIENT_INITIATED": "#2980b9",
    "CLIENT_INITIATED_INDIRECT": "#e07a3a",
    "DEP_INITIATED": "#c0392b",
    "DEP_INITIATED_INDIRECT": "#c0392b",
    "INDIRECT_DEP_INITIATED": "#6c4ab6",
}


# ---------------------------------------------------------------------------
# 8. Root cause attribution totals
# ---------------------------------------------------------------------------

def analyze_root_cause_totals(projects):
    totals = {k: 0 for k in ROOT_CAUSE_KEYS}
    total_additions = 0
    total_removals = 0
    per_project = {}

    for name, proj in projects.items():
        attr = proj.get("attribution")
        if not attr:
            continue
        summary = attr.get("summary", {})
        proj_counts = {}
        for k in ROOT_CAUSE_KEYS:
            count = summary.get(k, 0)
            totals[k] += count
            proj_counts[k] = count
        proj_adds = summary.get("totalAdditions", 0)
        proj_rems = summary.get("totalRemovals", 0)
        total_additions += proj_adds
        total_removals += proj_rems
        proj_counts["totalAdditions"] = proj_adds
        proj_counts["totalRemovals"] = proj_rems
        per_project[name] = proj_counts

    grand_total = sum(totals.values())
    percentages = {k: round(v / grand_total * 100, 1) if grand_total else 0
                   for k, v in totals.items()}

    return {
        "totals": totals,
        "grandTotal": grand_total,
        "totalAdditions": total_additions,
        "totalRemovals": total_removals,
        "percentages": percentages,
        "perProject": per_project,
    }


# ---------------------------------------------------------------------------
# 9. CVE × root cause cross-tabulation
# ---------------------------------------------------------------------------

def analyze_cve_root_cause(projects):
    cross_tab = {
        "introduced": {k: 0 for k in ROOT_CAUSE_KEYS},
        "resolved": {k: 0 for k in ROOT_CAUSE_KEYS},
    }
    critical_incidents = []

    for name, proj in projects.items():
        cve_data = proj.get("cveTracking")
        attr_data = proj.get("attribution")
        if not cve_data or not attr_data:
            continue

        # Build a lookup: (sha, depGa) → list of root causes from attribution
        attr_index = {}
        for transition in attr_data.get("transitions", []):
            sha = transition.get("currSha", "")
            for change in transition.get("changes", []):
                dep_ga = change.get("depGa", "")
                root_cause = change.get("rootCause", "")
                direction = change.get("direction", "")
                key = (sha, dep_ga)
                if key not in attr_index:
                    attr_index[key] = []
                attr_index[key].append({
                    "rootCause": root_cause,
                    "direction": direction,
                    "sensitiveApi": change.get("sensitiveApi", ""),
                    "criticality": change.get("criticality", 0),
                })

        # Match CVE events to attribution data
        for diff in cve_data.get("perCommit", []):
            if diff.get("isBaseline"):
                continue
            sha = diff.get("sha", "")
            date = diff.get("date", "")
            message = diff.get("message", "")

            for dd in diff.get("depDetails", []):
                dep = dd.get("dep", "")
                n_intro = len(dd.get("cvesIntroduced", []))
                n_res = len(dd.get("cvesResolved", []))
                if not n_intro and not n_res:
                    continue

                # Find matching attribution entries
                attr_entries = attr_index.get((sha, dep), [])
                if not attr_entries:
                    continue

                # Use the highest-criticality root cause for this (sha, dep)
                best = max(attr_entries, key=lambda a: a.get("criticality", 0))
                root_cause = best.get("rootCause", "")
                if root_cause not in ROOT_CAUSE_KEYS:
                    continue

                if n_intro:
                    cross_tab["introduced"][root_cause] += n_intro
                    # Track critical incidents (dep/indirect dep initiated)
                    if root_cause in ("DEP_INITIATED", "DEP_INITIATED_INDIRECT",
                                      "INDIRECT_DEP_INITIATED"):
                        cve_ids = [c.get("cveId", "")
                                   for c in dd.get("cvesIntroduced", [])]
                        critical_incidents.append({
                            "project": name,
                            "sha": sha,
                            "date": date,
                            "message": message[:80],
                            "dep": dep,
                            "rootCause": root_cause,
                            "cvesIntroduced": cve_ids,
                            "versionBefore": dd.get("versionBefore", ""),
                            "versionAfter": dd.get("versionAfter", ""),
                        })

                if n_res:
                    cross_tab["resolved"][root_cause] += n_res

    return {
        "crossTab": cross_tab,
        "criticalIncidents": critical_incidents,
        "totalCriticalIncidents": len(critical_incidents),
    }


# ---------------------------------------------------------------------------
# HTML Report
# ---------------------------------------------------------------------------

def _esc(s):
    return (str(s).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#39;"))


def _build_change_prob_html(chg_prob):
    pp = chg_prob.get("perProject", {})
    ov = chg_prob.get("overall", {})

    prob_rows = ""
    for pname in sorted(pp.keys()):
        p = pp[pname]
        pc = p.get("perCategory", {})
        cat_cells = ""
        for c in CATEGORIES:
            ci = pc.get(c, {})
            cat_cells += (f"<td>{ci.get('probability', 0):.1%}"
                          f" ({ci.get('changed', 0)})</td>")
        prob_rows += (
            f"<tr><td class='mono'>{_esc(pname)}</td>"
            f"<td>{p.get('totalTransitions', 0)}</td>"
            f"<td><b>{p.get('probAnyChange', 0):.1%}</b>"
            f" ({p.get('withAnyChange', 0)})</td>"
            f"{cat_cells}</tr>")

    ov_cats = ""
    ovc = ov.get("perCategory", {})
    for c in CATEGORIES:
        ci = ovc.get(c, {})
        ov_cats += (f"<td>{ci.get('probability', 0):.1%}"
                    f" ({ci.get('changed', 0)})</td>")

    return f"""<div class="section" id="change-prob">
    <h2>6. Probability of Sensitive API Change Per Commit</h2>
    <p class="note">
        For each pair of consecutive analyzed commits, what is the probability that
        the sensitive API reachability changed? Computed per category and overall (any category).
    </p>
    <table>
        <thead>
            <tr>
                <th>Project</th><th>Transitions</th>
                <th>P(Any Change)</th>
                <th>P(FileAccess)</th><th>P(Network)</th><th>P(Process)</th>
            </tr>
        </thead>
        <tbody>{prob_rows}
        <tr style="font-weight:700">
            <td>All Projects</td>
            <td>{ov.get('totalTransitions', 0)}</td>
            <td><b>{ov.get('probAnyChange', 0):.1%}</b>
                ({ov.get('withAnyChange', 0)})</td>
            {ov_cats}
        </tr>
        </tbody>
    </table>
    <p class="note" style="margin-top:8px">
        Values show probability and (count of commits with change) in parentheses.
    </p>
</div>"""


def _build_root_cause_html(rc):
    if not rc or not rc.get("totals"):
        return ""

    totals = rc["totals"]
    pcts = rc["percentages"]
    grand = rc["grandTotal"]
    pp = rc.get("perProject", {})

    # Totals table
    total_rows = ""
    for k in ROOT_CAUSE_KEYS:
        col = ROOT_CAUSE_COLORS.get(k, "#666")
        total_rows += (
            f"<tr><td style='color:{col};font-weight:600'>"
            f"{ROOT_CAUSE_LABELS.get(k, k)}</td>"
            f"<td>{totals.get(k, 0)}</td>"
            f"<td>{pcts.get(k, 0)}%</td></tr>")

    # Per-project table
    proj_rows = ""
    for pname in sorted(pp.keys()):
        p = pp[pname]
        cells = "".join(f"<td>{p.get(k, 0)}</td>" for k in ROOT_CAUSE_KEYS)
        total = sum(p.get(k, 0) for k in ROOT_CAUSE_KEYS)
        proj_rows += (f"<tr><td class='mono'>{_esc(pname)}</td>"
                      f"{cells}<td><b>{total}</b></td>"
                      f"<td>{p.get('totalAdditions', 0)}</td>"
                      f"<td>{p.get('totalRemovals', 0)}</td></tr>")

    # Chart data
    chart_labels = json.dumps([ROOT_CAUSE_LABELS.get(k, k) for k in ROOT_CAUSE_KEYS])
    chart_values = json.dumps([totals.get(k, 0) for k in ROOT_CAUSE_KEYS])
    chart_colors = json.dumps([ROOT_CAUSE_COLORS.get(k, "#666") for k in ROOT_CAUSE_KEYS])

    rc_header = "".join(
        f"<th style='color:{ROOT_CAUSE_COLORS.get(k, '#666')}'>"
        f"{ROOT_CAUSE_LABELS.get(k, k)[:15]}</th>"
        for k in ROOT_CAUSE_KEYS)

    return f"""<div class="section" id="root-cause">
    <h2>7. Root Cause Attribution</h2>
    <p class="note">
        For each sensitive API change, who initiated it? Based on boundary stability
        and dependency version comparison. {grand} total classified changes
        across {len(pp)} projects.
    </p>
    <table style="max-width:600px">
        <thead><tr><th>Root Cause</th><th>Count</th><th>%</th></tr></thead>
        <tbody>{total_rows}
        <tr style="font-weight:700"><td>Total</td><td>{grand}</td><td>100%</td></tr>
        </tbody>
    </table>
    <div style="max-width:600px;height:300px;margin:16px 0">
        <canvas id="rootCauseChart"></canvas>
    </div>
    <script>
    new Chart(document.getElementById('rootCauseChart'), {{
        type: 'bar',
        data: {{
            labels: {chart_labels},
            datasets: [{{
                data: {chart_values},
                backgroundColor: {chart_colors},
            }}]
        }},
        options: {{
            responsive: true, maintainAspectRatio: false,
            plugins: {{ legend: {{ display: false }} }},
            scales: {{ y: {{ beginAtZero: true, title: {{ display: true, text: 'Count' }} }} }}
        }}
    }});
    </script>

    <h3 style="margin-top:24px">Per Project</h3>
    <div style="overflow-x:auto">
    <table>
        <thead><tr><th>Project</th>{rc_header}
            <th>Total</th><th>Additions</th><th>Removals</th></tr></thead>
        <tbody>{proj_rows}</tbody>
    </table>
    </div>
</div>"""


def _build_cve_root_cause_html(cve_rc):
    if not cve_rc:
        return ""

    ct = cve_rc.get("crossTab", {})
    incidents = cve_rc.get("criticalIncidents", [])

    # Cross-tabulation table
    ct_rows = ""
    for k in ROOT_CAUSE_KEYS:
        col = ROOT_CAUSE_COLORS.get(k, "#666")
        intro = ct.get("introduced", {}).get(k, 0)
        resolved = ct.get("resolved", {}).get(k, 0)
        ct_rows += (
            f"<tr><td style='color:{col};font-weight:600'>"
            f"{ROOT_CAUSE_LABELS.get(k, k)}</td>"
            f"<td style='color:var(--red)'>{intro}</td>"
            f"<td style='color:var(--green)'>{resolved}</td></tr>")

    total_intro = sum(ct.get("introduced", {}).values())
    total_res = sum(ct.get("resolved", {}).values())

    # Critical incidents table
    incident_rows = ""
    for idx, inc in enumerate(incidents, 1):
        cves = ", ".join(inc.get("cvesIntroduced", []))
        rc_label = ROOT_CAUSE_LABELS.get(inc.get("rootCause", ""), "?")
        incident_rows += (
            f"<tr><td>{idx}</td>"
            f"<td class='mono'>{_esc(inc.get('project', ''))}</td>"
            f"<td class='mono'>{_esc(inc.get('sha', ''))}</td>"
            f"<td>{_esc(inc.get('date', ''))}</td>"
            f"<td class='mono'>{_esc(inc.get('dep', ''))}</td>"
            f"<td style='font-size:0.78rem'>"
            f"{_esc(inc.get('versionBefore', ''))} &rarr; "
            f"{_esc(inc.get('versionAfter', ''))}</td>"
            f"<td style='color:var(--red)'>{_esc(cves)}</td>"
            f"<td>{_esc(rc_label)}</td>"
            f"<td style='font-size:0.78rem'>{_esc(inc.get('message', ''))}</td></tr>")

    return f"""<div class="section" id="cve-root-cause">
    <h2>8. CVE &times; Root Cause Cross-Tabulation</h2>
    <p class="note">
        When a CVE is introduced or resolved, what was the root cause of the
        corresponding sensitive API change? This highlights silent dep-initiated
        changes that also introduce vulnerabilities.
    </p>
    <table style="max-width:500px">
        <thead><tr><th>Root Cause</th><th>CVEs Introduced</th><th>CVEs Resolved</th></tr></thead>
        <tbody>{ct_rows}
        <tr style="font-weight:700"><td>Total</td>
            <td>{total_intro}</td><td>{total_res}</td></tr>
        </tbody>
    </table>

    <h3 style="margin-top:24px">Critical Incidents: Dep-Initiated CVE Introductions</h3>
    <p class="note">
        CVEs introduced where the root cause was dep-initiated or indirect-dep-initiated —
        the most critical cases where vulnerabilities appeared silently.
        {len(incidents)} incidents found.
    </p>
    {"<div style='overflow-x:auto'><table><thead><tr>"
     "<th>#</th><th>Project</th><th>SHA</th><th>Date</th><th>Dep</th>"
     "<th>Version</th><th>CVEs</th><th>Root Cause</th><th>Message</th>"
     "</tr></thead><tbody>" + incident_rows + "</tbody></table></div>"
     if incidents else "<p>No dep-initiated CVE introductions found.</p>"}
</div>"""


def generate_summary_html(report):
    meta = report["metadata"]
    ct = report["changeTypes"]
    bcr = report["bigChangeReasons"]
    vol = report["volatileDeps"]
    chg_prob = report.get("changeProbability", {})
    trends = report["apiTrends"]
    high_deps = report["highApiDepTrends"]

    # Change types table
    ct_rows = ""
    for case_key, label in [("dep_removed", "Dep Removed"),
                             ("dep_added", "Dep Added"),
                             ("dep_updated", "Dep Updated"),
                             ("client_code_change", "Client/Dep Code Change")]:
        ct_rows += (f"<tr><td>{label}</td>"
                    f"<td>{ct['totals'].get(case_key, 0)}</td>"
                    f"<td>{ct['percentages'].get(case_key, 0)}%</td></tr>")

    # Per-project change types
    ct_proj_rows = ""
    for pname in sorted(ct.get("perProject", {}).keys()):
        p = ct["perProject"][pname]
        total = sum(p.values())
        ct_proj_rows += (f"<tr><td class='mono'>{_esc(pname)}</td>"
                         f"<td>{p.get('dep_removed', 0)}</td>"
                         f"<td>{p.get('dep_added', 0)}</td>"
                         f"<td>{p.get('dep_updated', 0)}</td>"
                         f"<td>{p.get('client_code_change', 0)}</td>"
                         f"<td><b>{total}</b></td></tr>")

    # Big change reasons
    bcr_rows = ""
    for reason, label in [("versionUpdate", "Version Update"),
                           ("depAdded", "Dep Added"),
                           ("depRemoved", "Dep Removed"),
                           ("clientCodeChange", "Client/Dep Code Change")]:
        bcr_rows += (f"<tr><td>{label}</td>"
                     f"<td>{bcr['reasonCounts'].get(reason, 0)}</td>"
                     f"<td>{bcr['percentages'].get(reason, 0)}%</td></tr>")

    # Volatile deps table
    vol_rows = ""
    for d in vol.get("deps", [])[:30]:
        vol_rows += (f"<tr><td class='mono'>{_esc(d['dep'])}</td>"
                     f"<td>{d['projectCount']}</td>"
                     f"<td>{d['totalEvents']}</td>"
                     f"<td>{d['updated']}</td>"
                     f"<td>{d['added']}</td>"
                     f"<td>{d['removed']}</td>"
                     f"<td>{d['codeChange']}</td>"
                     f"<td style='font-size:0.75rem'>"
                     f"{', '.join(d['projects'])}</td></tr>")

    # API trend per project
    trend_rows = ""
    trend_totals_first = {c: 0 for c in CATEGORIES}
    trend_totals_last = {c: 0 for c in CATEGORIES}
    for pname in sorted(trends.get("perProject", {}).keys()):
        t = trends["perProject"][pname]
        cells = ""
        for cat in CATEGORIES:
            delta = t["deltas"][cat]
            direction = t["direction"][cat]
            cls = ("delta-up" if direction == "increasing"
                   else "delta-down" if direction == "decreasing" else "")
            sign = f"+{delta}" if delta > 0 else str(delta)
            cells += (f"<td>{t['firstCats'][cat]}</td>"
                      f"<td>{t['lastCats'][cat]}</td>"
                      f"<td class='{cls}'>{sign}</td>")
            trend_totals_first[cat] += t["firstCats"][cat]
            trend_totals_last[cat] += t["lastCats"][cat]
        trend_rows += (f"<tr><td class='mono'>{_esc(pname)}</td>"
                       f"<td>{_esc(t['firstDate'])}</td>"
                       f"<td>{_esc(t['lastDate'])}</td>"
                       f"{cells}</tr>")

    # Totals row
    total_cells = ""
    for cat in CATEGORIES:
        td = trend_totals_last[cat] - trend_totals_first[cat]
        cls = "delta-up" if td > 0 else "delta-down" if td < 0 else ""
        sign = f"+{td}" if td > 0 else str(td)
        total_cells += (f"<td>{trend_totals_first[cat]}</td>"
                        f"<td>{trend_totals_last[cat]}</td>"
                        f"<td class='{cls}'>{sign}</td>")
    trend_rows += (f"<tr style='font-weight:700'><td>All Projects</td>"
                   f"<td>—</td><td>—</td>{total_cells}</tr>")

    # Overall direction
    dir_rows = ""
    for cat in CATEGORIES:
        d = trends["overallDirection"][cat]
        dir_rows += (f"<tr><td>{CAT_LABELS[cat]}</td>"
                     f"<td class='delta-up'>{d['increasing']}</td>"
                     f"<td class='delta-down'>{d['decreasing']}</td>"
                     f"<td>{d['stable']}</td></tr>")

    # High-API dep trends
    high_dep_rows = ""
    for d in high_deps.get("deps", [])[:30]:
        proj_details = []
        for h in d["perProject"]:
            delta = h["lastApis"] - h["firstApis"]
            sign = f"+{delta}" if delta > 0 else str(delta)
            proj_details.append(
                f"{h['project']}: {h['firstApis']}→{h['lastApis']} "
                f"({sign}, {h['trend']})")
        high_dep_rows += (
            f"<tr><td class='mono'>{_esc(d['dep'])}</td>"
            f"<td>{d['maxApis']}</td>"
            f"<td>{d['projectCount']}</td>"
            f"<td>{d['dominantTrend']}</td>"
            f"<td>{', '.join(d.get('depChanges', []))}</td>"
            f"<td style='font-size:0.75rem'>{'<br>'.join(proj_details)}</td>"
            f"</tr>")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Cross-Project Analysis</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4/dist/chart.umd.min.js"></script>
<style>
:root {{
    --bg: #fafafa; --fg: #1a1a1a; --card: #fff; --border: #e0e0e0;
    --muted: #666; --green: #2d6a4f; --red: #c0392b; --blue: #2980b9;
    --orange: #e07a3a; --purple: #6c4ab6;
    --badge-add: #e8f5e9; --badge-add-fg: #2e7d32;
}}
@media (prefers-color-scheme: dark) {{
    :root:not([data-theme="light"]) {{
        --bg: #181a1b; --fg: #d4d4d4; --card: #232526; --border: #3a3a3a;
        --muted: #999; --green: #52b788; --red: #e74c3c; --blue: #5dade2;
        --orange: #e8945a; --purple: #9b7fd4;
        --badge-add: #1b3a1b; --badge-add-fg: #81c784;
    }}
}}
:root[data-theme="dark"] {{
    --bg: #181a1b; --fg: #d4d4d4; --card: #232526; --border: #3a3a3a;
    --muted: #999; --green: #52b788; --red: #e74c3c; --blue: #5dade2;
    --orange: #e8945a; --purple: #9b7fd4;
    --badge-add: #1b3a1b; --badge-add-fg: #81c784;
}}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: var(--bg); color: var(--fg);
    padding: 24px 16px; max-width: 1400px; margin: 0 auto;
}}
h1 {{ font-size: 1.5rem; margin-bottom: 4px; }}
h2 {{ font-size: 1.1rem; margin-bottom: 12px; }}
.subtitle {{ color: var(--muted); font-size: 0.9rem; margin-bottom: 24px; }}
.section {{
    background: var(--card); border: 1px solid var(--border); border-radius: 8px;
    padding: 24px; margin-bottom: 24px;
}}
table {{ border-collapse: collapse; width: 100%; font-size: 0.85rem; }}
th, td {{ border: 1px solid var(--border); padding: 6px 10px; text-align: left; }}
th {{ background: var(--bg); font-weight: 600; position: sticky; top: 0; }}
.mono {{ font-family: monospace; font-size: 0.82rem; }}
.delta-up {{ color: var(--red); font-weight: 600; }}
.delta-down {{ color: var(--green); font-weight: 600; }}
.note {{ font-size: 0.82rem; color: var(--muted); margin-bottom: 12px; font-style: italic; }}
.toc {{ margin-bottom: 24px; }}
.toc a {{ color: var(--blue); text-decoration: none; margin-right: 16px; font-size: 0.9rem; }}
.toc a:hover {{ text-decoration: underline; }}
</style>
</head>
<body>

<h1>Cross-Project Analysis</h1>
<p class="subtitle">
    {meta['projectCount']} projects &middot; generated {meta['generated'][:16]}
</p>

<div class="toc">
    <a href="#change-types">1. Change Types</a>
    <a href="#big-changes">2. Big Change Reasons</a>
    <a href="#volatile">3. Volatile Deps</a>
    <a href="#trends">4. API Trends</a>
    <a href="#high-deps">5. High-API Dep Trends</a>
    <a href="#change-prob">6. Change Probability</a>
    <a href="#root-cause">7. Root Cause Attribution</a>
    <a href="#cve-root-cause">8. CVE &times; Root Cause</a>
</div>

<div class="section" id="change-types">
    <h2>1. Change Type Totals Across All Projects</h2>
    <table>
        <thead><tr><th>Change Type</th><th>Total</th><th>%</th></tr></thead>
        <tbody>{ct_rows}
        <tr style="font-weight:700"><td>Grand Total</td>
            <td>{ct['grandTotal']}</td><td>100%</td></tr>
        </tbody>
    </table>

    <h2 style="margin-top:24px">Per Project</h2>
    <div style="overflow-x:auto">
    <table>
        <thead><tr><th>Project</th><th>Removed</th><th>Added</th>
            <th>Updated</th><th>Client/Dep Code</th><th>Total</th></tr></thead>
        <tbody>{ct_proj_rows}</tbody>
    </table>
    </div>
</div>

<div class="section" id="big-changes">
    <h2>2. Top Reasons for Big Changes (top {bcr['topNPerProject']} per project)</h2>
    <p class="note">What type of dependency change most often causes the biggest
    sensitive API reachability swings?</p>
    <table>
        <thead><tr><th>Reason</th><th>Count</th><th>%</th></tr></thead>
        <tbody>{bcr_rows}
        <tr><td><i>Mixed (multiple types in one commit)</i></td>
            <td>{bcr['reasonCounts'].get('mixed', 0)}</td><td>—</td></tr>
        </tbody>
    </table>
</div>

<div class="section" id="volatile">
    <h2>3. Most Volatile Dependencies Across Projects</h2>
    <p class="note">Dependencies with the most change events across all projects,
    ranked by how many projects they appear in.</p>
    <div style="overflow-x:auto">
    <table>
        <thead><tr><th>Dependency</th><th>Projects</th><th>Total Events</th>
            <th>Updated</th><th>Added</th><th>Removed</th>
            <th>Code Change</th><th>In Projects</th></tr></thead>
        <tbody>{vol_rows}</tbody>
    </table>
    </div>
</div>

<div class="section" id="trends">
    <h2>4. Sensitive API Trends Over Time</h2>
    <p class="note">
        For each project, comparing the first and last analyzed commit:
        are sensitive APIs increasing or decreasing per category?
    </p>

    <h3 style="margin-top:16px">Overall direction across projects</h3>
    <table style="max-width:400px">
        <thead><tr><th>Category</th><th>↑ Increasing</th><th>↓ Decreasing</th><th>Stable</th></tr></thead>
        <tbody>{dir_rows}</tbody>
    </table>

    <h3 style="margin-top:16px">Per project (first → last commit)</h3>
    <div style="overflow-x:auto">
    <table>
        <thead>
            <tr>
                <th rowspan="2">Project</th><th rowspan="2">First</th><th rowspan="2">Last</th>
                <th colspan="3" style="text-align:center">FileAccess</th>
                <th colspan="3" style="text-align:center">Network</th>
                <th colspan="3" style="text-align:center">Process</th>
            </tr>
            <tr>
                <th>Start</th><th>End</th><th>Δ</th>
                <th>Start</th><th>End</th><th>Δ</th>
                <th>Start</th><th>End</th><th>Δ</th>
            </tr>
        </thead>
        <tbody>{trend_rows}</tbody>
    </table>
    </div>
</div>

<div class="section" id="high-deps">
    <h2>5. High Sensitive-API Dependencies — Trends</h2>
    <p class="note">
        Dependencies that reached ≥{high_deps['minApisThreshold']} reachable sensitive APIs
        at any point. Do they get replaced, reduced, or stay?
        ({high_deps['totalHighApiDeps']} total, showing top 30 by peak API count)
    </p>
    <div style="overflow-x:auto">
    <table>
        <thead><tr><th>Dependency</th><th>Peak APIs</th><th>Projects</th>
            <th>Dominant Trend</th><th>Dep Lifecycle</th>
            <th>Details</th></tr></thead>
        <tbody>{high_dep_rows}</tbody>
    </table>
    </div>
</div>

{_build_change_prob_html(chg_prob)}

{_build_root_cause_html(report.get("rootCauseAttribution", {}))}

{_build_cve_root_cause_html(report.get("cveRootCause", {}))}

</body>
</html>"""


def generate_cve_details_html(cve_api, meta, cve_sig=None):
    if cve_sig is None:
        cve_sig = {}
    details = cve_api.get("details", [])
    cve_sum = cve_api.get("summary", {})

    # Compute summary counts — separate pure intro/resolved from both
    counts = {
        "intro_only": {"up": 0, "down": 0, "same": 0},
        "resolved_only": {"up": 0, "down": 0, "same": 0},
        "both": {"up": 0, "down": 0, "same": 0},
    }
    for r in details:
        has_intro = bool(r["cvesIntroduced"])
        has_resolved = bool(r["cvesResolved"])
        delta = r["apisDelta"]
        bucket = "same" if delta == 0 else ("up" if delta > 0 else "down")
        if has_intro and has_resolved:
            counts["both"][bucket] += 1
        elif has_intro:
            counts["intro_only"][bucket] += 1
        elif has_resolved:
            counts["resolved_only"][bucket] += 1

    rows = ""
    for idx, r in enumerate(details, 1):
        cat_parts = []
        for cat in CATEGORIES:
            d = r["categoryDeltas"].get(cat, 0)
            if d != 0:
                sign = f"+{d}" if d > 0 else str(d)
                cat_parts.append(f"{CAT_LABELS[cat]}{sign}")
        cat_str = ", ".join(cat_parts) if cat_parts else "—"

        kw_cls = "style='background:var(--badge-add)'" if r["hasSecurityKeyword"] else ""
        rows += (
            f"<tr {kw_cls}>"
            f"<td style='text-align:right'>{idx}</td>"
            f"<td class='mono'>{_esc(r['project'])}</td>"
            f"<td class='mono'>{_esc(r['sha'])}</td>"
            f"<td>{_esc(r['date'])}</td>"
            f"<td class='mono'>{_esc(r['dep'])}</td>"
            f"<td style='font-size:0.78rem'>"
            f"{_esc(r['versionBefore'])} → {_esc(r['versionAfter'])}</td>"
            f"<td style='color:var(--red)'>"
            f"{', '.join(r['cvesIntroduced']) if r['cvesIntroduced'] else ''}</td>"
            f"<td style='color:var(--green)'>"
            f"{', '.join(r['cvesResolved']) if r['cvesResolved'] else ''}</td>"
            f"<td>{r['apisBefore']}</td><td>{r['apisAfter']}</td>"
            f"<td>{r['apisDelta']}</td>"
            f"<td style='font-size:0.78rem'>{cat_str}</td>"
            f"<td>{_esc(r['message'])}</td>"
            f"<td>{'Yes' if r['hasSecurityKeyword'] else ''}</td>"
            f"</tr>")

    # Build coincidence rows by category
    cve_sum_rows = ""
    for cat in CATEGORIES:
        label = CAT_LABELS[cat]
        intro_inc = cve_sum.get("cveIntroWithApiIncrease", {}).get(cat, 0)
        intro_dec = cve_sum.get("cveIntroWithApiDecrease", {}).get(cat, 0)
        intro_no = cve_sum.get("cveIntroNoApiChange", {}).get(cat, 0)
        res_dec = cve_sum.get("cveResolvedWithApiDecrease", {}).get(cat, 0)
        res_inc = cve_sum.get("cveResolvedWithApiIncrease", {}).get(cat, 0)
        res_no = cve_sum.get("cveResolvedNoApiChange", {}).get(cat, 0)
        cve_sum_rows += (
            f"<tr><td>{label}</td>"
            f"<td style='color:var(--red)'>{intro_inc}</td>"
            f"<td style='color:var(--green)'>{intro_dec}</td>"
            f"<td>{intro_no}</td>"
            f"<td style='color:var(--green)'>{res_dec}</td>"
            f"<td style='color:var(--red)'>{res_inc}</td>"
            f"<td>{res_no}</td></tr>")

    wo = cve_sig.get("withoutCoOccurrence", {})
    sig_api_inc_no_cve = wo.get("apiIncreaseWithoutCveIntro", "?")
    sig_api_dec_no_cve = wo.get("apiDecreaseWithoutCveResolved", "?")
    sig_cve_intro_no_api = wo.get("cveIntroWithoutApiIncrease", "?")
    sig_cve_res_no_api = wo.get("cveResolvedWithoutApiDecrease", "?")
    sig_total = cve_sig.get("totalTransitions", "?")
    sig_tests = cve_sig.get("tests", {})
    sig_calc_intro = _esc(sig_tests.get("cveIntroApiIncrease", {}).get("calculation", ""))
    sig_calc_res = _esc(sig_tests.get("cveResolvedApiDecrease", {}).get("calculation", ""))

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CVE &amp; Sensitive API Details — Cross-Project</title>
<style>
:root {{
    --bg: #fafafa; --fg: #1a1a1a; --card: #fff; --border: #e0e0e0;
    --muted: #666; --green: #2d6a4f; --red: #c0392b; --blue: #2980b9;
    --badge-add: #e8f5e9;
}}
@media (prefers-color-scheme: dark) {{
    :root:not([data-theme="light"]) {{
        --bg: #181a1b; --fg: #d4d4d4; --card: #232526; --border: #3a3a3a;
        --muted: #999; --green: #52b788; --red: #e74c3c; --blue: #5dade2;
        --badge-add: #1b3a1b;
    }}
}}
:root[data-theme="dark"] {{
    --bg: #181a1b; --fg: #d4d4d4; --card: #232526; --border: #3a3a3a;
    --muted: #999; --green: #52b788; --red: #e74c3c; --blue: #5dade2;
    --badge-add: #1b3a1b;
}}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: var(--bg); color: var(--fg);
    padding: 24px 16px; max-width: 1800px; margin: 0 auto;
}}
h1 {{ font-size: 1.3rem; margin-bottom: 4px; }}
.subtitle {{ color: var(--muted); font-size: 0.9rem; margin-bottom: 16px; }}
table {{ border-collapse: collapse; width: 100%; font-size: 0.8rem; }}
th, td {{ border: 1px solid var(--border); padding: 4px 8px; text-align: left; }}
th {{ background: var(--bg); font-weight: 600; position: sticky; top: 0; }}
.mono {{ font-family: monospace; font-size: 0.78rem; }}
.note {{ font-size: 0.82rem; color: var(--muted); margin-bottom: 12px; font-style: italic; }}
</style>
</head>
<body>

<h1>CVE &amp; Sensitive API Change Details</h1>
<p class="subtitle">
    {len(details)} dependency-level CVE change events across {meta['projectCount']} projects
    &middot; Highlighted rows contain a security keyword in the commit message
</p>
<p class="note">
    Each row is one dependency at one commit where a CVE was introduced or resolved.
    Category deltas show per-category sensitive API changes for that dependency.
</p>

<div style="display:flex;flex-wrap:wrap;gap:12px;margin-bottom:16px">
  <div style="background:var(--card);border:1px solid var(--border);border-radius:6px;padding:10px 16px;min-width:200px">
    <div style="font-weight:600;margin-bottom:6px;color:var(--red)">CVE Introduced Only ({sum(counts["intro_only"].values())})</div>
    <div>+ API increase: <b>{counts["intro_only"]["up"]}</b></div>
    <div>+ API decrease: <b>{counts["intro_only"]["down"]}</b></div>
    <div>+ API unchanged: <b>{counts["intro_only"]["same"]}</b></div>
  </div>
  <div style="background:var(--card);border:1px solid var(--border);border-radius:6px;padding:10px 16px;min-width:200px">
    <div style="font-weight:600;margin-bottom:6px;color:var(--green)">CVE Resolved Only ({sum(counts["resolved_only"].values())})</div>
    <div>+ API increase: <b>{counts["resolved_only"]["up"]}</b></div>
    <div>+ API decrease: <b>{counts["resolved_only"]["down"]}</b></div>
    <div>+ API unchanged: <b>{counts["resolved_only"]["same"]}</b></div>
  </div>
  <div style="background:var(--card);border:1px solid var(--border);border-radius:6px;padding:10px 16px;min-width:200px">
    <div style="font-weight:600;margin-bottom:6px;color:var(--blue)">CVE Introduced + Resolved ({sum(counts["both"].values())})</div>
    <div>+ API increase: <b>{counts["both"]["up"]}</b></div>
    <div>+ API decrease: <b>{counts["both"]["down"]}</b></div>
    <div>+ API unchanged: <b>{counts["both"]["same"]}</b></div>
  </div>
</div>

<h2 style="margin-top:24px">CVE &amp; Sensitive API Change Coincidence</h2>
<p class="note">
    When a CVE is introduced for a dependency, does the sensitive API count for that dep also change?
    And when a CVE is resolved, do APIs decrease?
    Counted per dep per commit, broken down by category.
</p>
<table style="margin-bottom:16px">
    <thead>
        <tr>
            <th rowspan="2">Category</th>
            <th colspan="3" style="text-align:center">CVE Introduced</th>
            <th colspan="3" style="text-align:center">CVE Resolved</th>
        </tr>
        <tr>
            <th>API ↑</th><th>API ↓</th><th>No change</th>
            <th>API ↓</th><th>API ↑</th><th>No change</th>
        </tr>
    </thead>
    <tbody>{cve_sum_rows}
    <tr style="font-weight:700">
        <td>Total CVE events</td>
        <td colspan="3" style="text-align:center">{cve_sum.get('totalCveIntroductions', 0)}</td>
        <td colspan="3" style="text-align:center">{cve_sum.get('totalCveResolutions', 0)}</td>
    </tr>
    </tbody>
</table>

<h3>Without co-occurrence</h3>
<table style="max-width:600px;margin-bottom:16px">
    <tbody>
    <tr><td>API increases WITHOUT CVE introduction</td>
        <td>{sig_api_inc_no_cve}</td></tr>
    <tr><td>API decreases WITHOUT CVE resolution</td>
        <td>{sig_api_dec_no_cve}</td></tr>
    <tr><td>CVE introductions WITHOUT API increase</td>
        <td>{sig_cve_intro_no_api}</td></tr>
    <tr><td>CVE resolutions WITHOUT API decrease</td>
        <td>{sig_cve_res_no_api}</td></tr>
    </tbody>
</table>

<h3>Statistical Significance (Fisher's Exact Test)</h3>
<p class="note">
    Tests whether CVE changes and matching-direction sensitive API changes co-occur
    more than expected by chance, using a 2×2 contingency table over all
    {sig_total} (dep, commit) transitions across all projects.
</p>
<pre style="background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:16px;font-size:0.82rem;overflow-x:auto;white-space:pre-wrap;margin-bottom:24px">{sig_calc_intro}\n{sig_calc_res}</pre>

<h2>All CVE Change Events</h2>
<div style="overflow-x:auto">
<table>
    <thead><tr>
        <th>#</th><th>Project</th><th>SHA</th><th>Date</th><th>Dependency</th>
        <th>Version</th><th>CVEs +</th><th>CVEs -</th>
        <th>APIs Before</th><th>APIs After</th><th>API Δ</th>
        <th>Category Δ</th><th>Message</th><th>Sec Keyword?</th>
    </tr></thead>
    <tbody>{rows}</tbody>
</table>
</div>


</body>
</html>"""


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Cross-project analysis across all Theo-tracked projects.")
    parser.add_argument("reports_dir",
                        help="Base directory containing per-project report subdirs")
    parser.add_argument("--output", help="Output directory (default: reports_dir)")
    parser.add_argument("--top-big", type=int, default=3,
                        help="Top N big changes per project to analyze (default 3)")
    args = parser.parse_args()

    base = Path(args.reports_dir)
    if not base.exists():
        print(f"Not found: {base}", file=sys.stderr)
        sys.exit(1)

    out_dir = Path(args.output) if args.output else base
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"Loading projects from {base}...")
    projects = load_all_projects(base)
    if not projects:
        print("No projects found.", file=sys.stderr)
        sys.exit(1)
    print(f"Loaded {len(projects)} projects\n")

    print("1. Change type totals...")
    change_types = analyze_change_types(projects)

    print("2. Big change reasons...")
    big_change_reasons = analyze_big_change_reasons(projects, args.top_big)

    print("3. Volatile dependencies...")
    volatile_deps = analyze_volatile_deps(projects)

    print("4. CVE & sensitive API coincidence...")
    cve_api = analyze_cve_api_coincidence(projects)

    print("4b. Statistical significance of CVE-API co-occurrence...")
    cve_significance = analyze_cve_api_significance(projects)
    print(cve_significance.get("calculationSteps", ""))

    print("5. Sensitive API trends...")
    api_trends = analyze_api_trends(projects)

    print("6. High-API dep trends...")
    high_api = analyze_high_api_dep_trends(projects)

    print("7. Change probability...")
    change_prob = analyze_change_probability(projects)

    print("8. Root cause attribution...")
    root_cause_totals = analyze_root_cause_totals(projects)

    print("9. CVE x root cause...")
    cve_root_cause = analyze_cve_root_cause(projects)

    meta = {
        "generated": datetime.now().isoformat(),
        "reportsDir": str(base),
        "projectCount": len(projects),
        "projects": sorted(projects.keys()),
        "topBigPerProject": args.top_big,
    }

    report = {
        "metadata": meta,
        "changeTypes": change_types,
        "bigChangeReasons": big_change_reasons,
        "volatileDeps": volatile_deps,
        "cveApiCoincidence": {"summary": cve_api["summary"]},
        "cveApiSignificance": {k: v for k, v in cve_significance.items()
                               if k != "calculationSteps"},
        "apiTrends": api_trends,
        "highApiDepTrends": high_api,
        "changeProbability": change_prob,
        "rootCauseAttribution": root_cause_totals,
        "cveRootCause": cve_root_cause,
    }

    # Summary JSON + HTML
    json_path = out_dir / "cross_project_summary.json"
    with open(json_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\nJSON: {json_path}")

    html_path = out_dir / "cross_project_summary.html"
    html_path.write_text(generate_summary_html(report), encoding="utf-8")
    print(f"HTML: {html_path}")

    # CVE details (separate file)
    cve_details_json = out_dir / "cross_project_cve_details.json"
    with open(cve_details_json, "w") as f:
        json.dump({"metadata": meta, "cveApiDetails": cve_api["details"]},
                  f, indent=2)
    print(f"CVE details JSON: {cve_details_json}")

    cve_details_html = out_dir / "cross_project_cve_details.html"
    cve_details_html.write_text(
        generate_cve_details_html(cve_api, meta, cve_sig=cve_significance),
        encoding="utf-8")
    print(f"CVE details HTML: {cve_details_html}")

    print(f"\nDone. {len(projects)} projects analyzed.")


if __name__ == "__main__":
    main()
