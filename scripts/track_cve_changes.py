#!/usr/bin/env python3
"""
Track CVE appearance and disappearance across a project's dependency history.

Reads timeline_data.json to get the dependency set at each commit, queries
OSV.dev for known vulnerabilities on each unique dependency version, then
tracks how CVEs come and go across commits — correlated with sensitive API
changes.

Usage:
    python3 track_cve_changes.py <timeline_data.json>
        [--repo-url <github_repo_url>]
        [--project <name>]
        [--output <output_dir>]
        [--cache <osv_cache.json>]
        [--refresh-cache]

The OSV cache is written next to the output so re-runs skip the query.
"""

import argparse
import json
import re
import sys
import time
import urllib.request
import urllib.error
from collections import defaultdict
from datetime import datetime
from pathlib import Path

CATEGORIES = ["FILESYSTEM", "NETWORK", "PROCESS", "OTHER"]


def load_json(path):
    with open(path) as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# CWE -> Theo category mapping (mirrors CweCategoryMapper.java)
# ---------------------------------------------------------------------------

CWE_TO_CATEGORIES = {}

def _add_mapping(cwes, category):
    for cwe in cwes:
        CWE_TO_CATEGORIES.setdefault(cwe, set()).add(category)

_add_mapping([73, 91, 319, 552, 576, 611], "FILESYSTEM")
_add_mapping([116, 117], "FILESYSTEM")
_add_mapping([22, 367, 732], "FILESYSTEM")
_add_mapping([214, 526, 291, 706, 755, 1327], "FILESYSTEM")
_add_mapping([89, 404, 444, 523, 600, 601, 772, 830, 918, 943, 1072], "NETWORK")
_add_mapping([20, 79, 213, 295, 352, 384, 602, 614, 754], "NETWORK")
_add_mapping([246, 577, 923, 941, 1385], "NETWORK")
_add_mapping([502], "NETWORK")
_add_mapping([84, 177, 261, 327], "PROCESS")
_add_mapping([111, 114], "PROCESS")
_add_mapping([470, 578, 749, 917], "PROCESS")
_add_mapping([78], "PROCESS")
_add_mapping([79], "PROCESS")
_add_mapping([1385], "PROCESS")
_add_mapping([116], "NETWORK")
_add_mapping([319], "NETWORK")


def cwe_to_categories(cwe_ids):
    cats = set()
    for cwe_str in cwe_ids:
        try:
            num = int(cwe_str.replace("CWE-", "").strip())
            mapped = CWE_TO_CATEGORIES.get(num, set())
            cats.update(mapped)
        except (ValueError, AttributeError):
            pass
    return sorted(cats) if cats else ["OTHER"]


# ---------------------------------------------------------------------------
# OSV.dev client
# ---------------------------------------------------------------------------

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_SINGLE_URL = "https://api.osv.dev/v1/query"
BATCH_SIZE = 100


def _parse_gav(gav_key):
    parts = gav_key.split(":")
    if len(parts) >= 3:
        return parts[0], parts[1], parts[2]
    elif len(parts) == 2:
        return parts[0], parts[1], ""
    return gav_key, "", ""


MAX_RETRIES = 10
INITIAL_BACKOFF = 2  # seconds


def _osv_query_batch(gavs):
    """Query OSV batch endpoint with retry + exponential backoff."""
    queries = []
    for g, a, v in gavs:
        queries.append({
            "package": {"name": f"{g}:{a}", "ecosystem": "Maven"},
            "version": v,
        })

    payload = json.dumps({"queries": queries}).encode("utf-8")
    for attempt in range(1, MAX_RETRIES + 1):
        req = urllib.request.Request(
            OSV_BATCH_URL,
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                return json.loads(resp.read().decode("utf-8")), []
        except (urllib.error.URLError, urllib.error.HTTPError, OSError) as e:
            if attempt < MAX_RETRIES:
                wait = INITIAL_BACKOFF * (2 ** (attempt - 1))
                wait = min(wait, 120)
                print(f"  OSV batch query attempt {attempt}/{MAX_RETRIES} failed: {e}  "
                      f"(retrying in {wait}s)", file=sys.stderr)
                time.sleep(wait)
            else:
                print(f"  OSV batch query FAILED after {MAX_RETRIES} attempts: {e}",
                      file=sys.stderr)

    failed_gavs = [f"{g}:{a}:{v}" for g, a, v in gavs]
    return {"results": [{"vulns": []} for _ in gavs]}, failed_gavs


def _extract_severity(vuln):
    """Extract severity from an OSV vulnerability entry."""
    db_specific = vuln.get("database_specific", {})
    sev = db_specific.get("severity")
    if sev:
        return sev.upper()

    for sv in vuln.get("severity", []):
        score_str = sv.get("score", "")
        if ":" in score_str:
            try:
                parts = score_str.split("/")
                for p in parts:
                    if p.startswith("CVSS:"):
                        continue
                    try:
                        score = float(p)
                        if score >= 9.0:
                            return "CRITICAL"
                        elif score >= 7.0:
                            return "HIGH"
                        elif score >= 4.0:
                            return "MEDIUM"
                        else:
                            return "LOW"
                    except ValueError:
                        continue
            except Exception:
                pass

    return ""


def _extract_cwe_ids(vuln):
    db_specific = vuln.get("database_specific", {})
    cwes = db_specific.get("cwe_ids", [])
    if cwes:
        return cwes
    return []


def _extract_fixed_version(vuln, pkg_name):
    """Find the fixed version for a specific package from affected ranges."""
    for affected in vuln.get("affected", []):
        pkg = affected.get("package", {})
        aff_name = pkg.get("name", "")
        if aff_name != pkg_name:
            continue
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                if "fixed" in event:
                    return event["fixed"]
    return None


def query_osv_for_deps(unique_gavs, cache_path=None, refresh=False):
    """Query OSV for all unique deps.

    Returns (cache_dict, failed_gavs_list).
    """
    cache = {}
    if cache_path and Path(cache_path).exists() and not refresh:
        try:
            with open(cache_path) as f:
                cache = json.load(f)
            print(f"  Loaded OSV cache: {len(cache)} entries from {cache_path}")
        except (json.JSONDecodeError, OSError):
            cache = {}

    to_query = []
    for gav in unique_gavs:
        if gav not in cache:
            to_query.append(gav)

    all_failed = []

    if to_query:
        print(f"  Querying OSV.dev for {len(to_query)} unique deps "
              f"({len(to_query) // BATCH_SIZE + 1} batch request(s))...")

        for i in range(0, len(to_query), BATCH_SIZE):
            batch = to_query[i:i + BATCH_SIZE]
            parsed = [_parse_gav(g) for g in batch]
            result, batch_failed = _osv_query_batch(parsed)

            if batch_failed:
                all_failed.extend(batch_failed)

            for j, gav in enumerate(batch):
                vulns_raw = result.get("results", [{}])
                if j < len(vulns_raw):
                    vulns = vulns_raw[j].get("vulns", [])
                else:
                    vulns = []

                g, a, v = parsed[j]
                pkg_name = f"{g}:{a}"

                cve_list = []
                for vuln in vulns:
                    vuln_id = vuln.get("id", "")
                    aliases = vuln.get("aliases", [])
                    cve_id = vuln_id
                    for alias in aliases:
                        if alias.startswith("CVE-"):
                            cve_id = alias
                            break

                    cwe_ids = _extract_cwe_ids(vuln)

                    cve_list.append({
                        "id": vuln_id,
                        "cveId": cve_id,
                        "summary": vuln.get("summary", "")[:200],
                        "severity": _extract_severity(vuln),
                        "cweIds": cwe_ids,
                        "theoCategories": cwe_to_categories(cwe_ids),
                        "link": f"https://osv.dev/vulnerability/{vuln_id}",
                        "fixedVersion": _extract_fixed_version(vuln, pkg_name),
                    })

                if gav not in all_failed:
                    cache[gav] = cve_list

            if i + BATCH_SIZE < len(to_query):
                time.sleep(0.5)

        if cache_path:
            Path(cache_path).parent.mkdir(parents=True, exist_ok=True)
            with open(cache_path, "w") as f:
                json.dump(cache, f, indent=2)
            print(f"  Saved OSV cache: {len(cache)} entries to {cache_path}")

    if all_failed:
        print(f"\n  WARNING: {len(all_failed)} deps failed after {MAX_RETRIES} "
              f"retries — CVE data for these is INCOMPLETE", file=sys.stderr)

    return cache, all_failed


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def dep_ga(dep_key):
    parts = dep_key.split(":")
    return ":".join(parts[:2]) if len(parts) >= 2 else dep_key


def dep_version(dep_key):
    parts = dep_key.split(":")
    return parts[2] if len(parts) >= 3 else ""


def extract_pr_number(message):
    m = re.search(r'\(#(\d+)\)', message or "")
    return int(m.group(1)) if m else None


# ---------------------------------------------------------------------------
# Core analysis
# ---------------------------------------------------------------------------

def build_commit_cve_states(timeline, osv_cache):
    """For each commit, build the full set of (cve_id, dep_gav) tuples present."""
    states = []
    for entry in timeline:
        reach = entry.get("reachability", {})
        cve_set = {}  # cve_id -> {cve_info + dep}
        dep_detail_all = {}

        for _mod, mod_data in reach.items():
            for dep_key, api_count in mod_data.get("depsDetail", {}).items():
                dep_detail_all[dep_key] = api_count
                for cve in osv_cache.get(dep_key, []):
                    cid = cve["cveId"]
                    if cid not in cve_set:
                        cve_set[cid] = {
                            **cve,
                            "dep": dep_key,
                            "depApis": api_count,
                        }

        states.append({
            "sha": entry.get("sha", ""),
            "date": entry.get("date", ""),
            "message": entry.get("message", ""),
            "cves": cve_set,
            "depsDetail": dep_detail_all,
        })

    return states


def classify_introduction(dep_key, prev_deps):
    """How did this CVE get introduced?"""
    ga = dep_ga(dep_key)
    if dep_key not in prev_deps:
        prev_gas = {dep_ga(d) for d in prev_deps}
        if ga in prev_gas:
            return "depUpdated"
        else:
            return "depAdded"
    return "alreadyPresent"


def classify_resolution(dep_key, cur_deps, _prev_deps):
    """How was this CVE resolved?"""
    ga = dep_ga(dep_key)
    if dep_key not in cur_deps:
        cur_gas = {dep_ga(d) for d in cur_deps}
        if ga in cur_gas:
            new_version = None
            for d in cur_deps:
                if dep_ga(d) == ga:
                    new_version = d
                    break
            return "depUpdated", new_version
        else:
            return "depRemoved", None
    return "unknown", None


def compute_cve_diffs(states):
    """Compute CVE introductions and resolutions between consecutive commits."""
    diffs = []
    for i, cur in enumerate(states):
        if i == 0:
            diffs.append({
                "sha": cur["sha"], "date": cur["date"], "message": cur["message"],
                "introduced": [], "resolved": [],
                "totalCves": len(cur["cves"]),
                "netChange": 0,
                "isBaseline": True,
                "baselineCves": list(cur["cves"].values()),
            })
            continue

        prev = states[i - 1]
        prev_cve_ids = set(prev["cves"].keys())
        cur_cve_ids = set(cur["cves"].keys())

        introduced_ids = cur_cve_ids - prev_cve_ids
        resolved_ids = prev_cve_ids - cur_cve_ids

        introduced = []
        for cid in sorted(introduced_ids):
            info = cur["cves"][cid]
            method = classify_introduction(info["dep"], prev["depsDetail"])
            dep_apis_before = prev["depsDetail"].get(info["dep"], 0)
            prev_dep_for_ga = None
            if method == "depUpdated":
                for d in prev["depsDetail"]:
                    if dep_ga(d) == dep_ga(info["dep"]):
                        prev_dep_for_ga = d
                        dep_apis_before = prev["depsDetail"][d]
                        break

            introduced.append({
                **{k: info[k] for k in ["cveId", "id", "severity", "summary",
                                         "link", "cweIds", "theoCategories"]},
                "dep": info["dep"],
                "depApis": info["depApis"],
                "introductionMethod": method,
                "previousDep": prev_dep_for_ga,
                "depApisBefore": dep_apis_before,
            })

        resolved = []
        for cid in sorted(resolved_ids):
            info = prev["cves"][cid]
            method, new_dep = classify_resolution(
                info["dep"], cur["depsDetail"], prev["depsDetail"])
            dep_apis_after = cur["depsDetail"].get(new_dep, 0) if new_dep else 0

            resolved.append({
                **{k: info[k] for k in ["cveId", "id", "severity", "summary",
                                         "link", "cweIds", "theoCategories"]},
                "dep": info["dep"],
                "depApis": info["depApis"],
                "resolutionMethod": method,
                "updatedTo": new_dep,
                "depApisAfter": dep_apis_after,
            })

        if introduced or resolved:
            diffs.append({
                "sha": cur["sha"], "date": cur["date"], "message": cur["message"],
                "introduced": sorted(introduced, key=lambda x: x["cveId"]),
                "resolved": sorted(resolved, key=lambda x: x["cveId"]),
                "totalCves": len(cur["cves"]),
                "netChange": len(introduced) - len(resolved),
                "isBaseline": False,
            })

    return diffs


def build_lifecycles(states):
    """Track each CVE's lifespan across commits."""
    lifecycles = {}

    for i, state in enumerate(states):
        for cid, info in state["cves"].items():
            if cid not in lifecycles:
                lifecycles[cid] = {
                    "cveId": info["cveId"],
                    "id": info["id"],
                    "severity": info["severity"],
                    "summary": info["summary"],
                    "link": info["link"],
                    "cweIds": info["cweIds"],
                    "theoCategories": info["theoCategories"],
                    "affectedDeps": set(),
                    "firstSeen": {"sha": state["sha"], "date": state["date"],
                                  "commitIndex": i},
                    "lastSeen": {"sha": state["sha"], "date": state["date"],
                                 "commitIndex": i},
                    "status": "open",
                    "resolutionMethod": None,
                    "resolvedAt": None,
                }
            lc = lifecycles[cid]
            lc["affectedDeps"].add(dep_ga(info["dep"]))
            lc["lastSeen"] = {"sha": state["sha"], "date": state["date"],
                              "commitIndex": i}

    for cid, lc in lifecycles.items():
        last_idx = lc["lastSeen"]["commitIndex"]
        if last_idx < len(states) - 1:
            lc["status"] = "resolved"
            resolved_state = states[last_idx + 1]
            lc["resolvedAt"] = {"sha": resolved_state["sha"],
                                "date": resolved_state["date"]}
            prev_deps = states[last_idx]["depsDetail"]
            cur_deps = resolved_state["depsDetail"]
            dep_key = None
            for d in prev_deps:
                if dep_ga(d) in lc["affectedDeps"]:
                    dep_key = d
                    break
            if dep_key:
                method, new_dep = classify_resolution(dep_key, cur_deps, prev_deps)
                lc["resolutionMethod"] = method
                if new_dep:
                    lc["updatedTo"] = new_dep

        first_date = lc["firstSeen"]["date"]
        last_date = lc["lastSeen"]["date"]
        try:
            d1 = datetime.strptime(first_date, "%Y-%m-%d")
            d2 = datetime.strptime(last_date, "%Y-%m-%d")
            lc["durationDays"] = (d2 - d1).days
        except (ValueError, TypeError):
            lc["durationDays"] = None
        lc["durationCommits"] = (lc["lastSeen"]["commitIndex"]
                                  - lc["firstSeen"]["commitIndex"] + 1)

        lc["affectedDeps"] = sorted(lc["affectedDeps"])
        del lc["firstSeen"]["commitIndex"]
        del lc["lastSeen"]["commitIndex"]

    return sorted(lifecycles.values(),
                  key=lambda x: (0 if x["status"] == "open" else 1,
                                 -(x.get("durationDays") or 0)))


def build_per_dep_summary(states, osv_cache):
    """Per-dependency CVE summary."""
    dep_info = defaultdict(lambda: {
        "versions": set(), "cves": set(), "currentCves": set(),
        "resolvedByUpdate": 0, "resolvedByRemoval": 0,
        "sensitiveApiTrend": [],
    })

    for state in states:
        seen_gas = set()
        for dep_key, api_count in state["depsDetail"].items():
            ga = dep_ga(dep_key)
            ver = dep_version(dep_key)
            info = dep_info[ga]
            info["versions"].add(ver)
            for cve in osv_cache.get(dep_key, []):
                info["cves"].add(cve["cveId"])

            if ga not in seen_gas:
                info["sensitiveApiTrend"].append({
                    "sha": state["sha"], "date": state["date"],
                    "version": ver, "apis": api_count,
                })
                seen_gas.add(ga)

    last_state = states[-1] if states else {"depsDetail": {}}
    last_gas = {}
    for dep_key in last_state["depsDetail"]:
        ga = dep_ga(dep_key)
        last_gas[ga] = dep_key

    result = []
    for ga, info in sorted(dep_info.items()):
        current_dep = last_gas.get(ga)
        current_cves = []
        if current_dep:
            current_cves = [c["cveId"] for c in osv_cache.get(current_dep, [])]

        result.append({
            "dep": ga,
            "versionsObserved": sorted(info["versions"]),
            "totalCvesAcrossVersions": len(info["cves"]),
            "currentCves": len(current_cves),
            "currentCveIds": current_cves,
            "sensitiveApiTrend": info["sensitiveApiTrend"][-10:],
        })

    result.sort(key=lambda d: -d["totalCvesAcrossVersions"])
    return result[:50]


def build_category_correlation(states, osv_cache):
    """Check how often a CVE's category matches the dep's reachable API categories."""
    cat_stats = {c: {"totalCves": 0, "depsWithBothCveAndApis": 0,
                      "cveMatchesReachableCategory": 0}
                 for c in CATEGORIES}

    seen = set()
    for state in states:
        for dep_key, api_count in state["depsDetail"].items():
            for cve in osv_cache.get(dep_key, []):
                pair = (cve["cveId"], dep_key)
                if pair in seen:
                    continue
                seen.add(pair)

                reach = state.get("reachability", {})
                dep_cats = set()
                for _mod, mod_data in (reach.items() if isinstance(reach, dict) else []):
                    if dep_key in mod_data.get("depsDetail", {}):
                        dep_cats.update(mod_data.get("reachableApisByCategory", {}).keys())

                for cve_cat in cve.get("theoCategories", ["OTHER"]):
                    if cve_cat in cat_stats:
                        cat_stats[cve_cat]["totalCves"] += 1
                        if api_count > 0:
                            cat_stats[cve_cat]["depsWithBothCveAndApis"] += 1
                        if cve_cat in dep_cats:
                            cat_stats[cve_cat]["cveMatchesReachableCategory"] += 1

    return cat_stats


def build_summary(diffs, lifecycles):
    sev_counts = defaultdict(int)
    resolved_sev = defaultdict(int)
    res_methods = defaultdict(int)
    intro_methods = defaultdict(int)

    all_cves = set()
    open_cves = set()

    for lc in lifecycles:
        cid = lc["cveId"]
        all_cves.add(cid)
        sev = lc.get("severity", "") or "UNKNOWN"
        sev_counts[sev] += 1
        if lc["status"] == "resolved":
            resolved_sev[sev] += 1
            rm = lc.get("resolutionMethod", "unknown")
            res_methods[rm] += 1
        else:
            open_cves.add(cid)

    for diff in diffs:
        for intro in diff.get("introduced", []):
            intro_methods[intro.get("introductionMethod", "unknown")] += 1

    return {
        "totalUniqueCves": len(all_cves),
        "currentlyOpen": len(open_cves),
        "resolved": len(all_cves) - len(open_cves),
        "cvesBySeverity": dict(sev_counts),
        "resolvedBySeverity": dict(resolved_sev),
        "resolutionMethods": dict(res_methods),
        "introductionMethods": dict(intro_methods),
    }


# ---------------------------------------------------------------------------
# HTML report
# ---------------------------------------------------------------------------

def generate_html(report):
    meta = report["metadata"]
    summary = report["summary"]
    diffs = report["perCommit"]
    lifecycles = report["cveLifecycles"]
    per_dep = report["perDependency"]
    cat_corr = report["categoryCorrelation"]

    # Summary cards
    cards = f"""
    <div class="cards">
        <div class="card">
            <div class="card-label">Total Unique CVEs</div>
            <div class="card-value">{summary['totalUniqueCves']}</div>
        </div>
        <div class="card">
            <div class="card-label">Currently Open</div>
            <div class="card-value" style="color:var(--red)">{summary['currentlyOpen']}</div>
        </div>
        <div class="card">
            <div class="card-label">Resolved</div>
            <div class="card-value" style="color:var(--green)">{summary['resolved']}</div>
        </div>
        <div class="card">
            <div class="card-label">By Severity</div>
            <div class="card-sub" style="margin-top:8px">
                {'<br>'.join(f'{k}: {v}' for k, v in sorted(summary.get('cvesBySeverity', {}).items()))}
            </div>
        </div>
        <div class="card">
            <div class="card-label">Resolution Methods</div>
            <div class="card-sub" style="margin-top:8px">
                {'<br>'.join(f'{k}: {v}' for k, v in sorted(summary.get('resolutionMethods', {}).items()))}
            </div>
        </div>
        <div class="card">
            <div class="card-label">Introduction Methods</div>
            <div class="card-sub" style="margin-top:8px">
                {'<br>'.join(f'{k}: {v}' for k, v in sorted(summary.get('introductionMethods', {}).items()))}
            </div>
        </div>
    </div>"""

    timeline_chart = json.dumps({
        "labels": [f"{d['sha']} ({d['date']})" for d in diffs],
        "totals": [d.get("totalCves", 0) for d in diffs],
        "nets": [d.get("netChange", 0) for d in diffs],
    })

    # Per-commit table
    commit_rows = []
    for diff in diffs:
        if diff.get("isBaseline"):
            n_baseline = len(diff.get("baselineCves", []))
            if n_baseline > 0:
                commit_rows.append(
                    f"<tr><td class='mono'>{_esc(diff['sha'])}</td>"
                    f"<td>{_esc(diff['date'])}</td>"
                    f"<td>{_esc(diff['message'][:60])}</td>"
                    f"<td>—</td><td>—</td>"
                    f"<td>{diff['totalCves']}</td>"
                    f"<td><span class='badge badge-baseline'>{n_baseline} at baseline</span></td></tr>")
            continue

        n_intro = len(diff.get("introduced", []))
        n_res = len(diff.get("resolved", []))
        if n_intro == 0 and n_res == 0:
            continue

        intro_badges = []
        for intr in diff.get("introduced", [])[:5]:
            sev_cls = f"sev-{intr.get('severity', '').lower()}"
            intro_badges.append(
                f"<span class='badge {sev_cls}'>+{_esc(intr['cveId'])}</span>")
        if n_intro > 5:
            intro_badges.append(f"<span class='badge'>+{n_intro - 5} more</span>")

        res_badges = []
        for res in diff.get("resolved", [])[:5]:
            res_badges.append(
                f"<span class='badge badge-resolved'>-{_esc(res['cveId'])}</span>")
        if n_res > 5:
            res_badges.append(f"<span class='badge'>-{n_res - 5} more</span>")

        net_cls = "delta-up" if diff["netChange"] > 0 else "delta-down" if diff["netChange"] < 0 else ""
        net_sign = f"+{diff['netChange']}" if diff["netChange"] > 0 else str(diff["netChange"])

        commit_rows.append(
            f"<tr class='clickable' onclick='toggleCommit(this)'>"
            f"<td class='mono'>{_esc(diff['sha'])}</td>"
            f"<td>{_esc(diff['date'])}</td>"
            f"<td>{_esc(diff['message'][:60])}</td>"
            f"<td style='color:var(--red)'>{'+' + str(n_intro) if n_intro else ''}</td>"
            f"<td style='color:var(--green)'>{'-' + str(n_res) if n_res else ''}</td>"
            f"<td class='{net_cls}'>{net_sign}</td>"
            f"<td>{' '.join(intro_badges)} {' '.join(res_badges)}</td></tr>"
            f"<tr class='expand-row'><td colspan='7' class='expand-cell'>"
            f"{_commit_detail_html(diff)}</td></tr>")

    # Lifecycle table
    lc_rows = []
    for lc in lifecycles[:100]:
        sev_cls = f"sev-{lc.get('severity', '').lower()}"
        status_badge = ('<span class="badge badge-resolved">resolved</span>'
                        if lc["status"] == "resolved"
                        else '<span class="badge sev-critical">open</span>')
        method = lc.get("resolutionMethod", "—") if lc["status"] == "resolved" else "—"
        dur = f"{lc.get('durationDays', '?')}d / {lc.get('durationCommits', '?')}c"
        deps_str = ", ".join(lc.get("affectedDeps", [])[:3])
        if len(lc.get("affectedDeps", [])) > 3:
            deps_str += f" +{len(lc['affectedDeps']) - 3}"

        lc_rows.append(
            f"<tr><td><a href='{_esc(lc['link'])}' target='_blank' "
            f"class='{sev_cls}'>{_esc(lc['cveId'])}</a></td>"
            f"<td><span class='badge {sev_cls}'>{_esc(lc.get('severity', '?'))}</span></td>"
            f"<td>{_esc(lc.get('summary', '')[:80])}</td>"
            f"<td class='mono'>{deps_str}</td>"
            f"<td>{_esc(lc['firstSeen']['date'])}</td>"
            f"<td>{_esc(lc['lastSeen']['date'])}</td>"
            f"<td>{dur}</td>"
            f"<td>{status_badge}</td>"
            f"<td>{_esc(method)}</td></tr>")

    # Per-dep table
    dep_rows = []
    for d in per_dep[:30]:
        dep_rows.append(
            f"<tr><td class='mono'>{_esc(d['dep'])}</td>"
            f"<td>{len(d.get('versionsObserved', []))}</td>"
            f"<td>{d['totalCvesAcrossVersions']}</td>"
            f"<td style='color:var(--red)'>{d['currentCves'] if d['currentCves'] else ''}</td>"
            f"<td class='mono' style='font-size:0.75rem'>"
            f"{', '.join(d.get('currentCveIds', [])[:3])}</td></tr>")

    # Category correlation
    cat_rows = []
    for cat in CATEGORIES:
        cc = cat_corr.get(cat, {})
        cat_rows.append(
            f"<tr><td>{cat}</td>"
            f"<td>{cc.get('totalCves', 0)}</td>"
            f"<td>{cc.get('depsWithBothCveAndApis', 0)}</td>"
            f"<td>{cc.get('cveMatchesReachableCategory', 0)}</td></tr>")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CVE Tracking — {_esc(meta.get('project', ''))}</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.4/chart.umd.min.js"></script>
<style>
:root {{
    --bg: #fafafa; --fg: #1a1a1a; --card: #fff; --border: #e0e0e0;
    --muted: #666; --green: #2d6a4f; --red: #c0392b; --blue: #2980b9;
    --orange: #e07a3a; --yellow: #d4a017; --purple: #6c4ab6;
    --expand-bg: #f5f5f5;
}}
@media (prefers-color-scheme: dark) {{
    :root:not([data-theme="light"]) {{
        --bg: #181a1b; --fg: #d4d4d4; --card: #232526; --border: #3a3a3a;
        --muted: #999; --green: #52b788; --red: #e74c3c; --blue: #5dade2;
        --orange: #e8945a; --yellow: #f0c040; --purple: #9b7fd4;
        --expand-bg: #2a2c2e;
    }}
}}
:root[data-theme="dark"] {{
    --bg: #181a1b; --fg: #d4d4d4; --card: #232526; --border: #3a3a3a;
    --muted: #999; --green: #52b788; --red: #e74c3c; --blue: #5dade2;
    --orange: #e8945a; --yellow: #f0c040; --purple: #9b7fd4;
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
.cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin-bottom: 24px; }}
.card {{ background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 16px; }}
.card-label {{ font-size: 0.78rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.5px; }}
.card-value {{ font-size: 1.5rem; font-weight: 700; margin-top: 4px; }}
.card-sub {{ font-size: 0.78rem; color: var(--muted); margin-top: 4px; }}
.section {{ background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 24px; margin-bottom: 24px; }}
.section h2 {{ font-size: 1.1rem; margin-bottom: 16px; }}
table {{ border-collapse: collapse; width: 100%; font-size: 0.85rem; }}
th, td {{ border: 1px solid var(--border); padding: 6px 10px; text-align: left; }}
th {{ background: var(--bg); font-weight: 600; position: sticky; top: 0; }}
.mono {{ font-family: monospace; font-size: 0.82rem; }}
.delta-up {{ color: var(--red); font-weight: 600; }}
.delta-down {{ color: var(--green); font-weight: 600; }}
.badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: 600; margin: 2px; }}
.sev-critical {{ background: #ffebee; color: #c62828; }}
.sev-high {{ background: #fff3e0; color: #e65100; }}
.sev-medium {{ background: #fffde7; color: #f57f17; }}
.sev-low {{ background: #e3f2fd; color: #1565c0; }}
.sev- {{ background: #f5f5f5; color: #666; }}
.sev-unknown {{ background: #f5f5f5; color: #666; }}
.badge-resolved {{ background: #e8f5e9; color: #2e7d32; }}
.badge-baseline {{ background: #f3e5f5; color: #6a1b9a; }}
@media (prefers-color-scheme: dark) {{
    :root:not([data-theme="light"]) .sev-critical {{ background: #3a1b1b; color: #ef9a9a; }}
    :root:not([data-theme="light"]) .sev-high {{ background: #3a2a1b; color: #ffcc80; }}
    :root:not([data-theme="light"]) .sev-medium {{ background: #3a3a1b; color: #fff59d; }}
    :root:not([data-theme="light"]) .sev-low {{ background: #1b2a3a; color: #90caf9; }}
    :root:not([data-theme="light"]) .badge-resolved {{ background: #1b3a1b; color: #81c784; }}
    :root:not([data-theme="light"]) .badge-baseline {{ background: #2a1b3a; color: #ce93d8; }}
}}
.clickable {{ cursor: pointer; }}
.clickable:hover {{ background: var(--expand-bg); }}
.expand-row {{ display: none; }}
.expand-row.open {{ display: table-row; }}
.expand-cell {{ padding: 16px 20px; background: var(--expand-bg); }}
a {{ color: var(--blue); text-decoration: none; }}
a:hover {{ text-decoration: underline; }}
.chart-container {{ height: 300px; margin: 16px 0; }}
.detail-section {{ margin-top: 12px; }}
.detail-section h4 {{ font-size: 0.85rem; color: var(--muted); margin-bottom: 6px; }}
.detail-table {{ font-size: 0.8rem; }}
.detail-table td {{ padding: 4px 8px; }}
</style>
</head>
<body>

<h1>CVE Tracking — {_esc(meta.get('project', ''))}</h1>
<p class="subtitle">
    {summary['totalUniqueCves']} unique CVEs tracked across {meta.get('totalCommits', '?')} commits
    &middot; {meta.get('uniqueDepsQueried', '?')} unique dependency versions queried
    &middot; {meta.get('dateRange', {}).get('from', '?')} to {meta.get('dateRange', {}).get('to', '?')}
    &middot; generated {meta.get('generated', '')[:16]}
</p>

{'<div style="background:var(--badge-rm,#ffebee);color:var(--badge-rm-fg,#c62828);border:1px solid;border-radius:8px;padding:12px 16px;margin-bottom:16px;font-size:0.9rem"><strong>Warning:</strong> CVE data is INCOMPLETE — ' + str(meta.get("failedDepsCount", 0)) + ' dependency version(s) could not be queried from OSV.dev after ' + str(MAX_RETRIES) + ' retries. Check metadata.failedDeps in the JSON for the list.</div>' if meta.get("failedDepsCount", 0) > 0 else ''}

{cards}

<div class="section">
    <h2>CVE Count Over Time</h2>
    <div class="chart-container">
        <canvas id="timelineChart"></canvas>
    </div>
</div>

<div class="section">
    <h2>CVE Changes Per Commit</h2>
    <div style="overflow-x:auto">
    <table>
        <thead><tr><th>Commit</th><th>Date</th><th>Message</th><th>Introduced</th><th>Resolved</th><th>Net</th><th>Details</th></tr></thead>
        <tbody>{''.join(commit_rows)}</tbody>
    </table>
    </div>
</div>

<div class="section">
    <h2>CVE Lifecycles</h2>
    <p style="font-size:0.82rem;color:var(--muted);margin-bottom:12px">Open CVEs first, then sorted by duration (longest first)</p>
    <div style="overflow-x:auto">
    <table>
        <thead><tr><th>CVE</th><th>Severity</th><th>Summary</th><th>Dependencies</th><th>First Seen</th><th>Last Seen</th><th>Duration</th><th>Status</th><th>Resolution</th></tr></thead>
        <tbody>{''.join(lc_rows)}</tbody>
    </table>
    </div>
</div>

<div class="section">
    <h2>Per-Dependency CVE Summary (top 30)</h2>
    <div style="overflow-x:auto">
    <table>
        <thead><tr><th>Dependency</th><th>Versions</th><th>Total CVEs</th><th>Current</th><th>Current CVE IDs</th></tr></thead>
        <tbody>{''.join(dep_rows)}</tbody>
    </table>
    </div>
</div>

<div class="section">
    <h2>Category Correlation</h2>
    <p style="font-size:0.82rem;color:var(--muted);margin-bottom:12px">
        How often a CVE's CWE category matches the dependency's reachable sensitive API category.
        Higher match = stronger (though not conclusive) signal of actual vulnerability exposure.
    </p>
    <table>
        <thead><tr><th>Category</th><th>CVEs in Category</th><th>Deps with CVE + Reachable APIs</th><th>CVE Category Matches Reachable Category</th></tr></thead>
        <tbody>{''.join(cat_rows)}</tbody>
    </table>
</div>

<script>
Chart.defaults.color = getComputedStyle(document.documentElement).getPropertyValue('--fg').trim() || '#1a1a1a';
Chart.defaults.borderColor = getComputedStyle(document.documentElement).getPropertyValue('--border').trim() || '#e0e0e0';

function toggleCommit(row) {{
    const next = row.nextElementSibling;
    if (next && next.classList.contains('expand-row')) {{
        next.classList.toggle('open');
    }}
}}

const tdata = {timeline_chart};
new Chart(document.getElementById('timelineChart'), {{
    type: 'line',
    data: {{
        labels: tdata.labels,
        datasets: [{{
            label: 'Total CVEs',
            data: tdata.totals,
            borderColor: getComputedStyle(document.documentElement).getPropertyValue('--red').trim(),
            backgroundColor: 'rgba(192,57,43,0.1)',
            borderWidth: 2, pointRadius: 1, pointHitRadius: 6,
            fill: true, tension: 0.3,
        }}]
    }},
    options: {{
        responsive: true, maintainAspectRatio: false,
        plugins: {{ legend: {{ position: 'bottom' }} }},
        scales: {{
            x: {{ ticks: {{ maxRotation: 45, autoSkip: true, maxTicksLimit: 25 }} }},
            y: {{ beginAtZero: true, title: {{ display: true, text: 'CVE count' }} }}
        }}
    }}
}});
</script>
</body>
</html>"""


def _commit_detail_html(diff):
    parts = []
    if diff.get("introduced"):
        rows = []
        for intr in diff["introduced"]:
            sev_cls = f"sev-{intr.get('severity', '').lower()}"
            rows.append(
                f"<tr><td><a href='{_esc(intr['link'])}' target='_blank'>"
                f"{_esc(intr['cveId'])}</a></td>"
                f"<td><span class='badge {sev_cls}'>{_esc(intr.get('severity', '?'))}</span></td>"
                f"<td>{_esc(intr.get('summary', '')[:80])}</td>"
                f"<td class='mono'>{_esc(intr['dep'])}</td>"
                f"<td>{_esc(intr.get('introductionMethod', ''))}</td>"
                f"<td>{intr.get('depApis', 0)} APIs</td>"
                f"<td>{', '.join(intr.get('theoCategories', []))}</td></tr>")
        parts.append(
            f"<div class='detail-section'><h4>Introduced ({len(diff['introduced'])})</h4>"
            f"<table class='detail-table'><thead><tr><th>CVE</th><th>Severity</th>"
            f"<th>Summary</th><th>Dependency</th><th>How</th><th>Dep APIs</th>"
            f"<th>CVE Categories</th></tr></thead>"
            f"<tbody>{''.join(rows)}</tbody></table></div>")

    if diff.get("resolved"):
        rows = []
        for res in diff["resolved"]:
            sev_cls = f"sev-{res.get('severity', '').lower()}"
            updated = f" → {_esc(res['updatedTo'])}" if res.get("updatedTo") else ""
            rows.append(
                f"<tr><td><a href='{_esc(res['link'])}' target='_blank'>"
                f"{_esc(res['cveId'])}</a></td>"
                f"<td><span class='badge {sev_cls}'>{_esc(res.get('severity', '?'))}</span></td>"
                f"<td>{_esc(res.get('summary', '')[:80])}</td>"
                f"<td class='mono'>{_esc(res['dep'])}{updated}</td>"
                f"<td>{_esc(res.get('resolutionMethod', ''))}</td>"
                f"<td>{res.get('depApis', 0)} → {res.get('depApisAfter', '?')}</td>"
                f"<td>{', '.join(res.get('theoCategories', []))}</td></tr>")
        parts.append(
            f"<div class='detail-section'><h4>Resolved ({len(diff['resolved'])})</h4>"
            f"<table class='detail-table'><thead><tr><th>CVE</th><th>Severity</th>"
            f"<th>Summary</th><th>Dependency</th><th>How</th><th>APIs Change</th>"
            f"<th>CVE Categories</th></tr></thead>"
            f"<tbody>{''.join(rows)}</tbody></table></div>")

    return "".join(parts) if parts else "<p style='color:var(--muted)'>No details</p>"


def _esc(s):
    return (str(s).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#39;"))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Track CVE changes across a project's dependency history.")
    parser.add_argument("timeline", help="Path to timeline_data.json")
    parser.add_argument("--repo-url", help="GitHub repo URL")
    parser.add_argument("--project", help="Project name")
    parser.add_argument("--output", help="Output directory (default: same as timeline)")
    parser.add_argument("--cache", help="OSV cache file path (default: <output>/osv_cache.json)")
    parser.add_argument("--refresh-cache", action="store_true",
                        help="Re-query OSV.dev even if cache exists")
    args = parser.parse_args()

    timeline_path = Path(args.timeline)
    if not timeline_path.exists():
        print(f"Not found: {timeline_path}", file=sys.stderr)
        sys.exit(1)

    data = load_json(timeline_path)
    timeline = data.get("timeline", [])
    if not timeline:
        print("No timeline entries found.", file=sys.stderr)
        sys.exit(1)

    project = args.project or timeline_path.parent.name
    out_dir = Path(args.output) if args.output else timeline_path.parent
    out_dir.mkdir(parents=True, exist_ok=True)
    cache_path = args.cache or str(out_dir / "osv_cache.json")

    print(f"Project: {project}")
    print(f"Timeline: {len(timeline)} commits")

    # Collect unique deps
    unique_gavs = set()
    for entry in timeline:
        for _mod, mod_data in entry.get("reachability", {}).items():
            for dep_key in mod_data.get("depsDetail", {}):
                unique_gavs.add(dep_key)

    print(f"Unique dependency versions: {len(unique_gavs)}")

    # Query OSV
    osv_cache, failed_deps = query_osv_for_deps(
        sorted(unique_gavs), cache_path, args.refresh_cache)

    deps_with_cves = sum(1 for g in unique_gavs if osv_cache.get(g))
    total_cve_entries = sum(len(osv_cache.get(g, [])) for g in unique_gavs)
    print(f"  {deps_with_cves} deps have CVEs ({total_cve_entries} total CVE entries)")
    if failed_deps:
        print(f"  WARNING: {len(failed_deps)} deps have INCOMPLETE CVE data "
              f"(OSV query failed after {MAX_RETRIES} retries)")

    # Build per-commit CVE state
    states = build_commit_cve_states(timeline, osv_cache)

    # Compute diffs
    diffs = compute_cve_diffs(states)
    commits_with_changes = sum(1 for d in diffs
                               if not d.get("isBaseline")
                               and (d.get("introduced") or d.get("resolved")))
    print(f"  {commits_with_changes} commits with CVE changes")

    # Build lifecycles
    lifecycles = build_lifecycles(states)

    # Per-dep summary
    per_dep = build_per_dep_summary(states, osv_cache)

    # Category correlation
    cat_corr = build_category_correlation(states, osv_cache)

    # Summary
    summary = build_summary(diffs, lifecycles)

    report = {
        "metadata": {
            "project": project,
            "generated": datetime.now().isoformat(),
            "timelineFile": str(timeline_path),
            "totalCommits": len(timeline),
            "commitsWithCveChanges": commits_with_changes,
            "dateRange": data.get("dateRange", {}),
            "uniqueDepsQueried": len(unique_gavs),
            "osvCacheFile": cache_path,
            "failedDeps": failed_deps,
            "failedDepsCount": len(failed_deps),
            "dataComplete": len(failed_deps) == 0,
        },
        "summary": summary,
        "perCommit": diffs,
        "cveLifecycles": lifecycles,
        "perDependency": per_dep,
        "categoryCorrelation": cat_corr,
    }

    json_path = out_dir / "cve_tracking.json"
    with open(json_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"JSON: {json_path}")

    html_path = out_dir / "cve_tracking.html"
    html_path.write_text(generate_html(report), encoding="utf-8")
    print(f"HTML: {html_path}")


if __name__ == "__main__":
    main()
