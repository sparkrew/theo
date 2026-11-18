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
# Snapshot loading (per-dep per-category)
# ---------------------------------------------------------------------------

def load_snapshots_index(snapshots_dir):
    """Build index: (groupId__artifactId, label) -> path.

    Accepts either:
      - The parent dir containing artifact subdirs (e.g. theo-history-snapshots/)
      - A single artifact subdir directly (e.g. theo-history-snapshots/com.x__y/)
    """
    idx = {}
    if not snapshots_dir or not Path(snapshots_dir).exists():
        return idx

    base = Path(snapshots_dir)

    # Check if this dir itself contains snapshot .json files (single artifact dir)
    direct_jsons = list(base.glob("*.json"))
    if direct_jsons:
        for f in direct_jsons:
            parts = f.stem.split("__", 1)
            if len(parts) == 2:
                idx[(base.name, parts[1])] = f
    else:
        # Parent dir with artifact subdirs
        for artifact_dir in base.iterdir():
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


def build_snapshot_dep_cats(timeline, snapshots_dir):
    """Build {sha: {dep_key: {cat: count}}} from snapshot files.

    Uses the sha (8-char prefix from timeline) to match snapshot labels.
    """
    snap_idx = load_snapshots_index(snapshots_dir)
    if not snap_idx:
        print("  No snapshot index entries found — check snapshots path",
              file=sys.stderr)
        return {}

    # Show sample keys for debugging
    sample_keys = list(snap_idx.keys())[:3]
    print(f"  Snapshot index: {len(snap_idx)} entries, "
          f"sample keys: {sample_keys}")

    timeline_shas = {entry.get("sha", "") for entry in timeline}
    sample_shas = list(timeline_shas)[:3]
    print(f"  Timeline SHAs (8-char): {sample_shas}")

    result = {}
    for entry in timeline:
        sha = entry.get("sha", "")
        dep_cats = {}
        for key, snap_path in snap_idx.items():
            label = key[1]
            if label == sha or label.startswith(sha) or sha.startswith(label):
                detail = load_snapshot_api_detail(snap_path)
                dep_cats.update(detail)
        if dep_cats:
            result[sha] = dep_cats

    if not result:
        print("  WARNING: No snapshot labels matched any timeline SHAs. "
              "Check that snapshot filenames contain the commit SHA prefix.",
              file=sys.stderr)
    return result


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

def build_commit_cve_states(timeline, osv_cache, snap_dep_cats=None):
    """For each commit, build the full set of (cve_id, dep_gav) tuples present."""
    snap_dep_cats = snap_dep_cats or {}
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

        sha = entry.get("sha", "")
        cat_totals = {}
        for _mod2, mod_data2 in reach.items():
            for cat, cnt in mod_data2.get("reachableApisByCategory", {}).items():
                cat_totals[cat] = cat_totals.get(cat, 0) + cnt
        states.append({
            "sha": sha,
            "date": entry.get("date", ""),
            "message": entry.get("message", ""),
            "cves": cve_set,
            "depsDetail": dep_detail_all,
            "depCats": snap_dep_cats.get(sha, {}),
            "categoryTotals": cat_totals,
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


def _get_category_totals(tl_entry):
    """Sum reachableApisByCategory across all modules for a timeline entry."""
    totals = {}
    for _mod, mod_data in tl_entry.get("reachability", {}).items():
        for cat, count in mod_data.get("reachableApisByCategory", {}).items():
            totals[cat] = totals.get(cat, 0) + count
    return totals


def compute_cve_diffs(states, timeline=None):
    """Compute CVE introductions and resolutions between consecutive commits."""
    timeline = timeline or []
    # Build sha->timeline entry index for category deltas
    sha_to_tl = {}
    for entry in timeline:
        sha_to_tl[entry.get("sha", "")] = entry

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
            cur_dep_cats = cur.get("depCats", {})
            prev_dep_cats = prev.get("depCats", {})

            # Group by dependency: show CVE + sensitive API changes together
            dep_map = defaultdict(lambda: {
                "cvesIntroduced": [], "cvesResolved": [],
                "apisBefore": 0, "apisAfter": 0, "apisDelta": 0,
                "versionBefore": "", "versionAfter": "",
                "catBefore": {}, "catAfter": {},
            })
            for intr in introduced:
                ga = dep_ga(intr["dep"])
                dm = dep_map[ga]
                dm["cvesIntroduced"].append(intr)
                dm["apisAfter"] = intr.get("depApis", 0)
                dm["apisBefore"] = intr.get("depApisBefore", 0)
                dm["versionAfter"] = dep_version(intr["dep"])
                dm["catAfter"] = cur_dep_cats.get(intr["dep"], {})
                if intr.get("previousDep"):
                    dm["versionBefore"] = dep_version(intr["previousDep"])
                    dm["catBefore"] = prev_dep_cats.get(intr["previousDep"], {})
            for res in resolved:
                ga = dep_ga(res["dep"])
                dm = dep_map[ga]
                dm["cvesResolved"].append(res)
                dm["apisBefore"] = res.get("depApis", 0)
                dm["apisAfter"] = res.get("depApisAfter", 0)
                dm["versionBefore"] = dep_version(res["dep"])
                dm["catBefore"] = prev_dep_cats.get(res["dep"], {})
                if res.get("updatedTo"):
                    dm["versionAfter"] = dep_version(res["updatedTo"])
                    dm["catAfter"] = cur_dep_cats.get(res["updatedTo"], {})

            for ga, dm in dep_map.items():
                dm["apisDelta"] = dm["apisAfter"] - dm["apisBefore"]

            dep_details = [
                {"dep": ga, **dm}
                for ga, dm in sorted(dep_map.items(),
                                     key=lambda x: -(len(x[1]["cvesIntroduced"])
                                                      + len(x[1]["cvesResolved"])))
            ]

            # Get category totals and deltas from timeline
            tl_entry = sha_to_tl.get(cur["sha"], {})
            prev_tl_entry = sha_to_tl.get(prev["sha"], {}) if prev else {}
            cat_after = _get_category_totals(tl_entry)
            cat_before = _get_category_totals(prev_tl_entry)
            cat_deltas = {}
            for cat in set(list(cat_after.keys()) + list(cat_before.keys())):
                diff_val = cat_after.get(cat, 0) - cat_before.get(cat, 0)
                if diff_val != 0:
                    cat_deltas[cat] = diff_val

            diffs.append({
                "sha": cur["sha"], "date": cur["date"], "message": cur["message"],
                "introduced": sorted(introduced, key=lambda x: x["cveId"]),
                "resolved": sorted(resolved, key=lambda x: x["cveId"]),
                "totalCves": len(cur["cves"]),
                "netChange": len(introduced) - len(resolved),
                "isBaseline": False,
                "depDetails": dep_details,
                "categoryBefore": cat_before,
                "categoryAfter": cat_after,
                "categoryDeltas": cat_deltas,
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

    CAT_LABELS = {"FILESYSTEM": "FileAccess", "NETWORK": "Network",
                  "PROCESS": "Process", "OTHER": "Other"}
    DISPLAY_CATS = ["FILESYSTEM", "NETWORK", "PROCESS"]

    # Per-dep CVE + sensitive API changes per commit
    dep_commit_sections = []
    for diff in diffs:
        if diff.get("isBaseline"):
            continue
        dep_details = diff.get("depDetails", [])
        if not dep_details:
            continue

        # Check if any dep has per-category data
        has_cat_data = any(dd.get("catBefore") or dd.get("catAfter")
                          for dd in dep_details)

        # Category column headers (only if snapshot data exists)
        cat_headers = ""
        cat_subheaders = ""
        if has_cat_data:
            for cat in DISPLAY_CATS:
                label = CAT_LABELS[cat]
                cat_headers += f"<th colspan='2' style='text-align:center'>{label}</th>"
                cat_subheaders += "<th>Before</th><th>Δ</th>"

        dep_rows = []
        for dd in dep_details:
            n_intro = len(dd.get("cvesIntroduced", []))
            n_res = len(dd.get("cvesResolved", []))

            ver_str = ""
            if dd.get("versionBefore") and dd.get("versionAfter"):
                ver_str = f"{_esc(dd['versionBefore'])} → {_esc(dd['versionAfter'])}"
            elif dd.get("versionAfter"):
                ver_str = f"→ {_esc(dd['versionAfter'])}"
            elif dd.get("versionBefore"):
                ver_str = f"{_esc(dd['versionBefore'])} →"

            cve_badges = []
            for ci in dd.get("cvesIntroduced", []):
                sc = f"sev-{ci.get('severity', '').lower()}"
                cve_badges.append(f"<span class='badge {sc}'>+{_esc(ci['cveId'])}</span>")
            for cr in dd.get("cvesResolved", []):
                cve_badges.append(f"<span class='badge badge-resolved'>-{_esc(cr['cveId'])}</span>")

            # Total APIs (always available from depsDetail)
            api_before = dd.get("apisBefore", 0)
            api_after = dd.get("apisAfter", 0)
            api_delta = dd.get("apisDelta", 0)
            api_cls = "delta-up" if api_delta > 0 else "delta-down" if api_delta < 0 else ""
            api_sign = f"+{api_delta}" if api_delta > 0 else str(api_delta) if api_delta != 0 else ""

            # Per-dep per-category cells (from snapshots)
            cat_cells = ""
            if has_cat_data:
                cb = dd.get("catBefore", {})
                ca = dd.get("catAfter", {})
                for cat in DISPLAY_CATS:
                    bv = cb.get(cat, 0)
                    av = ca.get(cat, 0)
                    dv = av - bv
                    d_cls = "delta-up" if dv > 0 else "delta-down" if dv < 0 else ""
                    d_sign = f"+{dv}" if dv > 0 else str(dv) if dv != 0 else ""
                    bv_str = str(bv) if bv else ""
                    cat_cells += f"<td>{bv_str}</td><td class='{d_cls}'>{d_sign}</td>"

            dep_rows.append(
                f"<tr>"
                f"<td class='mono'>{_esc(dd['dep'])}</td>"
                f"<td style='font-size:0.78rem'>{ver_str}</td>"
                f"<td style='color:var(--red)'>{'+' + str(n_intro) if n_intro else ''}</td>"
                f"<td style='color:var(--green)'>{'-' + str(n_res) if n_res else ''}</td>"
                f"<td>{api_before}</td><td>{api_after}</td>"
                f"<td class='{api_cls}'>{api_sign}</td>"
                f"{cat_cells}"
                f"<td style='font-size:0.75rem'>{' '.join(cve_badges)}</td>"
                f"</tr>")

        dep_commit_sections.append(f"""
        <div style="margin-bottom:24px">
            <h3 style="font-size:0.9rem;margin-bottom:8px">
                <span class="mono">{_esc(diff['sha'])}</span>
                <span style="color:var(--muted);font-weight:400"> — {_esc(diff['date'])} — {_esc(diff['message'][:80])}</span>
            </h3>
            <table class="dep-detail-table">
                <thead>
                    <tr>
                        <th rowspan="2">Dependency</th><th rowspan="2">Version</th>
                        <th rowspan="2">CVEs +</th><th rowspan="2">CVEs -</th>
                        <th colspan="3" style="text-align:center">Total APIs</th>
                        {cat_headers}
                        <th rowspan="2">CVE Details</th>
                    </tr>
                    <tr><th>Before</th><th>After</th><th>Δ</th>{cat_subheaders}</tr>
                </thead>
                <tbody>{''.join(dep_rows)}</tbody>
            </table>
        </div>""")

    # --- Per-category chart data: CVE bars (same) + category API delta line ---
    CHART_CATS = ["FILESYSTEM", "NETWORK", "PROCESS"]

    diff_by_sha = {}
    for diff in diffs:
        diff_by_sha[diff["sha"]] = diff

    all_commits = report.get("_allStates", [])
    chart_labels = []
    cve_introduced_data = []
    cve_resolved_data = []
    cat_api_deltas = {c: [] for c in CHART_CATS}

    for i, state in enumerate(all_commits):
        sha = state["sha"]
        chart_labels.append(sha)
        diff = diff_by_sha.get(sha)
        if diff and not diff.get("isBaseline"):
            cve_introduced_data.append(len(diff.get("introduced", [])))
            cve_resolved_data.append(-len(diff.get("resolved", [])))
        else:
            cve_introduced_data.append(0)
            cve_resolved_data.append(0)
        if i == 0:
            for c in CHART_CATS:
                cat_api_deltas[c].append(0)
        else:
            prev_cats = all_commits[i - 1].get("categoryTotals", {})
            cur_cats = state.get("categoryTotals", {})
            for c in CHART_CATS:
                cat_api_deltas[c].append(
                    cur_cats.get(c, 0) - prev_cats.get(c, 0))

    chart_labels_json = json.dumps(chart_labels)
    cve_intro_json = json.dumps(cve_introduced_data)
    cve_res_json = json.dumps(cve_resolved_data)
    cat_api_deltas_json = {c: json.dumps(v) for c, v in cat_api_deltas.items()}

    # --- Heatmap data: (commit, dep) -> category ---
    # Build from states (all commits) + diffs (CVE info)
    # Track per-dep API changes between consecutive commits
    all_heatmap_deps = set()
    heatmap_cells = {}  # (sha, dep_ga) -> "both"|"cve_only"|"api_only"
    heatmap_commit_list = []  # [{sha, date, message}] for commits with activity

    # Index CVE changes by (sha, dep_ga) -> {"intro": N, "resolved": N}
    cve_change_info = {}
    for diff in diffs:
        if diff.get("isBaseline"):
            continue
        for dd in diff.get("depDetails", []):
            n_intro = len(dd.get("cvesIntroduced", []))
            n_res = len(dd.get("cvesResolved", []))
            if n_intro or n_res:
                cve_change_info[(diff["sha"], dd["dep"])] = {
                    "intro": n_intro, "resolved": n_res}

    for i, state in enumerate(all_commits):
        if i == 0:
            continue
        prev = all_commits[i - 1]
        sha = state["sha"]
        cur_by_ga = {}
        for dk, cnt in state["depsDetail"].items():
            ga = dep_ga(dk)
            cur_by_ga[ga] = cur_by_ga.get(ga, 0) + cnt
        prev_by_ga = {}
        for dk, cnt in prev["depsDetail"].items():
            ga = dep_ga(dk)
            prev_by_ga[ga] = prev_by_ga.get(ga, 0) + cnt

        has_activity = False
        all_gas = set(cur_by_ga.keys()) | set(prev_by_ga.keys())
        for ga in all_gas:
            api_delta = cur_by_ga.get(ga, 0) - prev_by_ga.get(ga, 0)
            cve_info = cve_change_info.get((sha, ga))
            has_cve = cve_info is not None
            has_api = api_delta != 0
            if has_cve or has_api:
                all_heatmap_deps.add(ga)
                has_activity = True
                if has_cve and has_api:
                    cat = "both"
                elif has_cve:
                    cat = "cve_only"
                else:
                    cat = "api_only"
                heatmap_cells[(sha, ga)] = {
                    "cat": cat,
                    "cve_intro": cve_info["intro"] if cve_info else 0,
                    "cve_resolved": cve_info["resolved"] if cve_info else 0,
                    "api_delta": api_delta,
                }
        if has_activity:
            heatmap_commit_list.append({
                "sha": sha, "date": state["date"],
                "message": state.get("message", ""),
            })

    sorted_heatmap_deps = sorted(all_heatmap_deps)
    heatmap_html = ""
    if heatmap_commit_list and sorted_heatmap_deps:
        hm_header = "<th>Dependency</th>"
        for hc in heatmap_commit_list:
            hm_header += (f"<th class='hm-col' title='{_esc(hc['date'])} "
                          f"{_esc(hc['message'][:60])}'>{_esc(hc['sha'])}</th>")
        hm_rows = []
        for dep_ga_key in sorted_heatmap_deps:
            cells = f"<td class='mono' style='white-space:nowrap'>{_esc(dep_ga_key)}</td>"
            for hc in heatmap_commit_list:
                cell = heatmap_cells.get((hc["sha"], dep_ga_key))
                if not cell:
                    cls = "hm-none"
                    label = ""
                else:
                    cls = {"both": "hm-both", "cve_only": "hm-cve",
                           "api_only": "hm-api"}[cell["cat"]]
                    parts = []
                    if cell["cve_intro"]:
                        parts.append(f"CVE↑{cell['cve_intro']}")
                    if cell["cve_resolved"]:
                        parts.append(f"CVE↓{cell['cve_resolved']}")
                    ad = cell["api_delta"]
                    if ad > 0:
                        parts.append(f"API↑{ad}")
                    elif ad < 0:
                        parts.append(f"API↓{abs(ad)}")
                    label = " ".join(parts)
                cells += f"<td class='hm-cell {cls}'>{label}</td>"
            hm_rows.append(f"<tr>{cells}</tr>")

        heatmap_html = f"""
    <div class="section">
        <h2>CVE &amp; Sensitive API Change Heatmap</h2>
        <p style="font-size:0.82rem;color:var(--muted);margin-bottom:8px">
            Each cell shows whether a dependency had a CVE change, an API reachability change, or both at each commit.
        </p>
        <div style="margin-bottom:8px;font-size:0.8rem">
            <span class="hm-legend hm-both">CVE + API change</span>
            <span class="hm-legend hm-cve">CVE change only</span>
            <span class="hm-legend hm-api">API change only</span>
            <span style="color:var(--muted);margin-left:12px">↑ = introduced/increased &nbsp; ↓ = resolved/decreased</span>
        </div>
        <div style="overflow-x:auto">
        <table class="heatmap-table">
            <thead><tr>{hm_header}</tr></thead>
            <tbody>{''.join(hm_rows)}</tbody>
        </table>
        </div>
    </div>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CVE Tracking — {_esc(meta.get('project', ''))}</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4/dist/chart.umd.min.js"></script>
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
.section h3 {{ font-size: 0.95rem; color: var(--muted); margin-bottom: 8px; margin-top: 16px; }}
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
.detail-section {{ margin-top: 12px; }}
.detail-section h4 {{ font-size: 0.85rem; color: var(--muted); margin-bottom: 6px; }}
.detail-table {{ font-size: 0.8rem; }}
.detail-table td {{ padding: 4px 8px; }}
.dep-detail-table {{ font-size: 0.82rem; }}
.dep-detail-table td {{ padding: 5px 8px; }}
.chart-container {{ height: 350px; margin: 16px 0; }}
.heatmap-table {{ font-size: 0.75rem; }}
.heatmap-table th, .heatmap-table td {{ padding: 4px 6px; text-align: center; }}
.hm-col {{ writing-mode: vertical-rl; text-orientation: mixed; font-size: 0.7rem; max-width: 32px; }}
.hm-cell {{ min-width: 28px; font-size: 0.65rem; font-weight: 600; }}
.hm-both {{ background: var(--purple); color: #fff; }}
.hm-cve {{ background: var(--red); color: #fff; }}
.hm-api {{ background: var(--orange); color: #fff; }}
.hm-none {{ background: transparent; }}
.hm-legend {{ display: inline-block; padding: 2px 10px; border-radius: 4px; margin-right: 8px; font-weight: 600; color: #fff; }}
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
    <h2>CVE &amp; Sensitive API Changes Over Time</h2>
    <p style="font-size:0.82rem;color:var(--muted);margin-bottom:8px">
        Bars show CVE introductions (red, up) and resolutions (green, down) — same across all three charts.
        Each line shows the sensitive API reachability delta for that category.
    </p>
    <h3 style="margin-top:16px">FileAccess</h3>
    <div class="chart-container">
        <canvas id="chartFileAccess"></canvas>
    </div>
    <h3>Network</h3>
    <div class="chart-container">
        <canvas id="chartNetwork"></canvas>
    </div>
    <h3>Process</h3>
    <div class="chart-container">
        <canvas id="chartProcess"></canvas>
    </div>
</div>

{heatmap_html}

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
    <h2>Per-Dependency CVE &amp; Sensitive API Changes</h2>
    <p style="font-size:0.82rem;color:var(--muted);margin-bottom:16px">
        For each commit with CVE changes, shows how each involved dependency's CVEs and sensitive API count changed together.
    </p>
    {''.join(dep_commit_sections)}
</div>

<script>
function toggleCommit(row) {{
    const next = row.nextElementSibling;
    if (next && next.classList.contains('expand-row')) {{
        next.classList.toggle('open');
    }}
}}

// Per-category dual-axis charts
(function() {{
    const fg = getComputedStyle(document.documentElement).getPropertyValue('--fg').trim() || '#1a1a1a';
    const border = getComputedStyle(document.documentElement).getPropertyValue('--border').trim() || '#e0e0e0';
    Chart.defaults.color = fg;
    Chart.defaults.borderColor = border;

    const labels = {chart_labels_json};
    const cveIntro = {cve_intro_json};
    const cveRes = {cve_res_json};
    const catData = {{
        'FileAccess': {cat_api_deltas_json["FILESYSTEM"]},
        'Network': {cat_api_deltas_json["NETWORK"]},
        'Process': {cat_api_deltas_json["PROCESS"]},
    }};
    const lineColors = {{
        'FileAccess': 'rgba(41, 128, 185, 1)',
        'Network': 'rgba(108, 74, 182, 1)',
        'Process': 'rgba(224, 122, 58, 1)',
    }};
    const chartIds = {{
        'FileAccess': 'chartFileAccess',
        'Network': 'chartNetwork',
        'Process': 'chartProcess',
    }};

    for (const [catName, apiDeltas] of Object.entries(catData)) {{
        const ctx = document.getElementById(chartIds[catName]);
        if (!ctx) continue;
        new Chart(ctx, {{
            type: 'bar',
            data: {{
                labels: labels,
                datasets: [
                    {{
                        label: 'CVEs Introduced',
                        data: cveIntro,
                        backgroundColor: 'rgba(192, 57, 43, 0.7)',
                        borderColor: 'rgba(192, 57, 43, 1)',
                        borderWidth: 1,
                        yAxisID: 'yCve',
                        order: 2,
                    }},
                    {{
                        label: 'CVEs Resolved',
                        data: cveRes,
                        backgroundColor: 'rgba(45, 106, 79, 0.7)',
                        borderColor: 'rgba(45, 106, 79, 1)',
                        borderWidth: 1,
                        yAxisID: 'yCve',
                        order: 2,
                    }},
                    {{
                        label: catName + ' API Δ',
                        data: apiDeltas,
                        type: 'line',
                        borderColor: lineColors[catName],
                        backgroundColor: lineColors[catName].replace('1)', '0.1)'),
                        borderWidth: 2,
                        pointRadius: 3,
                        fill: false,
                        yAxisID: 'yApi',
                        order: 1,
                    }}
                ]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                interaction: {{ mode: 'index', intersect: false }},
                plugins: {{
                    legend: {{ position: 'bottom' }},
                }},
                scales: {{
                    x: {{
                        ticks: {{ maxRotation: 45, autoSkip: true, maxTicksLimit: 30, font: {{ size: 10 }} }}
                    }},
                    yCve: {{
                        type: 'linear',
                        position: 'left',
                        title: {{ display: true, text: 'CVE Changes' }},
                        grid: {{ drawOnChartArea: true }},
                    }},
                    yApi: {{
                        type: 'linear',
                        position: 'right',
                        title: {{ display: true, text: catName + ' API Δ' }},
                        grid: {{ drawOnChartArea: false }},
                    }}
                }}
            }}
        }});
    }}
}})();
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
    parser.add_argument("--snapshots", help="Path to snapshots directory (for per-dep per-category)")
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

    # Load per-dep per-category from snapshots
    snap_dep_cats = {}
    if args.snapshots:
        print(f"  Loading snapshots from {args.snapshots}...")
        snap_dep_cats = build_snapshot_dep_cats(timeline, args.snapshots)
        print(f"  Loaded per-dep category data for {len(snap_dep_cats)} commits")

    # Build per-commit CVE state
    states = build_commit_cve_states(timeline, osv_cache, snap_dep_cats)

    # Compute diffs
    diffs = compute_cve_diffs(states, timeline)
    commits_with_changes = sum(1 for d in diffs
                               if not d.get("isBaseline")
                               and (d.get("introduced") or d.get("resolved")))
    print(f"  {commits_with_changes} commits with CVE changes")

    # Build lifecycles (for summary stats)
    lifecycles = build_lifecycles(states)

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
        "_allStates": states,
    }

    html_path = out_dir / "cve_tracking.html"
    html_path.write_text(generate_html(report), encoding="utf-8")
    print(f"HTML: {html_path}")

    del report["_allStates"]
    json_path = out_dir / "cve_tracking.json"
    with open(json_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"JSON: {json_path}")


if __name__ == "__main__":
    main()
