#!/usr/bin/env python3
"""
History analysis script for Theo.

Walks through git history of Maven projects (oldest to newest), identifies
commits with actual dependency changes in pom.xml files, and runs Theo
reachable-only analysis on the affected modules.  Keeps all caches and
snapshots on disk so that consecutive runs compare with the previous state.

Usage:
    python3 run_history_analysis.py [path/to/client_project_histories.json]

Default input: theo-all/client-project-reports/client_project_histories.json

Input JSON format (array):
  [
    {
      "projectPath": "/data/rech/gamageyo/tmp/indigo-iam_iam",
      "lastCommit": "027afe12...",
      "packageName": "it.infn.mw.iam",
      "preCommand": "git stash apply",
      "postCommand": "git reset --hard HEAD",
      "javaVersions": [
        {"until": "8802b7e2...", "version": "17.0.20-tem"},
        {"version": "21.0.12+1.1-tem"}
      ]
    }
  ]

  javaVersions: ordered list of Java versions to use. Each entry has a
  "version" (sdkman identifier) and an optional "until" commit SHA.
  The version applies up to and including that commit; the last entry
  (without "until") applies to all remaining commits.

Report layout:
  <REPORTS_BASE>/<project>/
      history.json                  -- analysis tracking / results
      history.html                  -- Theo history (single-module)
      <commit_sha8>/                -- per-commit reports
          *.json / *.html           -- reachable, changes, stats, …
  Multi-module:
      <module>/
          history.html
          <commit_sha8>/
              *.json / *.html
"""

import json
import logging
import os
import subprocess
import shutil
import xml.etree.ElementTree as ET
import sys
import time
from pathlib import Path
from datetime import datetime, timedelta

LOG_FILE = Path(__file__).with_name("run_history_analysis.log")
log = logging.getLogger("run_history_analysis")


def setup_logging():
    log.setLevel(logging.DEBUG)
    fmt = logging.Formatter("%(asctime)s %(levelname)-5s %(message)s",
                            datefmt="%Y-%m-%d %H:%M:%S")
    fh = logging.FileHandler(LOG_FILE, mode="a", encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    ch.setFormatter(fmt)
    log.addHandler(fh)
    log.addHandler(ch)


REPORTS_BASE = Path("/home/yogya/projects/def-baudry/yogya/theo-all/client-results/history")
DEFAULT_INPUT = Path(
    "/home/yogya/projects/def-baudry/yogya/theo-all/theo/client_project_histories.json"
)

TMPDIR = os.environ.get("TMPDIR", "/tmp")
M2_REPO = f"{TMPDIR}/m2-repository"
THEO_CACHE = Path("/home/yogya/projects/def-baudry/yogya/theo-all/client-results/cache")

os.environ.pop("JAVA_TOOL_OPTIONS", None)
os.environ["MAVEN_OPTS"] = os.environ.get("MAVEN_OPTS", "") + " -Xmx64g"

THEO_PLUGIN = "io.github.sparkrew:theo-static-maven-plugin"
MVN_BUILD = (
    f"mvn clean install -DskipTests -Dcheckstyle.skip=true "
    f"-Dspotless.check.skip=true -Denforcer.skip=true "
    f"-Dmaven.repo.local={M2_REPO}"
)

BUILD_TIMEOUT = 7200     # 2 hours
THEO_TIMEOUT = 86400     # 1 day
HISTORY_TIMEOUT = 3600   # 1 hour
FIVE_YEARS = timedelta(days=5 * 365)

REACHABLE_FLAG = "-Dtheo.reachableOnly=true"
HISTORY_FILENAMES = {"history.html", "history.json"}
THEO_DIR = THEO_CACHE

import re
TEST_MODULE_PAT = re.compile(r'\btest(?:s|ing)?\b', re.IGNORECASE)



# Shared utilities
def run_cmd(cmd, cwd, timeout=120, label="command", quiet=False):
    if not quiet:
        log.info(f"  [{label}] {cmd[:120]}")
    try:
        result = subprocess.run(
            cmd, shell=True, cwd=str(cwd),
            capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"{label} timed out after {timeout}s")
    if result.returncode != 0:
        out = (result.stdout or "")[-1500:]
        err = (result.stderr or "")[-1500:]
        raise RuntimeError(
            f"{label} failed (exit {result.returncode}):\n{out}\n{err}"
        )
    return result


def select_java_version(java_versions, commit, project_path):
    """Pick the right Java version for a commit and set JAVA_HOME.

    java_versions is a list of {"version": "...", "until": "sha"} entries.
    Returns the version string used, or None if no switching configured.
    """
    if not java_versions:
        return None

    chosen = java_versions[-1]["version"]  # default: last entry
    for entry in java_versions:
        until = entry.get("until")
        if not until:
            continue
        try:
            r = subprocess.run(
                f"git merge-base --is-ancestor {commit} {until}",
                shell=True, cwd=str(project_path),
                capture_output=True, timeout=30,
            )
            if r.returncode == 0:
                chosen = entry["version"]
                break
        except Exception:
            pass

    sdkman_dir = Path.home() / ".sdkman"
    java_home = sdkman_dir / "candidates" / "java" / chosen
    if java_home.exists():
        os.environ["JAVA_HOME"] = str(java_home)
        os.environ["PATH"] = f"{java_home / 'bin'}:" + os.environ.get("PATH", "")
        log.info(f"  Java: {chosen}")
    else:
        log.warning(f"  Java version {chosen} not found at {java_home}")
    return chosen


def git_checkout(project_path, commit):
    run_cmd(f"git checkout {commit}", cwd=project_path, label="git checkout")


def git_info(project_path, commit):
    try:
        r = run_cmd(
            f"git log -1 --format='%H%n%s%n%ai' {commit}",
            cwd=project_path, label="git info",
        )
        lines = r.stdout.strip().splitlines()
        return {
            "sha": lines[0] if lines else commit,
            "message": lines[1] if len(lines) > 1 else "",
            "date": lines[2] if len(lines) > 2 else "",
        }
    except RuntimeError:
        return {"sha": commit, "message": "", "date": ""}


def build_project(project_path):
    run_cmd(MVN_BUILD, cwd=project_path, timeout=BUILD_TIMEOUT,
            label="mvn build (root)")


def get_submodules(project_path):
    pom = project_path / "pom.xml"
    if not pom.exists():
        return []
    try:
        tree = ET.parse(pom)
        root = tree.getroot()
        ns = ""
        if root.tag.startswith("{"):
            ns = root.tag.split("}")[0] + "}"
        return [m.text for m in root.findall(f".//{ns}modules/{ns}module")
                if m.text]
    except ET.ParseError:
        return []



# Git history helpers
def get_pom_commits(project_path, last_commit=None):
    """Return commits that touch any pom.xml, oldest-first.

    Starts from *last_commit* (inclusive) or 5 years ago, up to HEAD.
    """
    if last_commit:
        # Inclusive range: last_commit^ .. HEAD
        try:
            cmd = (
                f"git log --reverse --format=%H "
                f"{last_commit}^..HEAD "
                f"-- ':(glob)**/pom.xml' 'pom.xml'"
            )
            r = run_cmd(cmd, cwd=project_path, timeout=120,
                        label="git log pom commits")
            commits = [l.strip() for l in r.stdout.strip().splitlines()
                       if l.strip()]
            if commits:
                return commits
        except RuntimeError:
            pass
        # Fallback: exclusive (misses last_commit itself when it is the root)
        try:
            cmd = (
                f"git log --reverse --format=%H "
                f"{last_commit}..HEAD "
                f"-- ':(glob)**/pom.xml' 'pom.xml'"
            )
            r = run_cmd(cmd, cwd=project_path, timeout=120,
                        label="git log pom commits (excl)")
            return [l.strip() for l in r.stdout.strip().splitlines()
                    if l.strip()]
        except RuntimeError:
            return []
    else:
        since = (datetime.now() - FIVE_YEARS).strftime("%Y-%m-%d")
        cmd = (
            f"git log --reverse --format=%H "
            f"--since='{since}' "
            f"-- ':(glob)**/pom.xml' 'pom.xml'"
        )
        try:
            r = run_cmd(cmd, cwd=project_path, timeout=120,
                        label="git log pom commits (5yr)")
            return [l.strip() for l in r.stdout.strip().splitlines()
                    if l.strip()]
        except RuntimeError:
            return []


def get_changed_poms(project_path, commit):
    """List pom.xml paths changed in a single *commit*."""
    cmd = (
        f"git diff-tree --no-commit-id --name-only -r {commit} "
        f"-- ':(glob)**/pom.xml' 'pom.xml'"
    )
    try:
        r = run_cmd(cmd, cwd=project_path, timeout=60, label="diff-tree poms",
                    quiet=True)
        return [f.strip() for f in r.stdout.strip().splitlines()
                if f.strip().endswith("pom.xml")]
    except RuntimeError:
        return []



# Dependency-change detection (strict)
def _file_at_commit(project_path, commit, file_path):
    """Return file contents at *commit*, or None."""
    try:
        r = subprocess.run(
            f"git show {commit}:{file_path}",
            shell=True, cwd=str(project_path),
            capture_output=True, text=True, timeout=30,
        )
        return r.stdout if r.returncode == 0 else None
    except Exception:
        return None


def _extract_properties(root, ns):
    """Return frozenset of (name, value) from <properties>."""
    props = set()
    for prop_block in root.findall(f".//{ns}properties"):
        for child in prop_block:
            tag = child.tag.replace(ns, "") if ns else child.tag
            props.add((tag, (child.text or "").strip()))
    return frozenset(props)


def _extract_dependencies(pom_xml):
    """Return frozenset of (groupId, artifactId, version, scope) from all
    <dependency> elements, plus all <properties> entries (which often hold
    version variables)."""
    try:
        root = ET.fromstring(pom_xml)
    except ET.ParseError:
        return frozenset(), frozenset()
    ns = ""
    if root.tag.startswith("{"):
        ns = root.tag.split("}")[0] + "}"
    deps = set()
    for dep in root.findall(f".//{ns}dependency"):
        gid = (dep.findtext(f"{ns}groupId") or "").strip()
        aid = (dep.findtext(f"{ns}artifactId") or "").strip()
        ver = (dep.findtext(f"{ns}version") or "").strip()
        scope = (dep.findtext(f"{ns}scope") or "").strip()
        deps.add((gid, aid, ver, scope))
    props = _extract_properties(root, ns)
    return frozenset(deps), props


def has_dependency_changes(project_path, commit, pom_path):
    """True when <dependency> entries or <properties> (which often hold
    version variables) differ between *commit* and its parent."""
    cur = _file_at_commit(project_path, commit, pom_path)
    prev = _file_at_commit(project_path, f"{commit}^", pom_path)
    if cur is None and prev is None:
        return False
    if cur is None or prev is None:
        return True  # added or deleted
    cur_deps, cur_props = _extract_dependencies(cur)
    prev_deps, prev_props = _extract_dependencies(prev)
    return cur_deps != prev_deps or cur_props != prev_props


def pom_path_to_module(pom_path):
    """'pom.xml' -> '.', 'sub/pom.xml' -> 'sub'."""
    parent = str(Path(pom_path).parent)
    return "." if parent == "." else parent



# Module resolution
def get_all_modules(project_path):
    """Return all leaf modules in the project. Recurses into aggregator
    modules that themselves declare submodules."""
    def _collect(base, prefix=""):
        subs = get_submodules(base)
        if not subs:
            return [prefix or "."]
        leaves = []
        for sub in subs:
            full = f"{prefix}/{sub}" if prefix else sub
            child_path = base / sub
            if child_path.exists():
                leaves.extend(_collect(child_path, full))
            else:
                leaves.append(full)
        return leaves

    result = _collect(project_path)
    result = [m for m in result
              if not TEST_MODULE_PAT.search(m.split("/")[-1])]
    return sorted(set(result))


def resolve_modules(project_path, changed_modules):
    """Expand root ('.') to all submodules on a multi-module project."""
    resolved = set()
    for mod in changed_modules:
        if mod == ".":
            subs = get_submodules(project_path)
            if subs:
                resolved.update(subs)
            else:
                resolved.add(".")
        else:
            resolved.add(mod)
    return sorted(resolved)



# Theo execution
def run_theo_goal(project_path, module, package_name, goal,
                  extra_flags="", timeout=THEO_TIMEOUT):
    pl = module if module != "." else "."
    cmd = (
        f"mvn {THEO_PLUGIN}:{goal} -pl {pl} "
        f"-Dtheo.packageNames={package_name} {REACHABLE_FLAG} "
        f"-Dtheo.cacheDir={THEO_CACHE} "
        f"-Dmaven.repo.local={M2_REPO} "
        f"{extra_flags}"
    ).strip()
    run_cmd(cmd, cwd=project_path, timeout=timeout,
            label=f"theo {goal} ({module})")



# Report copying
def _module_report_src(project_path, module):
    if module == ".":
        return project_path / "target" / "theo-report"
    return project_path / module / "target" / "theo-report"


def _report_dirs(project_report_base, module, commit_sha):
    """Return (commit_report_dir, history_dir).

    Layout:  <project>/<commit8>/<module>/   — per-commit reports
             <project>/<module>/             — accumulated history
    """
    short = commit_sha[:8]
    if module == ".":
        return project_report_base / short, project_report_base
    return (project_report_base / short / module,
            project_report_base / module)


def copy_commit_reports(project_path, module, dest):
    """Copy per-commit files (everything except history) into *dest*."""
    src = _module_report_src(project_path, module)
    if not src.exists():
        return
    dest.mkdir(parents=True, exist_ok=True)
    for f in src.iterdir():
        if f.is_file() and f.name not in HISTORY_FILENAMES:
            shutil.copy2(f, dest / f.name)


def copy_history_reports(project_path, module, dest):
    """Copy history files to the module-level directory (outside commit
    folders) so they accumulate across the timeline."""
    src = _module_report_src(project_path, module)
    if not src.exists():
        return
    dest.mkdir(parents=True, exist_ok=True)
    for name in HISTORY_FILENAMES:
        f = src / name
        if f.exists():
            shutil.copy2(f, dest / name)



# Stats collection — sensitive API reachability
def read_stats_json(project_path, module):
    src = _module_report_src(project_path, module) / "stats.json"
    if not src.exists():
        return None
    try:
        with open(src) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


def find_latest_snapshot(project_path, module):
    """Find the most recent snapshot JSON under ~/.theo/history/ for this module."""
    pom = project_path / (module if module != "." else "") / "pom.xml"
    if not pom.exists():
        return None
    try:
        tree = ET.parse(pom)
        root = tree.getroot()
        ns = ""
        if root.tag.startswith("{"):
            ns = root.tag.split("}")[0] + "}"
        gid = (root.findtext(f"{ns}groupId") or "").strip()
        aid = (root.findtext(f"{ns}artifactId") or "").strip()
        if not gid:
            parent = root.find(f"{ns}parent")
            if parent is not None:
                gid = (parent.findtext(f"{ns}groupId") or "").strip()
    except ET.ParseError:
        return None
    if not gid or not aid:
        return None
    snap_dir = THEO_DIR / "history" / f"{gid}__{aid}"
    if not snap_dir.exists():
        return None
    snapshots = sorted(snap_dir.glob("*.json"), key=lambda p: p.stat().st_mtime)
    return snapshots[-1] if snapshots else None


def collect_reachability_summary(project_path, module):
    """Build a compact reachability summary for one module."""
    summary = {}

    stats = read_stats_json(project_path, module)
    if stats and "reachable" in stats:
        r = stats["reachable"]
        summary["reachableDeps"] = r.get("totalDeps", 0)
        summary["reachableDepsByCategory"] = {
            cat: info.get("deps", 0)
            for cat, info in r.get("byCategory", {}).items()
        }

    snap_path = find_latest_snapshot(project_path, module)
    if snap_path:
        try:
            with open(snap_path) as f:
                snap = json.load(f)
            apis = snap.get("reachableApis", [])
            summary["reachableApis"] = len(apis)

            by_cat = {}
            by_dep = {}
            for entry in apis:
                cat = entry.get("category", "OTHER")
                by_cat[cat] = by_cat.get(cat, 0) + 1
                dep_key = (f"{entry.get('depGroupId', '')}:"
                           f"{entry.get('depArtifactId', '')}:"
                           f"{entry.get('depVersion', '')}")
                by_dep[dep_key] = by_dep.get(dep_key, 0) + 1

            summary["reachableApisByCategory"] = by_cat
            summary["depsDetail"] = dict(
                sorted(by_dep.items(), key=lambda x: -x[1])
            )
        except (json.JSONDecodeError, OSError):
            pass

    return summary if summary else None


# Tracking / results persistence
def _history_path(project_report_base):
    return project_report_base / "analysis_results.json"


def load_tracking(project_report_base):
    p = _history_path(project_report_base)
    if p.exists():
        with open(p) as f:
            return json.load(f)
    return {"commits": [], "noDepChangeCommits": []}


def save_tracking(data, project_report_base):
    p = _history_path(project_report_base)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2)
    tmp.rename(p)



# Per-project processing
def process_project(entry):
    project_path = Path(entry["projectPath"])
    last_commit = entry.get("lastCommit")
    package_name = entry["packageName"]
    pre_command = entry.get("preCommand", "")
    post_command = entry.get("postCommand", "")
    java_versions = entry.get("javaVersions", [])

    project_name = project_path.name
    project_report_base = REPORTS_BASE / project_name
    project_report_base.mkdir(parents=True, exist_ok=True)

    tracking = load_tracking(project_report_base)
    done_shas = {c["sha"] for c in tracking["commits"]}
    no_dep_shas = set(tracking["noDepChangeCommits"])

    # ---- discover commits ----
    # Always start with lastCommit itself, then subsequent pom-changing commits
    commits_to_analyze = []
    if last_commit and last_commit not in done_shas:
        commits_to_analyze.append(last_commit)

    pom_commits = get_pom_commits(project_path, last_commit)
    log.info(f"  {len(pom_commits)} commits touch pom.xml")
    for c in pom_commits:
        if c not in commits_to_analyze:
            commits_to_analyze.append(c)

    for commit in commits_to_analyze:
        if commit in done_shas or commit in no_dep_shas:
            continue

        is_baseline = (commit == last_commit)

        if not is_baseline:
            # Strict check: only commits where <dependency> elements changed
            changed_poms = get_changed_poms(project_path, commit)
            dep_modules = []
            for pom in changed_poms:
                mod = pom_path_to_module(pom)
                if any(TEST_MODULE_PAT.search(part) for part in mod.split("/")):
                    continue
                if has_dependency_changes(project_path, commit, pom):
                    dep_modules.append(mod)

            if not dep_modules:
                log.debug(f"  {commit[:8]}: pom changed, no dep changes – skip")
                tracking["noDepChangeCommits"].append(commit)
                save_tracking(tracking, project_report_base)
                continue
        else:
            dep_modules = ["(baseline)"]

        info = git_info(project_path, commit)
        label = "BASELINE" if is_baseline else f"dep changes in: {dep_modules}"
        log.info(f"  Analyzing {commit[:8]} ({info.get('date','?')}) – {label}")

        result = {
            "sha": commit,
            "commitInfo": info,
            "changedModules": dep_modules,
        }

        try:
            # ---- checkout ----
            git_checkout(project_path, commit)

            # ---- select Java version ----
            select_java_version(java_versions, commit, project_path)

            if pre_command:
                run_cmd(pre_command, cwd=project_path, label="preCommand")

            # ---- build (root) ----
            try:
                build_project(project_path)
            except RuntimeError as e:
                log.warning(f"  Build failed for {commit[:8]}, skipping")
                log.debug(f"  {str(e)[:300]}")
                error_file = project_report_base / commit[:8] / "error.txt"
                error_file.parent.mkdir(parents=True, exist_ok=True)
                error_file.write_text(
                    f"Commit: {commit}\n"
                    f"Step: build\n"
                    f"Time: {datetime.now().isoformat()}\n\n"
                    f"{e}\n"
                )
                result["analysisResult"] = "build_failed"
                result["error"] = str(e)[:500]
                result["errorFile"] = str(error_file)
                tracking["commits"].append(result)
                save_tracking(tracking, project_report_base)
                if post_command:
                    _safe_run(post_command, project_path)
                continue

            # ---- always run all modules ----
            modules = get_all_modules(project_path)
            result["analyzedModules"] = modules

            # ---- run Theo on each module ----
            t = time.time()
            module_stats = {}
            for module in modules:
                try:
                    run_theo_goal(project_path, module, package_name,
                                  "cve-check")
                except RuntimeError as e:
                    log.warning(f"  cve-check failed on {module}: "
                                f"{str(e)[:150]}")

                try:
                    run_theo_goal(
                        project_path, module, package_name, "snapshot",
                        extra_flags=f"-Dtheo.snapshotLabel={commit[:8]}",
                    )
                except RuntimeError as e:
                    log.warning(f"  snapshot failed on {module}: "
                                f"{str(e)[:150]}")

                try:
                    run_theo_goal(project_path, module, package_name,
                                  "history", timeout=HISTORY_TIMEOUT)
                except RuntimeError as e:
                    log.warning(f"  history failed on {module}: "
                                f"{str(e)[:150]}")

                # ---- copy reports ----
                commit_dir, hist_dir = _report_dirs(
                    project_report_base, module, commit)
                copy_commit_reports(project_path, module, commit_dir)
                copy_history_reports(project_path, module, hist_dir)

                # ---- collect reachability stats ----
                mod_summary = collect_reachability_summary(
                    project_path, module)
                if mod_summary:
                    module_stats[module] = mod_summary

            if module_stats:
                result["reachability"] = module_stats
            result["durationSeconds"] = round(time.time() - t)
            result["analysisResult"] = "success"
            log.info(f"  OK {commit[:8]} ({result['durationSeconds']}s)")

        except Exception as e:
            result["analysisResult"] = "failed"
            result["error"] = str(e)[:500]
            log.error(f"  FAILED {commit[:8]}: {str(e)[:200]}")

        if post_command:
            _safe_run(post_command, project_path)

        tracking["commits"].append(result)
        save_tracking(tracking, project_report_base)
        done_shas.add(commit)

    # ---- summary ----
    success = sum(1 for c in tracking["commits"]
                  if c.get("analysisResult") == "success")
    failed = sum(1 for c in tracking["commits"]
                 if c.get("analysisResult") == "failed")
    build_fail = sum(1 for c in tracking["commits"]
                     if c.get("analysisResult") == "build_failed")
    no_dep = len(tracking["noDepChangeCommits"])

    log.info(f"  Summary: {success} analyzed, {failed} failed, "
             f"{build_fail} build failures, {no_dep} no-dep skips")


def _safe_run(cmd, cwd):
    try:
        run_cmd(cmd, cwd=cwd, label="postCommand")
    except RuntimeError as e:
        log.warning(f"  postCommand failed: {str(e)[:150]}")



# Entry point
def main():
    setup_logging()
    input_path = (Path(sys.argv[1]) if len(sys.argv) > 1
                  else DEFAULT_INPUT)
    if not input_path.exists():
        log.error(f"Input file not found: {input_path}")
        sys.exit(1)

    with open(input_path) as f:
        projects = json.load(f)

    log.info(f"Loaded {len(projects)} project(s) from {input_path}")

    for i, entry in enumerate(projects):
        project_name = Path(entry["projectPath"]).name
        log.info(f"[{i+1}/{len(projects)}] {project_name}")
        try:
            process_project(entry)
        except Exception as e:
            log.error(f"  Project failed entirely: {str(e)[:300]}")

    log.info("All projects processed")
    log.info(f"Reports: {REPORTS_BASE}")
    log.info(f"Log: {LOG_FILE}")


if __name__ == "__main__":
    main()
