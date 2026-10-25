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
      "modules": ["lang/java/avro", "lang/java/ipc"],
      "watchPoms": ["avro-parent", "lang/java"],
      "javaVersions": [
        {"until": "8802b7e2...", "version": "17.0.20-tem"},
        {"version": "21.0.12+1.1-tem"}
      ]
    }
  ]

  modules: optional list of modules to run Theo on. If omitted, discovers
  all leaf modules.

  watchPoms: optional list of additional module paths whose pom changes
  should trigger analysis (e.g. parent poms like "avro-parent"). Theo
  does NOT run on these — they only affect which commits are selected.

  oldReportsDir: optional path to a previous run's report directory.
  oldCacheDir: optional path to a previous run's Theo cache directory.
  oldSnapshotsDir: optional path to a previous run's snapshot directory.
  When set, commits already present in the old reports are copied instead
  of re-analyzed. Only reports for the selected modules are copied.

  javaVersions: ordered list of Java versions to use. Each entry has a
  "version" (sdkman identifier) and an optional "until" commit SHA.
  The version applies up to and including that commit; the last entry
  (without "until") applies to all remaining commits.

Report layout:
  <REPORTS_BASE>/<project>/
      analysis_results.json         -- tracking / results
      <commit_sha8>/                -- per-commit reports
          <module>/
              *.json / *.html       -- reachable, changes, stats, …
      <module>/                     -- accumulated history
          history.html
          history.json
"""

import json
import logging
import os
import re
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


REPORTS_BASE = Path("/scratch/yogya/client-results/history")
DEFAULT_INPUT = Path(
    "/home/yogya/projects/def-baudry/yogya/theo-all/theo/client_project_histories.json"
)

M2_REPO = "/scratch/yogya/m2-repository"
THEO_CACHE = Path("/scratch/yogya/client-results/theo-cache")
THEO_HISTORY = Path("/scratch/yogya/client-results/theo-history-snapshots")

os.environ.pop("JAVA_TOOL_OPTIONS", None)
os.environ["MAVEN_OPTS"] = os.environ.get("MAVEN_OPTS", "") + " -Xmx32g"

THEO_PLUGIN = "io.github.sparkrew:theo-static-maven-plugin"
MVN_BUILD = (
    f"mvn clean install -DskipTests -Dcheckstyle.skip=true "
    f"-Dspotless.check.skip=true -Denforcer.skip=true "
    f"-Dmaven.build.cache.enabled=false "
    f"-Dmaven.repo.local={M2_REPO}"
)

BUILD_TIMEOUT = 7200     # 2 hours
THEO_TIMEOUT = 86400     # 1 day
HISTORY_TIMEOUT = 3600   # 1 hour
FIVE_YEARS = timedelta(days=5 * 365)

REACHABLE_FLAG = "-Dtheo.reachableOnly=true"
HISTORY_FILENAMES = {"history.html", "history.json"}
THEO_DIR = THEO_HISTORY

TEST_MODULE_PAT = re.compile(r'\btest(?:s|ing)?\b', re.IGNORECASE)
_ORIGINAL_PATH = os.environ.get("PATH", "")



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
        os.environ["PATH"] = f"{java_home / 'bin'}:{_ORIGINAL_PATH}"
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


def build_project(project_path, modules=None):
    cmd = MVN_BUILD
    if modules:
        pl = ",".join(m for m in modules if m != ".")
        if pl:
            cmd += f" -pl {pl} -am"
    run_cmd(cmd, cwd=project_path, timeout=BUILD_TIMEOUT,
            label="mvn build")



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
                f"git log --first-parent --reverse --format=%H "
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
                f"git log --first-parent --reverse --format=%H "
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
            f"git log --first-parent --reverse --format=%H "
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
    """List pom.xml paths changed in a single *commit* vs its first parent."""
    cmd = (
        f"git diff --name-only {commit}^..{commit} "
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
def _module_pom_exists(project_path, module):
    """True when the module's pom.xml exists on disk (i.e. at the current checkout)."""
    if module == ".":
        return (project_path / "pom.xml").exists()
    return (project_path / module / "pom.xml").exists()


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




# Theo execution
def run_theo_goal(project_path, module, package_name, goal,
                  extra_flags="", timeout=THEO_TIMEOUT):
    pl = module if module != "." else "."
    cmd = (
        f"mvn {THEO_PLUGIN}:{goal} -pl {pl} "
        f"-Dtheo.packageNames={package_name} {REACHABLE_FLAG} "
        f"-Dtheo.cacheDir={THEO_CACHE} "
        f"-Dtheo.historyDir={THEO_HISTORY} "
        f"-Dmaven.repo.local={M2_REPO} "
        f"{extra_flags}"
    ).strip()
    label = f"theo {goal} ({module})"
    log.info(f"  [{label}] {cmd[:120]}")
    try:
        result = subprocess.run(
            cmd, shell=True, cwd=str(project_path),
            capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"{label} timed out after {timeout}s")
    if result.returncode != 0:
        _dump_theo_failure(project_path, module, goal, cmd, result)
        out = (result.stdout or "")[-1500:]
        err = (result.stderr or "")[-1500:]
        raise RuntimeError(
            f"{label} failed (exit {result.returncode}):\n{out}\n{err}"
        )
    return result


def _dump_theo_failure(project_path, module, goal, cmd, result):
    dump_dir = REPORTS_BASE / project_path.name / "errors"
    dump_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    mod_slug = module.replace("/", "_") if module != "." else "root"
    dump_file = dump_dir / f"{goal}_{mod_slug}_{ts}.log"
    dump_file.write_text(
        f"Command: {cmd}\n"
        f"Exit code: {result.returncode}\n"
        f"CWD: {project_path}\n"
        f"Time: {datetime.now().isoformat()}\n"
        f"\n=== STDOUT ===\n{result.stdout or ''}"
        f"\n=== STDERR ===\n{result.stderr or ''}\n"
    )
    log.info(f"  Full error log: {dump_file}")



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


def find_snapshot(project_path, module, commit_label=None):
    """Find a snapshot JSON under the Theo history dir for this module.

    If *commit_label* is given, matches the snapshot whose filename contains
    that label (e.g. the commit sha prefix). Otherwise returns the most
    recently written snapshot.
    """
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
    snap_dir = THEO_DIR / f"{gid}__{aid}"
    if not snap_dir.exists():
        return None
    if commit_label:
        matches = [p for p in snap_dir.glob("*.json")
                   if commit_label in p.name]
        if matches:
            return matches[0]
    snapshots = sorted(snap_dir.glob("*.json"), key=lambda p: p.stat().st_mtime)
    return snapshots[-1] if snapshots else None


def collect_reachability_summary(project_path, module, commit_label=None):
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

    snap_path = find_snapshot(project_path, module, commit_label)
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



def _load_old_tracking(old_reports_dir):
    """Load analysis_results.json from a previous run, indexed by sha."""
    if not old_reports_dir:
        return {}
    p = old_reports_dir / "analysis_results.json"
    if not p.exists():
        return {}
    try:
        with open(p) as f:
            data = json.load(f)
        return {c["sha"]: c for c in data.get("commits", [])}
    except (json.JSONDecodeError, OSError):
        return {}


def try_copy_from_old(commit, modules, project_report_base,
                      old_reports_dir, old_cache_dir, old_snapshots_dir):
    """Try to copy reports for a commit from a previous analysis run.

    Returns the old result dict if the old commit folder existed and reports
    were copied, or None otherwise. Only copies data for the given modules.
    """
    if not old_reports_dir:
        return None

    short = commit[:8]
    old_commit_dir = old_reports_dir / short
    if not old_commit_dir.exists():
        return None

    copied_any = False
    for module in modules:
        # -- commit reports --
        old_mod_dir = old_commit_dir / module
        if old_mod_dir.exists():
            new_commit_dir, new_hist_dir = _report_dirs(
                project_report_base, module, commit)
            new_commit_dir.mkdir(parents=True, exist_ok=True)
            for f in old_mod_dir.iterdir():
                if f.is_file():
                    shutil.copy2(f, new_commit_dir / f.name)
            copied_any = True

        # -- history files (module-level, outside commit folders) --
        old_hist_dir = old_reports_dir / module
        if old_hist_dir.exists():
            _, new_hist_dir = _report_dirs(
                project_report_base, module, commit)
            new_hist_dir.mkdir(parents=True, exist_ok=True)
            for name in HISTORY_FILENAMES:
                f = old_hist_dir / name
                if f.exists():
                    shutil.copy2(f, new_hist_dir / name)

    # -- cache (last-run.json etc.) --
    if old_cache_dir and old_cache_dir.exists():
        for item in old_cache_dir.iterdir():
            if item.is_dir():
                dest = THEO_CACHE / item.name
                if not dest.exists():
                    shutil.copytree(item, dest)

    # -- snapshots --
    if old_snapshots_dir and old_snapshots_dir.exists():
        for item in old_snapshots_dir.iterdir():
            if item.is_dir():
                dest = THEO_HISTORY / item.name
                if not dest.exists():
                    shutil.copytree(item, dest)
                else:
                    for f in item.iterdir():
                        if f.is_file() and not (dest / f.name).exists():
                            shutil.copy2(f, dest / f.name)

    if not copied_any:
        return None
    log.info(f"  {short}: copied from previous run")
    return True


# Per-project processing
def process_project(entry):
    project_path = Path(entry["projectPath"])
    last_commit = entry.get("lastCommit")
    package_name = entry["packageName"]
    pre_command = entry.get("preCommand", "")
    post_command = entry.get("postCommand", "")
    java_versions = entry.get("javaVersions", [])
    selected_modules = entry.get("modules", [])
    if not selected_modules and entry.get("module"):
        selected_modules = [entry["module"]]
    watch_poms = entry.get("watchPoms", [])
    old_reports_dir = Path(entry["oldReportsDir"]) if entry.get("oldReportsDir") else None
    old_cache_dir = Path(entry["oldCacheDir"]) if entry.get("oldCacheDir") else None
    old_snapshots_dir = Path(entry["oldSnapshotsDir"]) if entry.get("oldSnapshotsDir") else None

    branch = entry.get("branch", "main")

    project_name = project_path.name
    project_report_base = REPORTS_BASE / project_name
    project_report_base.mkdir(parents=True, exist_ok=True)

    run_cmd(f"git checkout {branch}", cwd=project_path, label=f"git checkout {branch}")

    tracking = load_tracking(project_report_base)
    done_shas = {c["sha"] for c in tracking["commits"]}
    old_tracking = _load_old_tracking(old_reports_dir)
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
        is_baseline = (commit == last_commit)
        if commit in done_shas:
            continue
        if commit in no_dep_shas and not is_baseline:
            continue

        if not is_baseline:
            # Strict check: only commits where <dependency> elements changed
            changed_poms = get_changed_poms(project_path, commit)
            dep_modules = []
            for pom in changed_poms:
                mod = pom_path_to_module(pom)
                if any(TEST_MODULE_PAT.search(part) for part in mod.split("/")):
                    continue
                if selected_modules or watch_poms:
                    tracked = selected_modules + watch_poms
                    is_root = (mod == ".")
                    is_relevant = any(
                        mod == m                        # exact module
                        or m.startswith(mod + "/")      # parent of a tracked module
                        for m in tracked)
                    if not is_root and not is_relevant:
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

        checked_out = False
        try:
            # ---- checkout ----
            git_checkout(project_path, commit)
            checked_out = True

            # ---- select Java version ----
            select_java_version(java_versions, commit, project_path)

            if pre_command:
                run_cmd(pre_command, cwd=project_path, label="preCommand")

            # ---- resolve modules at this commit ----
            available = set(get_all_modules(project_path))
            if selected_modules:
                modules = [m for m in selected_modules if m in available]
                if not modules:
                    log.warning(f"  {commit[:8]}: none of the selected "
                                f"modules exist in the reactor, skipping "
                                f"(available: {sorted(available)[:5]})")
                    result["analysisResult"] = "no_modules"
                    tracking["commits"].append(result)
                    save_tracking(tracking, project_report_base)
                    done_shas.add(commit)
                    continue
            else:
                modules = sorted(available)

            # ---- try reusing reports from a previous run ----
            if try_copy_from_old(commit, modules, project_report_base,
                                 old_reports_dir, old_cache_dir,
                                 old_snapshots_dir):
                old_result = old_tracking.get(commit, {})
                result["analyzedModules"] = modules
                result["analysisResult"] = "copied"
                for key in ("durationSeconds", "reachability"):
                    if key in old_result:
                        result[key] = old_result[key]
                if "reachability" in result and selected_modules:
                    result["reachability"] = {
                        m: v for m, v in result["reachability"].items()
                        if m in selected_modules
                    }
                tracking["commits"].append(result)
                save_tracking(tracking, project_report_base)
                done_shas.add(commit)
                continue

            # ---- build (root) ----
            try:
                build_project(project_path, modules)
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
                continue

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

                # ---- copy reports ----
                commit_dir, _ = _report_dirs(
                    project_report_base, module, commit)
                copy_commit_reports(project_path, module, commit_dir)

                # ---- collect reachability stats ----
                mod_summary = collect_reachability_summary(
                    project_path, module, commit_label=commit[:8])
                if mod_summary:
                    module_stats[module] = mod_summary

            if module_stats:
                result["reachability"] = module_stats
            result["durationSeconds"] = round(time.time() - t)
            result["analysisResult"] = "success"
            log.info(f"  OK {commit[:8]} ({result['durationSeconds']}s)")

        except Exception as e:
            result["analysisResult"] = result.get("analysisResult", "failed")
            if "error" not in result:
                result["error"] = str(e)[:500]
                log.error(f"  FAILED {commit[:8]}: {str(e)[:200]}")
        finally:
            if checked_out and post_command:
                _safe_run(post_command, project_path)

        tracking["commits"].append(result)
        save_tracking(tracking, project_report_base)
        done_shas.add(commit)

    # ---- summary ----
    success = sum(1 for c in tracking["commits"]
                  if c.get("analysisResult") == "success")
    copied = sum(1 for c in tracking["commits"]
                 if c.get("analysisResult") == "copied")
    failed = sum(1 for c in tracking["commits"]
                 if c.get("analysisResult") == "failed")
    build_fail = sum(1 for c in tracking["commits"]
                     if c.get("analysisResult") == "build_failed")
    no_dep = len(tracking["noDepChangeCommits"])

    log.info(f"  Summary: {success} analyzed, {copied} copied, {failed} failed, "
             f"{build_fail} build failures, {no_dep} no-dep skips")

    # ---- final history pass ----
    modules = selected_modules if selected_modules else get_all_modules(project_path)
    if success > 0 or copied > 0:
        log.info(f"  Running history goal for {len(modules)} module(s)")
        git_checkout(project_path, branch)
        select_java_version(java_versions, branch, project_path)
        if pre_command:
            try:
                run_cmd(pre_command, cwd=project_path, label="preCommand (history)")
            except RuntimeError:
                pass
        try:
            build_project(project_path, modules)
        except RuntimeError as e:
            log.warning(f"  Build for history pass failed: {str(e)[:200]}")
            return
        for module in modules:
            try:
                run_theo_goal(project_path, module, package_name,
                              "history", timeout=HISTORY_TIMEOUT)
                _, hist_dir = _report_dirs(
                    project_report_base, module, "history")
                copy_history_reports(project_path, module, hist_dir)
            except RuntimeError as e:
                log.warning(f"  history failed on {module}: {str(e)[:150]}")
        if post_command:
            _safe_run(post_command, project_path)
        log.info("  History pass complete")


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
