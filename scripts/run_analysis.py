#!/usr/bin/env python3
"""
Batch analysis script for Theo.

Runs theo cve-check, snapshot, and history on multiple Maven projects
for pre/post commit pairs defined in a JSON config file. Tracks results
incrementally so failed projects can be re-run after fixing.

Usage:
    python3 run_analysis.py [path/to/client_projects.json]

Default input: /Tmp/gamageyo/theo-all/client-project-reports/client_projects.json
"""

import json
import subprocess
import shutil
import sys
import time
from pathlib import Path
from datetime import datetime

REPORTS_BASE = Path("/Tmp/gamageyo/theo-all/client-project-reports")
DEFAULT_INPUT = REPORTS_BASE / "client_projects.json"
RESULTS_FILE = REPORTS_BASE / "client_project_results.json"
THEO_DIR = Path.home() / ".theo"

THEO_PLUGIN = "io.github.sparkrew:theo-static-maven-plugin"
MVN_BUILD = (
    "mvn clean install -DskipTests -Dcheckstyle.skip=true "
    "-Dspotless.check.skip=true -Denforcer.skip=true"
)

BUILD_TIMEOUT = 3600    # 60 minutes
THEO_TIMEOUT = 3600     # 60 minutes
HISTORY_TIMEOUT = 600   # 10 minutes


def run_cmd(cmd, cwd, timeout=120, label="command"):
    print(f"  [{label}] {cmd[:120]}")
    try:
        result = subprocess.run(
            cmd, shell=True, cwd=str(cwd),
            capture_output=True, text=True, timeout=timeout
        )
    except subprocess.TimeoutExpired as e:
        raise RuntimeError(f"{label} timed out after {timeout}s")
    if result.returncode != 0:
        # keep last 3000 chars of output for diagnostics
        out = (result.stdout or "")[-1500:]
        err = (result.stderr or "")[-1500:]
        raise RuntimeError(f"{label} failed (exit {result.returncode}):\n{out}\n{err}")
    return result


def git_checkout(project_path, commit):
    run_cmd(f"git checkout {commit}", cwd=project_path, label="git checkout")


def git_info(project_path, commit):
    """Returns commit metadata for the results JSON."""
    try:
        r = run_cmd(
            f"git log -1 --format='%H%n%s%n%ai' {commit}",
            cwd=project_path, label="git info"
        )
        lines = r.stdout.strip().splitlines()
        return {
            "sha": lines[0] if len(lines) > 0 else commit,
            "message": lines[1] if len(lines) > 1 else "",
            "date": lines[2] if len(lines) > 2 else "",
        }
    except RuntimeError:
        return {"sha": commit, "message": "", "date": ""}


def build_project(project_path, module):
    """Build from root; fall back to module dir on failure."""
    try:
        run_cmd(MVN_BUILD, cwd=project_path, timeout=BUILD_TIMEOUT, label="mvn build (root)")
        return
    except RuntimeError:
        if not module:
            raise
        print(f"  Root build failed, retrying from module: {module}")
    run_cmd(MVN_BUILD, cwd=project_path / module, timeout=BUILD_TIMEOUT, label="mvn build (module)")


def run_theo(module_path, package_name, goal, extra_flags="", timeout=THEO_TIMEOUT):
    cmd = f"mvn {THEO_PLUGIN}:{goal} -Dtheo.packageNames={package_name} {extra_flags}".strip()
    run_cmd(cmd, cwd=module_path, timeout=timeout, label=f"theo {goal}")


def copy_reports(module_path, dest):
    """Copy theo report files from target/theo-report/ to dest."""
    src = module_path / "target" / "theo-report"
    dest.mkdir(parents=True, exist_ok=True)
    if not src.exists():
        return
    for f in src.iterdir():
        if f.is_file():
            shutil.copy2(f, dest / f.name)


def read_stats(report_dir):
    """Read stats.json if it exists."""
    p = report_dir / "stats.json"
    if p.exists():
        with open(p) as f:
            return json.load(f)
    return None


def clear_cache():
    """Remove history so commit pairs don't interfere. Keep the dep cache for speed."""
    history = THEO_DIR / "history"
    if history.exists():
        shutil.rmtree(history)
    # last-run files live under cache/projects/ — remove those too so the
    # changes report compares pre vs post, not against a previous pair's run
    projects_cache = THEO_DIR / "cache" / "projects"
    if projects_cache.exists():
        shutil.rmtree(projects_cache)
    print("  Cleared history + last-run (dep cache kept)")


def save_results(results):
    """Atomic write to results JSON."""
    RESULTS_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = RESULTS_FILE.with_suffix(".tmp")
    with open(tmp, "w") as f:
        json.dump(results, f, indent=2)
    tmp.rename(RESULTS_FILE)


def load_results():
    if RESULTS_FILE.exists():
        with open(RESULTS_FILE) as f:
            return json.load(f)
    return []


def report_base_for(entry):
    """Compute the report output directory for a project entry."""
    project_name = Path(entry["projectPath"]).name
    module = entry.get("module", "")
    pre = entry["preCommit"][:8]
    post = entry["postCommit"][:8]
    pair_id = f"{pre}_{post}"
    if module:
        return REPORTS_BASE / project_name / module / pair_id
    return REPORTS_BASE / project_name / pair_id


def run_project(entry, result):
    project_path = Path(entry["projectPath"])
    module = entry.get("module", "")
    pre_commit = entry["preCommit"]
    post_commit = entry["postCommit"]
    package_name = entry["packageName"]
    pre_command = entry.get("preCommand", "")
    post_command = entry.get("postCommand", "")

    module_path = project_path / module if module else project_path
    report_base = report_base_for(entry)
    pre_dir = report_base / "precommit"
    post_dir = report_base / "postcommit"
    report_base.mkdir(parents=True, exist_ok=True)

    result["preCommitInfo"] = git_info(project_path, pre_commit)
    result["postCommitInfo"] = git_info(project_path, post_commit)
    result["reportDir"] = str(report_base)

    start = time.time()

    # ---- pre-commit ----
    result["_step"] = "checkout:pre"
    git_checkout(project_path, pre_commit)

    if pre_command:
        result["_step"] = "preCommand"
        run_cmd(pre_command, cwd=project_path, label="preCommand")

    result["_step"] = "build:pre"
    build_project(project_path, module)

    result["_step"] = "theo:pre"
    t = time.time()
    run_theo(module_path, package_name, "cve-check")
    run_theo(module_path, package_name, "snapshot",
             extra_flags=f"-Dtheo.snapshotLabel=pre-{pre_commit[:8]}")
    result["theoPreDurationSeconds"] = round(time.time() - t)

    copy_reports(module_path, pre_dir)
    result["preStats"] = read_stats(pre_dir)

    # ---- transition ----
    if post_command:
        result["_step"] = "postCommand"
        run_cmd(post_command, cwd=project_path, label="postCommand")

    # ---- post-commit ----
    result["_step"] = "checkout:post"
    git_checkout(project_path, post_commit)

    result["_step"] = "build:post"
    build_project(project_path, module)

    result["_step"] = "theo:post"
    t = time.time()
    run_theo(module_path, package_name, "cve-check")
    run_theo(module_path, package_name, "snapshot",
             extra_flags=f"-Dtheo.snapshotLabel=post-{post_commit[:8]}")
    run_theo(module_path, package_name, "history", timeout=HISTORY_TIMEOUT)
    result["theoPostDurationSeconds"] = round(time.time() - t)

    copy_reports(module_path, post_dir)
    # history.html goes in the pair root (spans both commits)
    history_src = module_path / "target" / "theo-report" / "history.html"
    if history_src.exists():
        shutil.copy2(history_src, report_base / "history.html")

    result["postStats"] = read_stats(post_dir)
    result["totalDurationSeconds"] = round(time.time() - start)
    result["analysisResult"] = "success"
    result["failedStep"] = None
    result["errorFile"] = None
    result.pop("_step", None)


def main():
    input_path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_INPUT
    if not input_path.exists():
        print(f"Input file not found: {input_path}")
        sys.exit(1)

    with open(input_path) as f:
        projects = json.load(f)

    results = load_results()
    while len(results) < len(projects):
        results.append({})

    # seed results with project metadata
    for i, entry in enumerate(projects):
        for key in entry:
            if key not in results[i] or key != "analysisResult":
                results[i].setdefault(key, entry[key])

    total = len(projects)
    succeeded = sum(1 for r in results if r.get("analysisResult") == "success")
    print(f"Loaded {total} projects ({succeeded} already done)\n")

    for i, entry in enumerate(projects):
        result = results[i]

        if result.get("analysisResult") == "success":
            continue

        project_name = Path(entry["projectPath"]).name
        module = entry.get("module", "")
        label = f"{project_name}/{module}" if module else project_name
        print(f"[{i+1}/{total}] {label}")
        print(f"  pre:  {entry['preCommit'][:8]}  post: {entry['postCommit'][:8]}")

        clear_cache()

        try:
            run_project(entry, result)
            print(f"  OK ({result.get('totalDurationSeconds', '?')}s)\n")
        except Exception as e:
            failed_step = result.pop("_step", "unknown")
            report_base = report_base_for(entry)
            report_base.mkdir(parents=True, exist_ok=True)

            error_file = report_base / "error.txt"
            error_file.write_text(
                f"Step: {failed_step}\n"
                f"Time: {datetime.now().isoformat()}\n\n"
                f"{e}\n"
            )

            result["analysisResult"] = "failed"
            result["failedStep"] = failed_step
            result["errorFile"] = str(error_file)
            print(f"  FAILED at {failed_step}: {str(e)[:200]}\n")

        save_results(results)

    done = sum(1 for r in results if r.get("analysisResult") == "success")
    failed = sum(1 for r in results if r.get("analysisResult") == "failed")
    remaining = total - done - failed
    print(f"Done: {done} succeeded, {failed} failed, {remaining} remaining")
    print(f"Results: {RESULTS_FILE}")


if __name__ == "__main__":
    main()
