#!/usr/bin/env python3
"""
For each project in a repos JSON file, walk its git history and find commits
where a pom.xml dependency version changed to match a critical version change.

Outputs one JSON file per project under the output directory.

Usage:
    GITHUB_TOKEN=ghp_token1,ghp_token2 python3 scripts/find_critical_commits.py \
        --repos-file scripts/top_42_repos.json \
        --critical-changes scripts/critical_version_changes.json \
        --output-dir scripts/critical_commits
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.request


class TokenRotator:
    """Rotates between multiple GitHub tokens, skipping exhausted ones."""

    def __init__(self, tokens):
        self.tokens = tokens
        self.current_index = 0
        self._check_initial_rates()

    def _check_initial_rates(self):
        print(f"Checking rate limits for {len(self.tokens)} tokens...", file=sys.stderr)
        for i, token in enumerate(self.tokens):
            remaining, limit, reset = self._get_rate_limit(token)
            print(f"  Token {i+1}: {remaining}/{limit} remaining "
                  f"(resets in {max(0, reset - int(time.time()))}s)", file=sys.stderr)

    def _get_rate_limit(self, token):
        try:
            req = urllib.request.Request(
                "https://api.github.com/rate_limit",
                headers={"Authorization": f"token {token}",
                         "Accept": "application/vnd.github+json"},
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode())
                core = data["resources"]["core"]
                return core["remaining"], core["limit"], core["reset"]
        except Exception:
            return 0, 0, 0

    def get_token(self):
        """Return a token with remaining quota. Waits if all are exhausted."""
        attempts = 0
        while attempts < len(self.tokens) * 2:
            token = self.tokens[self.current_index]
            remaining, limit, reset = self._get_rate_limit(token)

            if remaining > 10:
                return token

            print(f"  Token {self.current_index + 1} exhausted ({remaining}/{limit}), "
                  f"trying next...", file=sys.stderr)
            self.current_index = (self.current_index + 1) % len(self.tokens)
            attempts += 1

            if attempts == len(self.tokens):
                wait = max(reset - int(time.time()), 1)
                print(f"  All tokens exhausted. Waiting {wait}s for reset...",
                      file=sys.stderr)
                time.sleep(wait)

        raise RuntimeError("All GitHub tokens exhausted and reset wait failed")

    def rotate(self):
        """Switch to the next token."""
        self.current_index = (self.current_index + 1) % len(self.tokens)


def clone_repo(repo, token_rotator, dest):
    """Clone with token auth, rotating on auth failure."""
    token = token_rotator.get_token()
    url = f"https://x-access-token:{token}@github.com/{repo}.git"
    result = subprocess.run(
        ["git", "clone", "--single-branch", url, str(dest)],
        capture_output=True, text=True, timeout=1800,
    )
    if result.returncode != 0:
        if "403" in result.stderr or "rate limit" in result.stderr.lower():
            token_rotator.rotate()
            token = token_rotator.get_token()
            url = f"https://x-access-token:{token}@github.com/{repo}.git"
            result = subprocess.run(
                ["git", "clone", "--single-branch", url, str(dest)],
                capture_output=True, text=True, timeout=1800,
            )
        if result.returncode != 0:
            raise RuntimeError(f"git clone failed for {repo}: {result.stderr.strip()}")


def find_pom_files(repo_dir):
    """Find all pom.xml files in the repo."""
    poms = []
    for root, dirs, files in os.walk(repo_dir):
        dirs[:] = [d for d in dirs if d not in (".git", "target", "node_modules")]
        for f in files:
            if f == "pom.xml":
                poms.append(os.path.relpath(os.path.join(root, f), repo_dir))
    return poms


# Regex to extract <groupId>, <artifactId>, <version> from Maven dependency blocks
DEP_BLOCK_RE = re.compile(
    r"<dependency>\s*"
    r"<groupId>\s*([^<]+?)\s*</groupId>\s*"
    r"<artifactId>\s*([^<]+?)\s*</artifactId>\s*"
    r"(?:<version>\s*([^<$][^<]*?)\s*</version>)?",
    re.DOTALL,
)

# Also match <parent> blocks which set inherited versions
PARENT_BLOCK_RE = re.compile(
    r"<parent>\s*"
    r"<groupId>\s*([^<]+?)\s*</groupId>\s*"
    r"<artifactId>\s*([^<]+?)\s*</artifactId>\s*"
    r"<version>\s*([^<$][^<]*?)\s*</version>",
    re.DOTALL,
)

# Match properties-based version definitions like <logback.version>1.2.3</logback.version>
PROP_VERSION_RE = re.compile(r"<([a-zA-Z0-9._-]+\.version)>\s*([^<$]+?)\s*</\1>")


def parse_dep_versions(pom_content):
    """Parse dependency coordinates and their versions from pom.xml content.
    Returns dict: {groupId:artifactId -> version} (only for explicit versions)."""
    versions = {}

    for m in DEP_BLOCK_RE.finditer(pom_content):
        group_id, artifact_id, version = m.group(1), m.group(2), m.group(3)
        if version:
            coord = f"{group_id}:{artifact_id}"
            versions[coord] = version.strip()

    for m in PARENT_BLOCK_RE.finditer(pom_content):
        group_id, artifact_id, version = m.group(1), m.group(2), m.group(3)
        coord = f"{group_id}:{artifact_id}"
        versions[coord] = version.strip()

    return versions


def get_commit_list(repo_dir):
    """Get chronological list of (hash, parent_hash) tuples on the default branch."""
    result = subprocess.run(
        ["git", "-C", str(repo_dir), "log", "--first-parent", "--reverse",
         "--format=%H %P"],
        capture_output=True, text=True, timeout=120,
    )
    if result.returncode != 0:
        return []

    commits = []
    for line in result.stdout.strip().split("\n"):
        if not line.strip():
            continue
        parts = line.strip().split()
        commit_hash = parts[0]
        parent_hash = parts[1] if len(parts) > 1 else None
        commits.append((commit_hash, parent_hash))
    return commits


def decode_xml_bytes(data):
    """Decode XML bytes using BOM/XML encoding hints, with safe fallbacks.

    Maven POMs are XML and may be UTF-8, UTF-8 with BOM, UTF-16, or another
    encoding declared in the XML prolog. Returns None when the bytes cannot
    be decoded safely.
    """
    if not data:
        return ""

    # XML parsers conventionally use BOMs to identify UTF encodings.
    if data.startswith(b"\xef\xbb\xbf"):
        return data.decode("utf-8-sig")
    if data.startswith(b"\xff\xfe"):
        return data.decode("utf-16-le")
    if data.startswith(b"\xfe\xff"):
        return data.decode("utf-16-be")

    # Look at the XML declaration before choosing a codec. Keep this byte
    # oriented so we don't have to decode the whole document first.
    head = data[:512]
    match = re.search(br"encoding=[\"']([A-Za-z0-9._-]+)[\"']", head, re.I)
    if match:
        encoding = match.group(1).decode("ascii", errors="ignore")
        try:
            return data.decode(encoding)
        except (LookupError, UnicodeDecodeError):
            pass

    # Normal Maven POMs are UTF-8. utf-8-sig also handles an unexpected BOM.
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        pass

    # Last-resort XML-compatible fallback. This prevents one unusual POM
    # from aborting the entire repository scan while preserving ASCII/XML
    # markup and replacing undecodable characters.
    return data.decode("utf-8", errors="replace")


def get_file_at_commit(repo_dir, commit_hash, filepath):
    """Get and decode file content at a specific commit. Returns None if it doesn't exist."""
    result = subprocess.run(
        ["git", "-C", str(repo_dir), "show", f"{commit_hash}:{filepath}"],
        capture_output=True, timeout=30,
    )
    if result.returncode != 0:
        return None

    try:
        return decode_xml_bytes(result.stdout)
    except Exception as exc:
        print(
            f"    Warning: could not decode {filepath} at commit {commit_hash[:12]}: {exc}",
            file=sys.stderr,
        )
        return None


def get_changed_files_in_commit(repo_dir, commit_hash):
    """Get list of files changed in a commit."""
    result = subprocess.run(
        ["git", "-C", str(repo_dir), "diff-tree", "--no-commit-id", "-r",
         "--name-only", commit_hash],
        capture_output=True, text=True, timeout=30,
    )
    if result.returncode != 0:
        return []
    return [f.strip() for f in result.stdout.strip().split("\n") if f.strip()]


def build_version_change_index(critical_changes):
    """Build lookup: {coord -> [(from_ver, to_ver, api, change_type), ...]}"""
    index = {}
    for dep_entry in critical_changes:
        coord = dep_entry["dependency"]
        for change in dep_entry["critical_version_changes"]:
            from_ver, to_ver = change["version_change"]
            key = (from_ver, to_ver, change["api"], change["type"])
            index.setdefault(coord, []).append(key)
    return index


def parse_history_version(version):
    """Parse versions using the same ordering rules as package-miner's history."""
    version = version.strip()
    match = re.fullmatch(
        r"v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:[.\-](.+))?", version
    )
    if not match:
        return 0, 0, 0, version

    major, minor, patch = (int(match.group(1)), int(match.group(2) or 0),
                           int(match.group(3) or 0))
    qualifier = match.group(4)
    if qualifier and re.fullmatch(r"(?i)(final|release|ga|jre|android)", qualifier):
        qualifier = None
    return major, minor, patch, qualifier


def history_version_sort_key(version):
    """Return a sortable version key matching package-miner's version parser."""
    major, minor, patch, qualifier = parse_history_version(version)
    qualifier_key = (0, "") if qualifier is None else (1, qualifier)
    return major, minor, patch, *qualifier_key


def compare_history_versions(left, right):
    """Compare versions in the order used by package-miner's MavenVersionParser."""
    left_key = history_version_sort_key(left)
    right_key = history_version_sort_key(right)
    return (left_key > right_key) - (left_key < right_key)


def find_version_transitions(index, coord, old_version, new_version):
    """Find critical transitions fully covered by the project's version update."""
    if coord not in index:
        return []

    project_direction = compare_history_versions(old_version, new_version)
    if project_direction == 0:
        return []

    lower_bound, upper_bound = sorted(
        (old_version, new_version), key=history_version_sort_key
    )
    matches = []
    for from_ver, to_ver, api, change_type in index[coord]:
        transition_direction = compare_history_versions(from_ver, to_ver)
        transition_low, transition_high = sorted(
            (from_ver, to_ver), key=history_version_sort_key
        )
        if (transition_direction != 0
                and compare_history_versions(transition_low, lower_bound) >= 0
                and compare_history_versions(transition_high, upper_bound) <= 0):
            if project_direction != transition_direction:
                if change_type.startswith("addition_"):
                    change_type = change_type.replace("addition_", "removal_", 1)
                elif change_type.startswith("removal_"):
                    change_type = change_type.replace("removal_", "addition_", 1)
            matches.append({
                "api": api,
                "type": change_type,
                "version_change": [from_ver, to_ver],
            })
    return matches


def process_repo(repo_name, repo_dir, critical_index, target_coords):
    """Walk git history and find commits with critical dependency version changes."""
    commits = get_commit_list(repo_dir)
    if not commits:
        print(f"    No commits found", file=sys.stderr)
        return []

    print(f"    {len(commits)} commits on default branch", file=sys.stderr)

    results_by_dep = {}

    for i, (commit_hash, parent_hash) in enumerate(commits):
        if parent_hash is None:
            continue

        changed_files = get_changed_files_in_commit(repo_dir, commit_hash)
        pom_files = [f for f in changed_files if f.endswith("pom.xml")]
        if not pom_files:
            continue

        for pom_file in pom_files:
            old_content = get_file_at_commit(repo_dir, parent_hash, pom_file)
            new_content = get_file_at_commit(repo_dir, commit_hash, pom_file)
            if not old_content or not new_content:
                continue

            old_versions = parse_dep_versions(old_content)
            new_versions = parse_dep_versions(new_content)

            for coord in target_coords:
                old_ver = old_versions.get(coord)
                new_ver = new_versions.get(coord)
                if old_ver and new_ver and old_ver != new_ver:
                    matches = find_version_transitions(critical_index, coord, old_ver, new_ver)
                    if matches:
                        if coord not in results_by_dep:
                            results_by_dep[coord] = []
                        for match in matches:
                            results_by_dep[coord].append({
                                "api": match["api"],
                                "type": match["type"],
                                "version_change": match["version_change"],
                                "project_version_change": [old_ver, new_ver],
                                "project_commit_change": [parent_hash, commit_hash],
                                "pom_file": pom_file,
                            })

        if (i + 1) % 500 == 0:
            print(f"    Processed {i+1}/{len(commits)} commits...", file=sys.stderr)

    result = []
    for coord, changes in sorted(results_by_dep.items()):
        result.append({
            "dependency": coord,
            "critical_version_changes": changes,
        })
    return result


def main():
    parser = argparse.ArgumentParser(
        description="Find commits where pom.xml dependency versions match critical changes")
    parser.add_argument("--repos-file", required=True,
                        help="JSON file with repos and their dependencies (e.g. top_42_repos.json)")
    parser.add_argument("--critical-changes", required=True,
                        help="critical_version_changes.json from build_critical_changes.py")
    parser.add_argument("--output-dir", "-o", default="critical_commits",
                        help="Output directory for per-project JSON files (default: critical_commits/)")
    parser.add_argument("--clone-dir", default="/data/rech/gamageyo/tmp",
                        help="Directory to store per-repository clones "
                             "(default: /data/rech/gamageyo/tmp)")
    args = parser.parse_args()

    github_token_str = os.environ.get("GITHUB_TOKEN")
    if not github_token_str:
        print("Error: Set the GITHUB_TOKEN environment variable (comma-separated for multiple).",
              file=sys.stderr)
        sys.exit(1)

    tokens = [t.strip() for t in github_token_str.split(",") if t.strip()]
    print(f"Using {len(tokens)} GitHub token(s)", file=sys.stderr)
    token_rotator = TokenRotator(tokens)

    with open(args.repos_file) as f:
        repos = json.load(f)

    with open(args.critical_changes) as f:
        critical_changes = json.load(f)

    critical_index = build_version_change_index(critical_changes)
    critical_coords = set(critical_index.keys())
    print(f"Loaded {len(critical_coords)} dependencies with critical changes", file=sys.stderr)

    os.makedirs(args.output_dir, exist_ok=True)

    clone_base = args.clone_dir
    os.makedirs(clone_base, exist_ok=True)

    for i, repo_entry in enumerate(repos):
        repo_name = repo_entry["repo"]
        repo_deps = set(repo_entry.get("dependencies", []))
        target_coords = repo_deps & critical_coords

        if not target_coords:
            print(f"[{i+1}/{len(repos)}] {repo_name}: no critical dependencies, skipping",
                  file=sys.stderr)
            continue

        print(f"[{i+1}/{len(repos)}] {repo_name}: checking {len(target_coords)} critical deps",
              file=sys.stderr)

        safe_name = repo_name.replace("/", "_")
        output_file = os.path.join(args.output_dir, f"{safe_name}.json")

        if os.path.exists(output_file):
            print(f"    Output already exists, skipping (delete to reprocess)", file=sys.stderr)
            continue

        repo_dir = os.path.join(clone_base, safe_name)
        clone_needed = not os.path.exists(repo_dir)

        try:
            if clone_needed:
                print(f"    Cloning...", file=sys.stderr)
                clone_repo(repo_name, token_rotator, repo_dir)

            pom_files = find_pom_files(repo_dir)
            has_gradle = (os.path.exists(os.path.join(repo_dir, "build.gradle"))
                          or os.path.exists(os.path.join(repo_dir, "build.gradle.kts")))

            if not pom_files:
                reason = "Gradle-only project" if has_gradle else "no pom.xml found"
                print(f"    Skipping ({reason})", file=sys.stderr)
                continue

            result = process_repo(repo_name, repo_dir, critical_index, target_coords)

            output = {
                "repo": repo_name,
                "critical_dependency_changes": result,
            }

            with open(output_file, "w") as f:
                json.dump(output, f, indent=2)

            total_changes = sum(len(d["critical_version_changes"]) for d in result)
            if total_changes == 0:
                shutil.rmtree(repo_dir, ignore_errors=True)
                print(f"    No critical changes found; removed clone {repo_dir}",
                      file=sys.stderr)
            print(f"    Found {total_changes} critical version changes across {len(result)} deps. "
                  f"Saved to {output_file}", file=sys.stderr)

        except Exception as e:
            print(f"    Error: {e}", file=sys.stderr)
            error_output = {"repo": repo_name, "error": str(e)}
            with open(output_file, "w") as f:
                json.dump(error_output, f, indent=2)

    print(f"\nDone. Results saved in {args.output_dir}/", file=sys.stderr)


if __name__ == "__main__":
    main()
