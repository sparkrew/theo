#!/usr/bin/env python3
"""
Find the top GitHub repositories that depend on the most packages
from a given list of sensitive-API packages, filtered by GitHub metrics.

Repos must have: ≥42 stars, ≥10 contributors, ≥420 commits, and be
updated within the last 5 years. The top 42 qualifying repos (by
dependency count) are selected.

Usage:
    GITHUB_TOKEN=ghp_... python3 scripts/find_top_repos.py <sensitive_packages.json> [--output top_repos.json] [--top 42] [--max-pages 10]

Input JSON format (same as selected_packages.json):
    [{"groupId": "org.apache.poi", "artifactId": "poi", "latestVersion": "5.2.0", "dependentReposCount": 75000}, ...]

Output JSON:
    [{"repo": "owner/name", "dependency_count": 5, "dependencies": [...], "stars": 100, "contributors": 15, "commits": 500}, ...]
"""

import argparse
import json
import os
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone


API_BASE = "https://repos.ecosyste.ms/api/v1/usage/maven"
PER_PAGE = 100
RATE_LIMIT_SLEEP = 2.0  # seconds between API calls to stay under 5000/hr
MAX_RETRIES = 10
INITIAL_BACKOFF = 30  # seconds; doubles each retry

MIN_STARS = 42
MIN_CONTRIBUTORS = 5
MIN_COMMITS = 420
MAX_INACTIVE_YEARS = 5


def fetch_with_retry(url, headers=None):
    """Fetch a URL, retrying with exponential backoff on 403/429/5xx."""
    if headers is None:
        headers = {"Accept": "application/json", "User-Agent": "curl/8.0"}
    backoff = INITIAL_BACKOFF
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=30) as resp:
                return resp, json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            if e.code in (404, 451):
                return None, None
            if e.code in (403, 429) or e.code >= 500:
                if e.code == 403 and "rate limit" in e.read().decode().lower():
                    reset = int(e.headers.get("X-RateLimit-Reset", time.time() + 60))
                    backoff = max(reset - int(time.time()), 1)
                print(f"  HTTP {e.code} (attempt {attempt}/{MAX_RETRIES}), retrying in {backoff}s...", file=sys.stderr)
                time.sleep(backoff)
                backoff = min(backoff * 2, 600)
            else:
                raise
        except Exception:
            if attempt < MAX_RETRIES:
                print(f"  Error (attempt {attempt}/{MAX_RETRIES}), retrying in {backoff}s...", file=sys.stderr)
                time.sleep(backoff)
                backoff = min(backoff * 2, 600)
            else:
                raise
    raise RuntimeError(f"Failed after {MAX_RETRIES} retries: {url}")


def fetch_dependent_repos(package_coord, max_pages):
    """Fetch all GitHub repo full_names that depend on a given maven coordinate."""
    repos = set()
    page = 1
    while page <= max_pages:
        url = f"{API_BASE}/{package_coord}/dependencies?per_page={PER_PAGE}&page={page}&mailto=tulipgamage@gmail.com"
        try:
            _, data = fetch_with_retry(url)
        except Exception as e:
            print(f"  Giving up on {package_coord} page {page}: {e}", file=sys.stderr)
            break

        if not data:
            break

        for entry in data:
            repo = entry.get("repository")
            if repo and repo.get("full_name"):
                repos.add(repo["full_name"])

        if len(data) < PER_PAGE:
            break

        page += 1
        time.sleep(RATE_LIMIT_SLEEP)

    return repos


def load_cache(cache_file):
    """Load cached results: {coord: [repo_names]}."""
    if os.path.exists(cache_file):
        with open(cache_file) as f:
            return json.load(f)
    return {}


def save_cache(cache_file, cache):
    with open(cache_file, "w") as f:
        json.dump(cache, f, indent=2)


# --- GitHub API helpers ---

def gh_headers(token):
    return {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "curl/8.0",
    }


def gh_get_repo_info(repo, token):
    """Return (stars, pushed_at) or None if repo not found."""
    _, data = fetch_with_retry(f"https://api.github.com/repos/{repo}", gh_headers(token))
    if data is None:
        return None
    return data.get("stargazers_count", 0), data.get("pushed_at", "")


def gh_count_from_pagination(url, token):
    """Get total count using the Link header pagination trick (per_page=1)."""
    resp, data = fetch_with_retry(url, gh_headers(token))
    if resp is None or data is None:
        return 0
    link = resp.headers.get("Link", "") if hasattr(resp, 'headers') else ""
    if 'rel="last"' in link:
        from urllib.parse import urlparse, parse_qs
        last_url = [l.split(";")[0].strip("<> ") for l in link.split(",") if 'rel="last"' in l][0]
        return int(parse_qs(urlparse(last_url).query)["page"][0])
    return len(data) if isinstance(data, list) else 0


def gh_get_contributor_count(repo, token):
    return gh_count_from_pagination(
        f"https://api.github.com/repos/{repo}/contributors?per_page=1&anon=true", token)


def gh_get_commit_count(repo, token):
    return gh_count_from_pagination(
        f"https://api.github.com/repos/{repo}/commits?per_page=1", token)


def is_recently_updated(pushed_at_str, max_years=MAX_INACTIVE_YEARS):
    if not pushed_at_str:
        return False
    pushed = datetime.fromisoformat(pushed_at_str.replace("Z", "+00:00"))
    cutoff = datetime.now(timezone.utc).replace(year=datetime.now(timezone.utc).year - max_years)
    return pushed >= cutoff


def check_github_conditions(repo, token):
    """Check all GitHub conditions. Returns dict with metrics or None if disqualified."""
    info = gh_get_repo_info(repo, token)
    if info is None:
        return None
    stars, pushed_at = info

    if not is_recently_updated(pushed_at):
        return {"skip": "inactive", "pushed_at": pushed_at}
    if stars < MIN_STARS:
        return {"skip": "stars", "stars": stars}

    contributors = gh_get_contributor_count(repo, token)
    if contributors < MIN_CONTRIBUTORS:
        return {"skip": "contributors", "stars": stars, "contributors": contributors}

    commits = gh_get_commit_count(repo, token)
    if commits < MIN_COMMITS:
        return {"skip": "commits", "stars": stars, "contributors": contributors, "commits": commits}

    return {"stars": stars, "contributors": contributors, "commits": commits, "pushed_at": pushed_at}


def main():
    parser = argparse.ArgumentParser(description="Find top N repos using the most sensitive-API packages")
    parser.add_argument("input_file", help="JSON file with sensitive-API packages (selected_packages.json format)")
    parser.add_argument("--output", "-o", default="top_temp_repos.json", help="Output JSON file (default: top_42_repos.json)")
    parser.add_argument("--top", "-n", type=int, default=42, help="Number of top repos to select (default: 42)")
    parser.add_argument("--max-pages", type=int, default=10,
                        help="Max pages to fetch per package (default: 10, i.e. 1000 repos per package)")
    parser.add_argument("--cache", default=None,
                        help="Cache file for resuming (default: <input_file>.cache.json)")
    args = parser.parse_args()

    github_token = os.environ.get("GITHUB_TOKEN")
    if not github_token:
        print("Error: Set the GITHUB_TOKEN environment variable.", file=sys.stderr)
        sys.exit(1)

    cache_file = args.cache or args.input_file + ".cache.json"
    cache = load_cache(cache_file)
    if cache:
        print(f"Loaded cache with {len(cache)} packages already fetched.", file=sys.stderr)

    with open(args.input_file) as f:
        packages = json.load(f)

    coordinates = [f"{p['groupId']}:{p['artifactId']}" for p in packages]
    print(f"Loaded {len(coordinates)} packages with sensitive APIs.", file=sys.stderr)

    # repo_name -> set of package coordinates it depends on
    repo_deps = {}

    for i, coord in enumerate(coordinates, 1):
        if coord in cache:
            print(f"[{i}/{len(coordinates)}] {coord} (cached, {len(cache[coord])} repos)", file=sys.stderr)
            repos = cache[coord]
        else:
            print(f"[{i}/{len(coordinates)}] Fetching dependent repos for {coord}...", file=sys.stderr)
            repos = list(fetch_dependent_repos(coord, args.max_pages))
            print(f"  Found {len(repos)} repos.", file=sys.stderr)
            cache[coord] = repos
            save_cache(cache_file, cache)
            time.sleep(RATE_LIMIT_SLEEP)

        for repo_name in repos:
            if repo_name not in repo_deps:
                repo_deps[repo_name] = set()
            repo_deps[repo_name].add(coord)

    print(f"\nTotal unique repos found: {len(repo_deps)}", file=sys.stderr)

    # Rank candidates by dependency count (descending) before filtering
    ranked = sorted(repo_deps.items(), key=lambda x: (-len(x[1]), x[0]))

    print(f"\nFiltering repos: ≥{MIN_STARS} stars, ≥{MIN_CONTRIBUTORS} contributors, "
          f"≥{MIN_COMMITS} commits, updated within {MAX_INACTIVE_YEARS} years\n", file=sys.stderr)

    # Cache for GitHub checks so reruns don't repeat API calls
    gh_cache_file = args.input_file + ".gh_cache.json"
    gh_cache = load_cache(gh_cache_file)

    filtered = []
    checked = 0
    for repo_name, deps in ranked:
        if len(filtered) >= args.top:
            break

        checked += 1
        print(f"[{checked}] {repo_name} ({len(deps)} deps) ... ", end="", file=sys.stderr, flush=True)

        if repo_name in gh_cache:
            result = gh_cache[repo_name]
            cached_label = " (cached)"
        else:
            try:
                result = check_github_conditions(repo_name, github_token)
            except Exception as e:
                print(f"error ({e}), skipping", file=sys.stderr)
                gh_cache[repo_name] = {"skip": "error", "message": str(e)}
                continue
            gh_cache[repo_name] = result
            if checked % 20 == 0:
                save_cache(gh_cache_file, gh_cache)
            cached_label = ""

        if result is None:
            print(f"skip (not found){cached_label}", file=sys.stderr)
            continue
        if "skip" in result:
            reason = result["skip"]
            detail = {k: v for k, v in result.items() if k != "skip"}
            print(f"skip ({reason}: {detail}){cached_label}", file=sys.stderr)
            continue

        print(f"PASS (stars={result['stars']}, contributors={result['contributors']}, "
              f"commits={result['commits']}){cached_label}", file=sys.stderr)
        filtered.append({
            "repo": repo_name,
            "dependency_count": len(deps),
            "dependencies": sorted(deps),
            "stars": result["stars"],
            "contributors": result["contributors"],
            "commits": result["commits"],
        })

    save_cache(gh_cache_file, gh_cache)

    with open(args.output, "w") as f:
        json.dump(filtered, f, indent=2)

    print(f"\nDone. Checked {checked} repos, {len(filtered)} passed. Saved to {args.output}", file=sys.stderr)

    if filtered:
        print(f"  Max dependencies: {filtered[0]['dependency_count']}", file=sys.stderr)
        print(f"  Min dependencies: {filtered[-1]['dependency_count']}", file=sys.stderr)


if __name__ == "__main__":
    main()
