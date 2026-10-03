import csv
import os
import json
import sys

out = sys.argv[1] if len(sys.argv) > 1 else "outputs"

with open(os.path.join(out, "sensitive_api_usage.csv")) as f:
    reader = csv.DictReader(f)
    apis = [k for k in reader.fieldnames if k not in ("groupId", "artifactId", "latestVersion")]
    candidates = set()
    for r in reader:
        if any(r[a] == "True" for a in apis):
            candidates.add((r["groupId"], r["artifactId"]))

history_dir = os.path.join(out, "version-history")
have_history = set()
if os.path.isdir(history_dir):
    for f in os.listdir(history_dir):
        if f.endswith("-history.json"):
            parts = f.replace("-history.json", "").rsplit("_", 1)
            if len(parts) == 2:
                have_history.add((parts[0], parts[1]))

missing = candidates - have_history

skipped_files = {
    "download_failed": "skipped_version_download_failed.json",
    "timed_out": "skipped_version_timed_out.json",
    "scan_failed": "skipped_version_scan_failed.json",
    "oom": "skipped_version_oom.json",
    "history_timed_out": "skipped_version_history_timed_out.json",
}

skip_reasons = {}
for reason, filename in skipped_files.items():
    path = os.path.join(out, filename)
    if not os.path.exists(path):
        continue
    with open(path) as f:
        entries = json.load(f)
    for entry in entries:
        g = entry.get("groupId")
        a = entry.get("artifactId")
        if g and a:
            skip_reasons.setdefault((g, a), set()).add(reason)

found_in_skipped = {}
not_found_anywhere = []

for g, a in sorted(missing):
    reasons = skip_reasons.get((g, a))
    if reasons:
        found_in_skipped[(g, a)] = sorted(reasons)
    else:
        not_found_anywhere.append({"groupId": g, "artifactId": a})

print(f"Total missing version history: {len(missing)}")
print(f"Found in skipped files:        {len(found_in_skipped)}")
print(f"Not found anywhere:            {len(not_found_anywhere)}")
print()

if found_in_skipped:
    print("=== FOUND IN SKIPPED FILES ===")
    for (g, a), reasons in sorted(found_in_skipped.items()):
        print(f"  {g}:{a}  ->  {', '.join(reasons)}")
    print()

if not_found_anywhere:
    print("=== NOT FOUND ANYWHERE (no recorded skip reason) ===")
    for pkg in not_found_anywhere:
        print(f"  {pkg['groupId']}:{pkg['artifactId']}")

if not_found_anywhere:
    out_file = os.path.join(out, "packages_no_version_history_unknown.json")
    with open(out_file, "w") as f:
        json.dump(not_found_anywhere, f, indent=2)
    print(f"\nSaved {len(not_found_anywhere)} packages to {out_file}")
