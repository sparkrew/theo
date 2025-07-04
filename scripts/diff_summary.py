import json
from pathlib import Path

# File paths
static_file = Path("/Users/yogyagamage/Documents/UdeM/theo-reports/graphhopper10-11/theo-test-report.json")
dynamic_file = Path("/Users/yogyagamage/Documents/UdeM/theo-reports/graphhopper10-11/theo-static-report.json")

# Output files
deps_diff_file = Path("/Users/yogyagamage/Documents/UdeM/theo/report/dependency_diff_o.json")
sensitive_diff_file = Path("/Users/yogyagamage/Documents/UdeM/theo/report/sensitive_api_diff_o.json")

# Load JSON files
with open(dynamic_file) as f:
    dynamic_data = json.load(f)

with open(static_file) as f:
    static_data = json.load(f)

# ----------------------
# 1. Dependency Diff Report
# ----------------------

dynamic_deps = set(dynamic_data.keys())
static_deps = set(static_data.keys())

dep_report = {
    "dependenciesOnlyInDynamic": sorted(dynamic_deps - static_deps),
    "dependenciesOnlyInStatic": sorted(static_deps - dynamic_deps),
    "dependenciesInBoth": sorted(dynamic_deps & static_deps)
}

deps_diff_file.parent.mkdir(parents=True, exist_ok=True)

with open(deps_diff_file, "w") as f:
    json.dump(dep_report, f, indent=2)

print(f"Dependency diff report written to: {deps_diff_file}")

# ----------------------
# 2. Sensitive API Diff Report
# ----------------------

def extract_sensitive_apis_from_dynamic(dep_data):
    apis = set()
    for method_name in dep_data:
        if "." in method_name:  # crude filter for method-like strings
            apis.add(method_name)
    return apis

def extract_sensitive_apis_from_static(dep_data):
    apis = set()
    for method_sig in dep_data.get("apis", {}):
        # Try to extract the method name (e.g., java.lang.reflect.Method.invoke)
        if ":" in method_sig:
            class_method = method_sig.split(":")[0].strip("<>")
            apis.add(class_method)
    return apis

sensitive_report = {}

for dep in sorted(dynamic_deps | static_deps):
    dynamic_apis = extract_sensitive_apis_from_dynamic(dynamic_data.get(dep, {})) if dep in dynamic_data else set()
    static_apis = extract_sensitive_apis_from_static(static_data.get(dep, {})) if dep in static_data else set()

    only_in_dynamic = sorted(dynamic_apis - static_apis)
    only_in_static = sorted(static_apis - dynamic_apis)
    in_both = sorted(dynamic_apis & static_apis)

    if only_in_dynamic or only_in_static or in_both:
        sensitive_report[dep] = {
            "apisOnlyInDynamic": only_in_dynamic,
            "apisOnlyInStatic": only_in_static,
            "apisInBoth": in_both
        }

with open(sensitive_diff_file, "w") as f:
    json.dump(sensitive_report, f, indent=2)

print(f"Sensitive API diff report written to: {sensitive_diff_file}")
