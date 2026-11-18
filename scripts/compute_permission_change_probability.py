#!/usr/bin/env python3
"""
Parse the 'Sensitive API Permission Changes Across Versions' HTML report
and compute the probability that a version bump introduces a sensitive API
permission change — overall and per category (File, Network, Process).

The correct denominator is (Total Versions Analyzed - Number of Packages),
i.e. the total number of version *transitions* (bumps), not the total
versions. Each package's first version is a baseline with no predecessor.

Usage:
    python3 compute_permission_change_probability.py <html_report>
"""

import json
import re
import sys
from pathlib import Path
from html.parser import HTMLParser


# ---------------------------------------------------------------------------
# Category classification of sensitive APIs
# ---------------------------------------------------------------------------
# Loaded from Theo's authoritative source: sensitive_apis.json

SENSITIVE_APIS_PATH = (
    Path(__file__).resolve().parent.parent
    / "theo-commons" / "src" / "main" / "resources" / "sensitive_apis.json"
)

CATEGORIES = ["FILESYSTEM", "NETWORK", "PROCESS"]

# className -> set of categories (a class can appear with multiple methods
# in different categories, so we collect all)
_CLASS_TO_CATS = {}


def _load_sensitive_apis():
    if _CLASS_TO_CATS:
        return
    with open(SENSITIVE_APIS_PATH) as f:
        apis = json.load(f)
    for entry in apis:
        cls = entry["className"]
        cat = entry["category"]
        _CLASS_TO_CATS.setdefault(cls, set()).add(cat)


def classify_api(api_name):
    """Return set of categories for a fully qualified API method name."""
    _load_sensitive_apis()
    parts = api_name.rsplit(".", 1)
    if len(parts) < 2:
        return set()
    class_name = parts[0]

    if class_name in _CLASS_TO_CATS:
        return set(_CLASS_TO_CATS[class_name])
    # Try prefix match for inner classes
    for cls, cats in _CLASS_TO_CATS.items():
        if class_name.startswith(cls + "."):
            return set(cats)
    return set()


# ---------------------------------------------------------------------------
# HTML parsing
# ---------------------------------------------------------------------------

class ReportParser(HTMLParser):
    """Parse the summary table and per-package change-log entries."""

    def __init__(self):
        super().__init__()
        # Summary stats from stat cards
        self.stat_cards = []
        self._in_stat_number = False
        self._in_stat_label = False
        self._current_number = ""
        self._current_label = ""

        # Summary table (per-package row)
        self._in_summary_table = False
        self._in_summary_row = False
        self._summary_td_idx = 0
        self._summary_row_data = []
        self.summary_rows = []  # [{package, versions, patch, minor, major}]

        # Per-package change entries
        self._in_change_entry = False
        self._current_pkg = ""
        self._current_pkg_versions = 0
        self._change_text = ""
        self.pkg_changes = {}  # pkg -> [{from_ver, to_ver, added: [api], removed: [api]}]

        # Package section tracking
        self._in_pkg_section = False
        self._in_pkg_title = False
        self._in_coord = False
        self._coord_text = ""

    def handle_starttag(self, tag, attrs):
        d = dict(attrs)
        cls = d.get("class", "")

        if tag == "div" and "stat-card" in cls:
            pass
        if tag == "div" and "number" in cls:
            self._in_stat_number = True
            self._current_number = ""
        if tag == "div" and "label" in cls:
            self._in_stat_label = True
            self._current_label = ""

        if tag == "table" and "summary-table" in cls:
            self._in_summary_table = True
        if self._in_summary_table and tag == "tr":
            self._in_summary_row = True
            self._summary_td_idx = 0
            self._summary_row_data = []
        if self._in_summary_row and tag == "td":
            self._summary_td_idx += 1

        # Per-package sections
        if tag == "div" and "pkg-section" in cls:
            self._in_pkg_section = True
        if self._in_pkg_section and tag == "h3":
            self._in_pkg_title = True
            self._current_pkg = ""
        if self._in_pkg_section and tag == "div" and "coord" in cls:
            self._in_coord = True
            self._coord_text = ""
        if tag == "div" and "change-entry" in cls:
            self._in_change_entry = True
            self._change_text = ""

    def handle_data(self, data):
        if self._in_stat_number:
            self._current_number += data.strip()
        if self._in_stat_label:
            self._current_label += data.strip()

        if self._in_summary_row and self._summary_td_idx > 0:
            self._summary_row_data.append(data.strip())

        if self._in_pkg_title:
            self._current_pkg += data.strip()
        if self._in_coord:
            self._coord_text += data.strip()
        if self._in_change_entry:
            self._change_text += data

    def handle_endtag(self, tag):
        if tag == "div" and self._in_stat_number:
            self._in_stat_number = False
        if tag == "div" and self._in_stat_label:
            self._in_stat_label = False
            self.stat_cards.append((self._current_number, self._current_label))

        if self._in_summary_table and tag == "table":
            self._in_summary_table = False
        if self._in_summary_row and tag == "tr":
            self._in_summary_row = False
            if len(self._summary_row_data) >= 6:
                try:
                    row = {
                        "package": self._summary_row_data[1],
                        "versions": int(self._summary_row_data[2]),
                        "patch": int(self._summary_row_data[4]),
                        "minor": int(self._summary_row_data[5]),
                        "major": int(self._summary_row_data[6])
                                 if len(self._summary_row_data) > 6 else 0,
                    }
                    self.summary_rows.append(row)
                except (ValueError, IndexError):
                    pass

        if self._in_pkg_section and tag == "h3":
            self._in_pkg_title = False
        if self._in_coord and tag == "div":
            self._in_coord = False
            m = re.search(r'(\d+)\s+versions', self._coord_text)
            if m:
                self._current_pkg_versions = int(m.group(1))
            if self._current_pkg and self._current_pkg not in self.pkg_changes:
                self.pkg_changes[self._current_pkg] = {
                    "versions": self._current_pkg_versions,
                    "transitions": [],
                }
        if tag == "div" and self._in_change_entry:
            self._in_change_entry = False
            self._parse_change_entry()
        if tag == "div" and self._in_pkg_section:
            # Only close pkg section on the outermost div
            pass

    def _parse_change_entry(self):
        text = self._change_text
        # Extract version transition: "X.Y.Z → A.B.C"
        m = re.search(r'([\w.\-]+)\s*→\s*([\w.\-]+)', text)
        if not m:
            return
        from_ver, to_ver = m.group(1), m.group(2)

        added = re.findall(r'\+\s+([\w.<>]+)\s*\((direct|indirect)\)', text)
        removed = re.findall(r'-\s+([\w.<>]+)\s*\((direct|indirect)\)', text)

        entry = {
            "from": from_ver,
            "to": to_ver,
            "added": [(api, access) for api, access in added],
            "removed": [(api, access) for api, access in removed],
        }

        if self._current_pkg in self.pkg_changes:
            self.pkg_changes[self._current_pkg]["transitions"].append(entry)


def main():
    html_path = sys.argv[1] if len(sys.argv) > 1 else (
        "Sensitive API Permission Changes Across Versions.html")

    with open(html_path, encoding="utf-8") as f:
        content = f.read()

    parser = ReportParser()
    parser.feed(content)

    # --- Stat cards summary ---
    print("=== Report Summary Stats ===")
    for num, label in parser.stat_cards:
        print(f"  {label}: {num}")
    print()

    # --- Extract headline numbers ---
    total_versions = 0
    total_packages = 0
    patch_with_change = 0
    minor_with_change = 0
    major_with_change = 0
    for num, label in parser.stat_cards:
        n = int(num.replace(",", ""))
        if "Total Versions" in label:
            total_versions = n
        elif "Total Packages" in label:
            total_packages = n
        elif "Patch bumps" in label:
            patch_with_change = n
        elif "Minor bumps" in label:
            minor_with_change = n
        elif "Major bumps" in label:
            major_with_change = n

    total_bumps_with_change = patch_with_change + minor_with_change + major_with_change
    total_transitions = total_versions - total_packages

    print("=== Your proposed formula ===")
    print(f"  (Patch + Minor + Major with changes) / Total Versions Analyzed")
    print(f"  = ({patch_with_change} + {minor_with_change} + {major_with_change}) / {total_versions}")
    print(f"  = {total_bumps_with_change} / {total_versions}")
    print(f"  = {total_bumps_with_change / total_versions:.4f}"
          f" ({total_bumps_with_change / total_versions * 100:.2f}%)")
    print()

    print("=== Corrected formula ===")
    print(f"  Denominator should be Total Transitions (version bumps), not Total Versions.")
    print(f"  Total Transitions = Total Versions - Total Packages (each pkg's 1st version is baseline)")
    print(f"                    = {total_versions} - {total_packages} = {total_transitions}")
    print(f"  P(any API change) = {total_bumps_with_change} / {total_transitions}")
    print(f"                    = {total_bumps_with_change / total_transitions:.4f}"
          f" ({total_bumps_with_change / total_transitions * 100:.2f}%)")
    print()

    # --- Per-category analysis from change-log entries ---
    print("=== Per-Category Probability (from change-log entries) ===\n")

    total_transitions_from_data = 0
    transitions_with_file = 0
    transitions_with_network = 0
    transitions_with_process = 0
    transitions_with_unclassified = 0
    transitions_with_any = 0

    # Also track per bump type
    per_bump_type = {
        "patch": {"total": 0, "file": 0, "network": 0, "process": 0, "any": 0},
        "minor": {"total": 0, "file": 0, "network": 0, "process": 0, "any": 0},
        "major": {"total": 0, "file": 0, "network": 0, "process": 0, "any": 0},
        "other": {"total": 0, "file": 0, "network": 0, "process": 0, "any": 0},
    }

    for pkg_name, pkg_data in parser.pkg_changes.items():
        n_versions = pkg_data["versions"]
        # Total transitions for this package = versions - 1
        # But we only have entries for transitions WITH changes.
        # Transitions without changes are not in the change-log.
        # We get total transitions from the summary table.
        total_transitions_from_data += n_versions - 1

        for trans in pkg_data["transitions"]:
            all_apis = [api for api, _ in trans["added"]] + \
                       [api for api, _ in trans["removed"]]
            if not all_apis:
                continue

            cats_in_transition = set()
            for api in all_apis:
                cats_in_transition |= classify_api(api)

            has_file = "FILESYSTEM" in cats_in_transition
            has_network = "NETWORK" in cats_in_transition
            has_process = "PROCESS" in cats_in_transition
            has_unclassified = not cats_in_transition

            transitions_with_any += 1
            if has_file:
                transitions_with_file += 1
            if has_network:
                transitions_with_network += 1
            if has_process:
                transitions_with_process += 1
            if has_unclassified:
                transitions_with_unclassified += 1

            # Classify bump type
            bump = classify_bump(trans["from"], trans["to"])
            if bump in per_bump_type:
                per_bump_type[bump]["total"] += 1
                per_bump_type[bump]["any"] += 1
                if has_file:
                    per_bump_type[bump]["file"] += 1
                if has_network:
                    per_bump_type[bump]["network"] += 1
                if has_process:
                    per_bump_type[bump]["process"] += 1

    denom = total_transitions_from_data or 1
    print(f"  Total transitions (computed from per-package versions): {total_transitions_from_data}")
    print(f"  Transitions with any API change: {transitions_with_any}")
    print()
    print(f"  P(any change)       = {transitions_with_any}/{denom}"
          f" = {transitions_with_any/denom:.4f}"
          f" ({transitions_with_any/denom*100:.2f}%)")
    print(f"  P(FILESYSTEM change) = {transitions_with_file}/{denom}"
          f" = {transitions_with_file/denom:.4f}"
          f" ({transitions_with_file/denom*100:.2f}%)")
    print(f"  P(NETWORK change)    = {transitions_with_network}/{denom}"
          f" = {transitions_with_network/denom:.4f}"
          f" ({transitions_with_network/denom*100:.2f}%)")
    print(f"  P(PROCESS change)    = {transitions_with_process}/{denom}"
          f" = {transitions_with_process/denom:.4f}"
          f" ({transitions_with_process/denom*100:.2f}%)")
    if transitions_with_unclassified:
        print(f"  Unclassified (not in sensitive_apis.json) = {transitions_with_unclassified}/{denom}"
              f" = {transitions_with_unclassified/denom:.4f}"
              f" ({transitions_with_unclassified/denom*100:.2f}%)")
    print()

    print("=== Per Bump Type × Category ===\n")
    print(f"  {'Bump Type':<10} {'Total':>8} {'Any':>8} {'File':>8} {'Network':>8} {'Process':>8}")
    print(f"  {'-'*10} {'-'*8} {'-'*8} {'-'*8} {'-'*8} {'-'*8}")
    for bt in ["patch", "minor", "major", "other"]:
        d = per_bump_type[bt]
        print(f"  {bt:<10} {d['total']:>8} {d['any']:>8}"
              f" {d['file']:>8} {d['network']:>8} {d['process']:>8}")

    print()
    print("=== Verification ===")
    print(f"  Headline stat bumps with change: {total_bumps_with_change}"
          f"  (patch={patch_with_change} + minor={minor_with_change}"
          f" + major={major_with_change})")
    print(f"  Transitions with change from parsing: {transitions_with_any}")
    if transitions_with_any != total_bumps_with_change:
        sum_from_table = sum(r["patch"] + r["minor"] + r["major"]
                             for r in parser.summary_rows)
        print(f"  Sum from summary table rows: {sum_from_table}")
        print(f"  Note: difference may be due to version pairs that don't"
              f" cleanly classify as patch/minor/major.")


def classify_bump(from_ver, to_ver):
    """Classify version transition as patch, minor, major, or other."""
    def parse_semver(v):
        m = re.match(r'(\d+)\.(\d+)\.(\d+)', v)
        if m:
            return int(m.group(1)), int(m.group(2)), int(m.group(3))
        m = re.match(r'(\d+)\.(\d+)', v)
        if m:
            return int(m.group(1)), int(m.group(2)), 0
        return None

    f = parse_semver(from_ver)
    t = parse_semver(to_ver)
    if not f or not t:
        return "other"
    if t[0] != f[0]:
        return "major"
    if t[1] != f[1]:
        return "minor"
    if t[2] != f[2]:
        return "patch"
    return "other"


if __name__ == "__main__":
    main()
