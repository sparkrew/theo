import json
from collections import defaultdict
from pathlib import Path
import re

# Input/output paths
input_path = Path("/Users/yogyagamage/Documents/UdeM/theo/theo-dynamic/testHopperNew.json")
output_path = Path("/Users/yogyagamage/Documents/UdeM/theo/theo-dynamic/testHopperSummaryNew.json")

# Load input
with open(input_path, "r") as f:
    data = json.load(f)

summary = {}

for dependency, entries in data.items():
    events = defaultdict(lambda: defaultdict(set))  # event_type -> sensitiveAPI -> set of positions
    methods_set = set()

    for entry in entries:
        event = entry.get("event", {})
        event_type = event.get("type", "")
        sensitive_api = event.get("sensitiveAPI", "")
        position = entry.get("position", "")
        method = entry.get("method", "")

        if method:
            package_name = ".".join(method.split(".")[:-2])
            if package_name:
                methods_set.add(package_name)

        if event_type and sensitive_api and position:
            events[event_type][sensitive_api].add(position)

    formatted_events = {
        event_type: {
            api: sorted(list(positions))
            for api, positions in apis.items()
        }
        for event_type, apis in events.items()
    }

    summary[dependency] = {
        "events": formatted_events,
        "packageNames": sorted(methods_set)
    }

# Dump with normal indent
json_text = json.dumps(summary, indent=2)

# Compact all small lists (e.g., ["A", "B"]) onto one line using regex
def compact_lists(text):
    return re.sub(r'\[\n\s+("[^"]+")(?:,\n\s+("[^"]+"))*\n\s+\]', 
                  lambda m: "[" + ", ".join(re.findall(r'"[^"]+"', m.group(0))) + "]", 
                  text)

compact_json_text = compact_lists(json_text)

with open(output_path, "w") as f:
    f.write(compact_json_text)

print("Summary written to:", output_path)
