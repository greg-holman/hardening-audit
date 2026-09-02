"""Parse an audit report: gate on fail-on, write action outputs, emit annotations."""
import json
import os
import sys

path = sys.argv[1]
ranks = {"low": 0, "medium": 1, "high": 2, "critical": 3}
labels = ("critical", "high", "medium", "low")

with open(path, "r", encoding="utf-8") as handle:
    document = json.load(handle)

results = document.get("results", [])
counts = {severity: 0 for severity in labels}
max_rank = -1

for result in results:
    for finding in result.get("findings", []):
        severity = finding.get("severity")
        if severity in ranks:
            counts[severity] += 1
            max_rank = max(max_rank, ranks[severity])

fail_on = os.environ["AUDIT_FAIL_ON"]
threshold = ranks.get(fail_on, 4)
passed = fail_on == "none" or max_rank < threshold
parts = [
    f"{counts[severity]} {severity}"
    for severity in labels
    if counts[severity]
]
summary = f"{', '.join(parts) if parts else '0 findings'} ({len(results)} URLs)"

output_path = os.environ.get("GITHUB_OUTPUT", "")
if output_path:
    with open(output_path, "a", encoding="utf-8") as handle:
        handle.write(f"passed={'true' if passed else 'false'}\n")
        handle.write(f"summary={summary}\n")

if not passed:
    for result in results:
        url = result.get("url", "")
        for finding in result.get("findings", []):
            severity = finding.get("severity")
            if severity in ranks and ranks[severity] >= threshold:
                category = finding.get("category", "finding")
                detail = finding.get("detail", "")
                print(f"::error::{url}: {category} ({severity}): {detail}")

sys.exit(0 if passed else 1)
