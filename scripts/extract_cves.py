#!/usr/bin/env python3

import csv
import re
from collections import Counter
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]

SOURCE = BASE / "data/unified_findings.csv"
OUTPUT = BASE / "data/cve_findings.csv"

CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)

FIELDS = [
    "finding_id",
    "asset",
    "scanner",
    "title",
    "severity",
    "cvss",
    "cve",
    "source_report",
]

records = []
seen = set()

with SOURCE.open(encoding="utf-8-sig", newline="") as f:
    reader = csv.DictReader(f)

    for row in reader:
        raw_cves = row.get("cve", "") or ""

        cves = sorted({
            cve.upper()
            for cve in CVE_PATTERN.findall(raw_cves)
        })

        for cve in cves:
            key = (
                row.get("scanner", ""),
                row.get("finding_id", ""),
                cve,
            )

            if key in seen:
                continue

            seen.add(key)

            records.append({
                "finding_id": row.get("finding_id", ""),
                "asset": row.get("asset", ""),
                "scanner": row.get("scanner", ""),
                "title": row.get("title", ""),
                "severity": row.get("severity", ""),
                "cvss": row.get("cvss", ""),
                "cve": cve,
                "source_report": row.get("source_report", ""),
            })

OUTPUT.parent.mkdir(parents=True, exist_ok=True)

with OUTPUT.open("w", encoding="utf-8", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=FIELDS)
    writer.writeheader()
    writer.writerows(records)

unique_cves = {row["cve"] for row in records}

print("\n========== PATCHPROOF CVE EXTRACTION ==========")

print(f"[+] CVE associations: {len(records)}")
print(f"[+] Unique CVEs: {len(unique_cves)}")
print(f"[+] Saved: {OUTPUT}")

print("\nCVE associations by asset:")

for asset, count in sorted(
    Counter(row["asset"] for row in records).items()
):
    print(f"  {asset}: {count}")

print("\nSample CVEs:")

for cve in sorted(unique_cves)[:10]:
    print(f"  {cve}")

print("\n[+] Extraction completed.")
