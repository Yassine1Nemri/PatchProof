#!/usr/bin/env python3

import csv
from collections import Counter
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
DATA = BASE / "data"

SOURCES = [
    DATA / "findings.csv",
    DATA / "zap_findings.csv",
]

OUTPUT = DATA / "unified_findings.csv"

COMMON_FIELDS = [
    "finding_id",
    "asset",
    "ip",
    "scanner",
    "title",
    "severity",
    "cvss",
    "cve",
    "cwe",
    "qod",
    "confidence",
    "port",
    "protocol",
    "method",
    "url",
    "description",
    "solution",
    "source_report",
    "status",
]

findings = []
seen = set()
extra_fields = []

for source in SOURCES:
    with source.open(encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)

        for field in reader.fieldnames or []:
            if field not in COMMON_FIELDS and field not in extra_fields:
                extra_fields.append(field)

        for row in reader:
            scanner = row.get("scanner", "").strip()
            finding_id = row.get("finding_id", "").strip()

            if not finding_id:
                raise ValueError(
                    f"Missing finding_id in {source.name}"
                )

            key = (scanner, finding_id)

            if key in seen:
                continue

            seen.add(key)
            findings.append(row)

fields = COMMON_FIELDS + extra_fields

with OUTPUT.open("w", encoding="utf-8", newline="") as f:
    writer = csv.DictWriter(
        f,
        fieldnames=fields,
        extrasaction="ignore",
    )
    writer.writeheader()
    writer.writerows(findings)

print(f"\n[+] Unified records: {len(findings)}")
print(f"[+] Saved: {OUTPUT}")

print("\nRecords by scanner:")
for scanner, count in sorted(
    Counter(f["scanner"] for f in findings).items()
):
    print(f"  {scanner}: {count}")

print("\nRecords by severity:")
for severity, count in sorted(
    Counter(f["severity"] for f in findings).items()
):
    print(f"  {severity}: {count}")

print("\nRecords by asset:")
for asset, count in sorted(
    Counter(f["asset"] for f in findings).items()
):
    print(f"  {asset}: {count}")
