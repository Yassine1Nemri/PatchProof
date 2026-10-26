#!/usr/bin/env python3

import csv
import glob
import os
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
INPUT = BASE / "evidence" / "baseline"
OUTPUT = BASE / "data" / "findings.csv"

ASSETS = {
    "172.16.220.140": "MS2",
    "172.16.220.10": "DC01",
    "172.16.220.137": "WEB01",
    "172.16.220.11": "WIN-CL",
}

FIELDS = [
    "finding_id",
    "asset",
    "ip",
    "port",
    "protocol",
    "scanner",
    "scan_type",
    "title",
    "cve",
    "cvss",
    "severity",
    "qod",
    "description",
    "solution",
    "nvt_oid",
    "scan_timestamp",
    "source_report",
    "status",
]

findings = []
seen = set()

for file in sorted(INPUT.glob("*.csv")):

    with open(file, encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)

        for row in reader:

            ip = row.get("IP", "").strip()
            if not ip:
                continue

            result_id = row.get("Result ID", "").strip()

            # Deduplicate identical exported scanner results.
            key = result_id or (
                ip,
                row.get("NVT OID", ""),
                row.get("Port", ""),
                row.get("Port Protocol", ""),
                row.get("Specific Result", ""),
            )

            if key in seen:
                continue

            seen.add(key)

            finding = {
                "finding_id": result_id,
                "asset": ASSETS.get(ip, "UNKNOWN"),
                "ip": ip,
                "port": row.get("Port", ""),
                "protocol": row.get("Port Protocol", ""),
                "scanner": "Greenbone/OpenVAS",
                "scan_type": "Baseline",
                "title": row.get("NVT Name", ""),
                "cve": row.get("CVEs", ""),
                "cvss": row.get("CVSS", ""),
                "severity": row.get("Severity", ""),
                "qod": row.get("QoD", ""),
                "description": row.get("Summary", ""),
                "solution": row.get("Solution", ""),
                "nvt_oid": row.get("NVT OID", ""),
                "scan_timestamp": row.get("Timestamp", ""),
                "source_report": file.name,
                "status": "Open",
            }

            findings.append(finding)

OUTPUT.parent.mkdir(parents=True, exist_ok=True)

with open(OUTPUT, "w", encoding="utf-8", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=FIELDS)
    writer.writeheader()
    writer.writerows(findings)

print(f"\n[+] Imported {len(findings)} findings")
print(f"[+] Saved: {OUTPUT}")

from collections import Counter

print("\nFindings by asset:")
for asset, count in sorted(
    Counter(f["asset"] for f in findings).items()
):
    print(f"  {asset}: {count}")

print("\nFindings by severity:")
for severity, count in Counter(
    f["severity"] for f in findings
).items():
    print(f"  {severity}: {count}")
