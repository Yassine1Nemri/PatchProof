#!/usr/bin/env python3

import csv
import json
import time
import urllib.parse
import urllib.request

from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
DATA = BASE / "data"

CVE_SOURCE = DATA / "cve_findings.csv"
FINDINGS_SOURCE = DATA / "unified_findings.csv"

CVE_OUTPUT = DATA / "enriched_cves.csv"
PRIORITY_OUTPUT = DATA / "prioritized_findings.csv"

EPSS_API = "https://api.first.org/data/v1/epss"
KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)

ASSET_CRITICALITY = {
    "DC01": 5,
    "WIN-CL": 3,
    "WEB01": 4,
    "MS2": 1,
}


def fetch_json(url):
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "PatchProof/1.0"},
    )

    with urllib.request.urlopen(request, timeout=40) as response:
        return json.load(response)


def load_csv(path):
    with path.open(encoding="utf-8-sig", newline="") as file:
        return list(csv.DictReader(file))


def save_csv(path, rows, fields):
    with path.open("w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(
            file,
            fieldnames=fields,
            extrasaction="ignore",
        )
        writer.writeheader()
        writer.writerows(rows)


def number(value):
    try:
        return float(value)
    except (ValueError, TypeError):
        return None


print("\n========== PATCHPROOF INTELLIGENCE ENGINE ==========")

associations = load_csv(CVE_SOURCE)
findings = load_csv(FINDINGS_SOURCE)

unique_cves = sorted({
    row["cve"].strip()
    for row in associations
    if row.get("cve", "").strip()
})

print(f"[+] Unique CVEs: {len(unique_cves)}")
print(f"[+] Scanner records: {len(findings)}")

# --------------------------------------------------
# STEP A: EPSS ENRICHMENT
# --------------------------------------------------

print("\n[1/4] Fetching FIRST EPSS intelligence...")

epss_data = {}

# The FIRST API limits the CVE query parameter size.
# Batches of 25 keep requests comfortably below the limit.

for start in range(0, len(unique_cves), 25):

    batch = unique_cves[start:start + 25]

    query = urllib.parse.urlencode({
        "cve": ",".join(batch)
    })

    response = fetch_json(f"{EPSS_API}?{query}")

    if response.get("status") != "OK":
        raise RuntimeError("Unexpected EPSS API response")

    for item in response.get("data", []):
        epss_data[item["cve"]] = item

    print(f"    Processed {min(start + 25, len(unique_cves))} CVEs")

    time.sleep(0.3)

print(f"[+] EPSS matches: {len(epss_data)}")

# --------------------------------------------------
# STEP B: CISA KEV ENRICHMENT
# --------------------------------------------------

print("\n[2/4] Fetching CISA KEV catalog...")

kev_response = fetch_json(KEV_URL)

if not isinstance(kev_response.get("vulnerabilities"), list):
    raise RuntimeError("Invalid CISA KEV response")

kev_data = {
    item["cveID"]: item
    for item in kev_response["vulnerabilities"]
    if item.get("cveID")
}

print(f"[+] CISA KEV catalog entries: {len(kev_data)}")

# --------------------------------------------------
# STEP C: ENRICH CVE ASSOCIATIONS
# --------------------------------------------------

print("\n[3/4] Enriching CVE associations...")

enriched = []
cves_by_finding = defaultdict(list)

retrieved_at = datetime.now(timezone.utc).isoformat()

for row in associations:

    cve = row["cve"]
    epss = epss_data.get(cve)
    kev = kev_data.get(cve)

    enriched_row = {
        **row,
        "epss": epss.get("epss", "") if epss else "",
        "epss_percentile": (
            epss.get("percentile", "") if epss else ""
        ),
        "epss_date": epss.get("date", "") if epss else "",
        "kev": "Yes" if kev else "No",
        "kev_date_added": (
            kev.get("dateAdded", "") if kev else ""
        ),
        "kev_required_action": (
            kev.get("requiredAction", "") if kev else ""
        ),
        "intelligence_retrieved_at": retrieved_at,
    }

    enriched.append(enriched_row)

    key = (
        row.get("scanner", ""),
        row.get("finding_id", ""),
    )

    cves_by_finding[key].append(enriched_row)

cve_fields = list(associations[0].keys()) if associations else [
    "finding_id", "asset", "scanner", "title",
    "severity", "cvss", "cve", "source_report"
]

cve_fields += [
    "epss",
    "epss_percentile",
    "epss_date",
    "kev",
    "kev_date_added",
    "kev_required_action",
    "intelligence_retrieved_at",
]

save_csv(CVE_OUTPUT, enriched, cve_fields)

print(f"[+] Saved: {CVE_OUTPUT}")

# --------------------------------------------------
# STEP D: RISK PRIORITIZATION
# --------------------------------------------------

print("\n[4/4] Calculating risk priorities...")

prioritized = []

for finding in findings:

    key = (
        finding.get("scanner", ""),
        finding.get("finding_id", ""),
    )

    related = cves_by_finding.get(key, [])

    severity = finding.get("severity", "").strip().lower()
    asset = finding.get("asset", "")

    # Transparent heuristic, not an industry-standard score.
    # Maximum score: 100.

    severity_points = {
        "critical": 45,
        "high": 34,
        "medium": 22,
        "low": 10,
        "informational": 0,
    }.get(severity, 0)

    asset_points = ASSET_CRITICALITY.get(asset, 1) * 5

    available_epss = [
        number(item.get("epss"))
        for item in related
    ]

    available_epss = [
        value for value in available_epss
        if value is not None
    ]

    max_epss = (
        max(available_epss)
        if available_epss else None
    )

    epss_points = (
        15 * max_epss
        if max_epss is not None else 0
    )

    kev_present = any(
        item.get("kev") == "Yes"
        for item in related
    )

    kev_points = 15 if kev_present else 0

    score = round(
        severity_points
        + asset_points
        + epss_points
        + kev_points,
        2,
    )

    # Missing EPSS is explicitly marked rather than
    # interpreted as a genuine zero exploitation probability.
    intelligence_status = (
        "No CVE reference"
        if not related
        else "EPSS unavailable"
        if len(available_epss) < len({
            item["cve"] for item in related
        })
        else "EPSS available"
    )

    # MS2 is deliberately vulnerable.
    # Track its technical findings without suggesting
    # normal production patching priorities.
    if asset == "MS2":
        priority = "Lab / Accepted Exposure"
    elif kev_present or score >= 75:
        priority = "P1"
    elif score >= 55:
        priority = "P2"
    elif score >= 35:
        priority = "P3"
    else:
        priority = "P4"

    output = {
        **finding,
        "cve_count": len({
            item["cve"] for item in related
        }),
        "cves": ";".join(sorted({
            item["cve"] for item in related
        })),
        "max_epss": (
            round(max_epss, 6)
            if max_epss is not None else ""
        ),
        "kev_present": "Yes" if kev_present else "No",
        "asset_criticality": ASSET_CRITICALITY.get(asset, 1),
        "risk_score": score,
        "priority": priority,
        "intelligence_status": intelligence_status,
        "intelligence_retrieved_at": retrieved_at,
    }

    prioritized.append(output)

prioritized.sort(
    key=lambda row: row["risk_score"],
    reverse=True,
)

priority_fields = (
    list(findings[0].keys())
    if findings else []
)

priority_fields += [
    "cve_count",
    "cves",
    "max_epss",
    "kev_present",
    "asset_criticality",
    "risk_score",
    "priority",
    "intelligence_status",
    "intelligence_retrieved_at",
]

save_csv(
    PRIORITY_OUTPUT,
    prioritized,
    priority_fields,
)

print(f"[+] Saved: {PRIORITY_OUTPUT}")

# --------------------------------------------------
# SUMMARY
# --------------------------------------------------

kev_matches = {
    item["cve"]
    for item in enriched
    if item["kev"] == "Yes"
}

print("\n========== INTELLIGENCE SUMMARY ==========")

print(f"Scanner findings: {len(findings)}")
print(f"Unique CVEs: {len(unique_cves)}")
print(f"CVEs with EPSS: {len(epss_data)}")
print(f"Unique CVEs in KEV: {len(kev_matches)}")

print("\nPriority distribution:")

for priority, count in sorted(
    Counter(row["priority"] for row in prioritized).items()
):
    print(f"  {priority}: {count}")

print("\nTop 10 non-lab findings:")

production = [
    row for row in prioritized
    if row["asset"] != "MS2"
]

for row in production[:10]:
    print(
        f"  [{row['priority']}] "
        f"Score={row['risk_score']} | "
        f"{row['asset']} | "
        f"{row['title'][:65]}"
    )

print("\n[+] Intelligence enrichment completed!")
