#!/usr/bin/env python3

import csv
import hashlib
import re
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit

from bs4 import BeautifulSoup

BASE = Path(__file__).resolve().parents[1]
REPORT = next((BASE / "evidence/baseline").glob("*ZAP*.html"))
OUTPUT = BASE / "data/zap_findings.csv"

TARGET_IP = "172.16.220.137"
TARGET_PORTS = {80, 5000}

FIELDS = [
    "finding_id",
    "asset",
    "ip",
    "scanner",
    "title",
    "severity",
    "confidence",
    "method",
    "url",
    "cwe",
    "description",
    "solution",
    "source_report",
    "status",
]


def in_scope(url):
    try:
        parsed = urlsplit(url)
        return (
            parsed.scheme == "http"
            and parsed.hostname == TARGET_IP
            and (parsed.port or 80) in TARGET_PORTS
        )
    except ValueError:
        return False


def table_value(table, names):
    if not table:
        return ""

    for row in table.find_all("tr"):
        header = row.find("th")
        value = row.find("td")

        if not header or not value:
            continue

        label = header.get_text(" ", strip=True).lower()

        if any(name in label for name in names):
            return value.get_text(" ", strip=True)

    return ""


soup = BeautifulSoup(
    REPORT.read_text(encoding="utf-8", errors="replace"),
    "html.parser",
)

alerts = soup.find("section", id="alerts")

if alerts is None:
    raise RuntimeError("ZAP Alerts section not found")

findings = []
seen = set()
skipped_external = 0

for heading in alerts.find_all("h5"):

    alert_li = heading.find_parent("li")
    site_li = heading.find_parent(
        "li", class_="alerts--site-li"
    )

    if alert_li is None or site_li is None:
        continue

    site_heading = site_li.find("h4")
    site = (
        site_heading.get_text(" ", strip=True).split()[0]
        if site_heading else ""
    )

    # Remove the count displayed after the alert title.
    title = re.sub(
        r"\s*\(\d+\)\s*$",
        "",
        heading.get_text(" ", strip=True),
    )

    risk_li = heading.find_parent(
        "li", id=re.compile(r"^alerts--risk-")
    )

    risk_text = ""
    if risk_li:
        risk_heading = risk_li.find("h3")
        if risk_heading:
            risk_text = risk_heading.get_text(" ", strip=True)

    severity_match = re.search(
        r"Risk\s*=\s*([^,]+)", risk_text
    )
    confidence_match = re.search(
        r"Confidence\s*=\s*([^(]+)", risk_text
    )

    severity = (
        severity_match.group(1).strip()
        if severity_match else "Unknown"
    )
    confidence = (
        confidence_match.group(1).strip()
        if confidence_match else "Unknown"
    )

    if not in_scope(site):
        skipped_external += 1
        continue

    for table in alert_li.select("table.alerts-table"):

        # Each instance table belongs to an affected request.
        instance_li = table.find_parent("li")

        if instance_li is None:
            continue

        instance_text = instance_li.get_text(" ", strip=True)

        request = re.search(
            r"\b(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+"
            r"(https?://[^\s]+)",
            instance_text,
        )

        if not request:
            continue

        method = request.group(1)
        url = request.group(2).rstrip("),;")

        if not in_scope(url):
            continue

        table_text = table.get_text(" ", strip=True)

        cwe_match = re.search(r"\bCWE-(\d+)\b", table_text)
        cwe = (
            f"CWE-{cwe_match.group(1)}"
            if cwe_match else ""
        )

        description = table_value(
            table, ["alert description", "description"]
        )

        solution = table_value(
            table, ["solution", "remediation"]
        )

        fingerprint = f"ZAP|{title}|{method}|{url}"
        finding_id = (
            "ZAP-" + hashlib.sha256(
                fingerprint.encode()
            ).hexdigest()[:16]
        )

        if finding_id in seen:
            continue

        seen.add(finding_id)

        findings.append({
            "finding_id": finding_id,
            "asset": "WEB01",
            "ip": TARGET_IP,
            "scanner": "OWASP ZAP",
            "title": title,
            "severity": severity,
            "confidence": confidence,
            "method": method,
            "url": url,
            "cwe": cwe,
            "description": description,
            "solution": solution,
            "source_report": REPORT.name,
            "status": "Open",
        })

OUTPUT.parent.mkdir(parents=True, exist_ok=True)

with OUTPUT.open(
    "w", encoding="utf-8", newline=""
) as file:
    writer = csv.DictWriter(file, fieldnames=FIELDS)
    writer.writeheader()
    writer.writerows(findings)

print(f"\n[+] Imported {len(findings)} ZAP alert instances")
print(f"[+] Excluded {skipped_external} external site/alert groups")
print(f"[+] Saved: {OUTPUT}")

print("\nZAP findings by severity:")
for severity, count in sorted(
    Counter(f["severity"] for f in findings).items()
):
    print(f"  {severity}: {count}")

print("\nImported findings:")
for finding in findings:
    print(
        f"  [{finding['severity']}] "
        f"{finding['title']} -> {finding['url']}"
    )
