#!/usr/bin/env python3

"""
PatchProof - PostgreSQL Data Importer

Imports:
    1. prioritized_findings.csv -> findings
    2. enriched_cves.csv -> cve_intelligence
    3. ai_analysis.csv -> ai_analysis

Creates:
    dashboard_findings
    dashboard_ai_analysis
    dashboard_cve_intelligence

Requirements:
    - Docker
    - Running patchproof-postgres container
    - Python 3 standard library

No pip packages required.
"""

import csv
import re
import subprocess
from pathlib import Path


# ============================================================
# CONFIGURATION
# ============================================================

BASE = Path(__file__).resolve().parents[1]
DATA = BASE / "data"

CONTAINER = "patchproof-postgres"
DB_NAME = "patchproof"
DB_USER = "patchproof"

TABLES = {
    "findings": DATA / "prioritized_findings.csv",
    "cve_intelligence": DATA / "enriched_cves.csv",
    "ai_analysis": DATA / "ai_analysis.csv",
}


# ============================================================
# DOCKER / POSTGRESQL HELPERS
# ============================================================

def run_command(command):
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"Command failed:\n"
            f"{' '.join(command)}\n\n"
            f"{result.stderr}"
        )

    return result.stdout.strip()


def run_sql(sql):
    return run_command([
        "docker",
        "exec",
        CONTAINER,
        "psql",
        "-X",
        "-v",
        "ON_ERROR_STOP=1",
        "-U",
        DB_USER,
        "-d",
        DB_NAME,
        "-c",
        sql,
    ])


def quote_identifier(value):
    if not re.fullmatch(
        r"[A-Za-z_][A-Za-z0-9_]*",
        value,
    ):
        raise ValueError(
            f"Invalid SQL identifier: {value}"
        )

    return f'"{value}"'


# ============================================================
# READ CSV METADATA
# ============================================================

def inspect_csv(path):

    if not path.exists():
        raise FileNotFoundError(
            f"Missing CSV file: {path}"
        )

    with path.open(
        encoding="utf-8-sig",
        newline="",
    ) as file:

        reader = csv.DictReader(file)
        columns = reader.fieldnames

        if not columns:
            raise ValueError(
                f"No CSV header found: {path}"
            )

        if len(columns) != len(set(columns)):
            raise ValueError(
                f"Duplicate CSV columns: {path}"
            )

        for column in columns:
            quote_identifier(column)

        count = sum(1 for _ in reader)

    return columns, count


# ============================================================
# IMPORT CSV TO POSTGRESQL
# ============================================================

def import_table(table, source):

    table_sql = quote_identifier(table)

    columns, expected_count = inspect_csv(source)

    print(f"\n[+] Importing table: {table}")
    print(f"    Source: {source.name}")
    print(f"    Expected rows: {expected_count}")

    # Create all source columns as TEXT.
    # This preserves the original imported values.

    definitions = ", ".join(
        f"{quote_identifier(column)} TEXT"
        for column in columns
    )

    create_sql = (
        f"CREATE TABLE IF NOT EXISTS "
        f"{table_sql} ({definitions});"
    )

    run_sql(create_sql)

    # Copy CSV into the Docker container.
    # This avoids requiring psycopg2 or other pip packages.

    container_path = (
        f"/tmp/patchproof_{table}.csv"
    )

    run_command([
        "docker",
        "cp",
        str(source),
        f"{CONTAINER}:{container_path}",
    ])

    column_list = ", ".join(
        quote_identifier(column)
        for column in columns
    )

    # TRUNCATE and COPY run in the same transaction.
    # If COPY fails, PostgreSQL rolls back the transaction.

    sql = f"""
    BEGIN;

    TRUNCATE TABLE {table_sql};

    COPY {table_sql} ({column_list})
    FROM '{container_path}'
    WITH (
        FORMAT csv,
        HEADER true,
        ENCODING 'UTF8'
    );

    COMMIT;
    """

    try:
        run_sql(sql)
    finally:
        subprocess.run(
            [
                "docker",
                "exec",
                CONTAINER,
                "rm",
                "-f",
                container_path,
            ],
            capture_output=True,
        )

    actual_count = run_sql(
        f"SELECT COUNT(*) FROM {table_sql};"
    )

    print("    Import successful")
    print(actual_count.splitlines()[-3:])


# ============================================================
# GRAFANA SQL VIEWS
# ============================================================

def create_views():

    print("\n[+] Creating Grafana reporting views...")

    findings_view = """
    CREATE OR REPLACE VIEW dashboard_findings AS

    SELECT
        finding_id,
        asset,
        ip,
        scanner,
        title,
        severity,
        priority,

        NULLIF(risk_score, '')::NUMERIC
            AS risk_score,

        NULLIF(cvss, '')::NUMERIC
            AS cvss,

        NULLIF(max_epss, '')::NUMERIC
            AS max_epss,

        kev_present,

        NULLIF(cve_count, '')::INTEGER
            AS cve_count,

        source_report,
        status,
        intelligence_status

    FROM findings;
    """

    run_sql(findings_view)

    ai_view = """
    CREATE OR REPLACE VIEW dashboard_ai_analysis AS

    SELECT
        f.finding_id,
        f.asset,
        f.title,
        f.severity,
        f.priority,

        NULLIF(f.risk_score, '')::NUMERIC
            AS risk_score,

        a.model,
        a.technical_risk,
        a.business_impact,
        a.remediation,
        a.verification,
        a.limitations,
        a.review_status

    FROM findings f

    INNER JOIN ai_analysis a
        ON f.finding_id = a.finding_id
        AND f.asset = a.asset;
    """

    run_sql(ai_view)

    cve_view = """
    CREATE OR REPLACE VIEW dashboard_cve_intelligence AS

    SELECT
        finding_id,
        asset,
        scanner,
        title,
        cve,

        NULLIF(epss, '')::NUMERIC
            AS epss,

        NULLIF(epss_percentile, '')::NUMERIC
            AS epss_percentile,

        epss_date,
        kev,
        kev_date_added,
        kev_required_action

    FROM cve_intelligence;
    """

    run_sql(cve_view)

    print("    dashboard_findings: CREATED")
    print("    dashboard_ai_analysis: CREATED")
    print("    dashboard_cve_intelligence: CREATED")


# ============================================================
# DATABASE VERIFICATION
# ============================================================

def verify_database():

    print("\n========== DATABASE VERIFICATION ==========")

    query = """
    SELECT 'Findings' AS dataset, COUNT(*)
    FROM findings

    UNION ALL

    SELECT 'CVE Intelligence', COUNT(*)
    FROM cve_intelligence

    UNION ALL

    SELECT 'AI Analysis', COUNT(*)
    FROM ai_analysis;
    """

    print(run_sql(query))

    print("\nFindings by asset:")

    print(run_sql("""
        SELECT
            asset,
            COUNT(*) AS findings
        FROM dashboard_findings
        GROUP BY asset
        ORDER BY findings DESC;
    """))


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 60)
    print("       PATCHPROOF POSTGRESQL DATA IMPORTER")
    print("=" * 60)

    print("\n[+] Checking PostgreSQL connection...")

    run_sql("SELECT 1;")

    print("[+] PostgreSQL connection successful")

    for table, source in TABLES.items():
        import_table(table, source)

    create_views()

    verify_database()

    print("\n" + "=" * 60)
    print("       PATCHPROOF IMPORT COMPLETED")
    print("=" * 60)

    print("\n[+] PostgreSQL tables populated")
    print("[+] Grafana reporting views available")
    print("[+] Ready for dashboard development")


if __name__ == "__main__":
    main()
