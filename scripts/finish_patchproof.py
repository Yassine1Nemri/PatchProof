#!/usr/bin/env python3
"""PatchProof executive reporting: evidence-backed, refreshable PostgreSQL views.
Requires existing tables: findings, cve_intelligence, ai_analysis.
Uses docker exec; no external Python packages. Does not change scanner source data.
"""
import argparse
import subprocess
import sys
from pathlib import Path

CONTAINER = 'patchproof-postgres'
DB = 'patchproof'
USER = 'patchproof'

def sql(statement):
    p = subprocess.run(['docker','exec','-i',CONTAINER,'psql','-X','-v','ON_ERROR_STOP=1','-U',USER,'-d',DB], input=statement, text=True, capture_output=True)
    if p.returncode:
        raise RuntimeError(p.stderr.strip() or p.stdout.strip())
    return p.stdout.strip()

MIGRATION = r'''
BEGIN;
CREATE TABLE IF NOT EXISTS pp_assets (
 asset TEXT PRIMARY KEY, criticality TEXT NOT NULL, asset_class TEXT NOT NULL,
 description TEXT NOT NULL, CONSTRAINT class_valid CHECK (asset_class IN ('operational','training'))
);
INSERT INTO pp_assets(asset,criticality,asset_class,description) VALUES
 ('DC01','Critical','operational','Domain controller / DNS / DHCP'),
 ('WEB01','High','operational','Ubuntu Apache / Flask'),
 ('WIN-CL','Medium','operational','Windows workstation'),
 ('MS2','Low','training','Intentionally vulnerable Metasploitable 2')
ON CONFLICT(asset) DO NOTHING;

CREATE TABLE IF NOT EXISTS pp_assessments (
 asset TEXT PRIMARY KEY REFERENCES pp_assets(asset),
 coverage TEXT NOT NULL CHECK(coverage IN ('complete','partial','gap')),
 evidence TEXT NOT NULL,
 updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO pp_assessments(asset,coverage,evidence) VALUES
 ('DC01','partial','Greenbone imported; Nessus authenticated results not imported'),
 ('WEB01','partial','Greenbone and ZAP imported; Nessus authenticated results not imported'),
 ('WIN-CL','gap','Greenbone CSV returned no findings; Nessus authentication failed')
ON CONFLICT(asset) DO NOTHING;

CREATE TABLE IF NOT EXISTS pp_actions (
 scanner TEXT NOT NULL, finding_id TEXT NOT NULL, asset TEXT NOT NULL REFERENCES pp_assets(asset),
 state TEXT NOT NULL DEFAULT 'needs_review' CHECK (state IN ('needs_review','planned','in_progress','mitigated','verified','risk_accepted')),
 owner TEXT, note TEXT,
 updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 PRIMARY KEY(scanner,finding_id)
);
-- Seed actionable inventory without asserting confirmation or completed remediation.
INSERT INTO pp_actions(scanner,finding_id,asset)
 SELECT f.scanner,f.finding_id,f.asset
 FROM findings f INNER JOIN pp_assets a ON a.asset=f.asset
 WHERE a.asset_class='operational' AND NULLIF(f.finding_id,'') IS NOT NULL
ON CONFLICT(scanner,finding_id) DO NOTHING;

CREATE TABLE IF NOT EXISTS pp_verifications (
 id BIGSERIAL PRIMARY KEY,
 scanner TEXT NOT NULL,
 finding_id TEXT NOT NULL,
 evidence_ref TEXT NOT NULL CHECK(length(trim(evidence_ref))>4),
 analyst TEXT NOT NULL CHECK(length(trim(analyst))>1),
 verified_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 FOREIGN KEY(scanner,finding_id) REFERENCES pp_actions(scanner,finding_id)
);
CREATE UNIQUE INDEX IF NOT EXISTS pp_verification_unique ON pp_verifications(scanner,finding_id);

CREATE OR REPLACE VIEW pp_exec_exposure AS
 SELECT COUNT(*)::INTEGER AS requiring_review
 FROM pp_actions WHERE state NOT IN ('verified','risk_accepted');

CREATE OR REPLACE VIEW pp_exec_assurance AS
 SELECT a.asset, a.criticality, s.coverage,
 CASE s.coverage WHEN 'complete' THEN 100 WHEN 'partial' THEN 50 ELSE 0 END AS coverage_indicator,
 s.evidence, s.updated_at
 FROM pp_assets a JOIN pp_assessments s ON s.asset=a.asset
 WHERE a.asset_class='operational';
-- Indicator is a three-category UI encoding, NOT % of completed scans.

CREATE OR REPLACE VIEW pp_exec_kev AS
 SELECT a.asset_class,COUNT(DISTINCT c.cve)::INTEGER AS unique_kev_cves
 FROM pp_assets a LEFT JOIN cve_intelligence c ON c.asset=a.asset AND c.kev='Yes'
 GROUP BY a.asset_class;

CREATE OR REPLACE VIEW pp_exec_remediation AS
 SELECT COUNT(*)::INTEGER AS operational_actions,
 COUNT(*) FILTER (WHERE state='verified' AND EXISTS
   (SELECT 1 FROM pp_verifications v WHERE v.scanner=pp_actions.scanner AND v.finding_id=pp_actions.finding_id))::INTEGER AS verified_with_evidence,
 COUNT(*) FILTER (WHERE state='risk_accepted')::INTEGER AS documented_acceptances
 FROM pp_actions;
COMMIT;
'''

def quoted(value):
    return "'"+str(value).replace("'","''")+"'"

def setup():
    print(sql(MIGRATION))
    print('\nExecutive data views created. Current state:')
    print(sql('SELECT * FROM pp_exec_exposure; SELECT * FROM pp_exec_assurance; SELECT * FROM pp_exec_kev; SELECT * FROM pp_exec_remediation;'))

def coverage(args):
    if args.asset not in {'DC01','WEB01','WIN-CL'}:
        raise ValueError('Coverage updates apply to DC01, WEB01 or WIN-CL.')
    if not args.evidence.strip():
        raise ValueError('Include actual scan coverage evidence.')
    print(sql(f"INSERT INTO pp_assessments(asset,coverage,evidence,updated_at) VALUES ({quoted(args.asset)},{quoted(args.level)},{quoted(args.evidence)},now()) ON CONFLICT(asset) DO UPDATE SET coverage=EXCLUDED.coverage,evidence=EXCLUDED.evidence,updated_at=now();"))

def action(args):
    if args.state == 'verified':
        raise ValueError('Use verify command with rescan evidence; verified cannot be set directly.')
    print(sql(f"UPDATE pp_actions SET state={quoted(args.state)},owner={quoted(args.owner or '')},note={quoted(args.note or '')},updated_at=now() WHERE scanner={quoted(args.scanner)} AND finding_id={quoted(args.finding_id)}; SELECT COUNT(*) AS matching_actions FROM pp_actions WHERE scanner={quoted(args.scanner)} AND finding_id={quoted(args.finding_id)};"))

def verify(args):
    if not Path(args.evidence).exists():
        raise ValueError('Evidence file must exist on the Ubuntu host; use a real post-remediation report path.')
    if len(args.analyst.strip()) < 2:
        raise ValueError('Analyst is required.')
    # Verify exact key; a human must review post-rescan evidence before invoking.
    statement = f'''BEGIN;
INSERT INTO pp_verifications(scanner,finding_id,evidence_ref,analyst)
 VALUES ({quoted(args.scanner)},{quoted(args.finding_id)},{quoted(args.evidence)},{quoted(args.analyst)})
 ON CONFLICT(scanner,finding_id) DO UPDATE SET evidence_ref=excluded.evidence_ref,analyst=excluded.analyst,verified_at=now();
UPDATE pp_actions SET state='verified',updated_at=now()
 WHERE scanner={quoted(args.scanner)} AND finding_id={quoted(args.finding_id)};
COMMIT;'''
    print(sql(statement))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='PatchProof executive dashboard data')
    subs = parser.add_subparsers(dest='command',required=True)
    subs.add_parser('setup',help='Create dynamic PostgreSQL views and tracking tables')
    c=subs.add_parser('coverage',help='Update a documented asset coverage assessment')
    c.add_argument('--asset',required=True)
    c.add_argument('--level',required=True,choices=['complete','partial','gap'])
    c.add_argument('--evidence',required=True)
    a=subs.add_parser('action',help='Update a remediation action (not verified)')
    a.add_argument('--scanner',required=True)
    a.add_argument('--finding-id',required=True)
    a.add_argument('--state',required=True,choices=['needs_review','planned','in_progress','mitigated','risk_accepted'])
    a.add_argument('--owner',default='')
    a.add_argument('--note',default='')
    v=subs.add_parser('verify',help='Mark verified with an existing rescanned evidence file')
    v.add_argument('--scanner',required=True)
    v.add_argument('--finding-id',required=True)
    v.add_argument('--evidence',required=True)
    v.add_argument('--analyst',required=True)
    opts=parser.parse_args()
    try:
        {'setup':lambda:setup(),'coverage':lambda:coverage(opts),'action':lambda:action(opts),'verify':lambda:verify(opts)}[opts.command]()
    except Exception as ex:
        print(f'ERROR: {ex}',file=sys.stderr)
        sys.exit(1)
