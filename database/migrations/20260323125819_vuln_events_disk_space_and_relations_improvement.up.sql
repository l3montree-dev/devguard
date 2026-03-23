-- Drop updated_at column to save space since vuln_events are immutable
ALTER TABLE vuln_events DROP COLUMN IF EXISTS updated_at;

-- Now we want to migrate the existing single vuln_id column to 3 columns referencing the respective vuln id column

-- first create the new rows referencing the id columns
ALTER TABLE vuln_events
  ADD COLUMN dependency_vuln_id   UUID REFERENCES dependency_vulns(id)        ON DELETE CASCADE,
  ADD COLUMN license_risk_id      UUID REFERENCES license_risks(id)           ON DELETE CASCADE,
  ADD COLUMN first_party_vuln_id  UUID REFERENCES first_party_vulnerabilities(id) ON DELETE CASCADE;

-- then transform and copy the old values into the new columns

UPDATE vuln_events SET dependency_vuln_id  = substring(vuln_id,1,32)::UUID WHERE vuln_type = 'dependencyVulns';
UPDATE vuln_events SET license_risk_id     = substring(vuln_id,1,32)::UUID WHERE vuln_type = 'licenseRisk';
UPDATE vuln_events SET first_party_vuln_id = substring(vuln_id,1,32)::UUID WHERE vuln_type = 'firstPartyVuln';

-- add constraint to check that each vuln event has exactly one vuln_id as parent

ALTER TABLE vuln_events ADD CONSTRAINT one_vuln_parent CHECK (
  (dependency_vuln_id  IS NOT NULL)::int +
  (license_risk_id     IS NOT NULL)::int +
  (first_party_vuln_id IS NOT NULL)::int = 1
);

-- lastly drop the old column

ALTER TABLE vuln_events
  DROP COLUMN vuln_id;
  DROP COLUMN vuln_type;