-- This migration script migrates the id columns of the 3 vuln tables dependency_vulns, first_party_vulnerabilities and license_risk.
-- Previously the id was a 256 bit hash stored as a text -> Now its only a 128 bit hash stored as a uuid 
-- This leads to 1/4 of the disk space required and performance improvements regarding internal processing of UUIDs in comparison to text


-- dependency vulns
BEGIN;

-- add new uuid column

ALTER TABLE dependency_vulns ADD COLUMN new_id UUID;

-- transform and copy old values to new column

UPDATE dependency_vulns SET new_id= substring(id,1,32)::UUID;

-- do the same for the artifact_dependency_vulns pivot table

ALTER TABLE artifact_dependency_vulns ADD COLUMN new_dependency_vuln_id UUID;

UPDATE artifact_dependency_vulns SET new_dependency_vuln_id = substring(dependency_vuln_id,1,32)::UUID;

-- Drop the previous primary key of artifact dependency vulns table

ALTER TABLE artifact_dependency_vulns DROP CONSTRAINT artifact_dependency_vulns_pkey;

-- now we can drop the old dependency vuln id column in the pivot table

ALTER TABLE artifact_dependency_vulns DROP COLUMN dependency_vuln_id;

-- rebuild the primary key of the artifact pivot table with the new column

ALTER TABLE artifact_dependency_vulns ADD PRIMARY KEY (artifact_artifact_name,artifact_asset_version_name,artifact_asset_id,new_dependency_vuln_id);

-- now we can drop the primary key of the dependency vuln table

ALTER TABLE dependency_vulns DROP CONSTRAINT dependency_vulns_pkey;

-- Drop the old pkey of dependency vulns

ALTER TABLE dependency_vulns DROP COLUMN id;

-- now we can add the new primary key

ALTER TABLE dependency_vulns ADD PRIMARY KEY (new_id);

-- lastly re-add the foreign keys

ALTER TABLE artifact_dependency_vulns ADD FOREIGN KEY (new_dependency_vuln_id) REFERENCES dependency_vulns (new_id);

-- Finally rename columns in clean up process
ALTER TABLE dependency_vulns RENAME COLUMN new_id TO id;
ALTER TABLE artifact_dependency_vulns RENAME COLUMN new_dependency_vuln_id TO dependency_vuln_id;


COMMIT;


-- first party vulns

BEGIN;

-- add new uuid column

ALTER TABLE first_party_vulnerabilities ADD COLUMN new_id UUID;

-- transform and copy old values to new column

UPDATE first_party_vulnerabilities SET new_id= substring(id,1,32)::UUID;


-- now we can drop the primary key of the first_party_vulnerabilities table

ALTER TABLE first_party_vulnerabilities DROP CONSTRAINT first_party_vulnerabilities_pkey;

-- Drop the old pkey of dependency vulns

ALTER TABLE first_party_vulnerabilities DROP COLUMN id;

-- now we can add the new primary key

ALTER TABLE first_party_vulnerabilities ADD PRIMARY KEY (new_id);


-- Finally rename columns in clean up process
ALTER TABLE first_party_vulnerabilities RENAME COLUMN new_id TO id;


COMMIT;


-- license risks


BEGIN;

-- add new uuid column

ALTER TABLE license_risks ADD COLUMN new_id UUID;

-- transform and copy old values to new column

UPDATE license_risks SET new_id = substring(id,1,32)::UUID;

-- do the same for the artifact_license_risks pivot table
 
ALTER TABLE artifact_license_risks ADD COLUMN new_license_risk_id UUID;

UPDATE artifact_license_risks SET new_license_risk_id = substring(license_risk_id,1,32)::UUID;

-- Drop the previous primary key of artifact_license_risks table

ALTER TABLE artifact_license_risks DROP CONSTRAINT artifact_license_risks_pkey;

-- now we can drop the old license_risks id column in the pivot table

ALTER TABLE artifact_license_risks DROP COLUMN license_risk_id;

-- rebuild the primary key of the artifact_license_risks pivot table with the new column

ALTER TABLE artifact_license_risks ADD PRIMARY KEY (artifact_artifact_name,artifact_asset_version_name,artifact_asset_id,new_license_risk_id);

-- now we can drop the primary key of the license_risks table

ALTER TABLE license_risks DROP CONSTRAINT license_risks_pkey;

-- Drop the old pkey of license_risks

ALTER TABLE license_risks DROP COLUMN id;

-- now we can add the new primary key

ALTER TABLE license_risks ADD PRIMARY KEY (new_id);

-- lastly re-add the foreign keys

ALTER TABLE artifact_license_risks ADD FOREIGN KEY (new_license_risk_id) REFERENCES license_risks (new_id);

-- Finally rename columns in clean up process
ALTER TABLE license_risks RENAME COLUMN new_id TO id;
ALTER TABLE artifact_license_risks RENAME COLUMN new_license_risk_id TO license_risk_id;


COMMIT;