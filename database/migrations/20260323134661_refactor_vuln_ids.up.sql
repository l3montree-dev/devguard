-- This migration script migrates the id columns of the 3 vuln tables dependency_vulns, first_party_vulnerabilities and license_risk.
-- Previously the id was a 256 bit hash stored as a text -> Now its only a 128 bit hash stored as a uuid 
-- This leads to 1/4 of the disk space required and performance improvements regarding internal processing of UUIDs in comparison to text


-- dependency vulns
BEGIN;

-- add new uuid column

ALTER TABLE public.dependency_vulns ADD COLUMN new_id UUID;

-- transform and copy old values to new column

UPDATE public.dependency_vulns SET new_id= substring(id,1,32)::UUID;

-- do the same for the artifact_dependency_vulns pivot table

ALTER TABLE public.artifact_dependency_vulns ADD COLUMN new_dependency_vuln_id UUID;

UPDATE public.artifact_dependency_vulns SET new_dependency_vuln_id = substring(dependency_vuln_id,1,32)::UUID;

-- Drop the previous primary key of artifact dependency vulns table

ALTER TABLE public.artifact_dependency_vulns DROP CONSTRAINT artifact_dependency_vulns_pkey;

-- now we can drop the old dependency vuln id column in the pivot table

ALTER TABLE public.artifact_dependency_vulns DROP COLUMN dependency_vuln_id;

-- rebuild the primary key of the artifact pivot table with the new column

ALTER TABLE public.artifact_dependency_vulns ADD PRIMARY KEY (artifact_artifact_name,artifact_asset_version_name,artifact_asset_id,new_dependency_vuln_id);

-- now we can drop the primary key of the dependency vuln table

ALTER TABLE public.dependency_vulns DROP CONSTRAINT dependency_vulns_pkey;

-- Drop the old pkey of dependency vulns

ALTER TABLE public.dependency_vulns DROP COLUMN id;

-- now we can add the new primary key

ALTER TABLE public.dependency_vulns ADD PRIMARY KEY (new_id);

-- lastly re-add the foreign keys

ALTER TABLE public.artifact_dependency_vulns ADD FOREIGN KEY (new_dependency_vuln_id) REFERENCES public.dependency_vulns (new_id);

-- Finally rename columns in clean up process
ALTER TABLE public.dependency_vulns RENAME COLUMN new_id TO id;
ALTER TABLE public.artifact_dependency_vulns RENAME COLUMN new_dependency_vuln_id TO dependency_vuln_id;


COMMIT;


-- first party vulns

BEGIN;

-- add new uuid column

ALTER TABLE public.first_party_vulnerabilities ADD COLUMN new_id UUID;

-- transform and copy old values to new column

UPDATE public.first_party_vulnerabilities SET new_id= substring(id,1,32)::UUID;


-- now we can drop the primary key of the first_party_vulnerabilities table

ALTER TABLE public.first_party_vulnerabilities DROP CONSTRAINT first_party_vulnerabilities_pkey;

-- Drop the old pkey of dependency vulns

ALTER TABLE public.first_party_vulnerabilities DROP COLUMN id;

-- now we can add the new primary key

ALTER TABLE public.first_party_vulnerabilities ADD PRIMARY KEY (new_id);


-- Finally rename columns in clean up process
ALTER TABLE public.first_party_vulnerabilities RENAME COLUMN new_id TO id;


COMMIT;


-- license risks


BEGIN;

-- add new uuid column

ALTER TABLE public.license_risks ADD COLUMN new_id UUID;

-- transform and copy old values to new column

UPDATE public.license_risks SET new_id = substring(id,1,32)::UUID;

-- do the same for the artifact_license_risks pivot table

ALTER TABLE public.artifact_license_risks ADD COLUMN new_license_risk_id UUID;

UPDATE public.artifact_license_risks SET new_license_risk_id = substring(license_risk_id,1,32)::UUID;

-- Drop the previous primary key of artifact_license_risks table

ALTER TABLE public.artifact_license_risks DROP CONSTRAINT artifact_license_risks_pkey;

-- now we can drop the old license_risks id column in the pivot table

ALTER TABLE public.artifact_license_risks DROP COLUMN license_risk_id;

-- rebuild the primary key of the artifact_license_risks pivot table with the new column

ALTER TABLE public.artifact_license_risks ADD PRIMARY KEY (artifact_artifact_name,artifact_asset_version_name,artifact_asset_id,new_license_risk_id);

-- now we can drop the primary key of the license_risks table

ALTER TABLE public.license_risks DROP CONSTRAINT license_risks_pkey;

-- Drop the old pkey of license_risks

ALTER TABLE public.license_risks DROP COLUMN id;

-- now we can add the new primary key

ALTER TABLE public.license_risks ADD PRIMARY KEY (new_id);

-- lastly re-add the foreign keys

ALTER TABLE public.artifact_license_risks ADD FOREIGN KEY (new_license_risk_id) REFERENCES public.license_risks (new_id);

-- Finally rename columns in clean up process
ALTER TABLE public.license_risks RENAME COLUMN new_id TO id;
ALTER TABLE public.artifact_license_risks RENAME COLUMN new_license_risk_id TO license_risk_id;


COMMIT;


-- Create indexes at the end
DROP INDEX CONCURRENTLY IF EXISTS idx_artifact_dependency_vulns_dependency_vuln_id;
CREATE INDEX CONCURRENTLY idx_artifact_dependency_vulns_dependency_vuln_id ON public.artifact_dependency_vulns USING btree (dependency_vuln_id);

DROP INDEX CONCURRENTLY IF EXISTS idx_dependency_vulns_cve_id;
CREATE INDEX CONCURRENTLY idx_dependency_vulns_cve_id ON public.dependency_vulns USING btree (cve_id);

DROP INDEX CONCURRENTLY IF EXISTS idx_dependency_vulns_component_purl;
CREATE INDEX CONCURRENTLY idx_dependency_vulns_component_purl ON public.dependency_vulns USING btree (component_purl);

DROP INDEX CONCURRENTLY IF EXISTS idx_artifact_license_risks_license_risk_id;
CREATE INDEX CONCURRENTLY idx_artifact_license_risks_license_risk_id ON public.artifact_license_risks USING btree (license_risk_id);

DROP INDEX CONCURRENTLY IF EXISTS idx_license_risks_component_purl;
CREATE INDEX CONCURRENTLY idx_license_risks_component_purl ON public.license_risks USING btree (component_purl);