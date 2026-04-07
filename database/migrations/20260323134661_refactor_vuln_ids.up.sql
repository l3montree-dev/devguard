-- This migration script migrates the id columns of the 3 vuln tables dependency_vulns, first_party_vulnerabilities and license_risk.
-- Previously the id was a 256 bit hash stored as a text -> Now its only a 128 bit hash stored as a uuid 
-- This leads to 1/4 of the disk space required and performance improvements regarding internal processing of UUIDs in comparison to text


-- dependency vulns

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



-- first party vulns

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


-- license risks


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


-- In the second step we adjust the vuln_event table 

-- Drop updated_at column to save space since vuln_events are immutable
ALTER TABLE public.vuln_events DROP COLUMN IF EXISTS updated_at;

-- Now we want to migrate the existing single vuln_id column to 3 columns referencing the respective vuln id column

-- first create the new rows referencing the id columns
ALTER TABLE public.vuln_events
  ADD COLUMN dependency_vuln_id   UUID REFERENCES public.dependency_vulns(id)        ON DELETE CASCADE,
  ADD COLUMN license_risk_id      UUID REFERENCES public.license_risks(id)           ON DELETE CASCADE,
  ADD COLUMN first_party_vuln_id  UUID REFERENCES public.first_party_vulnerabilities(id) ON DELETE CASCADE;

-- then transform and copy the old values into the new columns

UPDATE public.vuln_events SET dependency_vuln_id  = substring(vuln_id,1,32)::UUID WHERE vuln_type = 'dependencyVuln';
UPDATE public.vuln_events SET license_risk_id     = substring(vuln_id,1,32)::UUID WHERE vuln_type = 'licenseRisk';
UPDATE public.vuln_events SET first_party_vuln_id = substring(vuln_id,1,32)::UUID WHERE vuln_type = 'firstPartyVuln';

-- add constraint to check that each vuln event has exactly one vuln_id as parent but don't validate yet

ALTER TABLE public.vuln_events ADD CONSTRAINT one_vuln_parent CHECK (
  (dependency_vuln_id  IS NOT NULL)::int +
  (license_risk_id     IS NOT NULL)::int +
  (first_party_vuln_id IS NOT NULL)::int = 1
);

-- lastly drop the old columns
ALTER TABLE public.vuln_events
  DROP COLUMN vuln_id,
  DROP COLUMN vuln_type;


-- Refactor the indexes at the end

-- First drop all obsolete/outdated ones

DROP INDEX IF EXISTS vuln_events_new_vuln_id_idx; --old vuln_events vuln id idx

DROP INDEX IF EXISTS vuln_events_new_type_vuln_id_vuln_type_justification_id_idx; -- 3 obsolete indexes 
DROP INDEX IF EXISTS idx_first_party_vulnerabilities_deleted_at; 
DROP INDEX IF EXISTS idx_license_risks_deleted_at;

DROP INDEX idx_artifact_dependency_vulns_dependency_vuln_id; -- covered by primary key index
DROP INDEX idx_artifact_license_risks_artifact; -- covered by primary key index

-- then create the new vuln event indexes

CREATE INDEX idx_vuln_events_dependency_vuln_id
  ON public.vuln_events USING hash (dependency_vuln_id)
  WHERE dependency_vuln_id IS NOT NULL;

CREATE INDEX idx_vuln_events_first_party_vuln_id
  ON public.vuln_events USING hash (first_party_vuln_id)
  WHERE first_party_vuln_id IS NOT NULL;

CREATE INDEX idx_vuln_events_license_risk_id
  ON public.vuln_events USING hash (license_risk_id)
  WHERE license_risk_id IS NOT NULL;


-- then create indexes for the vuln pivot tables

DROP INDEX IF EXISTS public.idx_artifact_dependency_vulns_dependency_vuln_id;
CREATE INDEX idx_artifact_dependency_vulns_dependency_vuln_id ON public.artifact_dependency_vulns USING hash (dependency_vuln_id);

DROP INDEX IF EXISTS public.idx_artifact_license_risks_license_risk_id;
CREATE INDEX idx_artifact_license_risks_license_risk_id ON public.artifact_license_risks USING hash (license_risk_id);
