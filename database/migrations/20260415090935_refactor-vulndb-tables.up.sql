-- Drop unused columns from affected_components table to save memory and improve query speed

ALTER TABLE public.affected_components DROP COLUMN IF EXISTS source; --source is currently always osv 

-- Drop all purl information duplicates
ALTER TABLE public.affected_components DROP COLUMN IF EXISTS scheme;
ALTER TABLE public.affected_components DROP COLUMN IF EXISTS type;
ALTER TABLE public.affected_components DROP COLUMN IF EXISTS name;
ALTER TABLE public.affected_components DROP COLUMN IF EXISTS namespace;
ALTER TABLE public.affected_components DROP COLUMN IF EXISTS qualifiers;

-- refactor the affected components id to a bigint to optimize memory and performance in affected_components as well as in cve_affected_component

-- add the new id column as type bigint then copy and transform the existing values to it
ALTER TABLE public.affected_components ADD COLUMN new_id bigint; 
UPDATE public.affected_components SET new_id = ('x' || id)::bit(64)::bigInt; 

ALTER TABLE public.cve_affected_component ADD COLUMN new_affected_component_id bigint; 
UPDATE public.cve_affected_component SET new_affected_component_id = ('x' || affected_component_id)::bit(64)::bigInt; 

-- drop all foreign keys pointing to affected_component id
ALTER TABLE public.cve_affected_component DROP CONSTRAINT IF EXISTS fk_cve_affected_component_affected_component;

-- then drop all primary keys where affected_component_id appears in
ALTER TABLE public.affected_components DROP CONSTRAINT affected_components_pkey;
ALTER TABLE public.cve_affected_component DROP CONSTRAINT cve_affected_component_pkey;

-- now we can drop the old id columns
ALTER TABLE public.affected_components DROP COLUMN id;
ALTER TABLE public.cve_affected_component DROP COLUMN affected_component_id;

-- re-add the primary key constraint on both tables
ALTER TABLE public.affected_components ADD PRIMARY KEY (new_id);

-- finally rename columns to keep database consistent
ALTER TABLE public.affected_components RENAME COLUMN new_id TO id;
ALTER TABLE public.cve_affected_component RENAME COLUMN new_affected_component_id TO affected_component_id;

-- then once everything is done re-add the foreign key constraints 
ALTER TABLE public.cve_affected_component
  ADD CONSTRAINT fk_cve_affected_component_affected_component
  FOREIGN KEY (affected_component_id)
  REFERENCES public.affected_components(id)
  ON DELETE CASCADE;



-- Next step is changing the primary key of the cve table to a smaller datatype
ALTER TABLE public.cves ADD COLUMN id bigint;

UPDATE public.cves SET id = ('x' || substr(md5(cve), 1, 16))::bit(64)::bigint & x'7fffffffffffffff'::bigint;

ALTER TABLE public.cve_relationships DROP CONSTRAINT IF EXISTS fk_cve_relationships_source;
ALTER TABLE public.dependency_vulns DROP CONSTRAINT IF EXISTS fk_dependency_vulns_cve; 
ALTER TABLE public.exploits DROP CONSTRAINT IF EXISTS fk_cves_exploits;
ALTER TABLE public.weaknesses DROP CONSTRAINT IF EXISTS fk_cves_weaknesses;
ALTER TABLE public.vex_rules DROP CONSTRAINT IF EXISTS fk_vex_rules_cve;
ALTER TABLE public.cve_affected_component DROP CONSTRAINT IF EXISTS fk_cve_affected_component_cve;


ALTER TABLE public.cves DROP CONSTRAINT cves_pkey;

ALTER TABLE public.cves ADD PRIMARY KEY (id);

ALTER TABLE public.cves ADD CONSTRAINT cves_cve_unique UNIQUE (cve);


-- now adjust the pivot table accordingly


ALTER TABLE public.cve_affected_component ADD COLUMN new_cve_id bigint;

UPDATE public.cve_affected_component AS pivot
SET new_cve_id = cves.id
FROM public.cves
WHERE pivot.cvecve = cves.cve;


ALTER TABLE public.cve_affected_component ADD PRIMARY KEY (affected_component_id, new_cve_id);

ALTER TABLE public.cve_affected_component DROP COLUMN cvecve;

ALTER TABLE public.cve_affected_component RENAME COLUMN new_cve_id TO cve_id;

ALTER TABLE public.cve_affected_component ADD CONSTRAINT fk_cve_affected_component_cve FOREIGN KEY (cve_id) REFERENCES public.cves (id) ON DELETE CASCADE;
ALTER TABLE public.dependency_vulns ADD CONSTRAINT fk_dependency_vulns_cve FOREIGN KEY (cve_id) REFERENCES public.cves (cve) ON DELETE CASCADE; 
ALTER TABLE public.exploits ADD CONSTRAINT fk_cves_exploits FOREIGN KEY (cve_id) REFERENCES public.cves (cve) ON DELETE CASCADE;
ALTER TABLE public.weaknesses ADD CONSTRAINT fk_cves_weaknesses FOREIGN KEY (cve_id) REFERENCES public.cves(cve) ON DELETE CASCADE;
ALTER TABLE public.vex_rules ADD CONSTRAINT fk_vex_rules_cve FOREIGN KEY (cve_id) REFERENCES public.cves (cve) ON DELETE CASCADE;
ALTER TABLE public.cve_relationships ADD CONSTRAINT fk_cve_relationships_source FOREIGN KEY (source_cve) REFERENCES public.cves (cve) ON DELETE CASCADE;

-- Drop unnecessary indexes; we add more optimized ones at the end
DROP INDEX IF EXISTS public.idx_affected_components_semver_fixed;
DROP INDEX IF EXISTS public.idx_affected_components_semver_introduced;
DROP INDEX IF EXISTS public.idx_affected_components_version_fixed;
DROP INDEX IF EXISTS public.idx_affected_components_version_introduced;
DROP INDEX IF EXISTS public.idx_affected_components_p_url;
DROP INDEX IF EXISTS public.idx_affected_components_purl_without_version;
DROP INDEX IF EXISTS public.idx_affected_components_version;

CREATE INDEX IF NOT EXISTS cve_affected_component_cve_id ON public.cve_affected_component USING hash (cve_id);

-- re-add optimized indexes for affected_components table
CREATE INDEX idx_affected_component_purl_version
  		ON public.affected_components (purl, version);

CREATE INDEX idx_affected_component_purl_semver_range
  		ON public.affected_components (purl, semver_introduced, semver_fixed)
 		WHERE semver_introduced IS NOT NULL OR semver_fixed IS NOT NULL;