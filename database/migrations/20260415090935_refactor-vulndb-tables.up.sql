-- Drop unused columns from affected_components table to save memory and improve query speed

ALTER TABLE public.affected_components DROP COLUMN IF EXISTS source; --source is currently always osv 

-- Drop all purl information duplicates
ALTER TABLE public.affected_components DROP COLUMN IF EXISTS scheme;
ALTER TABLE public.affected_components DROP COLUMN IF EXISTS type;
ALTER TABLE public.affected_components DROP COLUMN IF EXISTS name;
ALTER TABLE public.affected_components DROP COLUMN IF EXISTS namespace;
ALTER TABLE public.affected_components DROP COLUMN IF EXISTS qualifiers;

-- Drop left over index
DROP INDEX IF EXISTS idx_affected_components_p_url; -- duplicate

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
ALTER TABLE public.cve_affected_component ADD PRIMARY KEY (new_affected_component_id, cvecve);

-- finally rename columns to keep database consistent
ALTER TABLE public.affected_components RENAME COLUMN new_id TO id;
ALTER TABLE public.cve_affected_component RENAME COLUMN new_affected_component_id TO affected_component_id;

-- then once everything is done re-add the foreign key constraints 
ALTER TABLE public.cve_affected_component
  ADD CONSTRAINT fk_cve_affected_component_affected_component
  FOREIGN KEY (affected_component_id)
  REFERENCES public.affected_components(id)
  ON DELETE CASCADE;