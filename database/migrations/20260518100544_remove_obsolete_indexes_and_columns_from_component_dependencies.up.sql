ALTER TABLE public.component_dependencies
DROP COLUMN IF EXISTS semver_start,
DROP COLUMN IF EXISTS semver_end;

DROP INDEX IF EXISTS idx_component_dependencies_component_purl; 
DROP INDEX IF EXISTS component_purl_idx;
DROP INDEX IF EXISTS asset_version_name_idx; 
DROP INDEX IF EXISTS idx_component_dependencies_dependency_purl;
DROP INDEX IF EXISTS idx_component_dependencies_null_roots;
DROP INDEX IF EXISTS asset_id_idx;
DROP INDEX IF EXISTS idx_component_dependencies_component_id;
DROP INDEX IF EXISTS idx_component_dependencies_dependency_id;
DROP INDEX IF EXISTS idx_component_dependencies_recursive_lookup;
DROP INDEX IF EXISTS dependency_purl_idx;

-- remove the current id column and replace it with a composite key on all columns to make enforce deduplication on a data level and reduce complexity (also on indexes)

-- currently component_id can be NULL if its a root node; but primary keys cannot contain NULL values, so we replace it with a ROOT constant
INSERT INTO public.components VALUES('ROOT','',NULL,NULL,NULL); -- add a ROOT component to the components table to be referenced
UPDATE public.component_dependencies SET component_id = 'ROOT' WHERE component_id IS NULL; -- use an explicit value for ROOT component dependencies instead of NULL

ALTER TABLE public.component_dependencies DROP CONSTRAINT component_dependencies_pkey, DROP COLUMN id; -- drop primary key constraint and the primary key column

 -- remove all duplicate entries from the table so that the new primary key does not fail on creation
DELETE FROM public.component_dependencies a
USING public.component_dependencies b
WHERE a.ctid < b.ctid -- use the internal column id to choose only 1 candidate per duplicate row
AND a.asset_id = b.asset_id
AND a.asset_version_name = b.asset_version_name
AND a.dependency_id = b.dependency_id
AND a.component_id = b.component_id;       

ALTER TABLE public.component_dependencies ADD PRIMARY KEY (asset_id, asset_version_name, dependency_id, component_id); -- add the new primary key consisting of all 4 attributes