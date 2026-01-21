-- Migration: Replace artifact_component_dependencies table with artifact: prefix pattern
--
-- New structure for component_dependencies:
--   - NULL in component_id identifies root nodes of an asset version
--   - artifact:{name} nodes are created as roots (component_id = NULL)
--   - Direct dependencies point to artifact:{name} nodes
--
-- Before: junction table artifact_component_dependencies linked artifacts to dependencies
-- After:  (NULL) -> artifact:{name} -> (direct dependencies)

-- Step 1: Create component entries for artifact roots
-- These are needed because dependency_id has a FK constraint to components.id
INSERT INTO public.components (id)
SELECT DISTINCT 'artifact:' || artifact_artifact_name
FROM public.artifact_component_dependencies
ON CONFLICT (id) DO NOTHING;

-- Step 2: Create artifact root node dependencies (NULL -> artifact:name)
INSERT INTO public.component_dependencies (id, component_id, dependency_id, asset_version_name, asset_id)
SELECT
    gen_random_uuid(),
    NULL,  -- root nodes have NULL component_id
    'artifact:' || unique_artifacts.artifact_artifact_name,
    unique_artifacts.artifact_asset_version_name,
    unique_artifacts.artifact_asset_id
FROM (
    SELECT DISTINCT
        artifact_artifact_name,
        artifact_asset_version_name,
        artifact_asset_id
    FROM public.artifact_component_dependencies
) AS unique_artifacts;

-- Step 3: Update existing dependencies that were root nodes (component_id IS NULL)
-- to point to their artifact root instead
-- These are the direct dependencies that the junction table linked to artifacts
UPDATE public.component_dependencies cd
SET component_id = 'artifact:' || acd.artifact_artifact_name
FROM public.artifact_component_dependencies acd
WHERE cd.id = acd.component_dependency_id
AND cd.component_id IS NULL;

-- Step 4: Drop the junction table indices
DROP INDEX IF EXISTS idx_artifact_component_dependencies_component_dependency_id;
DROP INDEX IF EXISTS idx_artifact_component_dependencies_artifact;

-- Step 5: Drop the junction table
DROP TABLE IF EXISTS public.artifact_component_dependencies;
