INSERT INTO public.components (
    purl,
    component_type,
    version,
    license,
    published,
    project_key,
    is_license_overwritten
) VALUES (
    'DEFAULT',
    'library',
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
)
ON CONFLICT (purl) DO NOTHING;

INSERT INTO public.component_dependencies (component_purl, dependency_purl, asset_id, asset_version_name, depth)
SELECT DISTINCT
    NULL AS component_purl,
    'DEFAULT' AS dependency_purl,
    asset_id,
    asset_version_name,
    0 AS depth
FROM public.component_dependencies cd
WHERE NOT EXISTS (
    SELECT 1
    FROM public.component_dependencies existing
    WHERE existing.component_purl IS NULL
      AND existing.dependency_purl = 'DEFAULT'
      AND existing.asset_id = cd.asset_id
      AND existing.asset_version_name = cd.asset_version_name
);

UPDATE public.component_dependencies
SET component_purl = 'DEFAULT'
WHERE component_purl IS NULL
  AND dependency_purl != 'DEFAULT';




INSERT INTO public.artifact_component_dependencies (
    artifact_artifact_name,
    artifact_asset_version_name,
    artifact_asset_id,
    component_dependency_id
)
SELECT
    ad.artifact_name,
    ad.asset_version_name,
    ad.asset_id,
    ad.id
FROM (
SELECT artifact_name, artifacts.asset_id, artifacts.asset_version_name, id from component_dependencies
    left join public.artifacts ON artifacts.asset_id = component_dependencies.asset_id AND artifacts.asset_version_name = component_dependencies.asset_version_name
    WHERE component_purl IS NULL
    AND dependency_purl = 'DEFAULT'
) ad ON CONFLICT DO NOTHING