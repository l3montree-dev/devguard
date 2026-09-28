DROP INDEX IF EXISTS idx_sbom_asset_version;

ALTER TABLE public.sboms DROP CONSTRAINT sboms_pkey;
ALTER TABLE public.sboms ADD PRIMARY KEY (asset_id, asset_version_name, artifact_name,source);