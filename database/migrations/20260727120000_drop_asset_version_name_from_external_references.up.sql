DROP INDEX IF EXISTS public.idx_external_refs_asset_version;

ALTER TABLE public.external_references DROP CONSTRAINT IF EXISTS external_references_pkey;

ALTER TABLE public.external_references DROP COLUMN IF EXISTS asset_version_name;

ALTER TABLE public.external_references ADD PRIMARY KEY (asset_id, url);
