DROP INDEX IF EXISTS public.idx_external_refs_asset_version;

ALTER TABLE public.external_references DROP CONSTRAINT IF EXISTS external_references_pkey;

ALTER TABLE public.external_references DROP COLUMN IF EXISTS asset_version_name;

-- Dropping asset_version_name can uncover rows that only differed by that column,
-- leaving duplicate (asset_id, url) pairs that would violate the new primary key.
-- Deduplicate before enforcing it, same approach as 20260712120000_external_reference_composite_key.
DELETE FROM public.external_references a
USING public.external_references b
WHERE a.ctid < b.ctid
AND a.asset_id = b.asset_id
AND a.url = b.url;

ALTER TABLE public.external_references ADD PRIMARY KEY (asset_id, url);
