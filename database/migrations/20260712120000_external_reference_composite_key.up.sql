-- Copyright (C) 2026 l3montree GmbH
--
-- This program is free software: you can redistribute it and/or modify
-- it under the terms of the GNU Affero General Public License as
-- published by the Free Software Foundation, either version 3 of the
-- License, or (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU Affero General Public License for more details.
--
-- You should have received a copy of the GNU Affero General Public License
-- along with this program.  If not, see <https://www.gnu.org/licenses/>.

-- The external reference is now identified by (asset_id, asset_version_name, url)
-- instead of a surrogate id, so that deletes can target a reference by its url.
ALTER TABLE public.external_references DROP CONSTRAINT IF EXISTS external_references_pkey;
ALTER TABLE public.external_references DROP COLUMN IF EXISTS id;
ALTER TABLE public.external_references DROP COLUMN IF EXISTS artifact_name;
ALTER TABLE public.external_references DROP COLUMN IF EXISTS source;
ALTER TABLE public.external_references DROP COLUMN IF EXISTS created_at;
ALTER TABLE public.external_references DROP COLUMN IF EXISTS updated_at;

ALTER TABLE public.external_references ADD COLUMN IF NOT EXISTS error TEXT;

-- Deduplicate before enforcing the composite primary key
DELETE FROM public.external_references a
USING public.external_references b
WHERE a.ctid < b.ctid
AND a.asset_id = b.asset_id
AND a.asset_version_name = b.asset_version_name
AND a.url = b.url;

ALTER TABLE public.external_references ADD PRIMARY KEY (asset_id, asset_version_name, url);
