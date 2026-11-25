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

-- asset versions are addressed by their slug in URLs, so it has to be unique per asset.
-- slug.Make maps different names to the same slug (e.g. "feature/foo" and "feature-foo"):
-- the oldest asset version keeps the slug, every other one gets the first free "-<n>" suffix, like assets do.
DO $$
DECLARE
    duplicate RECORD;
    candidate text;
    suffix int;
BEGIN
    FOR duplicate IN
        SELECT id, asset_id, slug FROM (
            SELECT id, asset_id, slug, row_number() OVER (PARTITION BY asset_id, slug ORDER BY created_at, id) AS position
            FROM public.asset_versions
        ) ranked
        WHERE position > 1
    LOOP
        suffix := 1;
        LOOP
            candidate := duplicate.slug || '-' || suffix;
            EXIT WHEN NOT EXISTS (SELECT 1 FROM public.asset_versions WHERE asset_id = duplicate.asset_id AND slug = candidate);
            suffix := suffix + 1;
        END LOOP;
        UPDATE public.asset_versions SET slug = candidate WHERE id = duplicate.id;
    END LOOP;
END $$;

ALTER TABLE public.asset_versions ADD CONSTRAINT asset_versions_asset_id_slug_unique UNIQUE (asset_id, slug);
