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

ALTER TABLE public.components ADD COLUMN IF NOT EXISTS "tmp_purl" TEXT;

WITH normalized AS (
  SELECT
    purl AS old_purl,
    regexp_replace(
      purl,
      '@[^@?]+(?=[^@]*$)',
      '@' || version
    ) AS new_purl
  FROM public.components
  WHERE version IS NOT NULL
    AND version <> ''
    AND purl LIKE '%@%'
)
UPDATE public.components SET tmp_purl = (SELECT new_purl FROM normalized WHERE normalized.old_purl = public.components.purl);

UPDATE public.components SET tmp_purl = purl WHERE tmp_purl IS NULL;

WITH collisions AS (
  SELECT purl as "old", tmp_purl as "new" from public.components c1 where purl != tmp_purl AND EXISTS(SELECT 1 from public.components c2 where c2.purl = c1.tmp_purl)
)
UPDATE public.component_dependencies SET component_purl = col.new
FROM collisions col where public.component_dependencies.component_purl = col.old;

WITH collisions AS (
  SELECT purl as "old", tmp_purl as "new" from public.components c1 where purl != tmp_purl AND EXISTS(SELECT 1 from public.components c2 where c2.purl = c1.tmp_purl)
)
UPDATE public.component_dependencies SET dependency_purl = col.new FROM collisions col where public.component_dependencies.dependency_purl = col.old;


WITH collisions AS (
  SELECT purl as "old", tmp_purl as "new" from public.components c1 where purl != tmp_purl AND EXISTS(SELECT 1 from public.components c2 where c2.purl = c1.tmp_purl)
)
UPDATE public.dependency_vulns SET component_purl = col.new FROM collisions col where public.dependency_vulns.component_purl = col.old;

WITH collisions AS (
  SELECT purl as "old", tmp_purl as "new" from public.components c1 where purl != tmp_purl AND EXISTS(SELECT 1 from public.components c2 where c2.purl = c1.tmp_purl)
)
UPDATE public.license_risks SET component_purl = col.new FROM collisions col where public.license_risks.component_purl = col.old;


-- Drop the existing FK
ALTER TABLE public.component_dependencies
DROP CONSTRAINT fk_components_dependencies;

-- Recreate with ON UPDATE CASCADE
ALTER TABLE public.component_dependencies
ADD CONSTRAINT fk_components_dependencies
FOREIGN KEY (component_purl)
REFERENCES public.components(purl)
ON UPDATE CASCADE
ON DELETE CASCADE;

-- Drop the existing FK
ALTER TABLE public.component_dependencies
DROP CONSTRAINT fk_component_dependencies_dependency;

-- Recreate with ON UPDATE CASCADE
ALTER TABLE public.component_dependencies
ADD CONSTRAINT fk_component_dependencies_dependency
FOREIGN KEY (dependency_purl)
REFERENCES public.components(purl)
ON UPDATE CASCADE
ON DELETE CASCADE;

-- Drop existing FK
ALTER TABLE public.license_risks
DROP CONSTRAINT IF EXISTS fk_license_risks_component;

ALTER TABLE public.license_risks
DROP CONSTRAINT IF EXISTS component_fk;


-- Recreate with cascade rules
ALTER TABLE public.license_risks
ADD CONSTRAINT fk_license_risks_component
FOREIGN KEY (component_purl)
REFERENCES public.components(purl)
ON UPDATE CASCADE
ON DELETE CASCADE;

WITH ranked AS (
  SELECT
    purl,
    tmp_purl,
    ROW_NUMBER() OVER (PARTITION BY tmp_purl ORDER BY purl) AS "row_number"
  FROM public.components c1 where purl != tmp_purl AND not exists(SELECT 1 from public.components c2 where c2.purl = c1.tmp_purl)
)
UPDATE public.components t
SET purl = r.tmp_purl
FROM ranked r
WHERE t.purl = r.purl
  AND r.row_number = 1;  -- only update the first row per tmp_purl


WITH going_to_delete AS (
  select * from public.components where tmp_purl != purl
)
UPDATE public.dependency_vulns SET component_purl = going_to_delete.tmp_purl FROM going_to_delete WHERE public.dependency_vulns.component_purl = going_to_delete.purl;

WITH going_to_delete AS (
  select * from public.components where tmp_purl != purl
)
UPDATE public.license_risks SET component_purl = going_to_delete.tmp_purl FROM going_to_delete WHERE public.license_risks.component_purl = going_to_delete.purl;

WITH going_to_delete AS (
  select * from public.components where tmp_purl != purl
)
UPDATE public.component_dependencies SET component_purl = going_to_delete.tmp_purl FROM going_to_delete WHERE public.component_dependencies.component_purl = going_to_delete.purl;

WITH going_to_delete AS (
  select * from public.components where tmp_purl != purl
)
UPDATE public.component_dependencies SET dependency_purl = going_to_delete.tmp_purl FROM going_to_delete WHERE public.component_dependencies.dependency_purl = going_to_delete.purl;


DELETE from public.components where tmp_purl != purl;

DELETE FROM public.dependency_vulns WHERE NOT EXISTS(SELECT FROM components where component_purl = purl);

DELETE FROM public.vuln_events ve WHERE ve.vuln_type = 'dependencyVuln' AND NOT EXISTS (
    SELECT public.dependency_vulns.id FROM public.dependency_vulns WHERE public.dependency_vulns.id = ve.vuln_id
);

-- Recreate with cascade rules
ALTER TABLE public.dependency_vulns
ADD CONSTRAINT fk_dependency_vulns_component
FOREIGN KEY (component_purl)
REFERENCES public.components(purl)
ON UPDATE CASCADE
ON DELETE CASCADE;


ALTER TABLE public.components DROP COLUMN "version";
ALTER TABLE public.components DROP COLUMN "tmp_purl";