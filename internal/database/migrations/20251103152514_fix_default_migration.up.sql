-- Copyright (C) 2025 l3montree GmbH
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
DROP table IF EXISTS public.artifact_upstream_urls;

INSERT INTO public.components (
    purl,
    component_type,
    version,
    license,
    published,
    project_key,
    is_license_overwritten
) VALUES (
    'sbom:DEFAULT',
    'library',
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
)
ON CONFLICT (purl) DO NOTHING;


UPDATE public.component_dependencies
SET component_purl = 'sbom:DEFAULT'
WHERE component_purl = 'DEFAULT';

UPDATE public.component_dependencies
  SET dependency_purl = 'sbom:DEFAULT'
  WHERE dependency_purl = 'DEFAULT';
