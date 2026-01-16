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

-- Delete any dependency_vulns without a CVE (should not exist based on business logic)
DELETE FROM public.dependency_vulns WHERE cve_id IS NULL OR cve_id = '';

-- Make cve_id NOT NULL
ALTER TABLE public.dependency_vulns
ALTER COLUMN cve_id SET NOT NULL;

-- Make component_purl NOT NULL (dependency vulns must have a component)
ALTER TABLE public.dependency_vulns
ALTER COLUMN component_purl SET NOT NULL;

-- Drop any existing default null constraints
ALTER TABLE public.dependency_vulns
ALTER COLUMN cve_id DROP DEFAULT;

ALTER TABLE public.dependency_vulns
ALTER COLUMN component_purl DROP DEFAULT;

-- Add foreign key constraint to CVEs table
ALTER TABLE public.dependency_vulns
DROP CONSTRAINT IF EXISTS fk_dependency_vulns_cve;

ALTER TABLE public.dependency_vulns
ADD CONSTRAINT fk_dependency_vulns_cve
FOREIGN KEY (cve_id)
REFERENCES public.cves(cve)
ON DELETE CASCADE
ON UPDATE CASCADE;
