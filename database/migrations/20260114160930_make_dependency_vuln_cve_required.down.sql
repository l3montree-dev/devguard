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

-- Revert: Remove foreign key constraint
ALTER TABLE public.dependency_vulns
DROP CONSTRAINT IF EXISTS fk_dependency_vulns_cve;

-- Revert: Make columns nullable again
ALTER TABLE public.dependency_vulns
ALTER COLUMN component_purl DROP NOT NULL;

ALTER TABLE public.dependency_vulns
ALTER COLUMN cve_id DROP NOT NULL;

-- Restore default null
ALTER TABLE public.dependency_vulns
ALTER COLUMN cve_id SET DEFAULT NULL;

ALTER TABLE public.dependency_vulns
ALTER COLUMN component_purl SET DEFAULT NULL;
