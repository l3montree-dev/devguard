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

-- Add foreign key constraints to cve_relationships table

-- Drop existing constraints if they exist
ALTER TABLE public.cve_relationships
DROP CONSTRAINT IF EXISTS fk_cve_relationships_source;

ALTER TABLE public.cve_relationships
DROP CONSTRAINT IF EXISTS fk_cve_relationships_target;

-- Add foreign key for source_cve with CASCADE
ALTER TABLE public.cve_relationships
ADD CONSTRAINT fk_cve_relationships_source
FOREIGN KEY (source_cve)
REFERENCES public.cves(cve)
ON DELETE CASCADE
ON UPDATE CASCADE;