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

-- Drop the existing constraint
ALTER TABLE public.artifact_dependency_vulns
DROP CONSTRAINT fk_artifact_dependency_vulns_dependency_vuln;

-- Recreate the constraint with ON UPDATE CASCADE
ALTER TABLE public.artifact_dependency_vulns
ADD CONSTRAINT fk_artifact_dependency_vulns_dependency_vuln
FOREIGN KEY (dependency_vuln_id) REFERENCES public.dependency_vulns(id)
ON UPDATE CASCADE
ON DELETE CASCADE;
