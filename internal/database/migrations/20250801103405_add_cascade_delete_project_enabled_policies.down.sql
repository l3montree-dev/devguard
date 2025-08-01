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

-- Down migration: Revert cascade delete constraint on project_enabled_policies table
-- This removes the CASCADE DELETE behavior and restores the original foreign key constraints

-- Drop the CASCADE DELETE foreign key constraints
ALTER TABLE project_enabled_policies 
DROP CONSTRAINT IF EXISTS fk_project_enabled_policies_project;

ALTER TABLE project_enabled_policies 
DROP CONSTRAINT IF EXISTS fk_project_enabled_policies_policy;

-- Add back the original foreign key constraints without CASCADE DELETE
ALTER TABLE project_enabled_policies 
ADD CONSTRAINT fk_project_enabled_policies_project 
FOREIGN KEY (project_id) REFERENCES projects(id);

ALTER TABLE project_enabled_policies 
ADD CONSTRAINT fk_project_enabled_policies_policy 
FOREIGN KEY (policy_id) REFERENCES policies(id);
