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

-- Migration: Add cascade delete constraint to project_enabled_policies table
-- This ensures that when a project is deleted, all related entries in the project_enabled_policies join table are automatically deleted

-- Drop existing foreign key constraints (if they exist)
ALTER TABLE public.project_enabled_policies 
DROP CONSTRAINT IF EXISTS fk_project_enabled_policies_project;

ALTER TABLE public.project_enabled_policies 
DROP CONSTRAINT IF EXISTS fk_project_enabled_policies_policy;

-- Add the foreign key constraint for project_id with CASCADE DELETE
ALTER TABLE public.project_enabled_policies 
ADD CONSTRAINT fk_project_enabled_policies_project 
FOREIGN KEY (project_id) REFERENCES public.projects(id) ON DELETE CASCADE;

-- Add the foreign key constraint for policy_id with CASCADE DELETE  
ALTER TABLE public.project_enabled_policies 
ADD CONSTRAINT fk_project_enabled_policies_policy 
FOREIGN KEY (policy_id) REFERENCES public.policies(id) ON DELETE CASCADE;
